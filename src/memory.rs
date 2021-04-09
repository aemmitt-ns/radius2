use std::collections::HashMap;
use crate::r2_api::{R2Api, Endian};
use crate::value::Value;
use crate::boolector::{Btor, BV};
use std::rc::Rc;

const CHUNK: u64 = 8;

#[derive(Debug, Clone)]
pub struct Memory {
    pub mem: HashMap<u64, Value>,
    pub bits: u64,
    pub endian: Endian
}

impl Memory {

    pub fn read_value(&mut self, r2api: &mut R2Api, addr: u64, length: usize) -> Value {
        let data = self.read(r2api, addr, length);
        self.pack(&data)
    }

    pub fn write_value(&mut self, addr: u64, value: Value, length: usize) {
        let data = self.unpack(value, length);
        self.write(addr, &data)
    }

    /*pub fn read(&mut self, r2api: &mut R2Api, addr: u64, length: usize) -> Vec<Value> {
        let offset = addr % CHUNK;
        let maddr = addr - offset;
        let adjust = CHUNK - ((length as u64 + offset) % CHUNK);
        let chunks = (length as u64 + offset + adjust) / CHUNK;

        let mut data: Vec<Value> = vec!();
        let count = 0;

        while count < chunks {
            let caddr = maddr + count*CHUNK;
            let mem = self.mem.get(&caddr);
            match mem {
                Some(qword) => {
                    data.extend(qword.clone());
                },
                None => {
                    let mut new_data: Vec<Value> = vec!();
                    let bytes = r2api.read(caddr, CHUNK as usize);

                    for byte in bytes {
                        new_data.push(Value::Concrete(byte as u64));
                    }

                    self.mem.insert(caddr, new_data.clone());
                    data.extend(new_data);
                }
            }
        }

        data
    }*/

    pub fn read(&mut self, r2api: &mut R2Api, addr: u64, length: usize) -> Vec<Value> {
        let mut count: u64 = 0;
        let mut data: Vec<Value> = vec!();

        while count < length as u64 {
            let caddr = addr + count;
            let mem = self.mem.get(&caddr);
            match mem {
                Some(byte) => {
                    data.push(byte.clone());
                },
                None => {
                    let byte = r2api.read(caddr, 1).pop().unwrap();
                    let new_data = Value::Concrete(byte as u64);

                    self.mem.insert(caddr, new_data.clone());
                    data.push(new_data);
                }
            }

            count += 1;
        }

        data
    }

    /*pub fn write(&mut self, r2api: &mut R2Api, addr: u64, data: &Vec<Value>) {
        let length = data.len();
        let offset = addr % CHUNK;
        let maddr = addr - offset;
        let adjust = CHUNK - ((length as u64 + offset) % CHUNK);
        let chunks = (length as u64 + offset + adjust) / CHUNK;

        let count = 0;

        while count < chunks {

        }
    }*/

    pub fn write(&mut self, addr: u64, data: &Vec<Value>) {
        let mut count: usize = 0;
        let length = data.len();

        while count < length {
            let caddr = addr + count as u64;
            self.mem.insert(caddr, data.get(count).unwrap().clone());
            count += 1;
        }
    }

    // jesus this got huge
    pub fn pack(&self, data: &Vec<Value>) -> Value {
        let mut new_data = data.clone();
        let length = new_data.len();

        match self.endian {
            Endian::Big => new_data.reverse(),
            _ => {}
        }

        let mut count: usize = 0;
        let mut btor: Option<Rc<Btor>> = None;

        for datum in &new_data {
            match datum {
                Value::Symbolic(val) => {
                    btor = Some(val.get_btor());
                    break;
                },
                _ => {}
            }
        }

        if let Some(new_btor) = btor {
            let bv_len = 8*length as u32;
            let mut sym_val = BV::zero(new_btor.clone(), bv_len);

            while count < length {
                let datum = new_data.get(count).unwrap();

                match &datum {
                    Value::Symbolic(val) => {
                        let shift = BV::from_u64(
                            new_btor.clone(), 8*count as u64,bv_len);

                        sym_val = val.sll(&shift).add(&sym_val);
                    },
                    Value::Concrete(val) => {
                        let new_val = BV::from_u64(
                            new_btor.clone(), val << (8*count as u64), bv_len);

                        sym_val = new_val.add(&sym_val);
                    }
                }
                count += 1;
            }
            Value::Symbolic(sym_val)
        } else {
            let mut con_val: u64 = 0;

            while count < length {
                let datum = new_data.get(count).unwrap();
    
                match &datum {
                    Value::Concrete(val) => {
                        con_val += val << (8*count);
                    },
                    Value::Symbolic(_val) => {} // shouldnt happen
                }
                count += 1;
            }
            Value::Concrete(con_val)
        }
    }

    pub fn unpack(&self, value: Value, length: usize) -> Vec<Value> {
        let mut data: Vec<Value> = vec!();
        match value {
            Value::Concrete(val) => {
                let mut count: usize = 0;

                while count < length {
                    data.push(Value::Concrete((val >> 8*count) & 0xff));
                    count += 1;
                }
            },
            Value::Symbolic(val) => {
                let mut count: usize = 0;

                while count < length {
                    let bv = val.slice(((count as u32)+1)*8-1, (count as u32)*8);

                    if bv.is_const() {
                        data.push(Value::Concrete(bv.as_u64().unwrap()));
                    } else {
                        data.push(Value::Symbolic(bv));
                    }

                    count += 1;
                }
            }
        }

        match self.endian {
            Endian::Big => data.reverse(),
            _ => {}
        }

        data
    }
}

pub fn create(r2api: &mut R2Api) -> Memory {
    let info = r2api.info.as_ref().unwrap();
    let endian = info.bin.endian.as_str();

    Memory {
        mem: HashMap::new(),
        bits: info.bin.bits,
        endian: Endian::from_string(endian)
    }
}
