use std::collections::HashMap;
use crate::r2_api::{R2Api, Endian};
use crate::value::Value;
use crate::boolector::{Btor, BV};
use std::rc::Rc;

// const CHUNK: u64 = 8;

#[derive(Debug, Clone)]
pub struct Memory {
    pub solver: Rc<Btor>,
    pub mem: HashMap<u64, Value>,
    pub bits: u64,
    pub endian: Endian
}

impl Memory {
    pub fn new(r2api: &mut R2Api, btor: Rc<Btor>) -> Memory {
        let info = r2api.info.as_ref().unwrap();
        let endian = info.bin.endian.as_str();
    
        Memory {
            solver: btor,
            mem: HashMap::new(),
            bits: info.bin.bits,
            endian: Endian::from_string(endian)
        }
    }

    pub fn read_value(&mut self, r2api: &mut R2Api, addr: u64, length: usize) -> Value {
        let data = self.read(r2api, addr, length);
        self.pack(&data)
    }

    pub fn write_value(&mut self, addr: u64, value: Value, length: usize) {
        let data = self.unpack(value, length);
        self.write(addr, &data)
    }

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

        //println!("read {:?}", data);
        data
    }

    pub fn write(&mut self, addr: u64, data: &Vec<Value>) {
        //println!("write {:?}", data);
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
        let new_data = data;
        let length = new_data.len();

        match self.endian {
            Endian::Big => {
                let mut new_data = data.clone();
                new_data.reverse();
            },
            _ => {}
        }

        let mut count: usize = 0;
        let mut btor: Option<Rc<Btor>> = None;

        for datum in new_data {
            match datum {
                Value::Symbolic(val) => {
                    btor = Some(val.get_btor());
                    break;
                },
                _ => {}
            }
        }

        if let Some(_new_btor) = btor {
            let bv_len = 8*length as u32;
            let mut sym_val = BV::zero(self.solver.clone(), 1);

            while count < length {
                let datum = new_data.get(count).unwrap();

                match &datum {
                    Value::Symbolic(val) => {
                        let trans_val = Btor::get_matching_bv(
                            self.solver.clone(), val).unwrap();
                        sym_val = trans_val.slice(7, 0).concat(&sym_val);
                    },
                    Value::Concrete(val) => {
                        let new_val = BV::from_u64(
                            self.solver.clone(), val << (8*count as u64), 8);

                        sym_val = new_val.concat(&sym_val);
                    }
                }
                count += 1;
            }
            let bv = sym_val.slice(bv_len, 1);
            Value::Symbolic(bv)
        } else {
            let mut con_val: u64 = 0;

            while count < length {
                let datum = new_data.get(count).unwrap();
    
                match &datum {
                    Value::Concrete(val) => {
                        con_val += val << (8*count);
                    },
                    _ => {} // shouldnt happen
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
                    let trans_val = Btor::get_matching_bv(
                        self.solver.clone(), &val).unwrap();
                    let bv = trans_val.slice(((count as u32)+1)*8-1, (count as u32)*8);
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

