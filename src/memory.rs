use std::collections::HashMap;
use crate::r2_api::{R2Api, Endian};
use crate::value::Value;
use crate::boolector::{Btor, BV};
use std::sync::Arc;

// const CHUNK: u64 = 8;

#[derive(Clone)]
pub struct Memory {
    pub solver: Arc<Btor>,
    pub r2api:  R2Api,
    pub mem:    HashMap<u64, Value>,
    pub bits:   u64,
    pub endian: Endian
}

impl Memory {
    pub fn new(r2api: &mut R2Api, btor: Arc<Btor>) -> Memory {
        let info = r2api.info.as_ref().unwrap();
        let endian = info.bin.endian.as_str();
    
        Memory {
            solver: btor,
            r2api: r2api.clone(),
            mem: HashMap::new(),
            bits: info.bin.bits,
            endian: Endian::from_string(endian)
        }
    }

    pub fn read_value(&mut self, addr: u64, length: usize) -> Value {
        let data = self.read(addr, length);
        self.pack(&data)
    }

    pub fn write_value(&mut self, addr: u64, value: Value, length: usize) {
        let data = self.unpack(value, length);
        self.write(addr, data)
    }

    pub fn read(&mut self, addr: u64, length: usize) -> Vec<Value> {
        let mut data: Vec<Value> = vec!();
        for count in 0..length as u64 {
            let caddr = addr + count;
            let mem = self.mem.get(&caddr);
            match mem {
                Some(byte) => {
                    data.push(byte.clone());
                },
                None => {
                    let byte = self.r2api.read(caddr, 1).pop().unwrap();
                    let new_data = Value::Concrete(byte as u64);
                    self.mem.insert(caddr, new_data.clone());
                    data.push(new_data);
                }
            }
        }
        //println!("read {:?}", data);
        data
    }

    pub fn write(&mut self, addr: u64, mut data: Vec<Value>) {
        //println!("write {:?}", data);
        let length = data.len();
        for count in 0..length {
            let caddr = addr + count as u64;
            self.mem.insert(caddr, data.remove(0));
        }
    }

    pub fn write_ptr(&mut self, addr: u64, data: &Vec<Value>) {
        //println!("write {:?}", data);
        let length = data.len();
        for count in 0..length {
            let caddr = addr + count as u64;
            self.mem.insert(caddr, data.get(count).unwrap().clone());
        }
    }

    // jesus this got huge
    pub fn pack(&self, data: &Vec<Value>) -> Value {
        let new_data = data;
        let length = new_data.len();

        if self.endian == Endian::Big {
            let mut new_data = data.clone();
            new_data.reverse();
        }

        let mut is_sym = false;
        for datum in new_data {
            if let Value::Symbolic(_val) = datum {
                is_sym = true;
                break;
            }
        }

        if is_sym {
            // this value isn't used, idk
            let mut sym_val = BV::zero(self.solver.clone(), 1);

            for count in 0..length {
                let datum = new_data.get(count).unwrap();
                match &datum {
                    Value::Symbolic(val) => {
                        let trans_val = Btor::get_matching_bv(
                            self.solver.clone(), val).unwrap();

                        if sym_val.get_width() == 1 {
                            sym_val = trans_val.slice(7, 0);
                        } else {
                            sym_val = trans_val.slice(7, 0).concat(&sym_val);
                        }
                    },
                    Value::Concrete(val) => {
                        let new_val = BV::from_u64(
                            self.solver.clone(), val << (8*count as u64), 8);

                        if sym_val.get_width() == 1 {
                            sym_val = new_val;
                        } else {
                            sym_val = new_val.concat(&sym_val);
                        }
                    }
                }
            }
            Value::Symbolic(sym_val)
        } else {
            let mut con_val: u64 = 0;
            for count in 0..length {
                let datum = new_data.get(count).unwrap();
                if let Value::Concrete(val) = datum {
                    con_val += val << (8*count);
                }
            }
            Value::Concrete(con_val)
        }
    }

    pub fn unpack(&self, value: Value, length: usize) -> Vec<Value> {
        let mut data: Vec<Value> = vec!();
        match value {
            Value::Concrete(val) => {
                for count in 0..length {
                    data.push(Value::Concrete((val >> 8*count) & 0xff));
                }
            },
            Value::Symbolic(val) => {
                for count in 0..length {
                    let trans_val = Btor::get_matching_bv(
                        self.solver.clone(), &val).unwrap();
                    let bv = trans_val.slice(((count as u32)+1)*8-1, (count as u32)*8);
                    if bv.is_const() {
                        data.push(Value::Concrete(bv.as_u64().unwrap()));
                    } else {
                        data.push(Value::Symbolic(bv));
                    }
                }
            }
        }

        if self.endian == Endian::Big {
            data.reverse();
        }
        data
    }
}

