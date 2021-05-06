use std::collections::HashMap;
use crate::r2_api::{R2Api, Endian};
use crate::value::Value;
use crate::solver::Solver;

// const CHUNK: u64 = 8;
const READ_CACHE: usize = 256;

#[derive(Clone)]
pub struct Memory {
    pub solver: Solver,
    pub r2api:  R2Api,
    pub mem:    HashMap<u64, Value>,
    pub bits:   u64,
    pub endian: Endian
}

impl Memory {
    pub fn new(r2api: &mut R2Api, btor: Solver) -> Memory {
        let info = r2api.info.as_ref().unwrap();
        let endian = info.bin.endian.as_str();
    
        Memory {
            solver: btor.clone(),
            r2api: r2api.clone(),
            mem: HashMap::new(),
            bits: info.bin.bits,
            endian: Endian::from_string(endian)
        }
    }

    pub fn read_sym(&mut self, address: &Value, length: &Value) -> Value {
        // TODO "correctly" handle 
        let len = match length {
            Value::Concrete(l) => *l,
            Value::Symbolic(l) => self.solver.evalcon(l).unwrap()
        } as usize;

        match address {
            Value::Concrete(addr) => {
                self.read_value(*addr, len)
            },
            Value::Symbolic(addr) => {
                let addrs = self.solver.evaluate_many(addr);
                //println!("addrs: {:?}", addrs);
                let mut value = Value::Symbolic(self.solver.bvv(0, 64));
                for a in addrs {
                    let read_val = self.read_value(a, len);
                    let bv = self.solver.bvv(a, 64);
                    let cond = Value::Symbolic(addr._eq(&bv));
                    value = self.solver.conditional(&cond, &read_val, &value);
                }
                //println!("value: {:?}", value);
                value
            }
        }
    }

    pub fn write_sym(&mut self, address: &Value, value: Value, length: &Value) {
        // TODO "correctly" handle 
        let len = match length {
            Value::Concrete(l) => *l,
            Value::Symbolic(l) => self.solver.evalcon(l).unwrap()
        } as usize;

        match address {
            Value::Concrete(addr) => {
                self.write_value(*addr, value, len)
            },
            Value::Symbolic(addr) => {
                let addrs = self.solver.evaluate_many(addr);
                //let mut value = Value::Symbolic(self.solver.bvv(0, 64));
                for a in addrs {
                    let read_val = self.read_value(a, len);
                    let bv = self.solver.bvv(a, 64);
                    let cond = Value::Symbolic(addr._eq(&bv));
                    let new_val = self.solver.conditional(&cond, &value, &read_val);
                    self.write_value(a, new_val, len);
                }
            }
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
                    let bytes = self.r2api.read(caddr, READ_CACHE);
                    data.push(Value::Concrete(bytes[0] as u64));
                    for byte in bytes {
                        let new_data = Value::Concrete(byte as u64);
                        self.mem.insert(caddr, new_data);
                    }
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

        // if length > 64 use sym to cheat
        let mut is_sym = length > 64; 
        for datum in new_data {
            if let Value::Symbolic(_val) = datum {
                is_sym = true;
                break;
            }
        }

        if is_sym {
            // this value isn't used, idk
            let mut sym_val = self.solver.bvv(0, 1);

            for count in 0..length {
                let datum = new_data.get(count).unwrap();
                match &datum {
                    Value::Symbolic(val) => {
                        let trans_val = self.solver.translate(val).unwrap();

                        if sym_val.get_width() == 1 {
                            sym_val = trans_val.slice(7, 0);
                        } else {
                            sym_val = trans_val.slice(7, 0).concat(&sym_val);
                        }
                    },
                    Value::Concrete(val) => {
                        let new_val = self.solver.bvv(val << (8*count as u64), 8);

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
                    let trans_val = self.solver.translate(&val).unwrap();
                    let bv = trans_val.slice(((count as u32)+1)*8-1, (count as u32)*8);
                    /*if bv.is_const() { // don't do this here for taint analysis sake
                        data.push(Value::Concrete(bv.as_u64().unwrap()));
                    } else {
                        data.push(Value::Symbolic(bv));
                    }*/
                    data.push(Value::Symbolic(bv));
                }
            }
        }

        if self.endian == Endian::Big {
            data.reverse();
        }
        data
    }
}

