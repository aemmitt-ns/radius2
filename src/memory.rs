use std::collections::HashMap;
use crate::r2_api::{R2Api, Endian};
use crate::value::Value;
use crate::solver::Solver;

// const CHUNK: u64 = 8;
const READ_CACHE: usize = 256;
// const LEN_MAX: u64 = 65536;

// one day I will make a reasonable heap impl
// today is not that day
const HEAP_START: u64 = 0x10000000;
//const HEAP_SIZE:  u64 = 0x1000000;
const HEAP_CHUNK: u64 = 0x100;

#[derive(Clone)]
pub struct Memory {
    pub solver: Solver,
    pub r2api:  R2Api,
    pub mem:    HashMap<u64, Value>,
    pub heap:   HashMap<u64, u64>,
    pub bits:   u64,
    pub endian: Endian
}

impl Memory {
    pub fn new(r2api: &mut R2Api, btor: Solver) -> Memory {
        let info = r2api.info.as_ref().unwrap();
        let endian = info.bin.endian.as_str();
    
        Memory {
            solver: btor,
            r2api: r2api.clone(),
            mem: HashMap::new(),
            heap: HashMap::new(),
            bits: info.bin.bits,
            endian: Endian::from_string(endian)
        }
    }

    //TODO actually do this    
    pub fn alloc(&mut self, length: &Value) -> u64 {
        let len = self.solver.max_value(length);

        let mut addr = HEAP_START;
        while self.heap.contains_key(&addr) {
            addr += HEAP_CHUNK;
        }

        for i in 0..(len/HEAP_CHUNK + 1) {
            self.heap.insert(addr+i*HEAP_CHUNK, 1);
        }

        addr
    }

    //TODO actually do this
    pub fn free(&mut self, addr: &Value) -> Value {
        addr.clone()
    }

    pub fn read_sym(&mut self, address: &Value, len: usize) -> Value {
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

    pub fn write_sym(&mut self, address: &Value, value: Value, len: usize) {
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

    pub fn read_sym_len(&mut self, address: &Value, length: &Value) -> Vec<Value> {
        let len = self.solver.max_value(length) as usize;

        match address {
            Value::Concrete(addr) => {
                self.read(*addr, len)
            },
            Value::Symbolic(addr) => {
                let addrs = self.solver.evaluate_many(addr);
                //println!("addrs: {:?}", addrs);
                let mut values = vec!();
                for a in addrs {
                    let read_vals = self.read(a, len);
                    let mut new_vals = vec!();
                    if values.is_empty() {
                        new_vals = read_vals;
                    } else {
                        for count in 0..len {
                            let bv = self.solver.bvv(a, 64);
                            let cond = Value::Symbolic(addr._eq(&bv));
                            let value = self.solver.conditional(&cond, 
                                &read_vals[count], &values[count]);
                            
                            new_vals.push(value);
                        }
                    }
                    values = new_vals;
                }
                //println!("value: {:?}", value);
                values
            }
        }
    }

    pub fn write_sym_len(&mut self, address: &Value, values: Vec<Value>, length: &Value) {
        let mut len = self.solver.max_value(length) as usize;
        // hopefully this doesn't occur
        if len > values.len() {
            len = values.len();
        }

        let mut addrs = vec!();
        match address {
            Value::Concrete(addr) => addrs.push(*addr),
            Value::Symbolic(addr) => addrs.extend(self.solver.evaluate_many(addr))
        };

        for addr in addrs {
            let read_vals = self.read(addr, len);
            for count in 0..len {
                let addr_val = Value::Concrete(addr);
                let count_val = Value::Concrete(count as u64); 
                let cond = address.clone().eq(addr_val) & count_val.ult(length.clone());
                let value = self.solver.conditional(&cond, &values[count], &read_vals[count]);
                self.write(addr+count as u64, vec!(value));
            }
        }
    }

    pub fn memmove(&mut self, dst: &Value, src: &Value, length: &Value) {
        let data = self.read_sym_len(src, length);
        self.write_sym_len(dst, data, length);    }

    pub fn search(&mut self, addr: &Value, needle: &Value, length: &Value, reverse: bool) -> Value {
        //let mut search_data = self.read_sym_len(addr, length);
        let len = self.solver.max_value(length) as usize;

        // concrete needle ends at null
        // symbolic is given by width
        let needlen = match needle {
            Value::Concrete(val) => {
                let mut mask = 0xff;
                let mut l = 0;
                while val & mask != 0 {
                    mask <<= 8;
                    l += 1;
                }
                l + ((l == 0) as u32)
            },
            Value::Symbolic(val) => val.get_width()/8
        } as usize;

        let mut result = Value::Concrete(0);
        let mut cond = Value::Concrete(0);

        for pos in 0..(len - needlen) {
            // get value to test
            let mut pos_val = addr.clone() + Value::Concrete(pos as u64);
            let value = self.read_sym(&pos_val, needlen);
            if reverse {
                pos_val = addr.clone() + length.clone() - Value::Concrete(pos as u64);
            }

            let pos_cond = pos_val.clone().ult(addr.clone() + length.clone()) & 
                !pos_val.clone().ult(addr.clone());
            let new_cond = value.clone().eq(needle.clone()) & pos_cond & !cond.clone();
            //println!("{:?}", new_cond);
            result = self.solver.conditional(&new_cond, &pos_val, &result);
            cond = value.eq(needle.clone()) | cond;

            if let Value::Concrete(res) = &result {
                if *res != 0 {
                    break;
                }
            }
        }
        
        result
    }

    pub fn strlen(&mut self, addr: &Value, length: &Value) -> Value {
        let end = self.search(addr, &Value::Concrete(0), length, false);
        self.solver.conditional(
            &(end.clone().eq(Value::Concrete(0))), 
            &length,
            &(end - addr.clone())
        )
    }

    pub fn compare(&mut self, addr1: &Value, addr2: &Value, length: &Value) -> Value {
        let len = self.solver.max_value(length);
        let data1 = self.read_sym_len(addr1, &Value::Concrete(len));
        let data2 = self.read_sym_len(addr2, &Value::Concrete(len));

        let mut result = Value::Concrete(0);
        let mut same = Value::Concrete(1);

        for ind in 0..len as usize {
            let d1 = &data1[ind];
            let d2 = &data2[ind];

            let ind_val = Value::Concrete(ind as u64);
            let gt = !d1.clone().ult(d2.clone()) & !d1.clone().eq(d2.clone());
            let lt = d1.clone().ult(d2.clone()) & !d1.clone().eq(d2.clone());
            let len_cond = ind_val.clone().ult(length.clone());

            let lt_val = self.solver.conditional(
                &(lt & same.clone() & len_cond.clone()), 
                &Value::Concrete(-1i64 as u64), &result);

            result = self.solver.conditional(
                &(gt & same.clone() & len_cond), 
                &Value::Concrete(1), &lt_val);

            same = same & result.clone().eq(Value::Concrete(0));

            if let Value::Concrete(res) = &same {
                if *res != 0 {
                    break;
                }
            }
        }

        result
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
                    let mut c = 0;
                    for byte in bytes {
                        let new_data = Value::Concrete(byte as u64);
                        self.mem.entry(caddr + c).or_insert(new_data);
                        c += 1;
                    }
                }
            }
        }
        //println!("read {:?}", data);
        data
    }

    //read utf8 string
    pub fn read_string(&mut self, addr: u64, length: usize) -> String {
        let data = self.read(addr, length);
        let mut data_u8 = vec!();
        self.solver.push(1);
        for d in data {
            data_u8.push(self.solver.eval_to_u64(&d).unwrap() as u8);
        }
        self.solver.pop(1);
        String::from_utf8(data_u8).unwrap()
    }

    pub fn write_string(&mut self, addr: u64, string: &str) {
        let data = string.as_bytes();
        let mut data_value = vec!();
        for d in data {
            data_value.push(Value::Concrete(*d as u64));
        }
        self.write(addr, data_value);
    }

    pub fn write(&mut self, addr: u64, mut data: Vec<Value>) {
        //println!("write {:?}", data);
        let length = data.len();
        for count in 0..length {
            let caddr = addr + count as u64;
            self.mem.insert(caddr, data.remove(0));
        }
    }

    pub fn write_ptr(&mut self, addr: u64, data: &[Value]) {
        //println!("write {:?}", data);
        let length = data.len();
        for count in 0..length {
            let caddr = addr + count as u64;
            self.mem.insert(caddr, data.get(count).unwrap().clone());
        }
    }

    // jesus this got huge
    pub fn pack(&self, data: &[Value]) -> Value {
        let new_data = data;
        let length = new_data.len();

        if self.endian == Endian::Big {
            let mut new_data = data.to_owned();
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
                    data.push(Value::Concrete((val >> (8*count)) & 0xff));
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

