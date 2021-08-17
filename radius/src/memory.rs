use std::collections::HashMap;
use crate::r2_api::{R2Api, Endian};
use crate::value::Value;
use crate::solver::Solver;
use std::mem;

// const CHUNK: u64 = 8;
const READ_CACHE: usize = 256;
// const LEN_MAX: u64 = 65536;

// one day I will make a reasonable heap impl
// today is not that day
const HEAP_START: u64 = 0x40000000;
const HEAP_SIZE:  u64 = 0x4000000;
// const HEAP_CHUNK: u64 = 0x100;

const STACK_START: u64 = 0x100000;
const STACK_SIZE:  u64 = 0x78000*2;

pub const CHECK_PERMS: bool = false;

// i think these are different on darwin
const PROT_NONE:  u64 = 0x0;
const PROT_READ:  u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC:  u64 = 0x4;

#[derive(Clone)]
pub struct Memory {
    pub solver: Solver,
    pub r2api:  R2Api,
    pub mem:    HashMap<u64, Value>,
    pub heap:   Heap,
    pub bits:   u64,
    pub endian: Endian,
    pub segs:   Vec<MemorySegment>,
    pub blank:  bool
}

pub enum Permission {
    Read, 
    Write, 
    Execute
}

#[derive(Debug, Clone)]
pub struct MemorySegment {
    pub name:  String,
    pub addr:  u64,
    pub size:  u64,
    pub read:  bool,
    pub write: bool,
    pub exec:  bool
}

impl Memory {
    pub fn new(r2api: &mut R2Api, btor: Solver, blank: bool) -> Memory {
        let segments = r2api.get_segments().unwrap();
        let mut segs = vec!();

        for seg in segments {
            segs.push(MemorySegment {
                name:  seg.name,
                addr:  seg.vaddr,
                size:  seg.size,
                read:  seg.perm.contains('r'),
                write: seg.perm.contains('w'),
                exec:  seg.perm.contains('x')
            });
        }

        let info = r2api.info.as_ref().unwrap();
        let endian = info.bin.endian.as_str();
    
        Memory {
            solver: btor,
            r2api: r2api.clone(),
            mem: HashMap::new(),
            heap: Heap::new(HEAP_START, HEAP_SIZE),
            bits: info.bin.bits,
            endian: Endian::from_string(endian),
            segs,
            blank
        }
    }

    pub fn alloc(&mut self, length: &Value) -> u64 {
        let len = length.as_u64().unwrap(); //solver.max_value(length);
        self.heap.alloc(len)
    }

    pub fn free(&mut self, addr: &Value) -> Value {
        let address = addr.as_u64().unwrap(); //solver.evalcon_to_u64(addr).unwrap();
        if let Some(ret) = self.heap.free(address) {
            Value::Concrete(ret, addr.get_taint())
        } else {
            Value::Concrete(0, 0) // idk none of this is right
        }
    }

    #[inline]
    pub fn check_permission(&mut self, addr: u64, length: u64, perm: char) -> bool {
        for seg in &self.segs {
            if addr >= seg.addr && addr + length <= seg.addr+seg.size {
                match perm {
                    'r' => return seg.read,
                    'w' => return seg.write,
                    'x' => return seg.exec,
                     _  => return false // uhhh shouldnt happen
                }
            }
        }

        false
    }

    pub fn add_segment(&mut self, name: &str, addr: u64, size: u64, perms: &str) {
        self.segs.push(MemorySegment {
            name:  name.to_owned(),
            addr,
            size,
            read:  perms.contains('r'),
            write: perms.contains('w'),
            exec:  perms.contains('x')
        });
    }

    pub fn add_heap(&mut self) {
        self.add_segment("heap", HEAP_START, HEAP_SIZE, "rw-");
    }

    pub fn add_stack(&mut self) {
        self.add_segment("stack", STACK_START, STACK_SIZE, "rw-");
    }

    pub fn brk(&mut self, address: u64) -> bool {
        for seg in &mut self.segs {
            if seg.name == ".data" {
                seg.size = address-seg.addr;
                return true;
            } 
        }
        false
    }

    pub fn sbrk(&mut self, inc: u64) -> u64 {
        for seg in &mut self.segs {
            if seg.name == ".data" {
                seg.size = seg.addr+seg.size+inc;
                return seg.addr;
            } 
        }
        -1i64 as u64
    }

    pub fn read_sym(&mut self, address: &Value, len: usize, solver: &mut Solver) -> Value {
        match address {
            Value::Concrete(addr, _t) => {
                self.read_value(*addr, len)
            },
            Value::Symbolic(addr, t) => {
                let addrs = solver.evaluate_many(addr);
                let mut value = Value::Symbolic(solver.bvv(0, 64), 0);
                for a in addrs {
                    let read_val = self.read_value(a, len);
                    let bv = solver.bvv(a, 64);
                    let cond = Value::Symbolic(addr._eq(&bv), *t);
                    value = solver.conditional(&cond, &read_val, &value);
                }
                //println!("value: {:?}", value);
                value
            }
        }
    }

    pub fn write_sym(&mut self, address: &Value, value: &Value, len: usize, solver: &mut Solver) {
        match address {
            Value::Concrete(addr, _t) => {
                self.write_value(*addr, value, len)
            },
            Value::Symbolic(addr, t) => {
                let addrs = solver.evaluate_many(addr);
                //let mut value = Value::Symbolic(self.solver.bvv(0, 64));
                for a in addrs {
                    let read_val = self.read_value(a, len);
                    let bv = solver.bvv(a, 64);
                    let cond = Value::Symbolic(addr._eq(&bv), *t);
                    let new_val = solver.conditional(&cond, &value, &read_val);
                    self.write_value(a, &new_val, len);
                }
            }
        }
    }

    pub fn read_sym_len(&mut self, address: &Value, length: &Value, solver: &mut Solver) -> Vec<Value> {
        let len = solver.max_value(length) as usize;

        match address {
            Value::Concrete(addr, _t) => {
                self.read(*addr, len)
            },
            Value::Symbolic(addr, t) => {
                let addrs = solver.evaluate_many(addr);
                //println!("addrs: {:?}", addrs);
                let mut values = vec!();
                for a in addrs {
                    let read_vals = self.read(a, len);
                    let mut new_vals = vec!();
                    if values.is_empty() {
                        new_vals = read_vals;
                    } else {
                        for count in 0..len {
                            let bv = solver.bvv(a, 64);
                            let cond = Value::Symbolic(addr._eq(&bv), *t);
                            let value = solver.conditional(&cond, 
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

    pub fn write_sym_len(&mut self, address: &Value, values: &[Value], length: &Value, solver: &mut Solver) {
        let mut len = solver.max_value(length) as usize;
        // hopefully this doesn't occur
        if len > values.len() {
            len = values.len();
        }

        let mut addrs = Vec::with_capacity(128);
        let t = address.get_taint();
        match address {
            Value::Concrete(addr, _t) => addrs.push(*addr),
            Value::Symbolic(addr, _t) => addrs.extend(solver.evaluate_many(addr))
        };

        for addr in addrs {
            let read_vals = self.read(addr, len);
            for count in 0..len {
                let addr_val = Value::Concrete(addr, t);
                let count_val = Value::Concrete(count as u64, 0); 
                let cond = address.eq(&addr_val) & count_val.ult(&length);
                let value = solver.conditional(&cond, &values[count], &read_vals[count]);
                self.write(addr+count as u64, &mut [value]);
            }
        }
    }

    pub fn memmove(&mut self, dst: &Value, src: &Value, length: &Value, solver: &mut Solver) {
        let data = self.read_sym_len(src, length, solver);
        self.write_sym_len(dst, &data, length, solver);    
    }

    pub fn search(&mut self, addr: &Value, needle: &Value, length: &Value, reverse: bool, solver: &mut Solver) -> Value {
        //let mut search_data = self.read_sym_len(addr, length);
        let len = solver.max_value(length) as usize;

        // concrete needle ends at null
        // symbolic is given by width
        let needlen = match needle {
            Value::Concrete(val, _t) => {
                let mut mask = 0xff;
                let mut l = 1;
                for i in 1..9 {
                    if mask & val != 0 {
                        l = i;
                    }
                    mask <<= 8;
                }
                l
            },
            Value::Symbolic(val, _t) => val.get_width()/8
        } as usize;

        let mut result = Value::Concrete(0, 0);
        let mut cond = Value::Concrete(0, 0);

        for pos in 0..(len - needlen) {
            // get value to test
            let mut pos_val = addr.clone() + Value::Concrete(pos as u64, 0);
            let value = self.read_sym(&pos_val, needlen, solver);
            if reverse {
                pos_val = addr.clone() + length.clone() - Value::Concrete(pos as u64, 0);
            }

            let pos_cond = pos_val.ult(&(addr.clone() + length.clone())) & 
                !pos_val.ult(&addr);
            let new_cond = value.eq(&needle) & pos_cond & !cond.clone();
            //println!("{:?}", new_cond);
            result = solver.conditional(&new_cond, &pos_val, &result);
            cond = value.eq(&needle) | cond;

            if let Value::Concrete(res, _t) = &result {
                if *res != 0 {
                    break;
                }
            } /*else if value.id(&needle) == Value::Concrete(1, 0) {
                // this is weird but cuts searches on identical values
                break;
            }*/
        }
        
        result
    }

    pub fn strlen(&mut self, addr: &Value, length: &Value, solver: &mut Solver) -> Value {
        let end = self.search(addr, &Value::Concrete(0, 0), length, false, solver);
        solver.conditional(
            &(end.eq(&Value::Concrete(0, 0))), 
            length,
            &end.sub(addr)
        )
    }

    pub fn compare(&mut self, addr1: &Value, addr2: &Value, length: &Value, solver: &mut Solver) -> Value {
        let len = solver.max_value(length);
        let data1 = self.read_sym_len(addr1, &Value::Concrete(len, length.get_taint()), solver);
        let data2 = self.read_sym_len(addr2, &Value::Concrete(len, length.get_taint()), solver);

        let mut result = Value::Concrete(0, 0);
        let mut same = Value::Concrete(1, 0);

        for ind in 0..len as usize {
            let d1 = &data1[ind];
            let d2 = &data2[ind];

            let ind_val = Value::Concrete(ind as u64, 0);
            let gt = !d1.ult(&d2) & !d1.eq(&d2);
            let lt = d1.ult(&d2) & !d1.eq(&d2);
            let len_cond = ind_val.ult(&length);

            let lt_val = solver.conditional(
                &(lt & same.clone() & len_cond.clone()), 
                &Value::Concrete(-1i64 as u64, 0), &result);

            result = solver.conditional(
                &(gt & same.clone() & len_cond), 
                &Value::Concrete(1, 0), &lt_val);

            same = same & result.eq(&Value::Concrete(0, 0));

            if let Value::Concrete(res, _t) = &same {
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

    pub fn write_value(&mut self, addr: u64, value: &Value, length: usize) {
        let mut data = self.unpack(value, length);
        self.write(addr, &mut data)
    }

    pub fn read(&mut self, addr: u64, length: usize) -> Vec<Value> {

        if CHECK_PERMS && !self.check_permission(addr, length as u64, 'r') {
            // everything needs to be reworked to have Result<...> 
            // so that we can properly handle things like this
            self.handle_segfault(addr, length as u64, 'r');
        }

        let mut data: Vec<Value> = Vec::with_capacity(length);
        for count in 0..length as u64 {
            let caddr = addr + count;
            let mem = self.mem.get(&caddr);
            match mem {
                Some(byte) => {
                    data.push(byte.to_owned());
                },
                None => {
                    if self.blank {
                        let sym_name = format!("mem_{:08x}", caddr);
                        data.push(Value::Symbolic(self.solver.bv(sym_name.as_str(), 64), 0))
                    } else {
                        let bytes = self.r2api.read(caddr, READ_CACHE).unwrap();
                        data.push(Value::Concrete(bytes[0] as u64, 0));
                        for (c, byte) in bytes.into_iter().enumerate() {
                            let new_data = Value::Concrete(byte as u64, 0);
                            self.mem.entry(caddr + c as u64).or_insert(new_data);
                        }
                    }
                }
            }
        }
        //println!("read {:?}", data);
        data
    }

    pub fn prot_to_str(&self, prot: u64) -> String {
        let mut prot_str = String::from("");

        if prot == PROT_NONE {
            return String::from("---");
        }

        if prot & PROT_READ != 0 {
            prot_str += "r";
        } else {
            prot_str += "-";
        }
        if prot & PROT_WRITE != 0 {
            prot_str +=  "w";
        } else {
            prot_str += "-";
        }
        if prot & PROT_EXEC != 0 {
            prot_str += "x";
        } else {
            prot_str += "-";
        }
    
        prot_str
    }

    //read utf8 string
    pub fn read_string(&mut self, addr: u64, length: usize, solver: &mut Solver) -> String {
        let data = self.read(addr, length);
        let mut data_u8 = vec!();
        solver.push();
        for d in data {
            data_u8.push(solver.evalcon_to_u64(&d).unwrap() as u8);
        }
        solver.pop();
        String::from_utf8(data_u8).unwrap()
    }

    pub fn write_string(&mut self, addr: u64, string: &str) {
        let data = string.as_bytes();
        let mut data_value = vec!();
        for d in data {
            data_value.push(Value::Concrete(*d as u64, 0));
        }
        self.write(addr, &mut data_value);
    }

    pub fn write(&mut self, addr: u64, data: &mut [Value]) {
        //println!("write {:?}", data);
        let length = data.len();

        if CHECK_PERMS && !self.check_permission(addr, length as u64, 'w') {
            self.handle_segfault(addr, length as u64, 'w');
        }

        for (count, mut item) in data.iter_mut().enumerate().take(length) {
            let caddr = addr + count as u64;
            self.mem.insert(caddr, mem::take(&mut item));
        }
    }

    // this sucks, we need to properly do error handling to do this right
    // TODO make everything not suck
    pub fn handle_segfault(&self, addr: u64, length: u64, perm: char) {
        panic!("addr {} length {} does not have perm \"{}\"", addr, length, perm);
    }

    // jesus this got huge
    pub fn pack(&self, data: &[Value]) -> Value {
        let new_data = data;
        let length = new_data.len();
        let mut taint = 0;

        if self.endian == Endian::Big {
            let mut new_data = data.to_owned();
            new_data.reverse();
        }

        // if length > 64 bits use sym to cheat
        let mut is_sym = length > 8; 
        if !is_sym {
            for datum in new_data {
                if let Value::Symbolic(_val, _t) = datum {
                    is_sym = true;
                    break;
                }
            }
        }

        if is_sym {
            // this value isn't used, idk
            let mut sym_val = self.solver.bvv(0, 1);

            for count in 0..length {
                let datum = new_data.get(count).unwrap();
                match &datum {
                    Value::Symbolic(val, t) => {
                        //let trans_val = self.solver.translate(val).unwrap();

                        if sym_val.get_width() == 1 {
                            sym_val = val.slice(7, 0);
                        } else {
                            sym_val = val.slice(7, 0).concat(&sym_val);
                        }
                         
                        taint |= t;
                    },
                    Value::Concrete(val, t) => {
                        let new_val = self.solver.bvv(val << (8*count as u64), 8);

                        if sym_val.get_width() == 1 {
                            sym_val = new_val;
                        } else {
                            sym_val = new_val.concat(&sym_val);
                        }

                        taint |= t;
                    }
                }
            }
            Value::Symbolic(sym_val, taint)
        } else {
            let mut con_val: u64 = 0;
            for count in 0..length {
                let datum = new_data.get(count).unwrap();
                if let Value::Concrete(val, t) = datum {
                    con_val += val << (8*count);
                    taint |= t;
                }
            }
            Value::Concrete(con_val, taint)
        }
    }

    pub fn unpack(&self, value: &Value, length: usize) -> Vec<Value> {
        let mut data: Vec<Value> = Vec::with_capacity(length);

        match value {
            Value::Concrete(val, t) => {
                for count in 0..length {
                    data.push(Value::Concrete((*val >> (8*count)) & 0xff, *t));
                }
            },
            Value::Symbolic(val, t) => {
                for count in 0..length {
                    //let trans_val = self.solver.translate(&val).unwrap();
                    let bv = val.slice(((count as u32)+1)*8-1, (count as u32)*8);
                    data.push(Value::Symbolic(bv, *t));
                }
            }
        }

        if self.endian == Endian::Big {
            data.reverse();
        }
        data
    }

    pub fn addresses(&self) -> Vec<u64> {
        self.mem.keys().cloned().collect::<Vec<u64>>()
    }
}

#[derive(Clone)]
pub struct Heap {
    pub start: u64,
    pub size:  u64,
    pub chunks: Vec<Chunk>
}

#[derive(Clone, PartialEq)]
pub struct Chunk { 
    pub addr: u64,
    pub size: u64
}

// still a dumb af heap implementation
impl Heap {
    pub fn new(start: u64, size: u64) -> Self {
        Heap {
            start,
            size,
            chunks: vec!(Chunk { addr: start, size: 0 })
        }
    }

    pub fn alloc(&mut self, size: u64) -> u64 {
        let last = &self.chunks[self.chunks.len()-1];
        let addr = last.addr+last.size;
        self.chunks.push(Chunk { addr, size });
        addr
    }

    pub fn free(&mut self, addr: u64) -> Option<u64> {
        let last = &self.chunks[self.chunks.len()-1];
        if addr == last.addr {
            self.chunks.pop();
            Some(addr)
        } else {
            let mut rem = 0;
            for (i, chunk) in self.chunks.iter().enumerate() {
                if chunk.addr == addr {
                    rem = i;
                    break;
                }
            }
            if rem != 0 {
                self.chunks.remove(rem);
                Some(addr)
            } else {
                None
            }
        }
    }
}