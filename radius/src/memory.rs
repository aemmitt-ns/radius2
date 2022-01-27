//use std::collections::HashMap;
use ahash::AHashMap;
type HashMap<P, Q> = AHashMap<P, Q>;

use crate::r2_api::{Endian, R2Api, STACK_SIZE, STACK_START};
use crate::solver::Solver;
use crate::value::Value;
use std::mem;

const READ_CACHE: usize = 64;
// const LEN_MAX: u64 = 65536;

// one day I will make a reasonable heap impl
// today is not that day
const HEAP_START: u64 = 0x40000000;
const HEAP_SIZE: u64 = 0x04000000;
// const HEAP_CHUNK: u64 = 0x100;

// i think these are different on darwin
const PROT_NONE: u64 = 0x0;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;

#[derive(Clone)]
pub struct Memory {
    pub solver: Solver,
    pub r2api: R2Api,
    
    // TODO refactor merge to make this private
    pub mem: HashMap<u64, Value>,
    heap: Heap,
    pub bits: u64,
    pub endian: Endian,
    pub segs: Vec<MemorySegment>,
    pub blank: bool,
    pub check: bool,
}

pub enum Permission {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone)]
pub struct MemorySegment {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub init: bool,
}

impl Memory {
    pub fn new(r2api: &mut R2Api, btor: Solver, blank: bool, check: bool) -> Memory {
        let segments = r2api.get_segments().unwrap();
        let mut segs = vec![];

        for seg in segments {
            segs.push(MemorySegment {
                name: seg.name,
                addr: seg.vaddr,
                size: seg.size,
                read: seg.perm.contains('r'),
                write: seg.perm.contains('w'),
                exec: seg.perm.contains('x'),
                init: true,
            });
        }

        let endian = r2api.info.bin.endian.as_str();

        let bin = &r2api.info.bin;
        let bits = if bin.arch == "arm" && bin.bits == 16 {
            32 // says "16" for 32 bit arm cuz thumb
        } else {
            bin.bits
        };

        Memory {
            solver: btor,
            r2api: r2api.clone(),
            mem: HashMap::new(),
            heap: Heap::new(HEAP_START, HEAP_SIZE),
            bits,
            endian: Endian::from_string(endian),
            segs,
            blank,
            check,
        }
    }

    pub fn alloc(&mut self, length: &Value) -> u64 {
        let len = length.as_u64().unwrap();
        self.heap.alloc(len)
    }

    #[inline]
    pub fn alloc_sym(&mut self, length: &Value, solver: &mut Solver) -> Value {
        let len = solver.max_value(length);
        Value::Concrete(self.heap.alloc(len), 0)
    }

    pub fn free(&mut self, addr: &Value) -> Value {
        let address = addr.as_u64().unwrap(); 
        if let Some(ret) = self.heap.free(address) {
            Value::Concrete(ret, addr.get_taint())
        } else {
            Value::Concrete(0, 0) // idk none of this is right
        }
    }

    #[inline]
    pub fn free_sym(&mut self, addr: &Value, solver: &mut Solver) -> Value {
        let address = solver.evalcon_to_u64(addr).unwrap();
        self.free(&Value::Concrete(address, 0))
    }

    #[inline]
    pub fn check_permission(&self, addr: u64, length: u64, perm: char) -> bool {
        for seg in &self.segs {
            if addr >= seg.addr && addr + length <= seg.addr + seg.size {
                match perm {
                    'r' => return seg.read,
                    'w' => return seg.write,
                    'x' => return seg.exec,
                    'i' => return seg.init,
                    _ => return false, // uhhh shouldnt happen
                }
            }
        }

        false
    }

    pub fn add_segment(&mut self, name: &str, addr: u64, size: u64, perms: &str) {
        self.segs.push(MemorySegment {
            name: name.to_owned(),
            addr,
            size,
            read: perms.contains('r'),
            write: perms.contains('w'),
            exec: perms.contains('x'),
            init: perms.contains('i'),
        });
    }

    pub fn add_heap(&mut self) {
        self.add_segment("heap", HEAP_START, HEAP_SIZE, "rw--");
    }

    pub fn add_stack(&mut self) {
        self.add_segment("stack", STACK_START, STACK_SIZE, "rw--");
    }

    pub fn add_std_streams(&mut self) {
        let mut fd = 0;
        let stds = ["stdin", "stdout", "stderr"];
        for std in &stds {
            let mut addr = self.r2api.get_address(&("obj.".to_owned() + std)).unwrap();
            let mut offset = 112; // linux
            if addr == 0 {
                addr = self
                    .r2api
                    .get_address(&("reloc.__".to_owned() + std + "p"))
                    .unwrap();
                offset = 18; // macos, this is jank af
            }

            if addr != 0 {
                // from libc.rs should be in a common place
                let file_struct = self.alloc(&Value::Concrete(216, 0));
                self.write_value(file_struct + offset, &Value::Concrete(fd, 0), 4);
                self.write_value(
                    addr,
                    &Value::Concrete(file_struct, 0),
                    (self.bits / 8) as usize,
                );
                fd += 1;
            }
        }

        // Also put the macos canary here idk
        let stk_chk = self.r2api.get_address("reloc.__stack_chk_guard").unwrap();
        if stk_chk != 0 {
            let chk_value_addr = self.heap.alloc(8);
            self.write_value(
                chk_value_addr,
                &(Value::Symbolic(self.solver.bv("radius_canary", 64), 0)),
                (self.bits / 8) as usize,
            );
        }
    }

    pub fn brk(&mut self, address: u64) -> u64 {
        // check if this address is already mapped
        let avail = !self.check_permission(address, 1, 'i');

        for seg in &mut self.segs {
            if seg.name == ".data" {
                if avail {
                    // set size and return new break
                    seg.size = address - seg.addr;
                    return address;
                } else {
                    // return previous break
                    return seg.addr + seg.size;
                }
            }
        }
        0
    }

    pub fn sbrk(&mut self, inc: u64) -> u64 {
        for seg in &mut self.segs {
            if seg.name == ".data" {
                seg.size += inc;
                return seg.addr + seg.size - inc; // returns previous
            }
        }
        -1i64 as u64
    }

    #[inline]
    pub fn read_sym(&mut self, address: &Value, len: usize, solver: &mut Solver) -> Value {
        match address {
            Value::Concrete(addr, _t) => self.read_value(*addr, len),
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

    #[inline]
    pub fn write_sym(&mut self, address: &Value, value: &Value, len: usize, solver: &mut Solver) {
        match address {
            Value::Concrete(addr, _t) => self.write_value(*addr, value, len),
            Value::Symbolic(addr, t) => {
                let addrs = solver.evaluate_many(addr);
                for a in addrs {
                    let read_val = self.read_value(a, len);
                    let bv = solver.bvv(a, addr.get_width());
                    let cond = Value::Symbolic(addr._eq(&bv), *t);
                    let new_val = solver.conditional(&cond, &value, &read_val);
                    self.write_value(a, &new_val, len);
                }
            }
        }
    }

    pub fn read_sym_len(
        &mut self,
        address: &Value,
        length: &Value,
        solver: &mut Solver,
    ) -> Vec<Value> {
        let len = solver.max_value(length) as usize;

        match address {
            Value::Concrete(addr, _t) => {
                let mut data = vec![Value::Concrete(0, 0); len];
                self.read(*addr, len, &mut data);
                data
            }
            Value::Symbolic(addr, t) => {
                let addrs = solver.evaluate_many(addr);
                let mut values = vec![];
                for a in addrs {
                    let mut read_vals = vec![Value::Concrete(0, 0); len];
                    self.read(a, len, &mut read_vals);

                    let mut new_vals = vec![];
                    if values.is_empty() {
                        new_vals = read_vals;
                    } else {
                        for count in 0..len {
                            let bv = solver.bvv(a, 64);
                            let cond = Value::Symbolic(addr._eq(&bv), *t);
                            let value =
                                solver.conditional(&cond, &read_vals[count], &values[count]);

                            new_vals.push(value);
                        }
                    }
                    values = new_vals;
                }
                values
            }
        }
    }

    pub fn write_sym_len(
        &mut self,
        address: &Value,
        values: &[Value],
        length: &Value,
        solver: &mut Solver,
    ) {
        let mut len = solver.max_value(length) as usize;
        // hopefully this doesn't occur
        if len > values.len() {
            len = values.len();
        }

        let mut addrs = Vec::with_capacity(256);
        let t = address.get_taint();
        match address {
            Value::Concrete(addr, _t) => addrs.push(*addr),
            Value::Symbolic(addr, _t) => addrs.extend(solver.evaluate_many(addr)),
        };

        for addr in addrs {
            let mut read_vals = vec![Value::Concrete(0, 0); len];
            self.read(addr, len, &mut read_vals);

            for count in 0..len {
                let addr_val = Value::Concrete(addr, t);
                let count_val = Value::Concrete(count as u64, 0);
                let cond = address.eq(&addr_val) & count_val.ult(&length);
                let value = solver.conditional(&cond, &values[count], &read_vals[count]);
                self.write(addr + count as u64, &mut [value]);
            }
        }
    }

    pub fn memmove(&mut self, dst: &Value, src: &Value, length: &Value, solver: &mut Solver) {
        let data = self.read_sym_len(src, length, solver);
        self.write_sym_len(dst, &data, length, solver);
    }

    pub fn search(
        &mut self,
        addr: &Value,
        needle: &Value,
        length: &Value,
        reverse: bool,
        solver: &mut Solver,
    ) -> Value {
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
            }
            Value::Symbolic(val, _t) => val.get_width() / 8,
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

            let pos_cond = pos_val.ult(&(addr.clone() + length.clone())) & !pos_val.ult(&addr);
            let new_cond = value.eq(&needle) & pos_cond & !cond.clone();
            //println!("{:?}", new_cond);
            result = solver.conditional(&new_cond, &pos_val, &result);
            cond = value.eq(&needle) | cond;

            if let Value::Concrete(res, _t) = &result {
                if *res != 0 {
                    break;
                }
            } else if value.id(&needle).as_u64().unwrap() == 1 {
                // this is weird but cuts searches on identical values
                break;
            }
        }

        result
    }

    pub fn strlen(&mut self, addr: &Value, length: &Value, solver: &mut Solver) -> Value {
        let end = self.search(addr, &Value::Concrete(0, 0), length, false, solver);
        solver.conditional(&(end.eq(&Value::Concrete(0, 0))), length, &end.sub(addr))
    }

    pub fn compare(
        &mut self,
        addr1: &Value,
        addr2: &Value,
        length: &Value,
        solver: &mut Solver,
    ) -> Value {
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
                &Value::Concrete(-1i64 as u64, 0),
                &result,
            );

            result = solver.conditional(
                &(gt & same.clone() & len_cond),
                &Value::Concrete(1, 0),
                &lt_val,
            );

            same = same & result.eq(&Value::Concrete(0, 0));

            if let Value::Concrete(res, _t) = &same {
                if *res != 0 {
                    break;
                }
            }
        }

        result
    }

    #[inline]
    pub fn read_value(&mut self, addr: u64, length: usize) -> Value {
        if length <= 32 {
            let mut data: [Value; 32] = Default::default();
            self.read(addr, length, &mut data[..length]);
            self.pack(&data[..length])
        } else {
            let mut data = vec![Value::Concrete(0, 0); length];
            self.read(addr, length, &mut data);
            self.pack(&data)
        }
    }

    #[inline]
    pub fn write_value(&mut self, addr: u64, value: &Value, length: usize) {
        let mut data = self.unpack(value, length);
        self.write(addr, &mut data)
    }

    pub fn read(&mut self, addr: u64, length: usize, data: &mut [Value]) {
        //println!("length {} data len {}", length, data.());
        if length == 0 {
            return;
        }

        if self.check && !self.check_permission(addr, length as u64, 'r') {
            // everything needs to be reworked to have Result<...>
            // so that we can properly handle things like this
            self.handle_segfault(addr, length as u64, 'r');
        }

        let make_sym = self.blank && !self.check_permission(addr, length as u64, 'i');

        //let mut data: Vec<Value> = Vec::with_capacity(length);
        for count in 0..length as u64 {
            let caddr = addr + count;
            let mem = self.mem.get(&caddr);

            match mem {
                Some(byte) => {
                    data[count as usize] = byte.to_owned();
                }
                None => {
                    if make_sym {
                        let sym_name = format!("mem_{:08x}", caddr);
                        data[count as usize] =
                            Value::Symbolic(self.solver.bv(sym_name.as_str(), 8), 0);
                    } else {
                        let bytes = self.r2api.read(caddr, READ_CACHE).unwrap();
                        data[count as usize] = Value::Concrete(bytes[0] as u64, 0);
                        for (c, byte) in bytes.into_iter().enumerate() {
                            let new_data = Value::Concrete(byte as u64, 0);
                            self.mem.entry(caddr + c as u64).or_insert(new_data);
                        }
                    }
                }
            }
        }
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
            prot_str += "w";
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

    pub fn read_bytes(&mut self, addr: u64, length: usize, solver: &mut Solver) -> Vec<u8> {
        let mut data = vec![Value::Concrete(0, 0); length];
        self.read(addr, length, &mut data);
        solver.push();
        let data_u8 = data
            .iter()
            .map(|d| solver.evalcon_to_u64(&d).unwrap() as u8)
            .collect();
        solver.pop();
        data_u8
    }

    //read utf8 string
    pub fn read_string(&mut self, addr: u64, length: usize, solver: &mut Solver) -> String {
        String::from_utf8(self.read_bytes(addr, length, solver)).unwrap_or_default()
    }

    pub fn write_string(&mut self, addr: u64, string: &str) {
        let data = string.as_bytes();
        let mut data_value = Vec::with_capacity(string.len());
        for d in data {
            data_value.push(Value::Concrete(*d as u64, 0));
        }
        data_value.push(Value::Concrete(0, 0));
        self.write(addr, &mut data_value);
    }

    pub fn write(&mut self, addr: u64, data: &mut [Value]) {
        //println!("write {:?}", data);
        let length = data.len();

        if self.check && !self.check_permission(addr, length as u64, 'w') {
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
        panic!(
            "addr {} length {} does not have perm \"{}\"",
            addr, length, perm
        );
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
        if length > 8 || new_data.iter().any(|x| x.is_symbolic()) {
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
                    }
                    Value::Concrete(val, t) => {
                        let new_val = self.solver.bvv(*val, 8);

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
            for (count, datum) in new_data.iter().enumerate() {
                if let Value::Concrete(val, t) = datum {
                    con_val += val << (8 * count);
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
                    data.push(Value::Concrete((*val >> (8 * count)) & 0xff, *t));
                }
            }
            Value::Symbolic(val, t) => {
                for count in 0..length {
                    //let trans_val = self.solver.translate(&val).unwrap();
                    let bv = val.slice(((count as u32) + 1) * 8 - 1, (count as u32) * 8);
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
    pub size: u64,
    pub chunks: Vec<Chunk>,
}

#[derive(Clone, PartialEq)]
pub struct Chunk {
    pub addr: u64,
    pub size: u64,
}

// still a dumb af heap implementation
impl Heap {
    pub fn new(start: u64, size: u64) -> Self {
        Heap {
            start,
            size,
            chunks: vec![Chunk {
                addr: start,
                size: 0,
            }],
        }
    }

    pub fn alloc(&mut self, size: u64) -> u64 {
        let last = &self.chunks[self.chunks.len() - 1];
        let addr = last.addr + last.size;
        self.chunks.push(Chunk { addr, size });
        addr
    }

    pub fn free(&mut self, addr: u64) -> Option<u64> {
        let last = &self.chunks[self.chunks.len() - 1];
        if addr == last.addr {
            self.chunks.pop();
            Some(addr)
        } else {
            if let Some(rem) = self.chunks.iter().position(|x| x.addr == addr) {
                self.chunks.remove(rem);
                Some(addr)
            } else {
                None
            }
        }
    }
}
