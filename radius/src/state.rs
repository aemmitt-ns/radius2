use crate::r2_api::{R2Api, Endian};
use crate::registers::Registers;
use crate::memory::Memory;
use crate::value::Value;
use crate::solver::Solver;
use crate::sims::fs::SimFilesytem;

use boolector::{Btor, BV};
use std::sync::Arc;
use std::u8;
use std::collections::HashMap;

// use backtrace::Backtrace;

#[derive(Debug, Clone, PartialEq)]
pub enum ExecMode {
    If,
    Else,
    Exec,
    NoExec,
    Uncon,
}

#[derive(Debug, Clone)]
pub struct EsilState {
    pub mode: ExecMode,
    pub previous: Value,
    pub current:  Value,
    pub last_sz:  usize,
    pub stored_address: Option<Value>,
    pub temp1: Vec<StackItem>,
    pub temp2: Vec<StackItem>,
    pub pcs: Vec<u64>
}

#[derive(Debug, Clone)]
pub enum StackItem {
    StackRegister(usize),
    StackValue(Value)
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateStatus {
    Active,
    Break,
    Merge,
    PostMerge, // so we dont get caught in merge loop
    Unsat,
    Inactive
}

#[derive(Clone)]
pub struct State {
    pub solver:    Solver,
    pub r2api:     R2Api,
    pub stack:     Vec<StackItem>,
    pub esil:      EsilState,
    pub condition: Option<BV<Arc<Btor>>>,
    pub registers: Registers,
    pub memory:    Memory,
    pub filesystem:SimFilesytem,
    pub status:    StateStatus,
    pub context:   HashMap<String, Vec<Value>>,
    pub taints:    HashMap<String, u64>,
    pub pid:       u64,
    pub backtrace: Vec<u64>
}

impl State {
    pub fn new(r2api: &mut R2Api) -> Self {
        let esil_state = EsilState {
            mode: ExecMode::Uncon,
            previous: Value::Concrete(0, 0),
            current: Value::Concrete(0, 0),
            last_sz: 64,
            stored_address: None,
            temp1: vec!(), // these instances are actually not used
            temp2: vec!(),
            pcs: Vec::with_capacity(64)
        };

        let solver = Solver::new();
        let registers = Registers::new(r2api, solver.clone());
        let memory = Memory::new(r2api, solver.clone());

        State {
            solver,
            r2api: r2api.clone(),
            stack: Vec::with_capacity(128),
            esil: esil_state,
            condition: None,
            registers,
            memory,
            filesystem: SimFilesytem::new(),
            status: StateStatus::Active,
            context: HashMap::new(),
            taints: HashMap::new(),
            backtrace: Vec::with_capacity(128),
            pid: 1337 // sup3rh4x0r
        }
    }

    pub fn duplicate(&mut self) -> Self {
        let solver = self.solver.duplicate();

        let mut registers = self.registers.clone();
        registers.solver = solver.clone();

        let mut new_regs = vec!();
        for reg in &registers.values {
            new_regs.push(solver.translate_value(reg));
        }
        registers.values = new_regs;

        let mut memory = self.memory.clone();
        memory.solver = solver.clone();

        let addrs = memory.addresses();
        for addr in addrs {
            let value = memory.mem.remove(&addr).unwrap();
            memory.mem.insert(addr, solver.translate_value(&value));
        }

        let esil_state = EsilState {
            mode: ExecMode::Uncon,
            previous: Value::Concrete(0, 0),
            current: Value::Concrete(0, 0),
            last_sz: 64,
            stored_address: None,
            temp1: Vec::with_capacity(128),
            temp2: Vec::with_capacity(128),
            pcs: Vec::with_capacity(64)
        };

        State {
            solver,
            r2api: self.r2api.clone(),
            stack: Vec::with_capacity(128),
            esil: esil_state,
            condition: None,
            registers,
            memory,
            filesystem: self.filesystem.clone(),
            status: self.status.clone(),
            context: self.context.clone(),
            taints: self.taints.clone(),
            backtrace: self.backtrace.clone(),
            pid: self.pid
        }
    }

    // yes i hate all of this
    pub fn memory_read(&mut self, address: &Value, length: &Value) -> Vec<Value> {
        self.memory.read_sym_len(address, length, &mut self.solver)
    }

    pub fn memory_write(&mut self, address: &Value, values: &[Value], length: &Value) {
        self.memory.write_sym_len(address, values, length, &mut self.solver)
    }

    pub fn memory_read_value(&mut self, address: &Value, length: usize) -> Value {
        self.memory.read_sym(address, length, &mut self.solver)
    }

    pub fn memory_write_value(&mut self, address: &Value, value: &Value, length: usize) {
        self.memory.write_sym(address, value, length, &mut self.solver)
    }

    pub fn memory_search(&mut self, addr: &Value, needle: &Value, length: &Value, reverse: bool) -> Value {
        self.memory.search(addr, needle, length, reverse, &mut self.solver)
    }

    pub fn memory_compare(&mut self, dst: &Value, src: &Value, length: &Value) -> Value {
        self.memory.compare(dst, src, length, &mut self.solver)
    }

    pub fn memory_strlen(&mut self, addr: &Value, length: &Value) -> Value {
        self.memory.strlen(addr, length, &mut self.solver)
    }

    pub fn memory_move(&mut self, dst: &Value, src: &Value, length: &Value) {
        self.memory.memmove(dst, src, length, &mut self.solver)
    }

    pub fn memory_read_string(&mut self, address: u64, length: usize) -> String {
        self.memory.read_string(address, length, &mut self.solver)
    }

    // this doesnt need to be here, just for consistency sake
    pub fn memory_write_string(&mut self, address: u64, string: &str) {
        self.memory.write_string(address, string)
    }

    #[inline]
    pub fn bv(&self, s: &str, n: u32) -> BV<Arc<Btor>>{
        self.solver.bv(s, n)
    }

    #[inline]
    pub fn bvv(&self, v: u64, n: u32) -> BV<Arc<Btor>>{
        self.solver.bvv(v, n)
    }

    pub fn concrete_value(&self, v: u64, n: u32) -> Value {
        let mask = if n < 64 { 
            (1 << n) - 1
        } else {
            -1i64 as u64
        };
        Value::Concrete(v & mask, 0)
    }

    pub fn symbolic_value(&self, s: &str, n: u32) -> Value {
        Value::Symbolic(self.bv(s, n), 0)
    }

    pub fn tainted_concrete_value(&mut self, t: &str, v: u64, n: u32) -> Value {
        let mask = if n < 64 { 
            (1 << n) - 1
        } else {
            -1i64 as u64
        };
        let taint = self.get_tainted_identifier(t);
        Value::Concrete(v & mask, taint)
    }

    pub fn tainted_symbolic_value(&mut self, t: &str, s: &str, n: u32) -> Value {
        let taint = self.get_tainted_identifier(t);
        Value::Symbolic(self.bv(s, n), taint)
    }

    pub fn get_tainted_identifier(&mut self, t: &str) -> u64 {
        if let Some(taint) = self.taints.get(t) {
            *taint
        } else {
            let index = self.taints.len();
            if index < 64 {
                let new_taint = 1 << index as u64;
                self.taints.insert(t.to_owned(), new_taint);
                new_taint
            } else {
                panic!("Max of 64 taints allowed!");
            }
        }
    }

    pub fn is_tainted_with(&mut self, value: &Value, taint: &str) -> bool {
        value.get_taint() & self.get_tainted_identifier(taint) != 0
    }

    #[inline]
    pub fn translate(&mut self, bv: &BV<Arc<Btor>>) -> Option<BV<Arc<Btor>>> {
        self.solver.translate(bv)
    }

    #[inline]
    pub fn translate_value(&mut self, value: &Value) -> Value {
        self.solver.translate_value(value)
    }

    #[inline]
    pub fn eval(&mut self, val: &Value) -> Option<Value> {
        self.solver.eval(val)
    }

    #[inline]
    pub fn evaluate(&mut self, bv: &BV<Arc<Btor>>) -> Option<Value> {
        self.solver.evaluate(bv)
    }

    // evaluate and constrain the symbol to the value
    #[inline]
    pub fn evalcon(&mut self, bv: &BV<Arc<Btor>>) -> Option<u64> {
        self.solver.evalcon(bv)
    }

    // TODO
    /*pub fn constrain_bytes(&mut self, bv: &BV<Arc<Btor>>, pattern: &str) {

    }*/

    #[inline]
    pub fn is_sat(&mut self) -> bool {
        if self.solver.is_sat() {
            true
        } else {
            self.status = StateStatus::Unsat;
            false
        }
    }

    #[inline]
    pub fn assert(&mut self, bv: &BV<Arc<Btor>>) {
        self.solver.assert(bv)
    }

    pub fn evaluate_many(&mut self, bv: &BV<Arc<Btor>>) -> Vec<u64> {
        self.solver.evaluate_many(bv)
    }

    pub fn evaluate_string(&mut self, bv: &BV<Arc<Btor>>) -> Option<String> {
        let new_bv = self.translate(bv).unwrap();
        let mut data: Vec<u8> = vec!();
        if self.solver.is_sat() {
            //let one_sol = new_bv.get_a_solution().disambiguate();
            let solution = self.solver.solution(&new_bv).unwrap();
            for i in 0..(new_bv.get_width()/8) as usize {
                let sol = u8::from_str_radix(&solution[i*8..(i+1)*8], 2);
                data.push(sol.unwrap());
            }
            if self.memory.endian == Endian::Little {
                data.reverse();
            }
            Some(String::from_utf8(data).unwrap())
        } else {
            None
        }
    }

    pub fn evaluate_string_value(&mut self, value: &Value) -> Option<String> {
        self.evaluate_string(value.as_bv().as_ref().unwrap())
    }
}