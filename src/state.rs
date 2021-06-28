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

#[derive(Debug, Clone)]
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
    pub pid:       u64,
    pub backtrace: Vec<u64>
}

impl State {
    pub fn new(r2api: &mut R2Api) -> Self {
        let esil_state = EsilState {
            mode: ExecMode::Uncon,
            previous: Value::Concrete(0),
            current: Value::Concrete(0),
            last_sz: 64,
            stored_address: None,
            pcs: vec!()
        };

        let solver = Solver::new();
        let registers = Registers::new(r2api, solver.clone());
        let memory = Memory::new(r2api, solver.clone());

        State {
            solver: solver,
            r2api: r2api.clone(),
            stack: vec!(),
            esil: esil_state,
            condition: None,
            registers,
            memory,
            filesystem: SimFilesytem::new(),
            status: StateStatus::Active,
            context: HashMap::new(),
            backtrace: vec!(),
            pid: 1337 // sup3rh4x0r
        }
    }

    pub fn duplicate(&mut self) -> Self {
        let solver = self.solver.clone();

        let mut registers = self.registers.clone();
        registers.solver = solver.clone();

        let mut memory = self.memory.clone();
        memory.solver = solver.clone();

        State {
            solver,
            r2api: self.r2api.clone(),
            stack: self.stack.clone(),
            esil: self.esil.clone(),
            condition: None,
            registers,
            memory,
            filesystem: self.filesystem.clone(),
            status: self.status.clone(),
            context: self.context.clone(),
            backtrace: self.backtrace.clone(),
            pid: self.pid
        }
    }

    #[inline]
    pub fn bv(&mut self, s: &str, n: u32) -> BV<Arc<Btor>>{
        self.solver.bv(s, n)
    }

    #[inline]
    pub fn bvv(&mut self, v: u64, n: u32) -> BV<Arc<Btor>>{
        self.solver.bvv(v, n)
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
}