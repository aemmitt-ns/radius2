use crate::r2_api::{R2Api, Endian};
use crate::registers::Registers;
use crate::memory::Memory;
use crate::value::Value;
use crate::solver::{Solver, BitVec};
use crate::sims::fs::SimFilesytem;

use std::u8;
//use std::collections::HashMap;
use ahash::AHashMap;
type HashMap<P, Q> = AHashMap<P, Q>;

// use backtrace::Backtrace;

#[derive(Debug, Clone, PartialEq)]
pub enum ExecMode {
    If,     // in a symbolic if clause ?{,...,}
    Else,   // in a symbolic else clause ?{,---,}{,...,}
    Exec,   // in a clause that is always executed 1,?{,...,}
    NoExec, // in a clause that is never executed 0,?{,...,}
    Uncon,  // not in an if or else, regular parsing
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
    pub condition: Option<BitVec>,
    pub registers: Registers,
    pub memory:    Memory,
    pub filesystem:SimFilesytem,
    pub status:    StateStatus,
    pub context:   HashMap<String, Vec<Value>>,
    pub taints:    HashMap<String, u64>,
    pub pid:       u64,
    pub backtrace: Vec<u64>,
    pub blank:     bool,
    pub debug:     bool
}

impl State {
    /// Create a new state, should generally not be called directly
    pub fn new(r2api: &mut R2Api, eval_max: usize, debug: bool, blank: bool, check: bool) -> Self {
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

        let solver = Solver::new(eval_max);
        let registers = Registers::new(r2api, solver.clone(), blank);
        let memory = Memory::new(r2api, solver.clone(), blank, check);

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
            pid: 1337, // sup3rh4x0r
            blank,
            debug
        }
    }

    pub fn duplicate(&mut self) -> Self {
        let solver = self.solver.duplicate();

        let mut registers = self.registers.clone();
        registers.solver = solver.clone();
        registers.values = registers.values.iter()
            .map(|r| solver.translate_value(r)).collect();

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
            pid: self.pid,
            blank: self.blank,
            debug: self.debug
        }
    }

    // yes i hate all of this

    /// Allocate a block of memory `length` bytes in size
    pub fn memory_alloc(&mut self, length: &Value) -> Value {
        self.memory.alloc_sym(length, &mut self.solver)
    }

    /// Free a block of memory at `addr`
    pub fn memory_free(&mut self, addr: &Value) -> Value {
        self.memory.free_sym(addr, &mut self.solver)
    }

    /// Read `length` bytes from `address`
    pub fn memory_read(&mut self, address: &Value, length: &Value) -> Vec<Value> {
        self.memory.read_sym_len(address, length, &mut self.solver)
    }

    /// Write `length` bytes to `address`
    pub fn memory_write(&mut self, address: &Value, values: &[Value], length: &Value) {
        self.memory.write_sym_len(address, values, length, &mut self.solver)
    }

    /// Read `length` byte value from `address`
    pub fn memory_read_value(&mut self, address: &Value, length: usize) -> Value {
        self.memory.read_sym(address, length, &mut self.solver)
    }

    /// Write `length` byte value to `address`
    pub fn memory_write_value(&mut self, address: &Value, value: &Value, length: usize) {
        self.memory.write_sym(address, value, length, &mut self.solver)
    }

    /// Search for `needle` at the address `addr` for a maximum of `length` bytes 
    /// Returns a `Value` containing the **address** of the needle, not index
    pub fn memory_search(&mut self, addr: &Value, needle: &Value, length: &Value, reverse: bool) -> Value {
        self.memory.search(addr, needle, length, reverse, &mut self.solver)
    }

    /// Compare memory at `dst` and `src` address up to `length` bytes.
    /// This is akin to memcmp but will handle symbolic addrs and length
    pub fn memory_compare(&mut self, dst: &Value, src: &Value, length: &Value) -> Value {
        self.memory.compare(dst, src, length, &mut self.solver)
    }

    /// Get the length of the null terminated string at `addr`
    pub fn memory_strlen(&mut self, addr: &Value, length: &Value) -> Value {
        self.memory.strlen(addr, length, &mut self.solver)
    }

    /// Move `length` bytes from `src` to `dst`
    pub fn memory_move(&mut self, dst: &Value, src: &Value, length: &Value) {
        self.memory.memmove(dst, src, length, &mut self.solver)
    }

    /// Read `length` bytes from `address`
    pub fn memory_read_bytes(&mut self, address: u64, length: usize) -> Vec<u8> {
        self.memory.read_bytes(address, length, &mut self.solver)
    }

    /// Read a string from `address` up to `length` bytes long
    pub fn memory_read_string(&mut self, address: u64, length: usize) -> String {
        self.memory.read_string(address, length, &mut self.solver)
    }

    // this doesnt need to be here, just for consistency sake
    /// Write `string` to `address`
    pub fn memory_write_string(&mut self, address: u64, string: &str) {
        self.memory.write_string(address, string)
    }

    // TODO do this in a way that isn't a global maximum of stupidity
    /// Apply this state to the radare2 instance. This writes all the values
    /// in the states memory back to the memory in r2 as well as the register
    /// values, evaluating any symbolic expressions. 
    pub fn apply(&mut self) {
        let mut inds = vec!();
        for reg in &self.registers.indexes {
            if !inds.contains(&reg.value_index) {
                inds.push(reg.value_index);
                let rval = self.registers.values[reg.value_index].to_owned();
                let r = self.solver.evalcon_to_u64(&rval).unwrap();
                self.r2api.set_register_value(&reg.reg_info.name, r);
            }
        }

        for addr in self.memory.addresses() {
            let bval = self.memory.read_value(addr, 1);
            let b = self.solver.evalcon_to_u64(&bval).unwrap() as u8;
            self.r2api.write(addr, vec!(b));
        }
    }

    /// Use the constraints from the provided state. This is
    /// useful for constraining the data in some initial
    /// state with the assertions of some desired final state
    pub fn constrain_with_state(&mut self, state: &Self) {
       self.solver = state.solver.clone(); 
    }

    /// Create a bitvector from this states solver
    #[inline]
    pub fn bv(&self, s: &str, n: u32) -> BitVec {
        self.solver.bv(s, n)
    }

    /// Create a bitvector value from this states solver
    #[inline]
    pub fn bvv(&self, v: u64, n: u32) -> BitVec {
        self.solver.bvv(v, n)
    }

    /// Create a `Value::Concrete` from a value `v` and bit width `n`
    pub fn concrete_value(&self, v: u64, n: u32) -> Value {
        let mask = if n < 64 { 
            (1 << n) - 1
        } else {
            -1i64 as u64
        };
        Value::Concrete(v & mask, 0)
    }

    /// Create a `Value::Symbolic` from a name `s` and bit width `n` 
    pub fn symbolic_value(&self, s: &str, n: u32) -> Value {
        Value::Symbolic(self.bv(s, n), 0)
    }

    /// Create a tainted `Value::Concrete` from a value `v` and bit width `n`
    pub fn tainted_concrete_value(&mut self, t: &str, v: u64, n: u32) -> Value {
        let mask = if n < 64 { 
            (1 << n) - 1
        } else {
            -1i64 as u64
        };
        let taint = self.get_tainted_identifier(t);
        Value::Concrete(v & mask, taint)
    }

    /// Create a tainted `Value::Symbolic` from a name `s` and bit width `n` 
    pub fn tainted_symbolic_value(&mut self, t: &str, s: &str, n: u32) -> Value {
        let taint = self.get_tainted_identifier(t);
        Value::Symbolic(self.bv(s, n), taint)
    }

    /// Get the numeric identifier for the given taint name
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

    /// Check if the `value` is tainted with the given `taint`  
    pub fn is_tainted_with(&mut self, value: &Value, taint: &str) -> bool {
        (value.get_taint() & self.get_tainted_identifier(taint)) != 0
    }

    /// BitVectors will need to be translated if run is multithreaded
    #[inline]
    pub fn translate(&mut self, bv: &BitVec) -> Option<BitVec> {
        self.solver.translate(bv)
    }

    #[inline]
    pub fn translate_value(&mut self, value: &Value) -> Value {
        self.solver.translate_value(value)
    }

    /// Evaluate a `Value` `val`
    #[inline]
    pub fn eval(&mut self, val: &Value) -> Option<Value> {
        self.solver.eval(val)
    }

    /// Evaluate a bitvector `bv`
    #[inline]
    pub fn evaluate(&mut self, bv: &BitVec) -> Option<Value> {
        self.solver.evaluate(bv)
    }

    /// Evaluate and constrain the symbol to the u64
    #[inline]
    pub fn evalcon(&mut self, bv: &BitVec) -> Option<u64> {
        self.solver.evalcon(bv)
    }

    // TODO
    /*pub fn constrain_bytes(&mut self, bv: &BitVec, pattern: &str) {

    }*/

    /// Check if this state is satisfiable and mark the state `Unsat` if not
    #[inline]
    pub fn is_sat(&mut self) -> bool {
        if self.solver.is_sat() {
            true
        } else {
            self.status = StateStatus::Unsat;
            false
        }
    }

    /// Assert the truth of the given bitvector (value != 0)
    #[inline]
    pub fn assert(&mut self, bv: &BitVec) {
        self.solver.assert(bv)
    }

    /// Assert the truth of the given `Value` (lsb of value != 0)
    #[inline]
    pub fn assert_value(&mut self, value: &Value) {
        self.solver.assert_value(value)
    }

    /// Evaluate multiple solutions to bv
    pub fn evaluate_many(&mut self, bv: &BitVec) -> Vec<u64> {
        self.solver.evaluate_many(bv)
    }

    /// Evaluate a string from bitvector `bv` 
    pub fn evaluate_string(&mut self, bv: &BitVec) -> Option<String> {
        let new_bv = bv; //self.translate(bv).unwrap();
        let mut data: Vec<u8> = vec!();
        if self.solver.is_sat() {
            //let one_sol = new_bv.get_a_solution().disambiguate();
            let solution_opt = self.solver.solution(&new_bv);
            if let Some(solution) = solution_opt {
                for i in 0..(new_bv.get_width()/8) as usize {
                    let sol = u8::from_str_radix(&solution[i*8..(i+1)*8], 2);
                    data.push(sol.unwrap());
                }
                if self.memory.endian == Endian::Little {
                    data.reverse();
                }
                String::from_utf8(data).ok()
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Evaluate string from value
    pub fn evaluate_string_value(&mut self, value: &Value) -> Option<String> {
        self.evaluate_string(value.as_bv().as_ref().unwrap())
    }
}