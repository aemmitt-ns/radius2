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

// event hooks could be a performance issue at some point
// prolly not now cuz there are 10000 slower things
const DO_EVENT_HOOKS: bool = true;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum EventTrigger {
    Before, // call hook before event occurs 
    After   // call hook after
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Event {
    SymbolicRead(EventTrigger),    // read from symbolic address
    SymbolicWrite(EventTrigger),   // write to symbolic address
    SymbolicExec(EventTrigger),    // execute symbolic address
    Alloc(EventTrigger),           // allocate memory
    SymbolicAlloc(EventTrigger),   // allocate symbolic length
    Free(EventTrigger),            // free memory
    SymbolicFree(EventTrigger),    // free symbolic address
    Search(EventTrigger),          // mem search (strchr, memmem)
    SymbolicSearch(EventTrigger),  // search with symbolic addr, needle, or length
    Compare(EventTrigger),         // compare memory (memcmp, strcmp)
    SymbolicCompare(EventTrigger), // symbolic compare 
    StringLength(EventTrigger),    // string length check (strlen)
    SymbolicStrlen(EventTrigger),  // strlen of symbolic address
    Move(EventTrigger),            // move bytes from src to dst (memcpy, memmove)
    SymbolicMove(EventTrigger),    // symbolic move (memcpy, memmove)
    All(EventTrigger)              // gotta hook em all, ra! - di! - us!
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventContext {
    ReadContext(Value, Value),
    WriteContext(Value, Value),
    ExecContext(Value),
    AfterExecContext(Value, Vec<Value>), // eh idk maybe ill do something else
    AllocContext(Value),
    FreeContext(Value),
    SearchContext(Value, Value, Value),
    CompareContext(Value, Value, Value),
    StrlenContext(Value, Value),
    MoveContext(Value, Value, Value)
}

pub type EventHook = fn (&mut State, &EventContext);

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
    pub solver:     Solver,
    pub r2api:      R2Api,
    pub stack:      Vec<StackItem>,
    pub esil:       EsilState,
    pub condition:  Option<BitVec>,
    pub registers:  Registers,
    pub memory:     Memory,
    pub filesystem: SimFilesytem,
    pub status:     StateStatus,
    pub context:    HashMap<String, Vec<Value>>,
    pub taints:     HashMap<String, u64>,
    pub hooks:      HashMap<Event, EventHook>,
    pub pid:        u64,
    pub backtrace:  Vec<u64>,
    pub blank:      bool,
    pub debug:      bool,
    pub has_event_hooks: bool
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
            hooks: HashMap::new(),
            backtrace: Vec::with_capacity(128),
            pid: 1337, // sup3rh4x0r
            blank,
            debug,
            has_event_hooks: false
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
            hooks: self.hooks.clone(),
            backtrace: self.backtrace.clone(),
            pid: self.pid,
            blank: self.blank,
            debug: self.debug,
            has_event_hooks: self.has_event_hooks
        }
    }

    pub fn hook_event(&mut self, event: Event, hook: EventHook) {
        self.has_event_hooks = true;
        self.hooks.insert(event, hook);
    }
    
    pub fn do_hooked(&mut self, event: &Event, event_context: &EventContext) {
        if let Some(hook) = self.hooks.get(event) {
            hook(self, event_context)
        }
    }

    // yes i hate all of this

    /// Allocate a block of memory `length` bytes in size
    pub fn memory_alloc(&mut self, length: &Value) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if length.is_symbolic() {
                Event::SymbolicAlloc(EventTrigger::Before)
            } else {
                Event::Alloc(EventTrigger::Before)
            };
            self.do_hooked(&event, 
                &EventContext::AllocContext(length.to_owned()));
        }

        let ret = self.memory.alloc_sym(length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if length.is_symbolic() {
                Event::SymbolicAlloc(EventTrigger::After)
            } else {
                Event::Alloc(EventTrigger::After)
            };
            self.do_hooked(&event, 
                &EventContext::AllocContext(length.to_owned()));
        }

        ret
    }

    /// Free a block of memory at `addr`
    pub fn memory_free(&mut self, addr: &Value) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() {
                Event::SymbolicFree(EventTrigger::Before)
            } else {
                Event::Free(EventTrigger::Before)
            };
            self.do_hooked(&event, 
                &EventContext::FreeContext(addr.to_owned()));
        }

        let ret = self.memory.free_sym(addr, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() {
                Event::SymbolicFree(EventTrigger::After)
            } else {
                Event::Free(EventTrigger::After)
            };
            self.do_hooked(&event, 
                &EventContext::FreeContext(addr.to_owned()));
        }

        ret
    }

    /// Read `length` bytes from `address`
    pub fn memory_read(&mut self, address: &Value, length: &Value) -> Vec<Value> {
        if DO_EVENT_HOOKS && self.has_event_hooks && 
            (address.is_symbolic() || length.is_symbolic()) {
            self.do_hooked(&Event::SymbolicRead(EventTrigger::Before), 
                &EventContext::ReadContext(address.to_owned(), length.to_owned()));
        }

        let ret = self.memory.read_sym_len(address, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks && 
            (address.is_symbolic() || length.is_symbolic()) {
            self.do_hooked(&Event::SymbolicRead(EventTrigger::After), 
                &EventContext::ReadContext(address.to_owned(), length.to_owned()));
        }
    
        ret
    }

    /// Write `length` bytes to `address`
    pub fn memory_write(&mut self, address: &Value, values: &[Value], length: &Value) {
        if DO_EVENT_HOOKS && self.has_event_hooks && 
            (address.is_symbolic() || length.is_symbolic()) {
            self.do_hooked(&Event::SymbolicWrite(EventTrigger::Before), 
                &EventContext::WriteContext(address.to_owned(), length.to_owned()));
        }

        let ret = self.memory.write_sym_len(address, values, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks && 
            (address.is_symbolic() || length.is_symbolic()) {
            self.do_hooked(&Event::SymbolicWrite(EventTrigger::After), 
                &EventContext::WriteContext(address.to_owned(), length.to_owned()));
        }
        
        ret
    }

    /// Read `length` byte value from `address`
    pub fn memory_read_value(&mut self, address: &Value, length: usize) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks && address.is_symbolic() {
            self.do_hooked(&Event::SymbolicRead(EventTrigger::Before), 
                &EventContext::ReadContext(address.to_owned(), Value::Concrete(length as u64, 0)));
        }

        let ret = self.memory.read_sym(address, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks && address.is_symbolic() {
            self.do_hooked(&Event::SymbolicRead(EventTrigger::After), 
                &EventContext::ReadContext(address.to_owned(), Value::Concrete(length as u64, 0)));
        }

        ret
    }

    /// Write `length` byte value to `address`
    pub fn memory_write_value(&mut self, address: &Value, value: &Value, length: usize) {
        if DO_EVENT_HOOKS && self.has_event_hooks && address.is_symbolic() {
            self.do_hooked(&Event::SymbolicRead(EventTrigger::Before), 
                &EventContext::ReadContext(address.to_owned(), Value::Concrete(length as u64, 0)));
        }

        let ret = self.memory.write_sym(address, value, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks && address.is_symbolic() {
            self.do_hooked(&Event::SymbolicWrite(EventTrigger::After), 
                &EventContext::WriteContext(address.to_owned(), Value::Concrete(length as u64, 0)));
        }

        ret
    }

    /// Search for `needle` at the address `addr` for a maximum of `length` bytes 
    /// Returns a `Value` containing the **address** of the needle, not index
    pub fn memory_search(&mut self, addr: &Value, needle: &Value, length: &Value, reverse: bool) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() || length.is_symbolic() {
                Event::SymbolicSearch(EventTrigger::Before)
            } else {
                Event::Search(EventTrigger::Before)
            };
            self.do_hooked(&event, 
                &EventContext::SearchContext(addr.to_owned(), needle.to_owned(), length.to_owned()));
        }

        let ret = self.memory.search(addr, needle, length, reverse, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() || length.is_symbolic() {
                Event::SymbolicSearch(EventTrigger::After)
            } else {
                Event::Search(EventTrigger::After)
            };
            self.do_hooked(&event, 
                &EventContext::SearchContext(addr.to_owned(), needle.to_owned(), length.to_owned()));
        }

        ret
    }

    /// Compare memory at `dst` and `src` address up to `length` bytes.
    /// This is akin to memcmp but will handle symbolic addrs and length
    pub fn memory_compare(&mut self, dst: &Value, src: &Value, length: &Value) -> Value {

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if dst.is_symbolic() || src.is_symbolic() || length.is_symbolic() {
                Event::SymbolicCompare(EventTrigger::Before)
            } else {
                Event::Compare(EventTrigger::Before)
            };
            self.do_hooked(&event, 
                &EventContext::CompareContext(dst.to_owned(), src.to_owned(), length.to_owned()));
        }

        let ret = self.memory.compare(dst, src, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if dst.is_symbolic() || src.is_symbolic() || length.is_symbolic() {
                Event::SymbolicCompare(EventTrigger::After)
            } else {
                Event::Compare(EventTrigger::After)
            };
            self.do_hooked(&event,
                &EventContext::CompareContext(dst.to_owned(), src.to_owned(), length.to_owned()));
        }

        ret
    }

    /// Get the length of the null terminated string at `addr`
    pub fn memory_strlen(&mut self, addr: &Value, length: &Value) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() || length.is_symbolic() {
                Event::SymbolicStrlen(EventTrigger::Before)
            } else {
                Event::StringLength(EventTrigger::Before)
            };
            self.do_hooked(&event, 
                &EventContext::StrlenContext(addr.to_owned(), length.to_owned()));
        }

        let ret = self.memory.strlen(addr, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() || length.is_symbolic() {
                Event::SymbolicStrlen(EventTrigger::After)
            } else {
                Event::StringLength(EventTrigger::After)
            };
            self.do_hooked(&event, 
                &EventContext::StrlenContext(addr.to_owned(), length.to_owned()));
        }

        ret
    }

    /// Move `length` bytes from `src` to `dst`
    pub fn memory_move(&mut self, dst: &Value, src: &Value, length: &Value) {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if dst.is_symbolic() || src.is_symbolic() || length.is_symbolic() {
                Event::SymbolicMove(EventTrigger::Before)
            } else {
                Event::Move(EventTrigger::Before)
            };
            self.do_hooked(&event, 
                &EventContext::MoveContext(dst.to_owned(), src.to_owned(), length.to_owned()));
        }

        self.memory.memmove(dst, src, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if dst.is_symbolic() || src.is_symbolic() || length.is_symbolic() {
                Event::SymbolicMove(EventTrigger::After)
            } else {
                Event::Move(EventTrigger::After)
            };
            self.do_hooked(&event, 
                &EventContext::MoveContext(dst.to_owned(), src.to_owned(), length.to_owned()));
        }
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

    /// pack bytes into a single `Value`
    pub fn pack(&self, data: &[Value]) -> Value {
        self.memory.pack(data)
    }

    /// unpack `Value` into vector of bytes 
    pub fn unpack(&self, data: &Value, length: usize) -> Vec<Value> {
        self.memory.unpack(data, length)
    }

    pub fn fill_file(&mut self, fd: usize, data: &[Value]) {
        self.filesystem.fill(fd, data)
    }

    pub fn dump_file(&mut self, fd: usize) -> Vec<Value> {
        self.filesystem.dump(fd)
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
                // no need to panic
                println!("Max of 64 taints allowed!");
                0
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

    /// constrain bytes of bitvector to be an exact string eg. "ABC" 
    /// or use "[...]" to match a simple pattern eg. "[XYZa-z0-9]"
    pub fn constrain_bytes(&mut self, bv: &BitVec, pattern: &str) {
        if &pattern[..1] != "[" {
            for (i, c) in pattern.chars().enumerate() {
                self.assert(&bv
                    .slice(8*(i as u32 + 1)-1, 8*i as u32)
                    ._eq(&self.bvv(c as u64, 8)));
            }
        } else {
            let patlen = pattern.len();
            let newpat = &pattern[1..patlen-1]; 
            let mut assertions = Vec::with_capacity(256);

            for ind in 0..bv.get_width()/8 {
                assertions.clear();
                let s = &bv.slice(8*(ind + 1)-1, 8*ind);

                let mut i = 0;
                while i < patlen-2 {
                    let c = newpat.as_bytes()[i] as u64;
                    if i < patlen-4 && &newpat[i+1..i+2] == "-" {
                        let n = newpat.as_bytes()[i+2] as u64;
                        i += 3;
                        assertions.push(
                            s.ugte(&self.bvv(c, 8)).and(&
                            s.ulte(&self.bvv(n, 8))));
                    } else {
                        i += 1;
                        assertions.push(s._eq(&self.bvv(c, 8)));
                    }
                }

                self.assert(&self.solver.or_all(&assertions));
            }
        }
    }

    /// constrain bytes of bitvector to be an exact string eg. "ABC" 
    /// or use "[...]" to match a simple pattern eg. "[XYZa-z0-9]"
    pub fn constrain_bytes_value(&mut self, bv: &Value, pattern: &str) {
        if let Value::Symbolic(s, _) = bv { 
            self.constrain_bytes(&s, pattern)
        }
    }

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

    /// set status of state (active, inactive, merge, unsat...)
    pub fn set_status(&mut self, status: StateStatus) {
        self.status = status;
    }

    /// get status of state (active, inactive, merge, unsat...)
    pub fn get_status(&mut self) -> StateStatus {
        self.status.clone()
    }

    /// convenience method to mark state inactive
    pub fn set_inactive(&mut self) {
        self.set_status(StateStatus::Inactive);
    }

    /// convenience method to break 
    pub fn set_break(&mut self) {
        self.set_status(StateStatus::Break);
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

    /// Evaluate bytes from bitvector `bv` 
    pub fn evaluate_bytes(&mut self, bv: &BitVec) -> Option<Vec<u8>> {
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
                Some(data)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Evaluate bytes from bitvector `bv` 
    pub fn evaluate_string(&mut self, bv: &BitVec) -> Option<String> {
        if let Some(bytes) = self.evaluate_bytes(bv) {
            String::from_utf8(bytes).ok()
        } else {
            None
        }
    }

    /// Evaluate bytes from value
    pub fn evaluate_bytes_value(&mut self, value: &Value) -> Option<Vec<u8>> {
        self.evaluate_bytes(value.as_bv().as_ref().unwrap())
    }

    /// Evaluate string from value
    pub fn evaluate_string_value(&mut self, value: &Value) -> Option<String> {
        self.evaluate_string(value.as_bv().as_ref().unwrap())
    }
}