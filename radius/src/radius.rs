use crate::r2_api::{R2Api, R2Result, FunctionInfo, BasicBlock, Instruction, Information};
use crate::processor::{Processor, HookMethod};
use crate::state::{State, StateStatus};
//use crate::value::Value;
use crate::sims::{get_sims, SimMethod, zero};
use crate::sims::syscall::{indirect};
use crate::value::Value;

use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::HashMap;

//const DO_SYSCALLS: bool = true;
//const DO_SIMS:     bool = true;

#[derive(Debug, Clone, PartialEq)]
pub enum RadiusOption {
    Syscalls(bool),    // use simulated syscalls
    Sims(bool),        // use simulated imports 
    SimAll(bool),      // sim all imports, with stub if missing
    Optimize(bool),    // optimize executed ESIL expressions
    Debug(bool),       // enable debug output
    Lazy(bool),        // don't check sat on symbolic pcs
    Permissions(bool), // check memory permissions
    Force(bool),       // force execution of all branches
    Topological(bool)  // execute blocks in topological order
}

/**
 * Main Radius struct that coordinates and configures
 * the symbolic execution of a binary. 
 * 
 * Radius can be instantiated using either `Radius::new(filename: &str)`
 * or `Radius::new_with_options(...)` 
 * 
 * Example
 * 
 * ```
 * use radius::radius::Radius;
 * let mut radius = Radius::new("../tests/r200");
 * ```
 * 
 */
pub struct Radius {
    pub r2api: R2Api,
    pub processor: Processor,
    pub processors: Arc<Mutex<Vec<Processor>>>,
    pub states: Arc<Mutex<Vec<State>>>,
    pub merges: HashMap<u64, State>,
    pub check: bool
}

impl Radius {

    /**
     * Create a new Radius instance for the provided binary
     * 
     * **Example**
     * 
     * ```
     * use radius::radius::Radius;
     * let mut radius = Radius::new("../tests/r100");
     * ```
     */
    pub fn new(filename: &str) -> Self {
        // no radius options and no r2 errors by default
        Radius::new_with_options(filename, vec!(), Some(vec!("-2")))
    }

    /**
     * Create a new Radius instance for the provided binary with a vec of `RadiusOption`
     * And an optional vector of radare2 arguments
     * 
     * **Example**
     * 
     * ```
     * use radius::radius::{Radius, RadiusOption};
     * let options = vec!(RadiusOption::Optimize(false), RadiusOption::Sims(false));
     * let mut radius = Radius::new_with_options("../tests/baby-re", options, Some(vec!("-2")));
     * ```
     */
    pub fn new_with_options(filename: &str, options: Vec<RadiusOption>, 
            args: Option<Vec<&'static str>>) -> Self {
                
        let file = String::from(filename);
        let mut r2api = R2Api::new(Some(file), args);

        let opt = !options.contains(&RadiusOption::Optimize(false));
        let debug = options.contains(&RadiusOption::Debug(true));
        let lazy = !options.contains(&RadiusOption::Lazy(false));
        let force = options.contains(&RadiusOption::Force(true));
        let topological = options.contains(&RadiusOption::Topological(true));
        let check = options.contains(&RadiusOption::Permissions(true));
        let sim_all = options.contains(&RadiusOption::SimAll(true));

        let mut processor = Processor::new(opt, debug, lazy, force, topological);
        let processors = Arc::new(Mutex::new(vec!()));
        let states = Arc::new(Mutex::new(vec!()));

        if !options.contains(&RadiusOption::Syscalls(false)) {
            let syscalls = r2api.get_syscalls().unwrap();
            if let Some(sys) = syscalls.get(0) {
                processor.traps.insert(sys.swi, indirect);
            }

            for sys in &syscalls {
                processor.syscalls.insert(sys.num, sys.to_owned());
            }
        }

        // this is weird, idk
        if !options.contains(&RadiusOption::Sims(false)) {
            Radius::register_sims(&mut r2api, &mut processor, sim_all);
        }

        Radius {
            r2api,
            processor,
            processors,
            states,
            merges: HashMap::new(),
            check
        }
    }

    /**
     * Initialized state at the provided function address with an initialized stack
     * (if applicable) 
     * 
     * **Example**
     * 
     * ```
     * use radius::radius::Radius;
     * let mut radius = Radius::new("../tests/r100");
     * let mut state = radius.call_state(0x004006fd);
     * ```
     */
    pub fn call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        let mut state = self.init_state();
        state.memory.add_stack();
        state.memory.add_heap();
        state.memory.add_std_streams();
        state
    }

    /**
     * Initialized state at the program entry point (the first if multiple).
     * Can also be passed concrete args and env variables
     * 
     * **Example**
     * 
     * ```
     * use radius::radius::Radius;
     * let mut radius = Radius::new("../tests/r100");
     * let mut state = radius.entry_state(
     *     &["r100".to_string()], 
     *     &[]
     * );
     * ```
     */
    pub fn entry_state(&mut self, args: &[String], env: &[String]) -> State {
        //self.r2api.seek(addr);
        self.r2api.init_entry(args, env);
        let mut state = self.init_state();

        let start_main_reloc = self.r2api.get_address(
            "reloc.__libc_start_main").unwrap();

        self.hook(start_main_reloc, __libc_start_main);

        state.memory.add_stack();
        state.memory.add_heap();
        state.memory.add_std_streams();
        state
    }

    pub fn init_state(&mut self) -> State {
        State::new(&mut self.r2api, false, self.check)
    }

    pub fn blank_state(&mut self) -> State {
        State::new(&mut self.r2api, true, self.check)
    }

    /// Blank except for PC and SP
    pub fn blank_call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        let mut state = self.blank_state();
        let sp = self.r2api.get_register_value("SP").unwrap();
        state.registers.set_with_alias("PC", Value::Concrete(addr, 0));
        state.registers.set_with_alias("SP", Value::Concrete(sp, 0));
        state.memory.add_stack();
        state.memory.add_heap();
        state.memory.add_std_streams();
        state
    }

    /// Hook an address with a callback that is passed the `State`
    pub fn hook(&mut self, addr: u64, hook_callback: HookMethod) {
        let hooks = self.processor.hooks.remove(&addr);
        if let Some(mut hook_vec) = hooks {
            hook_vec.push(hook_callback);
            self.processor.hooks.insert(addr, hook_vec);
        } else {
            self.processor.hooks.insert(addr, vec!(hook_callback));
        }
    }

    // internal method to register import sims 
    pub fn register_sims(r2api: &mut R2Api, processor: &mut Processor, sim_all: bool) {
        let sims = get_sims();
        let symbols = r2api.get_imports().unwrap();
        let mut symmap: HashMap<String, u64> = HashMap::new();

        for symbol in symbols {
            symmap.insert(symbol.name, symbol.plt);
        }

        // TODO expand this to handle other symbols
        for sim in sims {
            let addropt = symmap.remove(&sim.symbol);
            if let Some(addr) = addropt {
                processor.sims.insert(addr, sim.function);
            }
        }

        if sim_all {
            for addr in symmap.values() {
                processor.sims.insert(*addr, zero);
            }
        }
    }

    /// Register a trap to call the provided `SimMethod`
    pub fn trap(&mut self, trap_num: u64, sim: SimMethod) {
        self.processor.traps.insert(trap_num, sim);
    }

    /// Register a `SimMethod` for the provided function address
    pub fn simulate(&mut self, addr: u64, sim: SimMethod) {
        self.processor.sims.insert(addr, sim);
    }

    /// Add a breakpoint at the provided address. 
    /// This is where execution will stop after `run` is called
    pub fn breakpoint(&mut self, addr: u64) {
        self.processor.breakpoints.insert(addr, true);
    }

    /// Add a mergepoint, an address where many states will be combined
    /// into a single state with the proper constraints
    pub fn mergepoint(&mut self, addr: u64) {
        self.processor.mergepoints.insert(addr, true);
    }

    /// Add addresses that will be avoided during execution. Any
    /// `State` that reaches these addresses will be marked inactive
    pub fn avoid(&mut self, addrs: Vec<u64>) {
        for addr in addrs {
            self.processor.avoidpoints.insert(addr, true);
        }
    }

    /// Simple way to execute until a given target address while avoiding a vec of other addrs
    pub fn run_until(&mut self, state: State, target: u64, avoid: Vec<u64>) -> Option<State> {
        self.processor.run_until(state, target, avoid)
    }

    /**
     * Main run method, start or continue a symbolic execution
     * 
     * More words 
     * 
     */
    pub fn run(&mut self, state: Option<State>, threads: usize) -> Option<State> {
        let mut handles = vec!();
        if let Some(s) = state {
            self.states.lock().unwrap().push(s);
        }

        // if there are multiple threads we need to duplicate solvers
        // else there will be race conditions. Unfortunately this 
        // will prevent mergers from happening. this sucks
        let duplicate = threads > 1 && self.processor.mergepoints.is_empty();

        loop {
            let mut count = 0;
            while count < threads && !self.states.lock().unwrap().is_empty() {
                //println!("on thread {}!", thread_count);
                let procs = self.processors.clone();
                let states = self.states.clone();
                let state = states.lock().unwrap().remove(0);

                let mut processor = if !procs.lock().unwrap().is_empty() {
                    procs.lock().unwrap().pop().unwrap()
                } else {
                    self.processor.clone()
                };

                match state.status {
                    StateStatus::Break => return Some(state),
                    StateStatus::Merge => {
                        self.merge(state);
                        continue;
                    },
                    _ => {}
                }

                let handle = thread::spawn(move || {
                    let new_states = processor.run(state, true, duplicate);
                    states.lock().unwrap().extend(new_states);
                    procs.lock().unwrap().push(processor);
                });
                handles.push(handle);
                count += 1;
            }
            
            while !handles.is_empty() {
                handles.pop().unwrap().join().unwrap();
            }

            if self.states.lock().unwrap().is_empty() {
                if self.merges.is_empty() {
                    break None
                } else {
                    // pop one out of mergers 
                    let key = *self.merges.keys().next().unwrap();
                    let mut merge = self.merges.remove(&key).unwrap();
                    merge.status = StateStatus::PostMerge;
                    self.states.lock().unwrap().push(merge);
                }
            }
        }
    }

    // TODO do not merge if backtraces are different
    // really i guess it should be a vector of states with
    // unique backtraces for every merge address
    // but thats complicated and i dont wanna do it right now
    pub fn merge(&mut self, mut state: State) {
        let pc = state.registers.get_with_alias("PC").as_u64().unwrap();
        
        let has_pc = self.merges.contains_key(&pc); 
        if !has_pc { // trick clippy idk
            self.merges.insert(pc, state);
        } else {
            let mut merge_state = self.merges.remove(&pc).unwrap();
            let state_asserts = state.solver.assertions.clone();
            let assertion = state.solver.and_all(&state_asserts).unwrap();
            let asserted = Value::Symbolic(assertion.clone(), 0);

            // merge registers 
            let mut new_regs = vec!();
            let reg_count = state.registers.values.len();
            for index in 0..reg_count {
                let reg = &merge_state.registers.values[index];
                let curr_reg  = state.registers.values[index].clone();
                new_regs.push(state.solver.conditional(&asserted, &curr_reg, &reg));
            }
            merge_state.registers.values = new_regs;

            // merge memory 
            let mut new_mem = HashMap::new();
            let merge_addrs = merge_state.memory.addresses();
            let state_addrs = state.memory.addresses();

            let mut addrs = vec!();
            addrs.extend(merge_addrs);
            addrs.extend(state_addrs);
            for addr in addrs {
                let mem = &merge_state.memory.read_value(addr, 1);
                let curr_mem = state.memory.read_value(addr, 1);
                new_mem.insert(addr, state.solver.conditional(&asserted, &curr_mem, mem));
            }
            merge_state.memory.mem = new_mem;

            // merge solvers
            let assertions = merge_state.solver.assertions.clone();
            let current = state.solver.and_all(&assertions).unwrap();
            merge_state.solver.reset();
            merge_state.assert(&current.or(&assertion));
            self.merges.insert(pc, merge_state);
        }
    }

    /// Run radare2 analysis
    pub fn analyze(&mut self, n: usize) {
        let _r = self.r2api.analyze(n);
    }

    /// Get information about the binary and radare2 session
    pub fn get_info(&mut self) -> R2Result<Information> {
        self.r2api.get_info()
    }

    /// Get address of symbol
    pub fn get_address(&mut self, symbol: &str) -> R2Result<u64> {
        self.r2api.get_address(symbol)
    }

    /// Get all functions
    pub fn get_functions(&mut self) -> R2Result<Vec<FunctionInfo>> {
        self.r2api.get_functions()
    }

    /// Get function information at this address
    pub fn get_function(&mut self, address: u64) -> R2Result<FunctionInfo> {
        self.r2api.get_function_info(address)
    }

    /// Get basic blocks of a function
    pub fn get_blocks(&mut self, address: u64) -> R2Result<Vec<BasicBlock>> {
        self.r2api.get_blocks(address)
    }

    /// Disassemble at the provided address
    pub fn disassemble(&mut self, address: u64, num: usize) -> R2Result<Vec<Instruction>> {
        self.r2api.disassemble(address, num)
    }

    /// Assemble the given instruction
    pub fn assemble(&mut self, instruction: &str) -> R2Result<Vec<u8>> {
        self.r2api.assemble(instruction)
    }

    /// Read directly from binary
    pub fn read(&mut self, address: u64, length: usize) -> R2Result<Vec<u8>> {
        self.r2api.read(address, length)
    }

    /// Patch binary
    pub fn write(&mut self, address: u64, data: Vec<u8>) {
        self.r2api.write(address, data)
    }

    /// Run any r2 command 
    pub fn cmd(&mut self, cmd: &str) -> R2Result<String> { 
        self.r2api.cmd(cmd)
    }

    // clear cached data from r2api and processors 
    pub fn clear(&mut self) {
        self.r2api.clear();
        self.processors.lock().unwrap().clear();
        //self.processor = Processor::new();
    }
}

pub fn __libc_start_main(state: &mut State) -> bool {
    let main = state.registers.get_with_alias("A0");
    let argc = state.registers.get_with_alias("A1");
    let argv = state.registers.get_with_alias("A2");

    // TODO go to init then main 
    // but we need a nice arch neutral way to push ret 
    // so until then 

    // go to main 
    state.registers.set_with_alias("PC", main);
    state.registers.set_with_alias("A0", argc);
    state.registers.set_with_alias("A1", argv);

    // TODO set env
    state.registers.set_with_alias("A2", Value::Concrete(0, 0));

    false
}