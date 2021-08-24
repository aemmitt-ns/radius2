use crate::r2_api::{R2Api, R2Result, FunctionInfo, BasicBlock, Instruction, Information};
use crate::processor::{Processor, HookMethod};
use crate::state::{State, StateStatus};
//use crate::value::Value;
use crate::sims::{get_sims, SimMethod};
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
    Optimize(bool),    // optimize executed ESIL expressions
    Debug(bool),       // enable debug output
    Lazy(bool),        // don't check sat on symbolic pcs
    Permissions(bool), // check memory permissions
    Force(bool),       // force execution of all branches
    Prune(bool)        // only exec blocks once per unique bt
}

pub struct Radius {
    pub r2api: R2Api,
    pub processor: Processor,
    pub processors: Arc<Mutex<Vec<Processor>>>,
    pub states: Arc<Mutex<Vec<State>>>,
    pub merges: HashMap<u64, State>,
    pub check: bool
}

impl Radius {

    pub fn new(filename: &str) -> Self {
        Radius::new_with_options(filename, vec!())
    }

    pub fn new_with_options(filename: &str, options: Vec<RadiusOption>) -> Self {
        let file = String::from(filename);
        let mut r2api = R2Api::new(Some(file));

        let opt = !options.contains(&RadiusOption::Optimize(false));
        let debug = options.contains(&RadiusOption::Debug(true));
        let lazy = !options.contains(&RadiusOption::Lazy(false));
        let force = options.contains(&RadiusOption::Force(true));
        let prune = options.contains(&RadiusOption::Prune(true));
        let check = options.contains(&RadiusOption::Permissions(true));

        let mut processor = Processor::new(opt, debug, lazy, force, prune);
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
            Radius::register_sims(&mut r2api, &mut processor);
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

    pub fn call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        let mut state = self.init_state();
        state.memory.add_stack();
        state.memory.add_heap();
        state
    }

    pub fn entry_state(&mut self, args: &[String], env: &[String]) -> State {
        //self.r2api.seek(addr);
        self.r2api.init_entry(args, env);
        let mut state = self.init_state();

        let start_main_reloc = self.r2api.get_address(
            "reloc.__libc_start_main").unwrap();

        self.hook(start_main_reloc, __libc_start_main);

        state.memory.add_stack();
        state.memory.add_heap();
        state
    }

    pub fn init_state(&mut self) -> State {
        State::new(&mut self.r2api, false, self.check)
    }

    pub fn blank_state(&mut self) -> State {
        State::new(&mut self.r2api, true, self.check)
    }

    // blank except for PC and SP
    pub fn blank_call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        let mut state = self.blank_state();
        let sp = self.r2api.get_register_value("SP").unwrap();
        state.registers.set_with_alias("PC", Value::Concrete(addr, 0));
        state.registers.set_with_alias("SP", Value::Concrete(sp, 0));
        state.memory.add_stack();
        state.memory.add_heap();
        state
    }

    pub fn hook(&mut self, addr: u64, hook_callback: HookMethod) {
        let hooks = self.processor.hooks.remove(&addr);
        if let Some(mut hook_vec) = hooks {
            hook_vec.push(hook_callback);
            self.processor.hooks.insert(addr, hook_vec);
        } else {
            self.processor.hooks.insert(addr, vec!(hook_callback));
        }
    }

    pub fn register_sims(r2api: &mut R2Api, processor: &mut Processor) {
        let sims = get_sims();

        // TODO expand this to handle other symbols
        let prefix = "sym.imp.";
        for sim in sims {
            let sym = String::from(prefix) + sim.symbol.as_str();
            let addr = r2api.get_address(sym.as_str()).unwrap();

            if addr != 0 {
                processor.sims.insert(addr, sim.function);
            }
        }
    }

    pub fn trap(&mut self, trap_num: u64, sim: SimMethod) {
        self.processor.traps.insert(trap_num, sim);
    }

    pub fn simulate(&mut self, addr: u64, sim: SimMethod) {
        self.processor.sims.insert(addr, sim);
    }

    pub fn breakpoint(&mut self, addr: u64) {
        self.processor.breakpoints.insert(addr, true);
    }

    pub fn mergepoint(&mut self, addr: u64) {
        self.processor.mergepoints.insert(addr, true);
    }

    pub fn avoid(&mut self, addrs: Vec<u64>) {
        for addr in addrs {
            self.processor.avoidpoints.insert(addr, true);
        }
    }

    pub fn run_until(&mut self, state: State, target: u64, avoid: Vec<u64>) -> Option<State> {
        self.processor.run_until(state, target, avoid)
    }

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

    // run r2 analysis
    pub fn analyze(&mut self, n: usize) {
        let _r = self.r2api.analyze(n);
    }

    pub fn get_info(&mut self) -> R2Result<Information> {
        self.r2api.get_info()
    }

    // get address of symbol
    pub fn get_address(&mut self, symbol: &str) -> R2Result<u64> {
        self.r2api.get_address(symbol)
    }

    // get all functions
    pub fn get_functions(&mut self) -> R2Result<Vec<FunctionInfo>> {
        self.r2api.get_functions()
    }

    // get function information at this address
    pub fn get_function(&mut self, address: u64) -> R2Result<FunctionInfo> {
        self.r2api.get_function_info(address)
    }

    // get basic blocks of a function
    pub fn get_blocks(&mut self, address: u64) -> R2Result<Vec<BasicBlock>> {
        self.r2api.get_blocks(address)
    }

    pub fn disassemble(&mut self, address: u64, num: usize) -> R2Result<Vec<Instruction>> {
        self.r2api.disassemble(address, num)
    }

    pub fn assemble(&mut self, instruction: &str) -> R2Result<Vec<u8>> {
        self.r2api.assemble(instruction)
    }

    // read directly from binary
    pub fn read(&mut self, address: u64, length: usize) -> R2Result<Vec<u8>> {
        self.r2api.read(address, length)
    }

    // patch binary
    pub fn write(&mut self, address: u64, data: Vec<u8>) {
        self.r2api.write(address, data)
    }

    // run an r2 command 
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