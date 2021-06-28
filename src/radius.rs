use crate::r2_api::R2Api;
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
pub enum RadiusOptions {
    Syscalls(bool),
    Sims(bool),
    Optimize(bool),
    Debug(bool),
    Lazy(bool)
}

pub struct Radius {
    pub r2api: R2Api,
    pub processor: Processor,
    pub processors: Arc<Mutex<Vec<Processor>>>,
    pub states: Arc<Mutex<Vec<State>>>,
    pub merges: HashMap<u64, State>
}

impl Radius {

    pub fn new(filename: &str) -> Self {
        Radius::new_with_options(filename, vec!())
    }

    pub fn new_with_options(filename: &str, options: Vec<RadiusOptions>) -> Self {
        let file = String::from(filename);
        let mut r2api = R2Api::new(Some(file));

        let opt = !options.contains(&RadiusOptions::Optimize(false));
        let debug = options.contains(&RadiusOptions::Debug(true));
        let lazy = !options.contains(&RadiusOptions::Lazy(false));

        let mut processor = Processor::new(opt, debug, lazy);
        let processors = Arc::new(Mutex::new(vec!()));
        let states = Arc::new(Mutex::new(vec!()));

        if !options.contains(&RadiusOptions::Syscalls(false)) {
            let syscalls = r2api.get_syscalls();
            if let Some(sys) = syscalls.get(0) {
                processor.traps.insert(sys.swi, indirect);
            }

            for sys in &syscalls {
                processor.syscalls.insert(sys.num, sys.to_owned());
            }
        }

        // this is weird, idk
        if !options.contains(&RadiusOptions::Sims(false)) {
            Radius::register_sims(&mut r2api, &mut processor);
        }

        Radius {
            r2api,
            processor,
            processors,
            states,
            merges: HashMap::new()
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
        state.memory.add_stack();
        state.memory.add_heap();
        state
    }

    pub fn init_state(&mut self) -> State {
        State::new(&mut self.r2api)
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
            let addr = r2api.get_address(sym.as_str());

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
                    let new_states = processor.run(state, true);
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
        
        if !self.merges.contains_key(&pc) {
            self.merges.insert(pc, state);
        } else {
            let mut merge_state = self.merges.remove(&pc).unwrap();
            let mut state_asserts = state.solver.assertions.clone();
            let assertion = state.solver.and_all(&mut state_asserts).unwrap();
            let asserted = Value::Symbolic(assertion.clone());

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
            let merge_addrs = merge_state.memory.mem.keys().cloned().collect::<Vec<u64>>();
            let state_addrs = state.memory.mem.keys().cloned().collect::<Vec<u64>>();

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
            let mut assertions = merge_state.solver.assertions.clone();
            let current = state.solver.and_all(&mut assertions).unwrap();
            merge_state.solver.reset();
            merge_state.assert(&current.or(&assertion));
            self.merges.insert(pc, merge_state);
        }
    }

    // clear cached data from r2api and processors 
    pub fn clear(&mut self) {
        self.r2api.clear();
        self.processors.lock().unwrap().clear();
        //self.processor = Processor::new();
    }
}