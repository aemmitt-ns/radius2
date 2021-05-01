use crate::r2_api::R2Api;
use crate::processor::Processor;
use crate::state::{State, StateStatus};
use crate::value::Value;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct Radius {
    pub r2api: R2Api,
    pub processor: Processor,
    pub processors: Arc<Mutex<Vec<Processor>>>,
    pub states: Arc<Mutex<Vec<State>>>
}

impl Radius {
    pub fn new(filename: &str) -> Self {
        let file = String::from(filename);
        let r2api = R2Api::new(Some(file));
        let processor = Processor::new();
        let processors = Arc::new(Mutex::new(vec!()));
        let states = Arc::new(Mutex::new(vec!()));

        Radius {
            r2api,
            processor,
            processors,
            states
        }
    }

    pub fn call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        State::new(&mut self.r2api)
    }

    pub fn hook(&mut self, addr: u64, hook_callback: fn (&mut State) -> bool) {
        let hooks = self.processor.hooks.remove(&addr);
        if let Some(mut hook_vec) = hooks {
            hook_vec.push(hook_callback);
            self.processor.hooks.insert(addr, hook_vec);
        } else {
            self.processor.hooks.insert(addr, vec!(hook_callback));
        }
    }

    pub fn simulate(&mut self, addr: u64, sim: fn (&mut State, Vec<Value>) -> Value) {
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

                let mut processor = if !procs.lock().unwrap().is_empty() {
                    procs.lock().unwrap().pop().unwrap()
                } else {
                    self.processor.clone()
                };

                let state = states.lock().unwrap().pop().unwrap();
                if state.status == StateStatus::Break {
                    return Some(state);
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
                break None
            }
        }
    }
}