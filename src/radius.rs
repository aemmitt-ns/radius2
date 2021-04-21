use crate::r2_api::R2Api;
use crate::processor::Processor;
use crate::state::State;

pub struct Radius {
    pub r2api: R2Api,
    pub processor: Processor
}

impl Radius {
    pub fn new(filename: &str) -> Self {
        let file = String::from(filename);
        let r2api = R2Api::new(Some(file));
        let processor = Processor::new();

        Radius {
            r2api,
            processor
        }
    }

    pub fn call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        State::new(&mut self.r2api)
    }

    pub fn run_until(&mut self, state: State, target: u64, avoid: u64) -> Option<State> {
        self.processor.run_until(&mut self.r2api, state, target, avoid)
    }
}