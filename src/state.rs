use crate::r2_api::R2Api;
use crate::registers;
use crate::memory;
use crate::value::Value;

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
    pub stored_address: Option<Value>
}

#[derive(Debug, Clone)]
pub enum StackItem {
    StackRegister(usize),
    StackValue(Value)
}

#[derive(Debug, Clone)]
pub struct State {
    pub stack: Vec<StackItem>,
    pub esil: EsilState,
    pub registers: registers::Registers,
    pub memory: memory::Memory
}

pub fn create(r2api: &mut R2Api) -> State {
    let esil_state = EsilState {
        mode: ExecMode::Uncon,
        previous: Value::Concrete(0),
        current: Value::Concrete(0),
        last_sz: 64,
        stored_address: None
    };

    State {
        stack: vec!(),
        esil: esil_state,
        registers: registers::create(r2api),
        memory: memory::create(r2api)
    }
}