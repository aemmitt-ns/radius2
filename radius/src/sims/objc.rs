use crate::value::Value;
use crate::state::State;
use crate::sims::syscall;

pub fn objc_msgSend(state: &mut State, args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
    //let pc = state.r2api.get_class_methods()
}

pub fn objc_msgSend_stret(state: &mut State, args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
}

pub fn objc_msgSendSuper(state: &mut State, args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
}

pub fn objc_msgSendSuper_stret(state: &mut State, args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
}