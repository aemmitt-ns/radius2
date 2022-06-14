use crate::state::{StackItem, State};
use crate::value::{Value, vc};
use std::f64;

pub const OPS: [&str; 16] = [
    "+", "-", "++", "--", "*", "/", "<<", ">>", "|", "&", "^", "%", "!", ">>>>", ">>>", "<<<",
];

pub const SIZE: u64 = 64;

#[derive(Debug, Clone, PartialEq)]
pub enum Operations {
    Trap,
    Interrupt,
    Syscall,
    PcAddress,
    If,
    Else,
    EndIf,
    Compare,
    LessThan,
    LessThanEq,
    GreaterThan,
    GreaterThanEq,
    LeftShift,
    LogicalRightShift,
    RightShift,
    LeftRotation,
    RightRotation,
    SignExtend,
    And,
    Or,
    Xor,
    Add,
    Subtract,
    Multiply,
    LongMultiply,
    Divide,
    LongDivide,
    Modulo,
    LongModulo,
    SignedDivide,
    SignedModulo,
    Not,
    Increment,
    Decrement,
    Equal,
    WeakEqual,
    Peek(usize),
    Poke(usize),
    PeekBits,
    PokeBits,
    PeekSize,
    PokeSize,
    PeekMany,
    PokeMany,
    PopCount,
    Ceiling,
    Floor,
    Round,
    SquareRoot,
    DoubleToInt,
    SignedToDouble,
    UnsignedToDouble,
    DoubleToFloat,
    FloatToDouble,
    FloatCompare,
    FloatLessThan,
    FloatAdd,
    FloatSubtract,
    FloatMultiply,
    FloatDivide,
    NaN,
    FloatNegate,
    AddressStore,
    AddressRestore,
    Swap,
    Pick,
    ReversePick,
    Pop,
    Duplicate,
    Number,
    Clear,
    Break,
    Repeat,
    GoTo,
    PrintStack,
    ToDo,
    NoOperation,

    Print,      // Tool for cli hooks
    PrintDebug, // Tool for cli hooks
    Backtrace,  // Tool for cli hooks
    Constrain,
    ConstraintPush,
    ConstraintPop,
    Terminate,
    Discard,

    // flag ops
    Zero,
    Carry,
    Borrow,
    Parity,
    Overflow,
    // SubOverflow,
    // i forget these
    S,
    Ds,
    JumpTarget,
    Js,
    R,

    Unknown,
}

impl Operations {
    pub fn from_string(s: &str) -> Self {
        match s {
            "TRAP" => Operations::Trap,
            "$" => Operations::Interrupt,
            "()" => Operations::Syscall,
            "$$" => Operations::PcAddress, // this is whack
            "?{" => Operations::If,
            "}{" => Operations::Else,
            "}" => Operations::EndIf,
            "==" => Operations::Compare,
            "<" => Operations::LessThan,
            "<=" => Operations::LessThanEq,
            ">" => Operations::GreaterThan,
            ">=" => Operations::GreaterThanEq,
            "<<" => Operations::LeftShift,
            ">>" => Operations::LogicalRightShift,
            ">>>>" => Operations::RightShift,
            "<<<" => Operations::LeftRotation,
            ">>>" => Operations::RightRotation,
            "~" => Operations::SignExtend,
            "SIGN" => Operations::SignExtend,
            "&" => Operations::And,
            "|" => Operations::Or,
            "^" => Operations::Xor,
            "+" => Operations::Add,
            "-" => Operations::Subtract,
            "*" => Operations::Multiply,
            "L*" => Operations::LongMultiply,
            "/" => Operations::Divide,
            "L/" => Operations::LongDivide,
            "%" => Operations::Modulo,
            "L%" => Operations::LongModulo,
            "~/" => Operations::SignedDivide,
            "~%" => Operations::SignedModulo,
            "!" => Operations::Not,
            "++" => Operations::Increment,
            "--" => Operations::Decrement,
            "=" => Operations::Equal,
            ":=" => Operations::WeakEqual,
            "[1]" => Operations::Peek(1),
            "[2]" => Operations::Peek(2),
            "[4]" => Operations::Peek(4),
            "[8]" => Operations::Peek(8),
            "[16]" => Operations::Peek(16),
            "=[1]" => Operations::Poke(1),
            "=[2]" => Operations::Poke(2),
            "=[4]" => Operations::Poke(4),
            "=[8]" => Operations::Poke(8),
            "=[16]" => Operations::Poke(16),
            "=[]" => Operations::PokeBits, 
            "[]" => Operations::PeekBits, 
            "=[n]" => Operations::PokeSize,
            "[n]" => Operations::PeekSize,
            "=[*]" => Operations::PokeMany,
            "[*]" => Operations::PeekMany,
            "POPCOUNT" => Operations::PopCount,
            "CEIL" => Operations::Ceiling,
            "FLOOR" => Operations::Floor,
            "ROUND" => Operations::Round,
            "SQRT" => Operations::SquareRoot,
            "D2I" => Operations::DoubleToInt,
            "I2D" => Operations::SignedToDouble,
            "S2D" => Operations::SignedToDouble,
            "U2D" => Operations::UnsignedToDouble,
            "F2D" => Operations::FloatToDouble,
            "D2F" => Operations::DoubleToFloat,
            "F+" => Operations::FloatAdd,
            "F-" => Operations::FloatSubtract,
            "F*" => Operations::FloatMultiply,
            "F/" => Operations::FloatDivide,
            "F==" => Operations::FloatCompare,
            "F<" => Operations::FloatLessThan,
            "NAN" => Operations::NaN,
            "-F" => Operations::FloatNegate,
            "SWAP" => Operations::Swap,
            "PICK" => Operations::Pick,
            "RPICK" => Operations::ReversePick,
            "POP" => Operations::Pop,
            "DUP" => Operations::Duplicate,
            "NUM" => Operations::Number,
            "CLEAR" => Operations::Clear,
            "BREAK" => Operations::Break,
            "REPEAT" => Operations::Repeat,
            "GOTO" => Operations::GoTo,
            "STACK" => Operations::PrintStack,
            "TODO" => Operations::ToDo,
            "" => Operations::NoOperation,

            // hax for use in the cli / plugin
            "." => Operations::Print,
            ".." => Operations::PrintDebug,
            "BT" => Operations::Backtrace,
            "_" => Operations::Constrain,
            "_+" => Operations::ConstraintPush,
            "_-" => Operations::ConstraintPop,
            "!!" => Operations::Terminate, // state.set_break()
            "!_" => Operations::Discard,  // state.set_inactive()

            "$z" => Operations::Zero,
            "$c" => Operations::Carry,
            "$b" => Operations::Borrow,
            "$p" => Operations::Parity,
            "$o" => Operations::Overflow,
            //"$so" => Operations::SubOverflow,
            "$s" => Operations::S,
            "$ds" => Operations::Ds,
            "$jt" => Operations::JumpTarget,
            "$js" => Operations::Js,
            "$r" => Operations::R,
            _ => Operations::Unknown,
        }
    }
}

#[inline]
pub fn get_size(state: &mut State) -> u32 {
    let item = state.stack.pop().unwrap_or_default();

    let sz = match &item {
        StackItem::StackValue(_val) => 64,
        StackItem::StackRegister(index) => {
            let reg = &state.registers.indexes[*index];
            reg.reg_info.size as u32
        }
    };

    state.stack.push(item);
    sz
}


#[inline]
pub fn pop_bv(state: &mut State, n: u32) -> Value {
    let value = pop_value(state, false, false);
    Value::Symbolic(state.solver.to_bv(&value, n), value.get_taint())
}

//#[inline]
pub fn pop_value(state: &mut State, set_size: bool, sign_ext: bool) -> Value {
    let item = state.stack.pop().unwrap_or_default();

    let value = match item {
        StackItem::StackValue(val) => val,
        StackItem::StackRegister(index) => {
            if set_size {
                let reg = &state.registers.indexes[index];
                state.esil.last_sz = reg.reg_info.size as usize;
            }
            state.registers.get_value(index)
        }
    };

    match &value {
        Value::Concrete(_v, _t) => value,
        Value::Symbolic(ov, t) => {
            // check const and fits in u64
            if ov.is_const() && ov.get_width() <= 64 {
                Value::Concrete(ov.as_u64().unwrap(), *t)
            } else {
                let v = ov; //state.translate(&ov).unwrap();
                let szdiff = SIZE as i32 - v.get_width() as i32;
                if szdiff > 0 {
                    if sign_ext {
                        Value::Symbolic(v.sext(szdiff as u32), *t)
                    } else {
                        Value::Symbolic(v.uext(szdiff as u32), *t)
                    }
                } else {
                    value
                }
            }
        }
    }
}

#[inline]
pub fn pop_stack_value(
    state: &mut State,
    stack: &mut Vec<StackItem>,
    set_size: bool,
    sign_ext: bool,
) -> Value {
    let item = stack.pop().unwrap_or_default();

    let value = match item {
        StackItem::StackValue(val) => val,
        StackItem::StackRegister(index) => {
            if set_size {
                let reg = state.registers.indexes.get(index).unwrap();
                state.esil.last_sz = reg.reg_info.size as usize;
            }
            state.registers.get_value(index)
        }
    };

    match &value {
        Value::Concrete(_v, _t) => value,
        Value::Symbolic(ov, t) => {
            if ov.is_const() && ov.get_width() <= 64 {
                Value::Concrete(ov.as_u64().unwrap(), *t)
            } else {
                let v = ov; //state.translate(&ov).unwrap();
                let szdiff = SIZE as u32 - v.get_width();
                if szdiff > 0 {
                    if sign_ext {
                        Value::Symbolic(v.sext(szdiff), *t)
                    } else {
                        Value::Symbolic(v.uext(szdiff), *t)
                    }
                } else {
                    value
                }
            }
        }
    }
}

#[inline]
pub fn push_value(state: &mut State, value: Value) {
    state.stack.push(StackItem::StackValue(value));
}

#[inline]
pub fn pop_concrete(state: &mut State, set_size: bool, sign_ext: bool) -> u64 {
    let value = pop_value(state, set_size, sign_ext);

    match &value {
        Value::Concrete(val, _t) => *val,
        Value::Symbolic(_val, _t) => state.solver.evalcon_to_u64(&value).unwrap(),
    }
}

#[inline]
pub fn get_stack_taint(state: &mut State, n: usize) -> u64 {
    let mut taint = 0;
    for _ in 0..n {
        let arg = pop_value(state, false, false);
        taint |= arg.get_taint();
        push_value(state, arg);
    }
    taint
}

#[inline]
pub fn pop_double(state: &mut State) -> f64 {
    let value = pop_concrete(state, false, false);
    f64::from_bits(value)
}

#[inline]
pub fn pop_float(state: &mut State) -> f32 {
    let value = pop_concrete(state, false, false);
    f32::from_bits(value as u32)
}

#[inline]
pub fn do_equal(state: &mut State, reg: StackItem, value: Value, set_esil: bool) {
    if let StackItem::StackRegister(index) = reg {
        let register = state.registers.indexes.get(index).unwrap();
        let size = register.reg_info.size as usize;
        let prev = state.registers.get_value(index);

        if let Some(cond) = &state.condition {
            state.registers.set_value(
                index,
                state
                    .solver
                    .conditional(&Value::Symbolic(cond.to_owned(), 0), &value, &prev),
            );
        } else {
            state.registers.set_value(index, value.to_owned());
        }

        if set_esil {
            state.esil.last_sz = size;
            state.esil.current = value;
            state.esil.previous = prev;
        }
    }
}

macro_rules! binary_operation {
    ($state:expr, $op:tt) => {
        let arg1 = pop_value($state, false, false);
        let arg2 = pop_value($state, false, false);
        push_value($state, arg1 $op arg2);
    };
}

macro_rules! binary_float_operation {
    ($state:expr, $op:tt) => {
        let t = get_stack_taint($state, 1);
        let arg1 = pop_double($state);
        let arg2 = pop_double($state);
        let value = Value::Concrete(f64::to_bits(arg1 $op arg2), t);
        push_value($state, value);
    };
}

macro_rules! binary_method {
    ($state:expr, $op:ident) => {
        let arg1 = pop_value($state, false, false);
        let arg2 = pop_value($state, false, false);
        push_value($state, arg1.$op(arg2));
    };
}

#[inline]
pub fn genmask(bits: u64) -> u64 {
    if bits > 0 && bits < 63 {
        (2u64 << bits) - 1
    } else {
        0xffffffffffffffff
    }
}

pub fn do_operation(state: &mut State, operation: &Operations) {
    match operation {
        Operations::Trap => {}
        Operations::Interrupt => {}
        Operations::Syscall => {}
        Operations::PcAddress => {
            push_value(state, state.esil.prev_pc.clone()); 
        }
        Operations::If => {} // these are handled in processor
        Operations::Else => {}
        Operations::EndIf => {}
        Operations::Compare => {
            let arg1 = pop_value(state, true, false);
            let arg2 = pop_value(state, false, false);
            state.esil.current = arg1.to_owned() - arg2;
            state.esil.previous = arg1;
        }
        Operations::LessThan => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.slt(&arg2));
        }
        Operations::LessThanEq => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.slte(&arg2));
        }
        Operations::GreaterThan => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.sgt(&arg2));
        }
        Operations::GreaterThanEq => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.sgte(&arg2));
        }
        Operations::LeftShift => {
            binary_operation!(state, <<);
        }
        Operations::LogicalRightShift => {
            binary_operation!(state, >>);
        }
        Operations::RightShift => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.asr(arg2, sz));
        }
        Operations::LeftRotation => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            push_value(state, arg1.rol(arg2, sz));
        }
        Operations::RightRotation => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            push_value(state, arg1.ror(arg2, sz));
        }
        Operations::SignExtend => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_concrete(state, false, false);

            match arg1 {
                Value::Concrete(val1, t) => {
                    let shift = (64 - arg2) as i64;
                    let val = Value::Concrete(((val1 << shift) as i64 >> shift) as u64, t);
                    push_value(state, val);
                }
                Value::Symbolic(val1, t) => {
                    let val =
                        Value::Symbolic(val1.slice((arg2 - 1) as u32, 0).sext(64 - arg2 as u32), t);
                    push_value(state, val);
                }
            }
        }
        Operations::And => {
            binary_operation!(state, &);
        }
        Operations::Or => {
            binary_operation!(state, |);
        }
        Operations::Xor => {
            binary_operation!(state, ^);
        }
        Operations::Add => {
            binary_operation!(state, +);
        }
        Operations::Subtract => {
            binary_operation!(state, -);
        }
        Operations::Multiply => {
            binary_operation!(state, *);
        }
        // here, unlike anywhere else, long means 128 bit
        // it should be long long long long multiply
        Operations::LongMultiply => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);

            match (arg1, arg2) {
                (Value::Concrete(val1, t1), Value::Concrete(val2, t2)) => {
                    let val = (val1 as u128) * (val2 as u128);
                    push_value(state, Value::Concrete((val >> 64) as u64, t1 | t2));
                    push_value(state, Value::Concrete(val as u64, t1 | t2));
                }
                (Value::Symbolic(val1, t1), Value::Concrete(val2, t2)) => {
                    let sval1 = val1.uext(64);
                    let sval2 = state.bvv(val2, 128);
                    let prod = sval1.mul(&sval2);
                    push_value(state, Value::Symbolic(prod.slice(127, 64), t1 | t2));
                    push_value(state, Value::Symbolic(prod.slice(63, 0), t1 | t2));
                }
                (Value::Concrete(val1, t1), Value::Symbolic(val2, t2)) => {
                    let sval2 = val2.uext(64);
                    let sval1 = state.bvv(val1, 128);
                    let prod = sval1.mul(&sval2);
                    push_value(state, Value::Symbolic(prod.slice(127, 64), t1 | t2));
                    push_value(state, Value::Symbolic(prod.slice(63, 0), t1 | t2));
                }
                (Value::Symbolic(val1, t1), Value::Symbolic(val2, t2)) => {
                    let sval1 = val1.uext(64);
                    let sval2 = val2.uext(64);
                    let prod = sval1.mul(&sval2);
                    push_value(state, Value::Symbolic(prod.slice(127, 64), t1 | t2));
                    push_value(state, Value::Symbolic(prod.slice(63, 0), t1 | t2));
                }
            }
        }
        Operations::LongDivide => {
            let arg1 = pop_bv(state, 128);
            let arg2 = pop_bv(state, 128);
            let arg3 = pop_bv(state, 128);

            push_value(state, ((arg2 << vc(64)) + arg1) / arg3);
        }
        Operations::LongModulo => {
            let arg1 = pop_bv(state, 128);
            let arg2 = pop_bv(state, 128);
            let arg3 = pop_bv(state, 128);

            //println!("{:?} {:?} {:?}", arg1, arg2, arg3);
            push_value(state, ((arg2 << vc(64)) + arg1) % arg3);
        }
        Operations::Divide => {
            binary_operation!(state, /);
        }
        Operations::Modulo => {
            binary_operation!(state, %);
        }
        Operations::SignedDivide => {
            binary_method!(state, sdiv);
        }
        Operations::SignedModulo => {
            binary_method!(state, srem);
        }
        Operations::Not => {
            let arg1 = pop_value(state, false, false);
            push_value(state, !arg1);
        }
        Operations::Increment => {
            let arg1 = pop_value(state, false, false);
            push_value(state, arg1 + Value::Concrete(1, 0));
        }
        Operations::Decrement => {
            let arg1 = pop_value(state, false, false);
            push_value(state, arg1 - Value::Concrete(1, 0));
        }
        Operations::Equal => {
            let reg_arg = state.stack.pop().unwrap();
            let value = pop_value(state, false, false);
            do_equal(state, reg_arg, value, true);
        }
        Operations::WeakEqual => {
            let reg_arg = state.stack.pop().unwrap();
            let value = pop_value(state, false, false);
            do_equal(state, reg_arg, value, false);
        }
        Operations::Peek(n) => {
            let addr = pop_value(state, false, false);

            let val = state.memory_read_value(&addr, *n);
            state.esil.current = val.to_owned();
            push_value(state, val);

            state.esil.previous = addr;
            state.esil.last_sz = 8 * (*n);
        }
        Operations::Poke(n) => {
            let addr = pop_value(state, false, false);
            let value = pop_value(state, false, false);

            if let Some(cond) = &state.condition.to_owned() {
                let prev = state.memory_read_value(&addr, *n);
                state.memory_write_value(
                    &addr,
                    &state
                        .solver
                        .conditional(&Value::Symbolic(cond.to_owned(), 0), &value, &prev),
                    *n,
                );
            } else {
                state.memory_write_value(&addr, &value, *n);
            }

            //state.memory.write_value(addr, value, n);
            state.esil.previous = addr;
            state.esil.last_sz = 8 * (*n);
        }
        Operations::PeekBits => {
            let n = (state.memory.bits/8) as usize;
            let addr = pop_value(state, false, false);

            let val = state.memory_read_value(&addr, n);
            state.esil.current = val.to_owned();
            push_value(state, val);

            state.esil.previous = addr;
            state.esil.last_sz = 8 * n;
        }
        Operations::PokeBits => {
            let n = (state.memory.bits/8) as usize;
            let addr = pop_value(state, false, false);
            let value = pop_value(state, false, false);

            if let Some(cond) = &state.condition.to_owned() {
                let prev = state.memory_read_value(&addr, n);
                state.memory_write_value(
                    &addr,
                    &state
                        .solver
                        .conditional(&Value::Symbolic(cond.to_owned(), 0), &value, &prev),
                    n,
                );
            } else {
                state.memory_write_value(&addr, &value, n);
            }

            //state.memory.write_value(addr, value, n);
            state.esil.previous = addr;
            state.esil.last_sz = 8 * n;
        }
        Operations::PeekSize => {
            let n = pop_concrete(state, false, false) as usize;
            let addr = pop_value(state, false, false);

            let val = state.memory_read_value(&addr, n);
            state.esil.current = val.to_owned();
            push_value(state, val);

            state.esil.previous = addr;
            state.esil.last_sz = 8 * n;
        }
        Operations::PokeSize => {
            let n = pop_concrete(state, false, false) as usize;
            let addr = pop_value(state, false, false);
            let value = pop_value(state, false, false);

            if let Some(cond) = &state.condition.to_owned() {
                let prev = state.memory_read_value(&addr, n);
                state.memory_write_value(
                    &addr,
                    &state
                        .solver
                        .conditional(&Value::Symbolic(cond.to_owned(), 0), &value, &prev),
                    n,
                );
            } else {
                state.memory_write_value(&addr, &value, n);
            }

            //state.memory.write_value(addr, value, n);
            state.esil.previous = addr;
            state.esil.last_sz = 8 * n;
        }
        Operations::PeekMany => {
            let mut addr = pop_value(state, false, false);
            let num = pop_concrete(state, false, false);

            for _ in 0..num {
                if let Some(StackItem::StackRegister(ind)) = state.stack.pop() {
                    let reg = state.registers.indexes[ind].clone();
                    let val = state.memory_read_value(&addr, reg.reg_info.size as usize/8);
                    do_equal(state, StackItem::StackRegister(ind), val, false);
                    addr = addr + vc(reg.reg_info.size);
                }
            }
        }
        Operations::PokeMany => {
            let mut addr = pop_value(state, false, false);
            let num = pop_concrete(state, false, false);

            for _ in 0..num {
                if let Some(StackItem::StackRegister(ind)) = state.stack.pop() {
                    let reg = state.registers.indexes[ind].clone();
                    let val = state.registers.get_value(ind);
                    state.memory_write_value(&addr, &val, reg.reg_info.size as usize/8);
                    addr = addr + vc(reg.reg_info.size);
                }
            }
        }
        // this is a hack to do op pokes ~efficiently
        Operations::AddressStore => {
            let addr = pop_value(state, false, false);
            state.esil.stored_address = Some(addr.to_owned());
            push_value(state, addr);
        }
        Operations::AddressRestore => {
            let addr = state.esil.stored_address.as_ref().unwrap().to_owned();
            push_value(state, addr);
            state.esil.stored_address = None;
        }
        Operations::PopCount => {
            let arg1 = pop_value(state, false, false);
            match arg1 {
                Value::Concrete(val, t) => {
                    let value = Value::Concrete(val.count_ones() as u64, t);
                    push_value(state, value);
                }
                Value::Symbolic(val, t) => {
                    let mut sym_val = state.bvv(0, 64);
                    for i in 0..val.get_width() {
                        sym_val = sym_val.add(&val.slice(i + 1, i).uext(63));
                    }
                    push_value(state, Value::Symbolic(sym_val, t));
                }
            }
        }
        Operations::Ceiling => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(arg1.ceil()), t));
        }
        Operations::Floor => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(arg1.floor()), t));
        }
        Operations::Round => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(arg1.round()), t));
        }
        Operations::SquareRoot => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(arg1.sqrt()), t));
        }
        Operations::DoubleToInt => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(arg1 as u64, t));
        }
        Operations::SignedToDouble => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_concrete(state, false, true);
            let value = Value::Concrete(f64::to_bits(arg1 as i64 as f64), t);
            push_value(state, value);
        }
        Operations::UnsignedToDouble => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_concrete(state, false, false);
            push_value(state, Value::Concrete(f64::to_bits(arg1 as f64), t));
        }
        Operations::FloatToDouble => {
            let val = pop_value(state, false, false);
            push_value(state, val.to_owned());

            let arg1 = pop_float(state);
            let size = pop_concrete(state, false, false);

            // i hate this but this is how I wrote r2
            // so i have only myself to blame
            let value = if size != 64 {
                Value::Concrete(f64::to_bits(arg1 as f64), val.get_taint())
            } else {
                val
            };
            push_value(state, value);
        }
        Operations::DoubleToFloat => {
            let t = get_stack_taint(state, 1);

            let arg1 = pop_double(state);
            let size = pop_concrete(state, false, false);

            // these casts will need casts when i'm done with em
            let value = if size != 64 {
                Value::Concrete(f32::to_bits(arg1 as f32) as u64, t)
            } else {
                Value::Concrete(f64::to_bits(arg1), t)
            };
            push_value(state, value);
        }
        Operations::FloatAdd => {
            binary_float_operation!(state, +);
        }
        Operations::FloatSubtract => {
            binary_float_operation!(state, -);
        }
        Operations::FloatMultiply => {
            binary_float_operation!(state, *);
        }
        Operations::FloatDivide => {
            binary_float_operation!(state, /);
        }
        Operations::FloatCompare => {
            let t = get_stack_taint(state, 2);
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            push_value(state, Value::Concrete((arg1 - arg2 == 0.0) as u64, t));
        }
        Operations::FloatLessThan => {
            let t = get_stack_taint(state, 2);
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            push_value(state, Value::Concrete((arg1 < arg2) as u64, t));
        }
        Operations::NaN => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(arg1.is_nan() as u64, t));
        }
        Operations::FloatNegate => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(-arg1), t));
        }
        Operations::Swap => {
            let arg1 = state.stack.pop().unwrap();
            let arg2 = state.stack.pop().unwrap();
            state.stack.push(arg1);
            state.stack.push(arg2);
        }
        Operations::Pick => {
            let n = pop_concrete(state, false, false);
            let item = state.stack[(state.stack.len() - n as usize)].to_owned();
            state.stack.push(item);
        }
        Operations::ReversePick => {
            let n = pop_concrete(state, false, false);
            let item = state.stack[n as usize].to_owned();
            state.stack.push(item);
        }
        Operations::Pop => {
            state.stack.pop();
        }
        Operations::Duplicate => {
            let item = state.stack.pop().unwrap();
            state.stack.push(item.clone());
            state.stack.push(item);
        }
        Operations::Number => {
            let value = pop_value(state, false, false);
            push_value(state, value);
        }
        Operations::Clear => {
            state.stack.clear();
        }
        Operations::PrintStack => {
            for value in state.stack.iter().rev() {
                    println!("{:?}", value);
            }
        }
        Operations::Break => {}
        Operations::Repeat => {}
        Operations::GoTo => {}
        Operations::NoOperation => {}

        Operations::Print => {
            let value = pop_value(state, false, false);
            if let Some(cond) = &state.condition {
                state.solver.push();
                let condition = cond.clone();
                state.assert_bv(&condition);
            }
            let ip = state.registers.get_pc().as_u64().unwrap_or_default();
            if let Some(bv) = state.solver.eval_to_bv(&value) {
                let hex = state.solver.hex_solution(&bv).unwrap();
                if let Some(string) = state.evaluate_string_bv(&bv) {
                    println!("\n0x{:08x}    0x{} {:?}\n", ip, hex, string);
                } else {
                    println!("\n0x{:08x}    0x{}\n", ip, hex);
                }
            } else {
                println!("\n0x{:08x}    unsat\n", ip);
            }
            if state.condition.is_some() {
                state.solver.pop();
            }
        }
        Operations::PrintDebug => {
            let value = pop_value(state, false, false);
            let ip = state.registers.get_pc().as_u64().unwrap_or_default();
            println!("\n0x{:08x}    {:?}\n", ip, value);
        }
        Operations::Backtrace => {
            state.print_backtrace();
        }
        Operations::Constrain => {
            let value = pop_value(state, false, false);
            state.assert(&value);
        }
        Operations::ConstraintPush => {
            state.solver.push();
        }
        Operations::ConstraintPop => {
            state.solver.pop();
        }
        Operations::Terminate => {
            state.set_break();
        }
        Operations::Discard => {
            state.set_inactive();
        }
        Operations::ToDo => {
            if state.strict {
                unimplemented!();
            }
        }

        Operations::Zero => {
            let cur = &state.esil.current;
            let mask = Value::Concrete(genmask((state.esil.last_sz - 1) as u64), 0);
            let zf = !(cur.and(&mask));
            push_value(state, zf);
        }
        Operations::Carry => {
            let bits = pop_concrete(state, false, false);
            let mask = Value::Concrete(genmask(bits & 0x3f), 0);
            let cur = &state.esil.current;
            let old = &state.esil.previous;

            let cf = cur.and(&mask).ult(&old.and(&mask));
            push_value(state, cf);
        }
        Operations::Borrow => {
            let bits = pop_concrete(state, false, false);
            let mask = Value::Concrete(genmask(bits & 0x3f), 0);
            let cur = &state.esil.current;
            let old = &state.esil.previous;

            let cf = old.and(&mask).ult(&cur.and(&mask));
            push_value(state, cf);
        }
        Operations::Parity => match &state.esil.current {
            Value::Concrete(val, t) => {
                let pf = Value::Concrete(!((val & 0xff).count_ones() % 2) as u64, *t);
                push_value(state, pf);
            }
            Value::Symbolic(_val, _t) => {
                let c1 = Value::Concrete(0x0101010101010101, 0);
                let c2 = Value::Concrete(0x8040201008040201, 0);
                let c3 = Value::Concrete(0x1ff, 0);

                let cur = state.esil.current.to_owned();
                let lsb = cur & Value::Concrete(0xff, 0);
                let pf = !((((lsb * c1) & c2) % c3) & Value::Concrete(1, 0));
                //let pf = Value::Symbolic(val.redxor(), *t); this is 2x slower wtf
                push_value(state, pf);
            }
        },
        Operations::Overflow => {
            let bits = pop_concrete(state, false, false);
            let mask1 = Value::Concrete(genmask(bits & 0x3f), 0);
            let mask2 = Value::Concrete(genmask((bits + 0x3f) & 0x3f), 0);

            let cur = &state.esil.current;
            let old = &state.esil.previous;

            let c_in = cur.and(&mask1).ult(&old.and(&mask1));
            let c_out = cur.and(&mask2).ult(&old.and(&mask2));
            let of = c_in ^ c_out;
            push_value(state, of);
        }
        Operations::S => {
            let size = pop_value(state, false, false);
            let cur = state.esil.current.to_owned();
            let value = (cur >> size) & Value::Concrete(1, 0);
            push_value(state, value);
        }
        Operations::Ds => {
            let cur = state.esil.current.to_owned();
            let sz = Value::Concrete(state.esil.last_sz as u64, 0);
            let ds = (cur >> sz) & Value::Concrete(1, 0);
            push_value(state, ds);
        }
        Operations::JumpTarget => {}
        Operations::Js => {}
        Operations::R => {
            push_value(state, Value::Concrete(64 >> 3, 0));
        }
        Operations::Unknown => {
            if state.strict {
                panic!("Encountered an unknown word!");
            }
        }
    }
}
