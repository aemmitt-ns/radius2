/// ESIL operations.
///
/// Types to represent ESIL operations.
/// Functions to manipulate the VM's stack.
/// Functions to emulate the effect of ESIL operations on a state.
use crate::state::{StackItem, State};
use crate::value::{vc, Value};
use std::f64;

pub const OPS: [&str; 16] = [
    "+", "-", "++", "--", "*", "/", "<<", ">>", "|", "&", "^", "%", "!", ">>>>", ">>>", "<<<",
];

pub const SIZE: u64 = 64;

/// An ESIL operation.
#[derive(Debug, Clone, PartialEq)]
pub enum Operation {
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
    //Repeat, // Not in current r2.
    GoTo,
    PrintStack,
    ToDo,
    NoOperation,

    Print,      // Tool for cli hooks
    PrintDebug, // Tool for cli hooks
    Backtrace,  // Tool for cli hooks
    Constrain,
    ConstrainEqual,
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
    //R, // Unused in current r2.
    SetD,
    SetJt,

    /// Everything that is not implemented gets deserialized to this.
    Unknown,
}

impl Operation {
    pub fn from_string(s: &str) -> Self {
        match s {
            "$" => Operation::Interrupt,
            "()" => Operation::Syscall,
            "$$" => Operation::PcAddress, // this is whack
            "?{" => Operation::If,
            "}{" => Operation::Else,
            "}" => Operation::EndIf,
            "==" => Operation::Compare,
            "<" => Operation::LessThan,
            "<=" => Operation::LessThanEq,
            ">" => Operation::GreaterThan,
            ">=" => Operation::GreaterThanEq,
            "<<" => Operation::LeftShift,
            ">>" => Operation::LogicalRightShift,
            ">>>>" => Operation::RightShift,
            "<<<" => Operation::LeftRotation,
            ">>>" => Operation::RightRotation,
            "~" => Operation::SignExtend,
            "SIGN" => Operation::SignExtend,
            "&" => Operation::And,
            "|" => Operation::Or,
            "^" => Operation::Xor,
            "+" => Operation::Add,
            "-" => Operation::Subtract,
            "*" => Operation::Multiply,
            "L*" => Operation::LongMultiply,
            "/" => Operation::Divide,
            "L/" => Operation::LongDivide,
            "%" => Operation::Modulo,
            "L%" => Operation::LongModulo,
            "~/" => Operation::SignedDivide,
            "~%" => Operation::SignedModulo,
            "!" => Operation::Not,
            "++" => Operation::Increment,
            "--" => Operation::Decrement,
            "=" => Operation::Equal,
            ":=" => Operation::WeakEqual,
            "[1]" => Operation::Peek(1),
            "[2]" => Operation::Peek(2),
            "[4]" => Operation::Peek(4),
            "[8]" => Operation::Peek(8),
            "[16]" => Operation::Peek(16),
            "=[1]" => Operation::Poke(1),
            "=[2]" => Operation::Poke(2),
            "=[4]" => Operation::Poke(4),
            "=[8]" => Operation::Poke(8),
            "=[16]" => Operation::Poke(16),
            "=[]" => Operation::PokeBits,
            "[]" => Operation::PeekBits,
            "=[n]" => Operation::PokeSize,
            "[n]" => Operation::PeekSize,
            "=[*]" => Operation::PokeMany,
            "[*]" => Operation::PeekMany,
            "POPCOUNT" => Operation::PopCount,
            "CEIL" => Operation::Ceiling,
            "FLOOR" => Operation::Floor,
            "ROUND" => Operation::Round,
            "SQRT" => Operation::SquareRoot,
            "D2I" => Operation::DoubleToInt,
            "I2D" => Operation::SignedToDouble,
            "S2D" => Operation::SignedToDouble,
            "U2D" => Operation::UnsignedToDouble,
            "F2D" => Operation::FloatToDouble,
            "D2F" => Operation::DoubleToFloat,
            "F+" => Operation::FloatAdd,
            "F-" => Operation::FloatSubtract,
            "F*" => Operation::FloatMultiply,
            "F/" => Operation::FloatDivide,
            "F==" => Operation::FloatCompare,
            "F<" => Operation::FloatLessThan,
            "NAN" => Operation::NaN,
            "-F" => Operation::FloatNegate,

            "TRAP" => Operation::Trap,
            "SWAP" => Operation::Swap,
            "PICK" => Operation::Pick,
            "RPICK" => Operation::ReversePick,
            "POP" => Operation::Pop,
            "DUP" => Operation::Duplicate,
            "NUM" => Operation::Number,
            "CLEAR" => Operation::Clear,
            "BREAK" => Operation::Break,
            //"REPEAT" => Operation::Repeat, // Does not exist in current r2.
            "GOTO" => Operation::GoTo,
            "STACK" => Operation::PrintStack,
            "TODO" => Operation::ToDo,
            "" => Operation::NoOperation,

            // hax for use in the cli / plugin
            "." => Operation::Print,
            ".." => Operation::PrintDebug,
            "BT" => Operation::Backtrace,
            "_" => Operation::Constrain,
            "_=" => Operation::ConstrainEqual,
            "_+" => Operation::ConstraintPush,
            "_-" => Operation::ConstraintPop,
            "!!" => Operation::Terminate, // state.set_break()
            "!_" => Operation::Discard,   // state.set_inactive()

            // Writing internal ESIL VM flags.
            "SETD" => Operation::SetD,
            "SETJT" => Operation::SetJt,

            // Reading internal ESIL VM flags.
            "$z" => Operation::Zero,
            "$c" => Operation::Carry,
            "$b" => Operation::Borrow,
            "$p" => Operation::Parity,
            "$o" => Operation::Overflow,
            //"$so" => Operations::SubOverflow,
            "$s" => Operation::S,
            "$ds" => Operation::Ds,
            "$jt" => Operation::JumpTarget,
            "$js" => Operation::Js,
            //"$r" => Operation::R, // Unused in current r2.
            _ => Operation::Unknown,
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
#[allow(dead_code)]
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

        state.registers.set_value(index, value.to_owned());

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

/// Computes the effect of a __non-control-flow__ `operation` on the given
/// `state`.
///
/// Control-flow constructs like ITE and GOTO must be handled separately.
/// Some "special" operations are also not handled here.
pub fn do_operation(state: &mut State, operation: &Operation) {
    match operation {
        // Control flow Constructs are handled separately.
        Operation::Trap
        | Operation::If
        | Operation::Else
        | Operation::EndIf
        | Operation::GoTo
        | Operation::Interrupt
        | Operation::Syscall
        | Operation::Break => {}
        Operation::PcAddress => {
            push_value(state, state.esil.insn_address.clone());
        }
        Operation::Compare => {
            let arg1 = pop_value(state, true, false);
            let arg2 = pop_value(state, false, false);
            state.esil.current = arg1.to_owned() - arg2;
            state.esil.previous = arg1;
        }
        Operation::LessThan => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.slt(&arg2));
        }
        Operation::LessThanEq => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.slte(&arg2));
        }
        Operation::GreaterThan => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.sgt(&arg2));
        }
        Operation::GreaterThanEq => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.sgte(&arg2));
        }
        Operation::LeftShift => {
            binary_operation!(state, <<);
        }
        Operation::LogicalRightShift => {
            binary_operation!(state, >>);
        }
        Operation::RightShift => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, true);
            let arg2 = pop_value(state, false, true);
            push_value(state, arg1.asr(arg2, sz));
        }
        Operation::LeftRotation => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            push_value(state, arg1.rol(arg2, sz));
        }
        Operation::RightRotation => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            push_value(state, arg1.ror(arg2, sz));
        }
        Operation::SignExtend => {
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
        Operation::And => {
            binary_operation!(state, &);
        }
        Operation::Or => {
            binary_operation!(state, |);
        }
        Operation::Xor => {
            binary_operation!(state, ^);
        }
        Operation::Add => {
            binary_operation!(state, +);
        }
        Operation::Subtract => {
            binary_operation!(state, -);
        }
        Operation::Multiply => {
            binary_operation!(state, *);
        }
        // here, unlike anywhere else, long means 128 bit
        // it should be long long long long multiply
        Operation::LongMultiply => {
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
        Operation::LongDivide => {
            let arg1 = pop_bv(state, 128);
            let arg2 = pop_bv(state, 128);
            let arg3 = pop_bv(state, 128);

            push_value(state, ((arg2 << vc(64)) + arg1) / arg3);
        }
        Operation::LongModulo => {
            let arg1 = pop_bv(state, 128);
            let arg2 = pop_bv(state, 128);
            let arg3 = pop_bv(state, 128);

            //println!("{:?} {:?} {:?}", arg1, arg2, arg3);
            push_value(state, ((arg2 << vc(64)) + arg1) % arg3);
        }
        Operation::Divide => {
            binary_operation!(state, /);
        }
        Operation::Modulo => {
            binary_operation!(state, %);
        }
        Operation::SignedDivide => {
            binary_method!(state, sdiv);
        }
        Operation::SignedModulo => {
            binary_method!(state, srem);
        }
        Operation::Not => {
            let arg1 = pop_value(state, false, false);
            push_value(state, !arg1);
        }
        Operation::Increment => {
            let arg1 = pop_value(state, false, false);
            push_value(state, arg1 + Value::Concrete(1, 0));
        }
        Operation::Decrement => {
            let arg1 = pop_value(state, false, false);
            push_value(state, arg1 - Value::Concrete(1, 0));
        }
        Operation::Equal => {
            let reg_arg = state.stack.pop().unwrap();
            let value = pop_value(state, false, false);
            do_equal(state, reg_arg, value, true);
        }
        Operation::WeakEqual => {
            let reg_arg = state.stack.pop().unwrap();
            let value = pop_value(state, false, false);
            do_equal(state, reg_arg, value, false);
        }
        Operation::Peek(n) => {
            let addr = pop_value(state, false, false);

            let val = state.memory_read_value(&addr, *n);
            state.esil.current = val.to_owned();
            push_value(state, val);

            state.esil.previous = addr;
            state.esil.last_sz = 8 * (*n);
        }
        Operation::Poke(n) => {
            let addr = pop_value(state, false, false);
            let value = pop_value(state, false, false);

            state.memory_write_value(&addr, &value, *n);

            //state.memory.write_value(addr, value, n);
            state.esil.previous = addr;
            state.esil.last_sz = 8 * (*n);
        }
        Operation::PeekBits => {
            let n = (state.memory.bits / 8) as usize;
            let addr = pop_value(state, false, false);

            let val = state.memory_read_value(&addr, n);
            state.esil.current = val.to_owned();
            push_value(state, val);

            state.esil.previous = addr;
            state.esil.last_sz = 8 * n;
        }
        Operation::PokeBits => {
            let n = (state.memory.bits / 8) as usize;
            let addr = pop_value(state, false, false);
            let value = pop_value(state, false, false);

            state.memory_write_value(&addr, &value, n);

            //state.memory.write_value(addr, value, n);
            state.esil.previous = addr;
            state.esil.last_sz = 8 * n;
        }
        Operation::PeekSize => {
            let n = pop_concrete(state, false, false) as usize;
            let addr = pop_value(state, false, false);

            let val = state.memory_read_value(&addr, n);
            state.esil.current = val.to_owned();
            push_value(state, val);

            state.esil.previous = addr;
            state.esil.last_sz = 8 * n;
        }
        Operation::PokeSize => {
            let n = pop_concrete(state, false, false) as usize;
            let addr = pop_value(state, false, false);
            let value = pop_value(state, false, false);

            state.memory_write_value(&addr, &value, n);

            //state.memory.write_value(addr, value, n);
            state.esil.previous = addr;
            state.esil.last_sz = 8 * n;
        }
        Operation::PeekMany => {
            let mut addr = pop_value(state, false, false);
            let num = pop_concrete(state, false, false);

            for _ in 0..num {
                if let Some(StackItem::StackRegister(ind)) = state.stack.pop() {
                    let reg = state.registers.indexes[ind].clone();
                    let val = state.memory_read_value(&addr, reg.reg_info.size as usize / 8);
                    do_equal(state, StackItem::StackRegister(ind), val, false);
                    addr = addr + vc(reg.reg_info.size);
                }
            }
        }
        Operation::PokeMany => {
            let mut addr = pop_value(state, false, false);
            let num = pop_concrete(state, false, false);

            for _ in 0..num {
                if let Some(StackItem::StackRegister(ind)) = state.stack.pop() {
                    let reg = state.registers.indexes[ind].clone();
                    let val = state.registers.get_value(ind);
                    state.memory_write_value(&addr, &val, reg.reg_info.size as usize / 8);
                    addr = addr + vc(reg.reg_info.size);
                }
            }
        }
        // this is a hack to do op pokes ~efficiently
        Operation::AddressStore => {
            let addr = pop_value(state, false, false);
            state.esil.stored_address = Some(addr.to_owned());
            push_value(state, addr);
        }
        Operation::AddressRestore => {
            let addr = state.esil.stored_address.as_ref().unwrap().to_owned();
            push_value(state, addr);
            state.esil.stored_address = None;
        }
        Operation::PopCount => {
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
        Operation::Ceiling => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(arg1.ceil()), t));
        }
        Operation::Floor => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(arg1.floor()), t));
        }
        Operation::Round => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(arg1.round()), t));
        }
        Operation::SquareRoot => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(arg1.sqrt()), t));
        }
        Operation::DoubleToInt => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(arg1 as u64, t));
        }
        Operation::SignedToDouble => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_concrete(state, false, true);
            let value = Value::Concrete(f64::to_bits(arg1 as i64 as f64), t);
            push_value(state, value);
        }
        Operation::UnsignedToDouble => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_concrete(state, false, false);
            push_value(state, Value::Concrete(f64::to_bits(arg1 as f64), t));
        }
        Operation::FloatToDouble => {
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
        Operation::DoubleToFloat => {
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
        Operation::FloatAdd => {
            binary_float_operation!(state, +);
        }
        Operation::FloatSubtract => {
            binary_float_operation!(state, -);
        }
        Operation::FloatMultiply => {
            binary_float_operation!(state, *);
        }
        Operation::FloatDivide => {
            binary_float_operation!(state, /);
        }
        Operation::FloatCompare => {
            let t = get_stack_taint(state, 2);
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            push_value(state, Value::Concrete((arg1 - arg2 == 0.0) as u64, t));
        }
        Operation::FloatLessThan => {
            let t = get_stack_taint(state, 2);
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            push_value(state, Value::Concrete((arg1 < arg2) as u64, t));
        }
        Operation::NaN => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(arg1.is_nan() as u64, t));
        }
        Operation::FloatNegate => {
            let t = get_stack_taint(state, 1);
            let arg1 = pop_double(state);
            push_value(state, Value::Concrete(f64::to_bits(-arg1), t));
        }
        Operation::Swap => {
            let arg1 = state.stack.pop().unwrap();
            let arg2 = state.stack.pop().unwrap();
            state.stack.push(arg1);
            state.stack.push(arg2);
        }
        Operation::Pick => {
            let n = pop_concrete(state, false, false);
            let item = state.stack[state.stack.len() - n as usize].to_owned();
            state.stack.push(item);
        }
        Operation::ReversePick => {
            let n = pop_concrete(state, false, false);
            let item = state.stack[n as usize].to_owned();
            state.stack.push(item);
        }
        Operation::Pop => {
            state.stack.pop();
        }
        Operation::Duplicate => {
            let item = state.stack.pop().unwrap();
            state.stack.push(item.clone());
            state.stack.push(item);
        }
        Operation::Number => {
            let value = pop_value(state, false, false);
            push_value(state, value);
        }
        Operation::Clear => {
            state.stack.clear();
        }
        Operation::PrintStack => {
            for value in state.stack.iter().rev() {
                println!("{:?}", value);
            }
        }
        Operation::NoOperation => {}

        Operation::Print => {
            let value = pop_value(state, false, false);
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
        }
        Operation::PrintDebug => {
            let value = pop_value(state, false, false);
            let ip = state.registers.get_pc().as_u64().unwrap_or_default();
            println!("\n0x{:08x}    {:?}\n", ip, value);
        }
        Operation::Backtrace => {
            state.print_backtrace();
        }
        Operation::Constrain => {
            let value = pop_value(state, false, false);
            state.assert(&value);
        }
        // im gettin tired of writing x,y,-,!,_
        Operation::ConstrainEqual => {
            let val1 = pop_value(state, false, false);
            let val2 = pop_value(state, false, false);
            state.assert(&val1.eq(&val2));
        }
        Operation::ConstraintPush => {
            state.solver.push();
        }
        Operation::ConstraintPop => {
            state.solver.pop();
        }
        Operation::Terminate => {
            state.set_break();
        }
        Operation::Discard => {
            state.set_inactive();
        }

        Operation::ToDo => {
            panic!("Attempt to execute TODO.");
        }

        // Writing internal ESIL VM flags.
        Operation::SetD => {
            let delay = pop_concrete(state, false, false) != 0;
            state.esil.delay = delay;
        }
        Operation::SetJt => {
            let jump_target = pop_value(state, false, false);
            state.esil.jump_target = Some(jump_target);
        }

        // Reading internal ESIL VM flags.
        Operation::Zero => {
            let cur = &state.esil.current;
            let mask = Value::Concrete(genmask((state.esil.last_sz - 1) as u64), 0);
            let zf = !(cur.and(&mask));
            push_value(state, zf);
        }
        Operation::Carry => {
            let bits = pop_concrete(state, false, false);
            let mask = Value::Concrete(genmask(bits & 0x3f), 0);
            let cur = &state.esil.current;
            let old = &state.esil.previous;

            let cf = cur.and(&mask).ult(&old.and(&mask));
            push_value(state, cf);
        }
        Operation::Borrow => {
            let bits = pop_concrete(state, false, false);
            let mask = Value::Concrete(genmask(bits & 0x3f), 0);
            let cur = &state.esil.current;
            let old = &state.esil.previous;

            let cf = old.and(&mask).ult(&cur.and(&mask));
            push_value(state, cf);
        }
        Operation::Parity => match &state.esil.current {
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
        Operation::Overflow => {
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
        Operation::S => {
            let size = pop_value(state, false, false);
            let cur = state.esil.current.to_owned();
            let value = (cur >> size) & Value::Concrete(1, 0);
            push_value(state, value);
        }
        Operation::Ds => {
            let delay = state.esil.delay;
            push_value(state, vc(delay as u64));
        }
        Operation::JumpTarget => {
            // `$jt` panics if SETJT was not executed before.
            let jump_target = state.esil.jump_target.clone().unwrap();
            push_value(state, jump_target);
        }
        Operation::Js => {
            let jump_target_set = state.esil.jump_target.is_some();
            push_value(state, vc(jump_target_set as u64));
        }
        Operation::Unknown => {
            panic!("Encountered an unknown word: {:?}", operation);
        }
    }
}
