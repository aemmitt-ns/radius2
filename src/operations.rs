use crate::value::{Value, cond_value};
use crate::state::{State, StackItem};
use std::f64;

pub const OPS: [&str; 16] = ["+", "-", "++", "--", "*", "/", "<<", ">>", "|", "&", "^", "%", "!", ">>>>", ">>>", "<<<"];
pub const SIZE: u64 = 64;

#[derive(Debug, Clone)]
pub enum Operations {
    Trap,
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
    Modulo,
    SignedDivide,
    SignedModulo,
    Not,
    Increment,
    Decrement,
    Equal,
    WeakEqual,
    Peek(usize),
    Poke(usize),
    PokeSize,
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
    AddressStore, // fuck
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
    ToDo,
    NoOperation,

    // flag ops
    Zero,
    Carry,
    Borrow,
    Parity,
    Overflow,
    SubOverflow,
    // i forget these
    S,
    Ds,
    JumpTarget,
    Js,
    R,

    Unknown
}

impl Operations {
    pub fn from_str(s: &str) -> Self {
        match s {
            "TRAP" => Operations::Trap,
            "$" => Operations::Syscall,
            "$$" => Operations::PcAddress,
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
            "%" => Operations::Modulo,
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
            "=[]" => Operations::PokeSize,
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
            "TODO" => Operations::ToDo,
            "" => Operations::NoOperation,
        
            "$z" => Operations::Zero,
            "$c" => Operations::Carry,
            "$b" => Operations::Borrow,
            "$p" => Operations::Parity,
            "$o" => Operations::Overflow,
            "$so" => Operations::SubOverflow,
            "$s" => Operations::S,
            "$ds" => Operations::Ds,
            "$jt" => Operations::JumpTarget,
            "$js" => Operations::Js,
            "$r" => Operations::R,
            _ => Operations::Unknown
        }
    }
}

#[inline]
pub fn get_size(state: &mut State) -> u32 {
    let item = state.stack.pop().unwrap();

    let sz = match &item {
        StackItem::StackValue(_val) => {
            64
        },
        StackItem::StackRegister(index) => {
            let reg = &state.registers.indexes[*index];
            reg.reg_info.size as u32
        }
    };

    state.stack.push(item);
    sz
}

#[inline]
pub fn pop_value(state: &mut State, set_size: bool, sign_ext: bool) -> Value {
    let item = state.stack.pop().unwrap();

    let value = match item {
        StackItem::StackValue(val) => {
            val
        },
        StackItem::StackRegister(index) => {
            if set_size {
                let reg = &state.registers.indexes[index];
                state.esil.last_sz = reg.reg_info.size as usize;
            }
            state.registers.get_value(index)
        }
    };

    match &value {
        Value::Concrete(_v) => value,
        Value::Symbolic(ov) => {
            if ov.is_const() {
                Value::Concrete(ov.as_u64().unwrap())
            } else {
                let v = state.translate(&ov).unwrap();
                let szdiff = SIZE - v.get_width() as u64;
                if szdiff > 0 {
                    if sign_ext {
                        Value::Symbolic(v.sext(szdiff as u32))
                    } else {
                        Value::Symbolic(v.uext(szdiff as u32))
                    }
                } else {
                    value
                }
            }
        }
    }
}

#[inline]
pub fn pop_stack_value(state: &mut State, stack: &mut Vec<StackItem>, set_size: bool, sign_ext: bool) -> Value {
    let item = stack.pop().unwrap();

    let value = match item {
        StackItem::StackValue(val) => {
            val
        },
        StackItem::StackRegister(index) => {
            if set_size {
                let reg = state.registers.indexes.get(index).unwrap();
                state.esil.last_sz = reg.reg_info.size as usize;
            }
            state.registers.get_value(index)
        }
    };

    match &value {
        Value::Concrete(_v) => value,
        Value::Symbolic(ov) => {
            if ov.is_const() {
                Value::Concrete(ov.as_u64().unwrap())
            } else {
                let v = state.translate(&ov).unwrap();
                let szdiff = SIZE - v.get_width() as u64;
                if szdiff > 0 {
                    if sign_ext {
                        Value::Symbolic(v.sext(szdiff as u32))
                    } else {
                        Value::Symbolic(v.uext(szdiff as u32))
                    }
                } else {
                    value
                }
            }
        }
    }
}

#[inline]
pub fn pop_concrete(state: &mut State, set_size: bool, sign_ext: bool) -> u64 {
    let value = pop_value(state, set_size, sign_ext);

    match value {
        Value::Concrete(val) => {
            val
        },
        Value::Symbolic(val) => {
            let solution = val.get_a_solution().as_u64().unwrap();
            let sol_bv = state.bvv(solution, 64);
            val._eq(&sol_bv).assert();
            solution
        }
    }
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
pub fn do_equal(state: &mut State, reg: StackItem, value: Value, 
    set_esil: bool, pc_index: usize) {

    match reg {
        StackItem::StackRegister(index) => {
            let register = state.registers.indexes.get(index).unwrap();
            let size = register.reg_info.size as usize;
            let mut prev = state.registers.get_value(index);
            prev = state.translate_value(&prev);

            if let Some(cond) = &state.condition {

                // tortured logic for lazy execution
                if index == pc_index {
                    if let Value::Concrete(val) = value {
                        if let Value::Concrete(pc) = prev {
                            if state.esil.pcs.is_empty() {
                                state.esil.pcs.push(pc);
                            }
                        }
                        state.esil.pcs.push(val);
                    }
                }
                state.registers.set_value(index, Value::Symbolic(
                    cond_value(cond, value.clone(), prev.clone())));
            } else {
                state.registers.set_value(index, value.clone());
            }

            if set_esil {
                state.esil.last_sz = size;
                state.esil.current = value;
                state.esil.previous = prev;
            }

        },
        _ => {} // shouldn't happen
    }
}

#[inline]
pub fn genmask(bits: u64) -> u64 {
    if bits > 0 && bits < 64 {
        (2 << bits) - 1
    } else {
        0xffffffffffffffff
    }
}

pub fn do_operation(state: &mut State, operation: Operations, pc_index: usize) {
    match operation {
        Operations::Trap => {},
        Operations::Syscall => {},
        Operations::PcAddress => {
            let pc_reg = state.registers.aliases["PC"].reg.clone();
            let pc = state.registers.get(&pc_reg);
            state.stack.push(StackItem::StackValue(pc));
        },
        Operations::If => {}, // these are handled in processor
        Operations::Else => {},
        Operations::EndIf => {},
        Operations::Compare => {
            let arg1 = pop_value(state, true, false);
            let arg2 = pop_value(state, false, false);

            state.esil.current = arg1.clone() - arg2;
            //println!("cmp {:?}", state.esil.current);
            state.esil.previous = arg1;
        },
        Operations::LessThan => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);

            state.stack.push(StackItem::StackValue(arg1.slt(arg2)));
        },
        Operations::LessThanEq => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);

            state.stack.push(StackItem::StackValue(
                arg1.clone().slt(arg2.clone()) | arg1.eq(arg2)));
        },
        Operations::GreaterThan => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);

            state.stack.push(StackItem::StackValue(
                !arg1.clone().slt(arg2.clone()) & !arg1.eq(arg2)));
        },
        Operations::GreaterThanEq => {
            let arg1 = pop_value(state, true, true);
            let arg2 = pop_value(state, false, true);

            state.stack.push(StackItem::StackValue(!arg1.slt(arg2)));
        },
        Operations::LeftShift => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 << arg2));
        },
        Operations::LogicalRightShift => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 >> arg2));
        },
        Operations::RightShift => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, true);
            let arg2 = pop_value(state, false, true);
            state.stack.push(StackItem::StackValue(arg1.asr(arg2, sz)));
        },
        Operations::LeftRotation => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1.rol(arg2, sz)));
        },
        Operations::RightRotation => {
            let sz = get_size(state);
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1.ror(arg2, sz)));
        },
        Operations::SignExtend => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_concrete(state, false, false);

            match arg1 {
                Value::Concrete(val1) => {
                    let shift = (64-arg2) as i64;
                    let val = Value::Concrete(((val1 << shift) as i64 >> shift) as u64);
                    state.stack.push(StackItem::StackValue(val));
                },
                Value::Symbolic(val1) => {
                    let val = Value::Symbolic(val1.slice((arg2-1) as u32, 0).sext(64-arg2 as u32));
                    state.stack.push(StackItem::StackValue(val));
                }
            }
        },
        Operations::And => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 & arg2))
        },
        Operations::Or => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 | arg2))
        },
        Operations::Xor => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 ^ arg2))
        },
        Operations::Add => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 + arg2))
        },
        Operations::Subtract => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 - arg2))
        },
        Operations::Multiply => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 * arg2))
        },
        // here, unlike anywhere else, long means 128 bit, it should be long long long long multiply
        Operations::LongMultiply => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);

            match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = (val1 as u128) << (val2 as u128);
                    state.stack.push(StackItem::StackValue(
                        Value::Concrete((val >> 64) as u64)));
                    state.stack.push(StackItem::StackValue(
                        Value::Concrete(val as u64)));
                },
                (Value::Symbolic(val1), Value::Concrete(val2)) => {
                    let sval1 = val1.uext(64);
                    let sval2 = state.bvv(val2, 128);
                    let prod  = sval1.mul(&sval2);
                    state.stack.push(StackItem::StackValue(
                        Value::Symbolic(prod.slice(127, 64))));
                    state.stack.push(StackItem::StackValue(
                        Value::Symbolic(prod.slice(63, 0))));
                },
                (Value::Concrete(val1), Value::Symbolic(val2)) => {
                    let sval2 = val2.uext(64);
                    let sval1 = state.bvv(val1, 128);
                    let prod  = sval1.mul(&sval2);
                    state.stack.push(StackItem::StackValue(
                        Value::Symbolic(prod.slice(127, 64))));
                    state.stack.push(StackItem::StackValue(
                        Value::Symbolic(prod.slice(63, 0))));
                },
                (Value::Symbolic(val1), Value::Symbolic(val2)) => {
                    let sval1 = val1.uext(64);
                    let sval2 = val2.uext(64);
                    let prod  = sval1.mul(&sval2);
                    state.stack.push(StackItem::StackValue(
                        Value::Symbolic(prod.slice(127, 64))));
                    state.stack.push(StackItem::StackValue(
                        Value::Symbolic(prod.slice(63, 0))));
                },
            }
        },
        Operations::Divide => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 / arg2))
        },
        Operations::Modulo => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 % arg2))
        },
        Operations::SignedDivide => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1.sdiv(arg2)));
        },
        Operations::SignedModulo => {
            let arg1 = pop_value(state, false, false);
            let arg2 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1.srem(arg2)));
        },
        Operations::Not => {
            let arg1 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(!arg1));
        },
        Operations::Increment => {
            let arg1 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 + Value::Concrete(1)));
        },
        Operations::Decrement => {
            let arg1 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1 - Value::Concrete(1)));
        },
        Operations::Equal => {
            let reg_arg = state.stack.pop().unwrap();
            let value = pop_value(state, false, false);
            do_equal(state, reg_arg, value, true, pc_index);
        },
        Operations::WeakEqual => {
            let reg_arg = state.stack.pop().unwrap();
            let value = pop_value(state, false, false);
            do_equal(state, reg_arg, value, false, pc_index);
        },
        Operations::Peek(n) => {
            // TODO: fix to allow symbolic (sort of done)
            let addr = pop_value(state, false, false);

            let len = Value::Concrete(n as u64);
            let val = state.memory.read_sym(&addr, &len);
            state.esil.current = val.clone();
            state.stack.push(StackItem::StackValue(val));

            state.esil.previous = addr;
            state.esil.last_sz = 8*n;
        },
        Operations::Poke(n) => {
            let addr = pop_value(state, false, false);
            let value = pop_value(state, false, false);
            let len = Value::Concrete(n as u64);

            if let Some(cond) = &state.condition.clone() {
                let mut prev = state.memory.read_sym(&addr, &len);
                prev = state.translate_value(&prev);
                
                state.memory.write_sym(&addr, 
                    Value::Symbolic(cond_value(cond, value, prev)), &len);
            } else {
                state.memory.write_sym(&addr, value.clone(), &len);
            }

            //state.memory.write_value(addr, value, n);
            state.esil.previous = addr;
            state.esil.last_sz = 8*n;
        },
        Operations::PokeSize => {
            let addr = pop_value(state, false, false);
            let n = (get_size(state)/8) as usize;
            let len = Value::Concrete(n as u64);
            let value = pop_value(state, false, false);

            if let Some(cond) = &state.condition.clone() {
                let mut prev = state.memory.read_sym(&addr, &len);
                prev = state.translate_value(&prev);
                
                state.memory.write_sym(&addr, 
                    Value::Symbolic(cond_value(cond, value, prev)), &len);
            } else {
                state.memory.write_sym(&addr, value.clone(), &len);
            }

            //state.memory.write_value(addr, value, n);
            state.esil.previous = addr;
            state.esil.last_sz = 8*n;
        },
        // this is a shit hack to do op pokes ~efficiently
        Operations::AddressStore => {
            let addr = pop_value(state, false, false);
            state.esil.stored_address = Some(addr.clone());
            state.stack.push(StackItem::StackValue(addr));
        },
        Operations::AddressRestore => {
            let addr = state.esil.stored_address.as_ref().unwrap();
            state.stack.push(StackItem::StackValue(addr.clone()));
            state.esil.stored_address = None;
        },
        Operations::PopCount => {
            let arg1 = pop_value(state, false, false);
            match arg1 {
                Value::Concrete(val) => {
                    let value = Value::Concrete(val.count_ones() as u64);
                    state.stack.push(StackItem::StackValue(value));
                },
                Value::Symbolic(val) => {
                    let mut sym_val = state.bvv(0, 64);
                    for i in 0..val.get_width() {
                        sym_val = sym_val.add(&val.slice(i+1, i).uext(63));
                    }
                    let value = Value::Symbolic(sym_val);
                    state.stack.push(StackItem::StackValue(value));
                }
            }
        }, // TODO for r2ghidra ESIL
        Operations::Ceiling => {
            let arg1 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(arg1.ceil()));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::Floor => {
            let arg1 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(arg1.floor()));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::Round => {
            let arg1 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(arg1.round()));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::SquareRoot => {
            let arg1 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(arg1.sqrt()));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::DoubleToInt => {
            let arg1 = pop_double(state);
            let value = Value::Concrete(arg1 as u64);
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::SignedToDouble => {
            let arg1 = pop_concrete(state, false, true);
            let value = Value::Concrete(f64::to_bits(arg1 as i64 as f64)); //hmm
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::UnsignedToDouble => {
            let arg1 = pop_concrete(state, false, false);
            let value = Value::Concrete(f64::to_bits(arg1 as f64)); 
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::FloatToDouble => {
            let arg1 = pop_float(state);
            let _size = pop_value(state, false, false);
            let value = Value::Concrete(f64::to_bits(arg1 as f64)); 
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::DoubleToFloat => {
            let arg1 = pop_double(state);
            let _size = pop_value(state, false, false);
            // these casts will need casts when i'm done with em
            let value = Value::Concrete(f32::to_bits(arg1 as f32) as u64); 
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::FloatAdd => {
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(arg1 + arg2));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::FloatSubtract => {
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(arg1 - arg2));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::FloatMultiply => {
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(arg1 * arg2));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::FloatDivide => {
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(arg1 / arg2));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::FloatCompare => {
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            let value = Value::Concrete((arg1 - arg2 == 0.0) as u64);
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::FloatLessThan => {
            let arg1 = pop_double(state);
            let arg2 = pop_double(state);
            let value = Value::Concrete((arg1 < arg2) as u64);
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::NaN => {
            let arg1 = pop_double(state);
            let value = Value::Concrete(arg1.is_nan() as u64);
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::FloatNegate => {
            let arg1 = pop_double(state);
            let value = Value::Concrete(f64::to_bits(-arg1));
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::Swap => {
            let arg1 = state.stack.pop().unwrap();
            let arg2 = state.stack.pop().unwrap();
            state.stack.push(arg1);
            state.stack.push(arg2);
        },
        Operations::Pick => {
            let n = pop_concrete(state, false, false);
            let item = state.stack[(state.stack.len()-n as usize)].clone();
            state.stack.push(item);
        },
        Operations::ReversePick => {
            let n = pop_concrete(state, false, false);
            let item = state.stack[n as usize].clone();
            state.stack.push(item.clone());
        },
        Operations::Pop => {
            state.stack.pop();
        },
        Operations::Duplicate => {
            let item = state.stack.pop().unwrap();
            state.stack.push(item.clone());
            state.stack.push(item);
        },
        Operations::Number => {
            let arg1 = pop_value(state, false, false);
            state.stack.push(StackItem::StackValue(arg1));
        },
        Operations::Clear => {
            state.stack.clear();
        },
        Operations::Break => {},
        Operations::Repeat => {},
        Operations::GoTo => {},
        Operations::ToDo => {},
        Operations::NoOperation => {},
    
        Operations::Zero => {
            let cur = state.esil.current.clone();
            let mask = Value::Concrete(genmask((state.esil.last_sz-1) as u64));
            let zf = !(cur & mask);
            state.stack.push(StackItem::StackValue(zf));
        },
        Operations::Carry => {
            let bits = pop_concrete(state, false, false);
            let mask = Value::Concrete(genmask(bits & 0x3f));
            let cur = state.esil.current.clone();
            let old = state.esil.previous.clone();

            let cf = (cur & mask.clone()).ult(old & mask);
            state.stack.push(StackItem::StackValue(cf));
        },
        Operations::Borrow => {
            let bits = pop_concrete(state, false, false);
            let mask = Value::Concrete(genmask(bits & 0x3f));
            let cur = state.esil.current.clone();
            let old = state.esil.previous.clone();

            let cf = (old & mask.clone()).ult(cur & mask);
            state.stack.push(StackItem::StackValue(cf));
        },
        Operations::Parity => {
            match &state.esil.current {
                Value::Concrete(val) => {
                    let pf = Value::Concrete(!(val.count_ones()%2) as u64);
                    state.stack.push(StackItem::StackValue(pf));
                },
                Value::Symbolic(_val) => {
                    let c1 = Value::Concrete(0x0101010101010101);
                    let c2 = Value::Concrete(0x8040201008040201);
                    let c3 = Value::Concrete(0x1ff);

                    let cur = state.esil.current.clone();
                    let lsb = cur & Value::Concrete(0xff); 
                    let pf = !((((lsb * c1) & c2) % c3) & Value::Concrete(1));
                    state.stack.push(StackItem::StackValue(pf));
                }
            }
        },
        Operations::Overflow => {
            let bits = pop_concrete(state, false, false);
            let mask1 = Value::Concrete(genmask(bits & 0x3f));
            let mask2 = Value::Concrete(genmask((bits + 0x3f) & 0x3f));

            let cur = state.esil.current.clone();
            let old = state.esil.previous.clone();

            let c_in = (cur.clone() & mask1.clone()).ult(old.clone() & mask1);
            let c_out = (cur & mask2.clone()).ult(old & mask2);
            let of = c_in ^ c_out;
            state.stack.push(StackItem::StackValue(of));
        },
        // i don't think this is used anymore
        // i added it to r2 then removed it
        Operations::SubOverflow => {
            // c_0 = z3.If(((old-cur) & m[0]) == (1<<bit), ONE, ZERO)

            let bits = pop_concrete(state, false, false);
            let mask1 = genmask(bits & 0x3f);
            let mask2 = genmask((bits + 0x3f) & 0x3f);

            match (&state.esil.current, &state.esil.previous) {
                (Value::Concrete(cur), Value::Concrete(old)) => {
                    let c0 = (((old-cur) & mask1) == (1 << bits)) as u64;
                    let c_in = ((cur & mask1) < (old & mask1)) as u64;
                    let c_out = ((cur & mask2) < (old & mask2)) as u64;
                    let of = Value::Concrete((((c0 ^ c_in) ^ c_out) == 1) as u64);
                    state.stack.push(StackItem::StackValue(of));
                },
                _ => {}
            }
        },
        Operations::S => {
            let size = pop_value(state, false, false);
            let cur = state.esil.current.clone();
            let value = (cur >> size) & Value::Concrete(1);
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::Ds => {
            let cur = state.esil.current.clone();
            let sz = Value::Concrete(state.esil.last_sz as u64);
            let ds = (cur >> sz) & Value::Concrete(1);
            state.stack.push(StackItem::StackValue(ds));
        },
        Operations::JumpTarget => {},
        Operations::Js => {},
        Operations::R => {
            let value = Value::Concrete(64 >> 3);
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::Unknown => {}
    }
}
