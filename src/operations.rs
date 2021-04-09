use crate::r2_api::R2Api;
use crate::value::Value;
use crate::state::{State, StackItem, ExecMode};
use crate::boolector::{Btor, BV};
use std::rc::Rc;
use std::f64;

pub const OPS: [&str; 16] = ["+", "-", "++", "--", "*", "/", "<<", ">>", "|", "&", "^", "%", "!", ">>>>", ">>>", "<<<"];

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
    FloatAdd,
    FloatSubtract,
    FloatMultiply,
    FloatDivide,
    NaN,
    FloatNegate,
    AddressStore, // fuck
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

pub fn op_from_str(s: &str) -> Operations {
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

pub fn pop_value(state: &mut State, set_size: bool) -> Value {
    let item = state.stack.pop().unwrap();

    match item {
        StackItem::StackValue(val) => val,
        StackItem::StackRegister(index) => {
            if set_size {
                let reg = state.registers.indexes.get(index).unwrap();
                state.esil.last_sz = reg.reg_info.size as usize;
            }
            state.registers.get_value(index)
        }
    }
}

pub fn make_bv(bv: &BV<Rc<Btor>>, val: u64, n: u32) -> BV<Rc<Btor>> {
    BV::from_u64(bv.get_btor().clone(), val, n)
}

pub fn pop_concrete(state: &mut State, set_size: bool) -> u64 {
    let value = pop_value(state, set_size);

    match value {
        Value::Concrete(val) => {
            val
        },
        Value::Symbolic(val) => {
            let solution = val.get_a_solution().as_u64().unwrap();
            let sol_bv = make_bv(&val, solution, 64);
            val._eq(&sol_bv).assert();
            solution
        }
    }
}

pub fn do_equal(state: &mut State, reg: StackItem, value: Value) {
    match reg {
        StackItem::StackRegister(index) => {
            let register = state.registers.indexes.get(index).unwrap();
            state.esil.last_sz = register.reg_info.size as usize;

            let prev = state.registers.get_value(index);
            state.registers.set_value(index, value.clone());

            state.esil.current = value;
            state.esil.previous = prev;

        },
        _ => {} // shouldn't happen
    }
}

pub fn genmask(bits: u64) -> u64 {
    if bits > 0 && bits < 64 {
        (2 << bits) - 1
    } else {
        0xffffffffffffffff
    }
}

pub fn do_operation(r2api: &mut R2Api, state: &mut State, operation: Operations) {
    match operation {
        Operations::Trap => {},
        Operations::Syscall => {},
        Operations::PcAddress => {
            let pc_reg = state.registers.aliases.get("PC").unwrap().clone();
            let pc = state.registers.get(&pc_reg.reg);
            state.stack.push(StackItem::StackValue(pc));
        },
        Operations::If => {
            let arg1 = pop_value(state, false);

            match (arg1, &state.esil.mode) {
                (Value::Concrete(val1), ExecMode::Uncon) => {
                    if val1 == 0 {
                        state.esil.mode = ExecMode::NoExec;
                    } else {
                        state.esil.mode = ExecMode::Exec;
                    }
                },
                _ => {}
            }
        },
        Operations::Else => {
            match &state.esil.mode {
                ExecMode::Exec => state.esil.mode = ExecMode::NoExec,
                ExecMode::NoExec => state.esil.mode = ExecMode::Exec,
                _ => {}
            }
        },
        Operations::EndIf => {
            state.esil.mode = ExecMode::Uncon;
        },
        Operations::Compare => {
            let arg1 = pop_value(state, true);
            let arg2 = pop_value(state, true);

            state.esil.current = arg1.clone() - arg2;
            state.esil.previous = arg1;
        },
        Operations::LessThan => {
            let arg1 = pop_value(state, true);
            let arg2 = pop_value(state, true);

            match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = Value::Concrete(
                        ((val1 as i64) < val2 as i64) as u64);

                    state.stack.push(StackItem::StackValue(val.clone()));
                    state.esil.current = val;
                    state.esil.previous = Value::Concrete(val1);
                },
                _ => {}
            }
        },
        Operations::LessThanEq => {
            let arg1 = pop_value(state, true);
            let arg2 = pop_value(state, true);

            match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = Value::Concrete(
                        ((val1 as i64) <= val2 as i64) as u64);

                    state.stack.push(StackItem::StackValue(val.clone()));
                    state.esil.current = val;
                    state.esil.previous = Value::Concrete(val1);
                },
                _ => {}
            }
        },
        Operations::GreaterThan => {
            let arg1 = pop_value(state, true);
            let arg2 = pop_value(state, true);

            match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = Value::Concrete(
                        ((val1 as i64) > val2 as i64) as u64);

                    state.stack.push(StackItem::StackValue(val.clone()));
                    state.esil.current = val;
                    state.esil.previous = Value::Concrete(val1);
                },
                _ => {}
            }
        },
        Operations::GreaterThanEq => {
            let arg1 = pop_value(state, true);
            let arg2 = pop_value(state, true);

            match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = Value::Concrete(
                        ((val1 as i64) >= val2 as i64) as u64);

                    state.stack.push(StackItem::StackValue(val.clone()));
                    state.esil.current = val;
                    state.esil.previous = Value::Concrete(val1);
                },
                _ => {}
            }
        },
        Operations::LeftShift => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);

            state.stack.push(StackItem::StackValue(arg1 << arg2));
        },
        Operations::LogicalRightShift => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);

            state.stack.push(StackItem::StackValue(arg1 >> arg2));
        },
        Operations::RightShift => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);

            /*match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = Value::Concrete(((val1 as i64) >> (val2 as i64)) as u64);
                    state.stack.push(StackItem::StackValue(val));
                    return;
                },
                _ => {}
            }*/

            // TODO: fix this
            state.stack.push(StackItem::StackValue(arg1 >> arg2));
        },
        Operations::LeftRotation => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
        },
        Operations::RightRotation => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
        },
        Operations::SignExtend => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_concrete(state, false);

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
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 & arg2))
        },
        Operations::Or => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 | arg2))
        },
        Operations::Xor => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 ^ arg2))
        },
        Operations::Add => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 + arg2))
        },
        Operations::Subtract => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 - arg2))
        },
        Operations::Multiply => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 * arg2))
        },
        // here, unlike anywhere else, long means 128 bit
        Operations::LongMultiply => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);

            match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = (val1 as u128) << (val2 as u128);
                    state.stack.push(StackItem::StackValue(
                        Value::Concrete((val >> 64) as u64)));
                    state.stack.push(StackItem::StackValue(
                        Value::Concrete(val as u64)));
                },
                _ => {}
            }
        },
        Operations::Divide => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 / arg2))
        },
        Operations::Modulo => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 % arg2))
        },
        Operations::SignedDivide => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);

            match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = Value::Concrete(((val1 as i64) / (val2 as i64)) as u64);
                    state.stack.push(StackItem::StackValue(val));
                },
                _ => {}
            }
        },
        Operations::SignedModulo => {
            let arg1 = pop_value(state, false);
            let arg2 = pop_value(state, false);

            match (arg1, arg2) {
                (Value::Concrete(val1), Value::Concrete(val2)) => {
                    let val = Value::Concrete(((val1 as i64) % (val2 as i64)) as u64);
                    state.stack.push(StackItem::StackValue(val));
                },
                _ => {}
            }
        },
        Operations::Not => {
            let arg1 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(!arg1));
        },
        Operations::Increment => {
            let arg1 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 + Value::Concrete(1)));
        },
        Operations::Decrement => {
            let arg1 = pop_value(state, false);
            state.stack.push(StackItem::StackValue(arg1 - Value::Concrete(1)));
        },
        Operations::Equal => {
            let reg_arg = state.stack.pop().unwrap();
            let value = pop_value(state, false);
            do_equal(state, reg_arg, value);
        },
        Operations::WeakEqual => {
            let reg_arg = state.stack.pop().unwrap();
            let value = pop_value(state, false);

            match reg_arg {
                StackItem::StackRegister(index) => {
                    state.registers.set_value(index, value);
                },
                _ => {} // shouldn't happen
            }
        },
        Operations::Peek(n) => {
            let arg1 = pop_value(state, false);

            match arg1 {
                Value::Concrete(addr) => {
                    let val = state.memory.read_value(r2api, addr, n);
                    state.esil.current = val.clone();
                    state.stack.push(StackItem::StackValue(val));
                },
                _ => {}
            }

            state.esil.previous = arg1;
            state.esil.last_sz = 8*n;
        },
        Operations::Poke(n) => {
            let arg1;

            if let Some(address) = &state.esil.stored_address {
                arg1 = address.clone();
                state.esil.stored_address = None;
            } else {
                arg1 = pop_value(state, false);
            }

            let arg2 = pop_value(state, false);

            match arg1 {
                Value::Concrete(addr) => {
                    state.memory.write_value(addr, arg2, n);
                },
                _ => {}
            }

            state.esil.previous = arg1;
            state.esil.last_sz = 8*n;
        },
        // this is a shit hack to do op pokes ~efficiently
        Operations::AddressStore => {
            let addr = pop_value(state, false);
            state.esil.stored_address = Some(addr.clone());
            state.stack.push(StackItem::StackValue(addr));
        },
        Operations::PopCount => {},
        Operations::Ceiling => {},
        Operations::Floor => {},
        Operations::Round => {},
        Operations::SquareRoot => {},
        Operations::DoubleToInt => {},
        Operations::SignedToDouble => {},
        Operations::UnsignedToDouble => {},
        Operations::FloatToDouble => {},
        Operations::DoubleToFloat => {},
        Operations::FloatAdd => {},
        Operations::FloatSubtract => {},
        Operations::FloatMultiply => {},
        Operations::FloatDivide => {},
        Operations::FloatCompare => {},
        Operations::NaN => {},
        Operations::FloatNegate => {},
        Operations::Swap => {
            let arg1 = state.stack.pop().unwrap();
            let arg2 = state.stack.pop().unwrap();
            state.stack.push(arg1);
            state.stack.push(arg2);
        },
        Operations::Pick => {
            let n = pop_concrete(state, false);
            let item = state.stack.get(state.stack.len()-n as usize).unwrap().clone();
            state.stack.push(item);
        },
        Operations::ReversePick => {
            let n = pop_concrete(state, false);
            let item = state.stack.get(n as usize).unwrap().clone();
            state.stack.push(item.clone());
        },
        Operations::Pop => {
            state.stack.pop();
        },
        Operations::Duplicate => {
            let item = state.stack.pop().unwrap();
            state.stack.push(item.clone());
            state.stack.push(item.clone());
        },
        Operations::Number => {
            let arg1 = pop_value(state, false);
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
            /*
                bits, = pop_values(stack, state)
                mask = genmask(bits & 0x3f)
                old = prepare(state.esil["old"])
                cur = prepare(state.esil["cur"])
                cf = z3.ULT((cur & mask), (old & mask))
                stack.append(z3.If(cf, ONE, ZERO))
            */
            let bits = pop_concrete(state, false);
            let mask = Value::Concrete(genmask(bits & 0x3f));

            /*match (&state.esil.current, &state.esil.previous) {
                (Value::Concrete(cur), Value::Concrete(old)) => {
                    let cf = Value::Concrete(((cur & mask) < (old & mask)) as u64);
                    state.stack.push(StackItem::StackValue(cf));
                },
                _ => {}
            }*/
            let cur = state.esil.current.clone();
            let old = state.esil.previous.clone();

            let cf = ((old & mask.clone()) - (cur & mask)) >> Value::Concrete(63);
            state.stack.push(StackItem::StackValue(cf));
        },
        Operations::Borrow => {
            /*
                bits, = pop_values(stack, state)
                mask = genmask(bits & 0x3f)
                old = prepare(state.esil["old"])
                cur = prepare(state.esil["cur"])
                bf = z3.ULT((old & mask), (cur & mask))
                stack.append(z3.If(bf, ONE, ZERO))
            */

            let bits = pop_concrete(state, false);
            let mask = Value::Concrete(genmask(bits & 0x3f));

            /*match (&state.esil.current, &state.esil.previous) {
                (Value::Concrete(cur), Value::Concrete(old)) => {
                    let cf = Value::Concrete(((old & mask) < (cur & mask)) as u64);
                    state.stack.push(StackItem::StackValue(cf));
                },
                _ => {}
            }*/
            let cur = state.esil.current.clone();
            let old = state.esil.previous.clone();

            let cf = ((cur & mask.clone()) - (old & mask)) >> Value::Concrete(63);
            state.stack.push(StackItem::StackValue(cf));
        },
        Operations::Parity => {
            /*
                c1 = z3.BitVecVal(0x0101010101010101, SIZE)
                c2 = z3.BitVecVal(0x8040201008040201, SIZE)
                c3 = z3.BitVecVal(0x1FF, SIZE)

                cur = prepare(state.esil["cur"])
                lsb = cur & z3.BitVecVal(0xff, SIZE)
                #pf = (((((lsb * c1) & c2) % c3) & ONE) != 1)
                pf = ((z3.URem(((lsb * c1) & c2), c3) & ONE) != ONE)
                stack.append(z3.If(pf, ONE, ZERO))
            */

            let c1: u64 = 0x0101010101010101;
            let c2: u64 = 0x8040201008040201;
            let c3: u64 = 0x1ff;

            match state.esil.current {
                Value::Concrete(cur) => {
                    let lsb = cur & 0xff; 
                    let pf = Value::Concrete(
                        (((((lsb * c1) & c2) % c3) & 1) != 1) as u64);

                    state.stack.push(StackItem::StackValue(pf));
                },
                _ => {}
            }
        },
        Operations::Overflow => {
            /*
                bit, = pop_values(stack, state)
                old = prepare(state.esil["old"])
                cur = prepare(state.esil["cur"])
                m = [genmask (bit & 0x3f), genmask ((bit + 0x3f) & 0x3f)]
                c_in = z3.If(z3.ULT((cur & m[0]), (old & m[0])), ONE, ZERO)
                c_out = z3.If(z3.ULT((cur & m[1]), (old & m[1])), ONE, ZERO)

                of = ((c_in ^ c_out) == 1)

                stack.append(z3.If(of, ONE, ZERO))
            */
            let bits = pop_concrete(state, false);
            let mask1 = genmask(bits & 0x3f);
            let mask2 = genmask((bits + 0x3f) & 0x3f);

            match (&state.esil.current, &state.esil.previous) {
                (Value::Concrete(cur), Value::Concrete(old)) => {
                    let c_in = ((cur & mask1) < (old & mask1)) as u64;
                    let c_out = ((cur & mask2) < (old & mask2)) as u64;
                    let of = Value::Concrete(((c_in ^ c_out) == 1) as u64);
                    state.stack.push(StackItem::StackValue(of));
                },
                _ => {}
            }
        },
        Operations::SubOverflow => {
            // c_0 = z3.If(((old-cur) & m[0]) == (1<<bit), ONE, ZERO)

            let bits = pop_concrete(state, false);
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
            /*
                size, = pop_values(stack, state)
                cur = prepare(state.esil["cur"])
                s = ((cur >> size) & ONE) == ONE
                stack.append(z3.If(s, ONE, ZERO))
            */

            let size = pop_value(state, false);

            /*match state.esil.current {
                Value::Concrete(cur) => {
                    let s = Value::Concrete((((cur >> size) & 1) == 1) as u64);
                    state.stack.push(StackItem::StackValue(s));
                },
                _ => {}
            }*/

            let cur = state.esil.current.clone();
            let value = (cur >> size) & Value::Concrete(1);
            state.stack.push(StackItem::StackValue(value));
        },
        Operations::Ds => {
            match state.esil.current {
                Value::Concrete(cur) => {
                    let s = Value::Concrete(
                        (((cur >> state.esil.last_sz) & 1) == 1) as u64);
                    state.stack.push(StackItem::StackValue(s));
                },
                _ => {}
            }
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
