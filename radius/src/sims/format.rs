use crate::state::State;
use crate::value::{vc, Value};

const MAXLEN: usize = 8192;
const FORMATS: [char; 19] = [
    'd', 'i', 'u', 'o', 'x', 'X', 'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A', 'c', 's', 'p', 'n', '%',
];

const UINTS: [char; 4] = ['u', 'o', 'x', 'X'];
const NONUINTS: [char; 15] = [
    'd', 'i', 'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A', 'c', 's', 'n', '%', 'p',
];

// the value returned is the formatted string
pub fn format(state: &mut State, args: &[Value]) -> Vec<Value> {
    let length = state.memory_strlen(&args[0], &vc(MAXLEN as u64));
    let mut formatstr = state.memory_read(&args[0], &length);
    let mut result = Vec::with_capacity(MAXLEN);

    let mut count = 0;
    let mut ind = 0; // argument index
    while !formatstr.is_empty() {
        let c = formatstr.remove(0);
        if !formatstr.is_empty() && state.check(&c.eq(&vc('%' as u64))) {
            if formatstr[0].as_u64() != Some('%' as u64) {
                ind += 1; // jank fix cuz %% shouldnt increment
            }
            // if it can be % it *must* be %
            state.assert(&c.eq(&vc('%' as u64)));
            let formatted = format_one(state, &mut formatstr, &args[ind], count);
            count += formatted.len();
            result.extend(formatted);
        } else {
            result.push(c);
            count += 1
        }
    }
    result.push(vc(0));
    result
}

// get list of possible formats, we will let uints stay symbolic
pub fn may_be_formats(state: &mut State, c: &Value) -> Vec<char> {
    let mut formats = Vec::with_capacity(8);
    for f in FORMATS.iter() {
        if state.check(&c.eq(&vc(*f as u64))) {
            formats.push(*f);
        }
    }
    formats
}

// c must be in the resulting formats
pub fn must_be_formats(state: &mut State, c: &Value, formats: &[char]) {
    if !c.is_concrete() {
        let mut asserts = vec![];
        for f in formats.iter() {
            asserts.push(state.solver.to_bv(&c.eq(&vc(*f as u64)), 1));
        }
        state.assert_bv(&state.solver.or_all(&asserts));
    }
}

// do one format string, "%10s", "%03x", etc
// count is just for %n
pub fn format_one(
    state: &mut State,
    formatstr: &mut Vec<Value>,
    arg: &Value,
    count: usize,
) -> Vec<Value> {
    let mut preformat = Vec::with_capacity(64); // eg the 08 in %08x, ignore for now
    let mut result = Vec::with_capacity(MAXLEN);

    while !formatstr.is_empty() {
        let c = formatstr.remove(0);
        let formats = may_be_formats(state, &c);

        if !formats.is_empty() {
            let preformat_str = if preformat.is_empty() {
                "".to_owned()
            } else {
                let preformat_val = state.memory.pack(&preformat);
                let preformat_bv = state
                    .solver
                    .to_bv(&preformat_val, 8 * preformat.len() as u32);
                state.evaluate_string_bv(&preformat_bv).unwrap_or_default()
            };

            let maybe_uint = formats.iter().any(|f| UINTS.contains(f));

            if maybe_uint {
                // ensure that it *is* a uint format
                must_be_formats(state, &c, &UINTS);
                result.extend(format_uint(state, &c, arg, &preformat_str));
            } else {
                must_be_formats(state, &c, &NONUINTS);
                let cl = tolower(state, &[c.clone()]);
                let cc = state.solver.evalcon_to_u64(&cl).unwrap_or(0) as u8;

                match cc as char {
                    'c' => result.push(arg.and(&vc(0xff))),
                    'p' => result.extend(format_uint(state, &c, arg, &preformat_str)),
                    'd' | 'i' => result.extend(format_int(state, &c, arg, &preformat_str)),
                    'f' | 'e' | 'g' | 'a' => result.extend(format_float(state, &c, arg)),
                    's' => result.extend(format_string(state, &c, arg, &preformat_str)),
                    'n' => state.memory_write_value(arg, &vc(count as u64), 32),
                    '%' => result.push(vc('%' as u64)),
                    _ => {}
                }
            }

            // capitalize letters if format is uppercase (X, F, G etc)
            let up = isupper(state, &[c]);
            if up.as_u64() != Some(0) {
                for i in 0..result.len() {
                    let upper = toupper(state, &[result[i].clone()]);
                    result[i] = state.cond(&up, &upper, &result[i]);
                }
            }

            break;
        } else {
            preformat.push(c);
        }
    }
    result
}

fn format_to_base(state: &mut State, c: &Value) -> Value {
    let f = tolower(state, &[c.to_owned()]); // X -> x
    let mut base = vc(10); // default to 10
    base = state.cond(&f.eq(&vc('x' as u64)), &vc(16), &base);
    base = state.cond(&f.eq(&vc('p' as u64)), &vc(16), &base);
    state.cond(&f.eq(&vc('o' as u64)), &vc(8), &base)
}

fn format_uint(state: &mut State, c: &Value, arg: &Value, pre: &str) -> Vec<Value> {
    let base = format_to_base(state, c);
    let temp = vc(state.memory.alloc(&vc(MAXLEN as u64)));
    itoa_helper(state, arg, &temp, &base, false, 32);
    let length = state.memory_strlen(&temp, &vc(MAXLEN as u64));
    let mut result = state.memory_read(&temp, &length);
    state.memory.free(&temp); // like it never happened

    let padding = pre.parse::<usize>().unwrap_or(0);
    if result.len() < padding {
        let extra = padding - result.len();
        let pad = if pre.starts_with("0") {
            vec![vc('0' as u64); extra]
        } else {
            vec![vc(' ' as u64); extra]
        };
        result = [pad, result].concat();
    }

    result
}

fn format_int(state: &mut State, _c: &Value, arg: &Value, pre: &str) -> Vec<Value> {
    // this is a bit jank, i should redo how itoa_helper works
    let temp = vc(state.memory.alloc(&vc(MAXLEN as u64)));
    itoa_helper(state, arg, &temp, &vc(10), true, 64);
    let length = state.memory_strlen(&temp, &vc(MAXLEN as u64));
    let mut result = state.memory_read(&temp, &length);
    state.memory.free(&temp); // like it never happened

    let padding = pre.parse::<usize>().unwrap_or(0);
    if result.len() < padding {
        let extra = padding - result.len();
        let pad = if pre.starts_with("0") {
            vec![vc('0' as u64); extra]
        } else {
            vec![vc(' ' as u64); extra]
        };
        result = [pad, result].concat();
    }

    result
}

fn format_float(state: &mut State, _c: &Value, arg: &Value) -> Vec<Value> {
    let f = f32::from_bits(state.solver.evalcon_to_u64(arg).unwrap_or_default() as u32);
    format!("{:e}", f).chars().map(|c| vc(c as u64)).collect() // jank
}

fn format_string(state: &mut State, _c: &Value, arg: &Value, pre: &str) -> Vec<Value> {
    let length = state.memory_strlen(arg, &vc(MAXLEN as u64));
    let mut result = state.memory_read(arg, &length);

    let padding = pre.parse::<usize>().unwrap_or(0);
    if result.len() < padding {
        let extra = padding - result.len();
        let pad = vec![vc(' ' as u64); extra];
        result = [pad, result].concat();
    }
    result
}

pub fn scan(state: &mut State, args: &[Value]) -> Value {
    let flength = state.memory_strlen(&args[1], &vc(MAXLEN as u64));
    let mut formatstr = state.memory_read(&args[1], &(flength + vc(1)));
    let mut data = args[0].to_owned();

    let mut count = 0;
    let mut ind = 1; // argument index
    while !formatstr.is_empty() {
        let c = formatstr.remove(0);
        if !formatstr.is_empty() && state.check(&c.eq(&vc('%' as u64))) {
            if formatstr[0].as_u64() != Some('%' as u64) {
                ind += 1; // jank fix cuz %% shouldnt increment
            }
            // if it can be % it *must* be %
            state.assert(&c.eq(&vc('%' as u64)));
            scan_one(state, &mut formatstr, &args[ind], &mut data);
            count += 1;
        } else {
            data = data + vc(1);
        }
    }

    vc(count as u64)
}

pub fn scan_one(state: &mut State, formatstr: &mut Vec<Value>, arg: &Value, data: &mut Value) {
    let mut preformat = Vec::with_capacity(64); // eg the 08 in %08x, ignore for no

    while !formatstr.is_empty() {
        let c = formatstr.remove(0);
        let formats = may_be_formats(state, &c);

        if !formats.is_empty() {
            let preformat_str = if preformat.is_empty() {
                "".to_owned()
            } else {
                let preformat_val = state.memory.pack(&preformat);
                let preformat_bv = state
                    .solver
                    .to_bv(&preformat_val, 8 * preformat.len() as u32);
                state.evaluate_string_bv(&preformat_bv).unwrap_or_default()
            };
            let maybe_uint = formats.iter().any(|f| UINTS.contains(f));
            let next = formatstr.remove(0); // get delimiter maybe?
            let delim = state.memory_search(data, &next, &vc(MAXLEN as u64), false);
            state.memory_write_value(&delim, &vc(0), 1); // write a null there

            if maybe_uint {
                // ensure that it *is* a uint format
                must_be_formats(state, &c, &UINTS);
                scan_uint(state, &c, arg, data);
            } else {
                must_be_formats(state, &c, &NONUINTS);
                let cl = tolower(state, &[c]);
                let cc = state.solver.evalcon_to_u64(&cl).unwrap_or(0) as u8;

                match cc as char {
                    'c' => state.memory_write_value(arg, data, 1),
                    'p' => scan_uint(state, &vc(cc as u64), arg, data),
                    'd' | 'i' => scan_int(state, arg, data),
                    'f' | 'e' | 'g' | 'a' => scan_float(state, arg, data),
                    's' => scan_string(state, arg, data, &preformat_str),
                    _ => {}
                }
            }
            break;
        } else {
            preformat.push(c);
        }
    }
}

pub fn scan_uint(state: &mut State, c: &Value, arg: &Value, data: &mut Value) {
    let base = format_to_base(state, c);
    let value = atoi_helper(state, data, &base, 32); // TODO need to fix size for p, llx etc
    state.memory_write_value(arg, &value, 4);
    *data = data.add(&state.memory_strlen(data, &vc(MAXLEN as u64))) + vc(1);
}

pub fn scan_int(state: &mut State, arg: &Value, data: &mut Value) {
    let value = atoi_helper(state, data, &vc(10), 32); // TODO need to fix size for p, llx etc
    state.memory_write_value(arg, &value, 4);
    *data = data.add(&state.memory_strlen(data, &vc(MAXLEN as u64))) + vc(1);
}

pub fn scan_float(state: &mut State, arg: &Value, data: &mut Value) {
    let addr = state.solver.evalcon_to_u64(data).unwrap_or_default();
    let fs = state.memory_read_cstring(addr);
    let f = fs.parse::<f32>().unwrap_or_default();
    state.memory_write_value(arg, &vc(f32::to_bits(f) as u64), 4);
    *data = data.add(&state.memory_strlen(data, &vc(MAXLEN as u64))) + vc(1);
}

pub fn scan_string(state: &mut State, arg: &Value, data: &mut Value, pre: &str) {
    let limit = pre.parse::<u64>().unwrap_or(MAXLEN as u64);
    let length = state.memory_strlen(data, &vc(limit)) + vc(1);
    state.memory_move(arg, data, &length);
    *data = data.add(&length);
}

fn bv_pow(bv: &Value, exp: u32) -> Value {
    let mut result = vc(1);
    for _ in 0..exp {
        result = result * bv.clone();
    }
    result
}

// is digit
#[inline]
fn isdig(c: &Value) -> Value {
    c.ult(&vc(0x3a)) & !c.ult(&vc(0x30))
}

// is valid digit of base
fn isbasedigit(state: &State, c: &Value, base: &Value) -> Value {
    state.cond(
        &base.ult(&vc(11)),
        &(c.ult(&(vc('0' as u64) + base.clone())) & !c.ult(&vc('0' as u64))),
        &(isdig(c)
            | (c.ult(&(vc('a' as u64) + base.sub(&vc(10)))) & !c.ult(&vc('a' as u64)))
            | (c.ult(&(vc('A' as u64) + base.sub(&vc(10)))) & !c.ult(&vc('A' as u64)))),
    )
}

fn tonum(state: &State, c: &Value) -> Value {
    let alpha = state.cond(
        &c.ulte(&vc('Z' as u64)),
        &c.sub(&vc('A' as u64 - 10)),
        &c.sub(&vc('a' as u64 - 10)),
    );

    state
        .solver
        .conditional(&c.ulte(&vc('9' as u64)), &c.sub(&vc('0' as u64)), &alpha)
}

fn atoi_concrete(state: &mut State, addr: &Value, base: &Value, len: usize) -> Value {
    // TODO fix this to not use string because 123\xff will be 0 right now
    let numstr = state.memory_read_string(addr.as_u64().unwrap(), len);
    let numstr = numstr.trim_start(); // trim whitespace

    if numstr.len() == 0 {
        return vc(0);
    }

    let start = if numstr.len() > 1 && &numstr[0..2] == "0x" {
        2
    } else {
        0
    }; // offset
    let end = if let Some(n) = numstr[start + 1..]
        .chars()
        .position(|c| isbasedigit(state, &vc(c as u64), base).as_u64().unwrap() != 1)
    {
        start + n + 1
    } else {
        len
    }; // oof

    let numopt = u64::from_str_radix(&numstr[start..end], base.as_u64().unwrap() as u32);
    numopt.map(vc).unwrap_or_default()
}

/*
 * From SO
 * atoi reads digits from the buffer until it can't any more. It stops when it
 * encounters any character that isn't a digit, except whitespace (which it skips)
 * or a '+' or a '-' before it has seen any digits (which it uses to select the
 * appropriate sign for the result). It returns 0 if it saw no digits.
 */

// for now and maybe forever this only works for strings that
// don't have garbage in them. so only strings with digits or +/-
pub fn atoi_helper(state: &mut State, addr: &Value, base: &Value, size: u64) -> Value {
    let length = state.memory_strlen(&addr, &Value::Concrete(64, 0));
    let data = state.memory_read(addr, &length);
    let len = data.len();

    state.assert(&length.eq(&vc(len as u64)));
    if len == 0 {
        return Value::Concrete(0, 0);
    }

    // gonna take the easy way out and special case out all concrete
    if addr.is_concrete() && base.is_concrete() && data.iter().all(|x| x.is_concrete()) {
        return atoi_concrete(state, addr, base, len);
    }

    let mut result = Value::Concrete(0, 0);

    // multiplier for negative nums
    let neg_mul = state.cond(
        &data[0].eq(&vc('-' as u64)),
        &Value::Concrete(-1i64 as u64, 0),
        &Value::Concrete(1, 0),
    );

    for (i, d) in data.iter().enumerate() {
        let dx = d.uext(&vc(8));
        let exp = (len - i - 1) as u32;

        // digit or + / -
        let cond = if i == 0 {
            isbasedigit(state, &dx, base) | dx.eq(&vc('-' as u64)) | dx.eq(&vc('+' as u64))
        } else {
            isbasedigit(state, &dx, base)
        };
        state.assert(&cond);

        // add d*10**n to result
        result = result
            + state.cond(
                &!isbasedigit(state, &dx, base),
                &vc(0),
                &(bv_pow(base, exp) * tonum(state, &dx)),
            );
    }
    // this assertion is much faster than slicing dx
    if size < 64 {
        let mask = (1i64.wrapping_shl(size as u32) - 1) as u64 ;
        state.assert(&result.ulte(&Value::Concrete(mask, 0)));
    }

    result * neg_mul
}

pub fn itoa_concrete(
    state: &mut State,
    value: &Value,
    string: &Value,
    base: &Value,
    sign: bool,
    size: usize,
) -> Value {
    let sz = size as u64;
    if let Value::Concrete(v, t) = value {
        let mut masked = v & ((1 << sz) - 1);
        if sign && sz < 64 {
            masked = (((masked as i64) << (64 - sz)) >> sz) as u64;
        }
        let vstr = match (base.as_u64().unwrap(), sign) {
            (2, _) => format!("{:b}", masked),
            (8, _) => format!("{:o}", masked),
            (16, _) => format!("{:x}", masked),
            (_, false) => format!("{}", masked),
            (_, true) => format!("{}", masked as i64),
        };
        let mut data: Vec<Value> = vstr
            .chars()
            .map(|c| Value::Concrete(c as u64, *t))
            .collect();

        data.push(vc(0));
        state.memory_write(string, &data, &vc(data.len() as u64));
    }
    string.to_owned()
}

pub fn itoa_helper(
    state: &mut State,
    value: &Value,
    string: &Value,
    base: &Value,
    sign: bool,
    size: usize,
) -> Value {

    if value.is_concrete() && base.is_concrete() {
        return itoa_concrete(state, value, string, base, sign, size);
    }

    let mut data = Vec::with_capacity(size);

    // condition to add a minus sign -
    let neg_cond = &(value.slt(&vc(0)) & base.eq(&vc(10)) & vc(sign as u64));

    let uval = state
        .solver
        .conditional(neg_cond, &value.mul(&vc(-1i64 as u64)), value);

    let uval = Value::Symbolic(state.solver.to_bv(&uval, 128), 0);
    let ubase = Value::Symbolic(state.solver.to_bv(base, 128), 0);
    let mut shift = Value::Symbolic(state.solver.bvv(0, 64), 0);

    for i in 0..size as u32 {
        let dx = uval.rem(&bv_pow(&ubase, i + 1)).div(&bv_pow(&ubase, i));

        // shift that will be applied to remove 00000...
        shift = state
            .solver
            .conditional(&!dx.clone(), &shift.add(&vc(8)), &vc(0));

        data.push(state.cond(
            &dx.ult(&vc(10)),
            &dx.add(&vc('0' as u64)),
            &dx.sub(&vc(10)).add(&vc('a' as u64)),
        ));
    }

    data.reverse();

    let bv = state.memory.pack(&data).as_bv().unwrap();
    let shift_bits = 31 - bv.get_width().leading_zeros(); // log2(n)
    let bv = bv.srl(&shift.as_bv().unwrap().slice(shift_bits - 1, 0));
    let mut new_addr = string.clone();

    if sign {
        let b = state
            .solver
            .conditional(neg_cond, &vc('-' as u64), &vc('+' as u64));

        state.memory_write_value(string, &b, 1);

        // if we add a minus, write number to addr+1
        new_addr = state
            .solver
            .conditional(neg_cond, &(new_addr.clone() + vc(1)), &new_addr);
    }
    state.memory_write_value(&new_addr, &Value::Symbolic(bv, 0), data.len());
    state.memory_write_value(&new_addr.add(&vc(data.len() as u64)), &vc(0), 8);

    string.to_owned()
}

pub fn islower(_state: &mut State, args: &[Value]) -> Value {
    let c = args[0].slice(7, 0);
    c.ult(&Value::Concrete(0x7b, 0)) & !c.ult(&Value::Concrete(0x61, 0))
}

pub fn isupper(_state: &mut State, args: &[Value]) -> Value {
    let c = args[0].slice(7, 0);
    c.ult(&Value::Concrete(0x5b, 0)) & !c.ult(&Value::Concrete(0x41, 0))
}

pub fn toupper(state: &mut State, args: &[Value]) -> Value {
    let islo = islower(state, args);
    state
        .solver
        .conditional(&islo, &args[0].sub(&vc(0x20)), &args[0])
}

pub fn tolower(state: &mut State, args: &[Value]) -> Value {
    let isup = isupper(state, args);
    state
        .solver
        .conditional(&isup, &args[0].add(&vc(0x20)), &args[0])
}
