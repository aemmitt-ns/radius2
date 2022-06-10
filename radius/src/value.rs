use crate::solver::BitVec;
use boolector::{Btor, BV};
use std::cmp::Ordering;
use std::ops;
use std::sync::Arc;

#[inline]
pub fn log2(x: u32) -> u32 {
    31 - x.leading_zeros()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Concrete(u64, u64),
    Symbolic(BitVec, u64),
}

impl Default for Value {
    fn default() -> Self {
        Value::Concrete(0, 0)
    }
}

#[inline]
pub fn make_bv(bv: &BitVec, val: u64, n: u32) -> BitVec {
    BV::from_u64(bv.get_btor(), val, n)
}

#[inline]
pub fn value_to_bv(btor: Arc<Btor>, value: Value) -> BitVec {
    match value {
        Value::Concrete(val, _t) => BV::from_u64(btor, val, 64),
        Value::Symbolic(val, _t) => val,
    }
}

#[inline]
pub fn cond_value(cond: &BitVec, v1: Value, v2: Value) -> BitVec {
    cond.cond_bv(
        &value_to_bv(cond.get_btor(), v1),
        &value_to_bv(cond.get_btor(), v2),
    )
}

macro_rules! binary_ops {
    ($self:expr, $rhs:expr, $method:ident, $op:tt) => {
        match ($self, $rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                Value::Concrete(*a $op *b, *t1 | *t2)
            },
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(a, *b, a.get_width());
                Value::Symbolic(a.$method(&bv), *t1 | *t2)
            },
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(b, *a, b.get_width());
                Value::Symbolic(bv.$method(&b), *t1 | *t2)
            },
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.$method(&b), *t1 | *t2),
                    Ordering::Greater => Value::Symbolic(a.$method(&b.uext(width_diff as u32)), *t1 | *t2),
                    Ordering::Less => Value::Symbolic(a.uext((-width_diff) as u32).$method(&b), *t1 | *t2)
                }
            }
        }
    };
}

macro_rules! wrapping_binary_ops {
    ($self:expr, $rhs:expr, $method:ident, $wrapping:ident) => {
        match ($self, $rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                Value::Concrete(a.$wrapping(*b), *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(a, *b, a.get_width());
                Value::Symbolic(a.$method(&bv), *t1 | *t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(b, *a, b.get_width());
                Value::Symbolic(bv.$method(&b), *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.$method(&b), *t1 | *t2),
                    Ordering::Greater => {
                        Value::Symbolic(a.$method(&b.uext(width_diff as u32)), *t1 | *t2)
                    }
                    Ordering::Less => {
                        Value::Symbolic(a.uext((-width_diff) as u32).$method(&b), *t1 | *t2)
                    }
                }
            }
        }
    };
}

impl ops::Add<Value> for Value {
    type Output = Value;

    #[inline]
    fn add(self, rhs: Value) -> Value {
        wrapping_binary_ops!(&self, &rhs, add, wrapping_add)
    }
}

impl ops::Sub<Value> for Value {
    type Output = Value;

    #[inline]
    fn sub(self, rhs: Value) -> Value {
        wrapping_binary_ops!(&self, &rhs, sub, wrapping_sub)
    }
}

impl ops::Mul<Value> for Value {
    type Output = Value;

    #[inline]
    fn mul(self, rhs: Value) -> Value {
        wrapping_binary_ops!(&self, &rhs, mul, wrapping_mul)
    }
}

impl ops::Div<Value> for Value {
    type Output = Value;

    #[inline]
    fn div(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                // boolector makes /0 always -1 so 
                if b != 0 {
                    Value::Concrete(a.wrapping_div(b), t1 | t2)
                } else {
                    Value::Concrete(-1i64 as u64, t1 | t2)
                }
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.udiv(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.udiv(&b), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.udiv(&b), t1 | t2),
                    Ordering::Greater => {
                        Value::Symbolic(a.udiv(&b.uext(width_diff as u32)), t1 | t2)
                    }
                    Ordering::Less => Value::Symbolic(a.uext(-width_diff as u32).udiv(&b), t1 | t2),
                }
            }
        }
    }
}

impl ops::Rem<Value> for Value {
    type Output = Value;

    #[inline]
    fn rem(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                if b != 0 {
                    Value::Concrete(a.wrapping_rem(b), t1 | t2)
                } else {
                    Value::Concrete(a, t1 | t2)
                }
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.urem(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.urem(&b), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.urem(&b), t1 | t2),
                    Ordering::Greater => {
                        Value::Symbolic(a.urem(&b.uext(width_diff as u32)), t1 | t2)
                    }
                    Ordering::Less => Value::Symbolic(a.uext(-width_diff as u32).urem(&b), t1 | t2),
                }
            }
        }
    }
}

impl ops::BitAnd<Value> for Value {
    type Output = Value;

    #[inline]
    fn bitand(self, rhs: Value) -> Value {
        binary_ops!(&self, &rhs, and, &)
    }
}

impl ops::BitOr<Value> for Value {
    type Output = Value;

    #[inline]
    fn bitor(self, rhs: Value) -> Value {
        binary_ops!(&self, &rhs, or, |)
    }
}

impl ops::BitXor<Value> for Value {
    type Output = Value;

    // ok here we could clear taint if a == b since this is used to zero regs
    // idk if this is actually a good idea or not. but something needs to be done
    // to stop wild overtainting
    #[inline]
    fn bitxor(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                Value::Concrete(a ^ b, (t1 | t2) * ((a != b || t1 != t2) as u64))
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.xor(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.xor(&b), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.xor(&b), t1 | t2),
                    Ordering::Greater => {
                        Value::Symbolic(a.xor(&b.uext(width_diff as u32)), t1 | t2)
                    }
                    Ordering::Less => Value::Symbolic(a.uext(-width_diff as u32).xor(&b), t1 | t2),
                }
            }
        }
    }
}

impl ops::Not for Value {
    type Output = Value;

    #[inline]
    fn not(self) -> Value {
        match self {
            Value::Concrete(a, t) => Value::Concrete((a == 0) as u64, t),
            Value::Symbolic(a, t) => {
                let zero = BV::zero(a.get_btor(), a.get_width());
                Value::Symbolic(a._eq(&zero).uext(a.get_width() - 1), t)
            }
        }
    }
}

impl ops::Neg for Value {
    type Output = Value;

    #[inline]
    fn neg(self) -> Value {
        match self {
            Value::Concrete(a, t) => Value::Concrete(a.wrapping_neg(), t),
            Value::Symbolic(a, t) => Value::Symbolic(a.neg(), t),
        }
    }
}

impl ops::Shl<Value> for Value {
    type Output = Value;

    #[inline]
    fn shl(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                if b > 63 {
                    Value::Concrete(0, t1 | t2)
                } else {
                    Value::Concrete(a.wrapping_shl(b as u32), t1 | t2)
                }
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, log2(a.get_width()));
                Value::Symbolic(a.sll(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, 64);
                Value::Symbolic(bv.sll(&b.slice(5, 0)), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                Value::Symbolic(a.sll(&b.slice(log2(a.get_width()) - 1, 0)), t1 | t2)
            }
        }
    }
}

impl ops::Shr<Value> for Value {
    type Output = Value;

    #[inline]
    fn shr(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                if b > 63 {
                    Value::Concrete(0, t1 | t2)
                } else {
                    Value::Concrete(a.wrapping_shr(b as u32), t1 | t2)
                }
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, log2(a.get_width()));
                //println!("{:?} {:?}", a, b);
                Value::Symbolic(a.srl(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, 64);
                Value::Symbolic(bv.srl(&b.slice(5, 0)), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                Value::Symbolic(a.srl(&b.slice(log2(a.get_width()) - 1, 0)), t1 | t2)
            }
        }
    }
}

impl Value {
    #[inline]
    pub fn sdiv(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                // boolector makes /0 always -1 so 
                if b != 0 {
                    Value::Concrete(((a as i64).wrapping_div(b as i64)) as u64, t1 | t2)
                } else {
                    Value::Concrete(-1i64 as u64, t1 | t2)
                }
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.sdiv(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.sdiv(&b), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.sdiv(&b), t1 | t2),
                    Ordering::Greater => {
                        Value::Symbolic(a.sdiv(&b.sext(width_diff as u32)), t1 | t2)
                    }
                    Ordering::Less => Value::Symbolic(a.sext(-width_diff as u32).sdiv(&b), t1 | t2),
                }
            }
        }
    }

    #[inline]
    pub fn srem(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                if b != 0 {
                    Value::Concrete(((a as i64).wrapping_rem(b as i64)) as u64, t1 | t2)
                } else {
                    Value::Concrete(a, t1 | t2)
                }
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.srem(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.srem(&b), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.srem(&b), t1 | t2),
                    Ordering::Greater => {
                        Value::Symbolic(a.srem(&b.sext(width_diff as u32)), t1 | t2)
                    }
                    Ordering::Less => Value::Symbolic(a.sext(-width_diff as u32).srem(&b), t1 | t2),
                }
            }
        }
    }

    #[inline]
    pub fn asr(self, rhs: Value, sz: u32) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                let shift = 64 - sz as i64;
                let sign_ext = ((a as i64) << shift) >> shift;
                Value::Concrete(((sign_ext as i64) >> (b as i64)) as u64, t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, log2(sz));
                Value::Symbolic(a.slice(sz - 1, 0).sra(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, sz);
                Value::Symbolic(bv.sra(&b.slice(log2(sz) - 1, 0)), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                Value::Symbolic(a.slice(sz - 1, 0).sra(&b.slice(log2(sz) - 1, 0)), t1 | t2)
            }
        }
    }

    #[inline]
    pub fn ror(self, rhs: Value, sz: u32) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                // uhhh
                let rot = (a & ((1 << sz) - 1)).rotate_right(b as u32);
                let mask = ((1 << b) - 1) << (64 - b);
                let val = rot - (rot & mask) + ((rot & mask) >> (64 - sz as u64));
                Value::Concrete(val, t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, log2(sz));
                Value::Symbolic(a.slice(sz - 1, 0).ror(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, sz);
                Value::Symbolic(bv.slice(sz - 1, 0).ror(&b.slice(log2(sz) - 1, 0)), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                Value::Symbolic(a.slice(sz - 1, 0).ror(&b.slice(log2(sz) - 1, 0)), t1 | t2)
            }
        }
    }

    #[inline]
    pub fn rol(self, rhs: Value, sz: u32) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                // uhhh
                let na = a << (64 - sz);
                let rot = na.rotate_left(b as u32);
                let mask = (1 << b) - 1;
                let val = ((rot - (rot & mask)) >> (64 - sz as u64)) + (rot & mask);
                Value::Concrete(val, t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, b, log2(sz));
                Value::Symbolic(a.slice(sz - 1, 0).rol(&bv), t1 | t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, a, sz);
                Value::Symbolic(bv.slice(sz - 1, 0).rol(&b.slice(log2(sz) - 1, 0)), t1 | t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                Value::Symbolic(a.slice(sz - 1, 0).rol(&b.slice(log2(sz) - 1, 0)), t1 | t2)
            }
        }
    }

    // get whether values are equivalent
    #[inline]
    pub fn eq(&self, rhs: &Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                Value::Concrete((*a == *b) as u64, *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(a, *b, a.get_width());
                Value::Symbolic(a._eq(&bv), *t1 | *t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(b, *a, b.get_width());
                Value::Symbolic(bv._eq(&b), *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a._eq(b), *t1 | *t2),
                    Ordering::Greater => {
                        Value::Symbolic(a._eq(&b.uext(width_diff as u32)), *t1 | *t2)
                    }
                    Ordering::Less => {
                        Value::Symbolic(b._eq(&a.uext(-width_diff as u32)), *t1 | *t2)
                    }
                }
            }
        }
    }

    // check if values are *identical*
    #[inline]
    pub fn id(&self, rhs: &Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                Value::Concrete((a == b) as u64, *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                if a.is_const() {
                    Value::Concrete((a.as_u64().unwrap() == *b) as u64, *t1 | *t2)
                } else {
                    Value::Concrete(0, *t1 | *t2)
                }
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                if b.is_const() {
                    Value::Concrete((b.as_u64().unwrap() == *a) as u64, *t1 | *t2)
                } else {
                    Value::Concrete(0, *t1 | *t2)
                }
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                Value::Concrete((a == b) as u64, *t1 | *t2)
            }
        }
    }

    #[inline]
    pub fn slt(&self, rhs: &Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                Value::Concrete(((*a as i64) < (*b as i64)) as u64, *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(a, *b, a.get_width());
                Value::Symbolic(a.slt(&bv), *t1 | *t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(b, *a, b.get_width());
                Value::Symbolic(bv.slt(&b), *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.slt(b), *t1 | *t2),
                    Ordering::Greater => {
                        Value::Symbolic(a.slt(&b.sext(width_diff as u32)), *t1 | *t2)
                    }
                    Ordering::Less => {
                        Value::Symbolic(a.uext((-width_diff) as u32).slt(b), *t1 | *t2)
                    }
                }
            }
        }
    }

    #[inline]
    pub fn slte(&self, rhs: &Value) -> Value {
        self.slt(rhs) | self.eq(rhs)
    }

    #[inline]
    pub fn sgt(&self, rhs: &Value) -> Value {
        !self.slt(rhs) & !self.eq(rhs)
    }

    #[inline]
    pub fn sgte(self, rhs: &Value) -> Value {
        !self.slt(rhs)
    }

    #[inline]
    pub fn ult(&self, rhs: &Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                Value::Concrete((*a < *b) as u64, *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                let bv = make_bv(&a, *b, a.get_width());
                Value::Symbolic(a.ult(&bv), *t1 | *t2)
            }
            (Value::Concrete(a, t1), Value::Symbolic(b, t2)) => {
                let bv = make_bv(&b, *a, b.get_width());
                Value::Symbolic(bv.ult(&b), *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Symbolic(b, t2)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                match width_diff.cmp(&0) {
                    Ordering::Equal => Value::Symbolic(a.ult(&b), *t1 | *t2),
                    Ordering::Greater => {
                        Value::Symbolic(a.ult(&b.uext(width_diff as u32)), *t1 | *t2)
                    }
                    Ordering::Less => {
                        Value::Symbolic(a.uext((-width_diff) as u32).ult(&b), *t1 | *t2)
                    }
                }
            }
        }
    }

    #[inline]
    pub fn ulte(&self, rhs: &Value) -> Value {
        self.ult(rhs) | self.eq(rhs)
    }

    #[inline]
    pub fn ugt(&self, rhs: &Value) -> Value {
        !self.ult(rhs) & !self.eq(rhs)
    }

    #[inline]
    pub fn ugte(&self, rhs: &Value) -> Value {
        !self.ult(rhs)
    }

    #[inline]
    pub fn uext(&self, rhs: &Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                Value::Concrete(a & ((1 << b) - 1), *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                //let bv = make_bv(&a, b, a.get_width());
                let bits = if *b <= 64 { *b } else { 64 };
                Value::Symbolic(a.slice(*b as u32 - 1, 0).uext(64 - bits as u32), *t1 | *t2)
            }
            (Value::Concrete(a, t), Value::Symbolic(_b, _t)) => {
                // uh hopefully this doesnt happen
                Value::Concrete(*a, *t)
            }
            (Value::Symbolic(a, t), Value::Symbolic(_b, _t)) => {
                // uh hopefully this doesnt happen
                let szdiff = 64 - a.get_width();
                Value::Symbolic(a.uext(szdiff), *t)
            }
        }
    }

    #[inline]
    pub fn sext(&self, rhs: &Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a, t1), Value::Concrete(b, t2)) => {
                let szdiff = 64 - *b as i64;
                Value::Concrete((((*a as i64) << szdiff) >> szdiff) as u64, *t1 | *t2)
            }
            (Value::Symbolic(a, t1), Value::Concrete(b, t2)) => {
                //let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.slice(*b as u32 - 1, 0).sext(64 - (*b % 64) as u32), *t1 | *t2)
            }
            (Value::Concrete(a, t), Value::Symbolic(_b, _t)) => {
                // uh hopefully this doesnt happen
                Value::Concrete(*a, *t)
            }
            (Value::Symbolic(a, t), Value::Symbolic(_b, _t)) => {
                // uh hopefully this doesnt happen
                let szdiff = 64 - a.get_width();
                Value::Symbolic(a.sext(szdiff), *t)
            }
        }
    }

    #[inline]
    pub fn slice(&self, high: u64, low: u64) -> Value {
        match self {
            Value::Concrete(a, t) => {
                let mask = if (high - low) < 63 { (1 << (high - low + 1)) - 1 } else { -1i64 as u64 };
                Value::Concrete((*a >> low) & mask, *t)
            }
            Value::Symbolic(a, t) => Value::Symbolic(a.slice(high as u32, low as u32), *t),
        }
    }

    #[inline]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Concrete(a, _t) => Some(*a),
            Value::Symbolic(a, _t) => a.as_u64(),
        }
    }

    /// tries to convert to Concrete
    #[inline]
    pub fn try_con(&self) -> Self {
        match self {
            Value::Concrete(_a, _t) => self.to_owned(),
            Value::Symbolic(a, t) => {
                if let Some(v) = a.as_u64() {
                    Value::Concrete(v, *t)
                } else {
                    self.to_owned()
                }
            }
        }
    }

    #[inline]
    pub fn as_bv(&self) -> Option<BitVec> {
        match self {
            Value::Concrete(_a, _t) => None,
            Value::Symbolic(a, _t) => Some(a.to_owned()),
        }
    }

    #[inline]
    pub fn get_taint(&self) -> u64 {
        match self {
            Value::Concrete(_a, t) => *t,
            Value::Symbolic(_a, t) => *t,
        }
    }

    #[inline]
    pub fn with_taint(&self, taint: u64) -> Value {
        match self {
            Value::Concrete(a, t) => Value::Concrete(*a, *t | taint),
            Value::Symbolic(a, t) => Value::Symbolic(a.to_owned(), *t | taint),
        }
    }

    pub fn depends(&self, rhs: &Value) -> bool {
        match rhs {
            Value::Concrete(_a, t1) => self.get_taint() & *t1 != 0,
            Value::Symbolic(abv, t1) => match self {
                Value::Concrete(_b, t2) => *t1 & *t2 != 0,
                Value::Symbolic(bbv, t2) => {
                    let mut tainted = false;
                    if let Some(sym) = abv.get_symbol() {
                        tainted = format!("{:?}", bbv).contains(sym);
                    }
                    tainted || (*t1 & *t2 != 0)
                }
            },
        }
    }

    #[inline]
    pub fn is_concrete(&self) -> bool {
        matches!(self, Value::Concrete(_, _))
    }

    #[inline]
    pub fn is_symbolic(&self) -> bool {
        matches!(self, Value::Symbolic(_, _))
    }

    #[inline]
    pub fn add(&self, rhs: &Value) -> Value {
        wrapping_binary_ops!(self, rhs, add, wrapping_add)
    }

    #[inline]
    pub fn sub(&self, rhs: &Value) -> Value {
        wrapping_binary_ops!(self, rhs, sub, wrapping_sub)
    }

    #[inline]
    pub fn mul(&self, rhs: &Value) -> Value {
        wrapping_binary_ops!(self, rhs, mul, wrapping_mul)
    }

    #[inline]
    pub fn div(&self, rhs: &Value) -> Value {
        wrapping_binary_ops!(self, rhs, udiv, wrapping_div)
    }

    #[inline]
    pub fn rem(&self, rhs: &Value) -> Value {
        wrapping_binary_ops!(self, rhs, urem, wrapping_rem)
    }

    #[inline]
    pub fn and(&self, rhs: &Value) -> Value {
        binary_ops!(self, rhs, and, &)
    }

    #[inline]
    pub fn or(&self, rhs: &Value) -> Value {
        binary_ops!(self, rhs, or, |)
    }

    #[inline]
    pub fn xor(&self, rhs: &Value) -> Value {
        binary_ops!(self, rhs, xor, ^)
    }

    #[inline]
    pub fn size(&self) -> u32 {
        match self {
            Value::Concrete(_a, _t) => 64,
            Value::Symbolic(a, _t) => a.get_width(),
        }
    }
}

/// convenience method for making an untainted `Value::Concrete`
#[inline]
pub fn vc(v: u64) -> Value {
    Value::Concrete(v, 0)
}

/// convert strings into vecs of values
#[inline]
pub fn byte_values<T: AsRef<str>>(string: T) -> Vec<Value> {
    string.as_ref().chars().map(|c| vc(c as u64)).collect()
}
