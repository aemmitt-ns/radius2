
use boolector::{Btor, BV};
use std::rc::Rc;
use std::ops;

pub const LOG: [u32; 65] = [0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6];

#[derive(Debug, Clone)]
pub enum Value {
    Concrete(u64),
    Symbolic(BV<Rc<Btor>>)
}

pub fn make_bv(bv: &BV<Rc<Btor>>, val: u64, n: u32) -> BV<Rc<Btor>> {
    BV::from_u64(bv.get_btor().clone(), val, n)
}

pub fn value_to_bv(btor: Rc<Btor>, value: Value) -> BV<Rc<Btor>> {
    match value {
        Value::Concrete(val) => {
            BV::from_u64(btor.clone(), val, 64)
        },
        Value::Symbolic(val) => val 
    }
}

pub fn cond_value(cond: &BV<Rc<Btor>>, v1: Value, v2: Value) -> BV<Rc<Btor>> {
    cond.cond_bv(
        &value_to_bv(cond.get_btor().clone(), v1), 
        &value_to_bv(cond.get_btor().clone(), v2)
    )
}

impl ops::Add<Value> for Value {
    type Output = Value;

    fn add(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a + b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.add(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(b.add(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.add(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.add(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.add(&a.uext(-width_diff as u32)))
                }
            }
        }
    }
}

impl ops::Sub<Value> for Value {
    type Output = Value;

    fn sub(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a - b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.sub(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.sub(&b))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.sub(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.sub(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(a.uext(-width_diff as u32).sub(&b))
                }
            }
        }
    }
}

impl ops::Mul<Value> for Value {
    type Output = Value;

    fn mul(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a * b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.mul(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(b.mul(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.mul(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.mul(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.mul(&a.uext(-width_diff as u32)))
                }
            }
        }
    }
}

impl ops::Div<Value> for Value {
    type Output = Value;

    fn div(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a / b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.udiv(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.udiv(&b))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.udiv(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.udiv(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(a.uext(-width_diff as u32).udiv(&b))
                }
            }
        }
    }
}

impl ops::Rem<Value> for Value {
    type Output = Value;

    fn rem(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a % b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.urem(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.urem(&b))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.urem(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.urem(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(a.uext(-width_diff as u32).urem(&b))
                }
            }
        }
    }
}

impl ops::BitAnd<Value> for Value {
    type Output = Value;

    fn bitand(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a & b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.and(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(b.and(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.and(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.and(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.and(&a.uext(-width_diff as u32)))
                }
            }
        }
    }
}

impl ops::BitOr<Value> for Value {
    type Output = Value;

    fn bitor(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a | b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.or(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(b.or(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.or(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.or(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.or(&a.uext(-width_diff as u32)))
                }
            }
        }
    }
}

impl ops::BitXor<Value> for Value {
    type Output = Value;

    fn bitxor(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a ^ b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.xor(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(b.xor(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.xor(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.xor(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.xor(&a.uext(-width_diff as u32)))
                }
            }
        }
    }
}

impl ops::Not for Value {
    type Output = Value;

    fn not(self) -> Value {
        match self {
            Value::Concrete(a) => {
                Value::Concrete((a == 0) as u64)
            },
            Value::Symbolic(a) => {
                let zero = BV::zero(a.get_btor().clone(), a.get_width());
                Value::Symbolic(a._eq(&zero).uext(a.get_width()-1))
            }
        }
    }
}

impl ops::Shl<Value> for Value {
    type Output = Value;

    fn shl(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a << b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, LOG[a.get_width() as usize]);
                Value::Symbolic(a.sll(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, 64);
                Value::Symbolic(bv.sll(&b.slice(5, 0)))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                Value::Symbolic(a.sll(&b.slice(LOG[a.get_width() as usize]-1, 0)))
            }
        }
    }
}

impl ops::Shr<Value> for Value {
    type Output = Value;

    fn shr(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a >> b)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, LOG[a.get_width() as usize]);
                //println!("{:?} {:?}", a, b);
                Value::Symbolic(a.srl(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, 64);
                Value::Symbolic(bv.srl(&b.slice(5, 0)))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                Value::Symbolic(a.srl(&b.slice(LOG[a.get_width() as usize]-1, 0)))
            }
        }
    }
}

impl Value {
    pub fn sdiv(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(((a as i64) / (b as i64)) as u64)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.sdiv(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.sdiv(&b))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.sdiv(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.sdiv(&b.sext(width_diff as u32)))
                } else {
                    Value::Symbolic(a.sext(-width_diff as u32).sdiv(&b))
                }
            }
        }
    }

    pub fn srem(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(((a as i64) % (b as i64)) as u64)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.srem(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.srem(&b))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.srem(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.srem(&b.sext(width_diff as u32)))
                } else {
                    Value::Symbolic(a.sext(-width_diff as u32).srem(&b))
                }
            }
        }
    }

    pub fn asr(self, rhs: Value, sz: u32) -> Value {
        //println!("{:?}, {:?}", rhs, sz);
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                let shift = 64 - sz as i64;
                let sign_ext = ((a as i64) << shift) >> shift;
                Value::Concrete(((sign_ext as i64) >> (b as i64)) as u64)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, LOG[a.get_width() as usize]);
                Value::Symbolic(a.slice(sz-1, 0).sra(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, 64);
                Value::Symbolic(bv.slice(sz-1, 0).sra(&b.slice(5, 0)))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                Value::Symbolic(a.slice(sz-1, 0).sra(&b.slice(LOG[sz as usize]-1, 0)))
            }
        }
    }

    pub fn ror(self, rhs: Value, sz: u32) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                // uhhh
                let rot = (a & ((1 << sz)-1)).rotate_right(b as u32);
                let mask = ((1 << b)-1) << (64 - b);
                let val = rot - (rot & mask) + ((rot & mask) >> (64 - sz as u64));
                Value::Concrete(val)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, LOG[sz as usize]);
                Value::Symbolic(a.slice(sz-1, 0).ror(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, sz);
                Value::Symbolic(bv.slice(sz-1, 0).ror(&b.slice(LOG[sz as usize]-1, 0)))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                Value::Symbolic(a.slice(sz-1, 0).ror(&b.slice(LOG[sz as usize]-1, 0)))
            }
        }
    }

    pub fn rol(self, rhs: Value, sz: u32) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                // uhhh
                let na = a << (64 - sz);
                let rot = na.rotate_left(b as u32);
                let mask = (1 << b)-1;
                let val = ((rot - (rot & mask)) >> (64 - sz as u64)) + (rot & mask);
                Value::Concrete(val)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, LOG[sz as usize]);
                Value::Symbolic(a.slice(sz-1, 0).rol(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, sz);
                Value::Symbolic(bv.slice(sz-1, 0).rol(&b.slice(LOG[sz as usize]-1, 0)))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                Value::Symbolic(a.slice(sz-1, 0).rol(&b.slice(LOG[sz as usize]-1, 0)))
            }
        }
    }

    pub fn eq(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete((a == b) as u64)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a._eq(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv._eq(&b))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a._eq(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a._eq(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b._eq(&a.uext(-width_diff as u32)))
                }
            }
        }
    }

    pub fn slt(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(((a as i64) < (b as i64)) as u64)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.slt(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.slt(&b))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.slt(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.slt(&b.sext(width_diff as u32)))
                } else {
                    Value::Symbolic(a.uext(-width_diff as u32).slt(&b))
                }
            }
        }
    }

    pub fn ult(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete((a < b) as u64)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.ult(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(bv.ult(&b))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.ult(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.ult(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(a.uext(-width_diff as u32).ult(&b))
                }
            }
        }
    }

    pub fn uext(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(a & ((1 << b) - 1))
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                //let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.slice(b as u32 - 1, 0).uext(64 - b as u32))
            },
            (Value::Concrete(a), Value::Symbolic(_b)) => {
                // uh hopefully this doesnt happen
                Value::Concrete(a)
            },
            (Value::Symbolic(a), Value::Symbolic(_b)) => {
                // uh hopefully this doesnt happen
                let szdiff = 64 - a.get_width();
                Value::Symbolic(a.uext(szdiff))
            }
        }
    }

    pub fn sext(self, rhs: Value) -> Value {
        match (self, rhs) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                let szdiff = 64 - b as i64;
                Value::Concrete((((a as i64) << szdiff) >> szdiff) as u64)
            },
            (Value::Symbolic(a), Value::Concrete(b)) => {
                //let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.slice(b as u32 - 1, 0).sext(64 - b as u32))
            },
            (Value::Concrete(a), Value::Symbolic(_b)) => {
                // uh hopefully this doesnt happen
                Value::Concrete(a)
            },
            (Value::Symbolic(a), Value::Symbolic(_b)) => {
                // uh hopefully this doesnt happen
                let szdiff = 64 - a.get_width();
                Value::Symbolic(a.sext(szdiff))
            }
        }
    }

    /*pub fn uext(self, bits: u64) -> Value {
        match self {
            Value::Concrete(a) => {
                Value::Concrete(a)
            },
            Value::Symbolic(a) => {
                Value::Symbolic(b.rol(&a.uext(-width_diff as u32)))
            }
        }
    }*/
}