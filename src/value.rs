
use boolector::{Btor, BV};
use std::rc::Rc;
use std::ops;

#[derive(Debug, Clone)]
pub enum Value {
    Concrete(u64),
    Symbolic(BV<Rc<Btor>>)
}

pub fn make_bv(bv: &BV<Rc<Btor>>, val: u64, n: u32) -> BV<Rc<Btor>> {
    BV::from_u64(bv.get_btor().clone(), val, n)
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
                Value::Symbolic(b.sub(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.sub(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.sub(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.sub(&a.uext(-width_diff as u32)))
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
                Value::Symbolic(b.udiv(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.udiv(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.udiv(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.udiv(&a.uext(-width_diff as u32)))
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
                Value::Symbolic(b.urem(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.urem(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.urem(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.urem(&a.uext(-width_diff as u32)))
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
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.sll(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(b.sll(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.sll(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.sll(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.sll(&a.uext(-width_diff as u32)))
                }
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
                let bv = make_bv(&a, b, a.get_width());
                Value::Symbolic(a.srl(&bv))
            },
            (Value::Concrete(a), Value::Symbolic(b)) => {
                let bv = make_bv(&b, a, b.get_width());
                Value::Symbolic(b.srl(&bv))
            },
            (Value::Symbolic(a), Value::Symbolic(b)) => {
                let width_diff = a.get_width() as i32 - b.get_width() as i32;
                if width_diff == 0 {
                    Value::Symbolic(a.srl(&b))
                } else if width_diff > 0 {
                    Value::Symbolic(a.srl(&b.uext(width_diff as u32)))
                } else {
                    Value::Symbolic(b.srl(&a.uext(-width_diff as u32)))
                }
            }
        }
    }
}
