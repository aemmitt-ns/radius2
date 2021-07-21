use crate::value::Value;
use boolector::{Btor, BV, SolverResult};
use boolector::option::{BtorOption, ModelGen, NumberFormat};
use std::sync::Arc;

const EVAL_MAX: u64 = 256;

type BitVec = BV<Arc<Btor>>;

#[derive(Debug, Clone)]
pub struct Solver {
    pub btor: Arc<Btor>,
    pub assertions: Vec<BitVec>, // yo dawg i heard you like types
    pub indexes: Vec<usize>
}

impl Solver {

    pub fn new() -> Self {
        let btor = Arc::new(Btor::new());
        btor.set_opt(BtorOption::ModelGen(ModelGen::All));
        btor.set_opt(BtorOption::Incremental(true));
        btor.set_opt(BtorOption::OutputNumberFormat(NumberFormat::Hexadecimal));
        btor.set_opt(BtorOption::PrettyPrint(false));

        Solver {
            btor,
            assertions: vec!(),
            indexes: vec!()
        }
    }

    pub fn duplicate(&self) -> Self {
        let btor = Arc::new(self.btor.duplicate());
        let mut assertions = vec!();

        for assertion in &self.assertions {
            let new_assert = self.translate(assertion);
            assertions.push(new_assert.unwrap());
        }

        Solver {
            btor,
            assertions,
            indexes: self.indexes.clone()
        }
    }

    pub fn apply_assertions(&self) {
        for assertion in &self.assertions {
            assertion.assert();
        }
    }

    #[inline]
    pub fn bv(&self, s: &str, n: u32) -> BitVec {
        BV::new(self.btor.clone(), n, Some(s))
    }

    #[inline]
    pub fn bvv(&self, v: u64, n: u32) -> BitVec {
        BV::from_u64(self.btor.clone(), v, n)
    }

    #[inline]
    pub fn translate(&self, bv: &BitVec) -> Option<BitVec> {
        //Some(bv.to_owned())
        //println!("{:?}", bv);
        Btor::get_matching_bv(self.btor.clone(), bv)
    }

    #[inline]
    pub fn translate_value(&self, value: &Value) -> Value {
        match value {
            Value::Concrete(val, t) => Value::Concrete(*val, *t),
            Value::Symbolic(val, t) => Value::Symbolic(
                self.translate(val).unwrap(), *t)
        }
    }

    #[inline]
    pub fn to_bv(&self, value: &Value, length: u32) -> BitVec {
        match value {
            Value::Concrete(val, _t) => {
                self.bvv(*val, length)
            },
            Value::Symbolic(val, _t) => {
                //let new_val = self.translate(val).unwrap();
                let szdiff = (val.get_width() - length) as i32;
                if szdiff == 0 {
                    val.to_owned()
                } else if szdiff > 0 {
                    val.slice(length-1, 0)
                } else {
                    val.uext(-szdiff as u32)
                }
            }
        }
    }

    #[inline]
    pub fn conditional(&self, cond: &Value, if_val: &Value, else_val: &Value) -> Value {
        match cond {
            Value::Concrete(val, t) => {
                if *val != 0 {
                    if_val.with_taint(*t)
                } else {
                    else_val.with_taint(*t)
                }
            },
            Value::Symbolic(val, t) => {
                let taint = if_val.get_taint() | else_val.get_taint();
                Value::Symbolic(val.cond_bv(
                    &self.to_bv(if_val, 64),
                    &self.to_bv(else_val, 64)), taint | t)
            }
        }
    }


    #[inline]
    pub fn evaluate(&self, bv: &BitVec) -> Option<Value> {
        self.btor.push(1);
        self.apply_assertions();
        //let new_bv = self.translate(bv).unwrap();
        let sol = if self.btor.sat() == SolverResult::Sat {
            Some(Value::Concrete(bv.get_a_solution().as_u64().unwrap(), 0))
        } else {
            None
        };
        self.btor.pop(1);
        sol
    }


    #[inline]
    pub fn eval(&self, value: &Value) -> Option<Value> {
        match value {
            Value::Concrete(val, t) => {
                Some(Value::Concrete(*val, *t))
            },
            Value::Symbolic(bv, t) => {
                self.btor.push(1);
                self.apply_assertions();
                //let new_bv = self.translate(bv).unwrap();
                let sol = if self.btor.sat() == SolverResult::Sat {
                    Some(Value::Concrete(bv.get_a_solution().as_u64().unwrap(), *t))
                } else {
                    None
                };
                self.btor.pop(1);
                sol
            }
        }
    }

    #[inline]
    pub fn eval_to_u64(&self, value: &Value) -> Option<u64> {
        if let Some(Value::Concrete(val, _t)) = self.eval(value) {
            Some(val)
        } else {
            None
        }
    }

    #[inline]
    pub fn eval_to_bv(&mut self, value: &Value) -> Option<BitVec> {
        match value {
            Value::Concrete(val, _t) => {
                Some(self.bvv(*val, 64))
            },
            Value::Symbolic(bv, _t) => {
                self.btor.push(1);
                self.apply_assertions();
                //let new_bv = self.translate(bv).unwrap();
                let sol_bv = if self.btor.sat() == SolverResult::Sat {
                    let sol = bv.get_a_solution().disambiguate();
                    let bv_str = sol.as_01x_str();
                    Some(BV::from_binary_str(self.btor.clone(), bv_str))
                } else {
                    None
                };
                self.btor.pop(1);
                sol_bv
            }
        }
    }

    #[inline]
    pub fn evalcon_to_u64(&mut self, value: &Value) -> Option<u64> {
        match value {
            Value::Concrete(val, _t) => {
                Some(*val)
            },
            Value::Symbolic(bv, _t) => {
                self.evalcon(&bv)
            }
        }
    }

    #[inline]
    pub fn push(&mut self) {
        self.indexes.push(self.assertions.len());
        self.btor.push(1)
    }

    #[inline]
    pub fn pop(&mut self) {
        self.btor.pop(1);
        let index = self.indexes.pop().unwrap();
        self.assertions = self.assertions[..index].to_owned();
    }

    #[inline]
    pub fn reset(&mut self) { // uhhh this might work?
        self.assertions.clear();
        self.indexes.clear();
    }

    // evaluate and constrain the symbol to the value
    #[inline]
    pub fn evalcon(&mut self, bv: &BitVec) -> Option<u64> {
        self.btor.push(1);
        self.apply_assertions();
        //let new_bv = self.translate(bv).unwrap();
        let sol = if self.btor.sat() == SolverResult::Sat {
            let conval = bv.get_a_solution().as_u64().unwrap();
            let assertion = bv._eq(&self.bvv(conval, bv.get_width()));
            self.assert(&assertion);
            Some(conval)
        } else {
            None
        };
        self.btor.pop(1);
        sol
    }

    #[inline]
    pub fn assert_in(&mut self, bv: &BitVec, values: &[u64]) {
        let mut cond = self.bvv(1, 1);
        for val in values {
            let nbv = self.bvv(*val, 64);
            cond = cond.or(&bv._eq(&nbv));
        }
        self.assert(&cond);
    }

    #[inline]
    pub fn assert(&mut self, bv: &BV<Arc<Btor>>) {
        //let new_bv = self.translate(bv).unwrap();
        //new_bv.assert();
        self.assertions.push(bv.to_owned());
    }

    #[inline]
    pub fn is_sat(&self) -> bool {
        self.btor.push(1);
        self.apply_assertions();
        let sat = self.btor.sat() == SolverResult::Sat;
        self.btor.pop(1);
        sat
    }

    pub fn evaluate_many(&mut self, bv: &BitVec) -> Vec<u64> {
        let mut solutions: Vec<u64> = Vec::with_capacity(EVAL_MAX as usize);
        //let new_bv = self.translate(bv).unwrap();
        self.btor.push(1);
        self.apply_assertions();
        for _i in 0..EVAL_MAX {
            if self.btor.sat() == SolverResult::Sat {
                let sol = bv.get_a_solution().as_u64().unwrap();
                solutions.push(sol);
                let sol_bv = BV::from_u64(
                    self.btor.clone(), sol, bv.get_width());

                bv._eq(&sol_bv).not().assert();
            } else {
                break
            }
        }
        self.btor.pop(1);

        if solutions.len() == EVAL_MAX as usize {
            // if there are more possibilities than EVAL_MAX
            // constrain it to be in the eval subset
            self.assert_in(bv, &solutions);
        }

        solutions 
    }

    pub fn solution(&self, bv: &BitVec) -> Option<String> {
        self.btor.push(1);
        self.apply_assertions();
        let sol = if self.btor.sat() == SolverResult::Sat {
            let solution = bv.get_a_solution().disambiguate();
            let sol_str = solution.as_01x_str(); 
            Some(sol_str.to_string())
        } else {
            None
        };
        self.btor.pop(1);
        sol
    }

    pub fn and_all(&self, bvs: &Vec<BitVec>) -> Option<BitVec> {
        let mut bv = BV::from_bool(self.btor.clone(), true);
        for next_bv in bvs {
            bv = bv.and(next_bv);
        }
        Some(bv)
    }

    pub fn or_all(&self, bvs: &mut Vec<BitVec>) -> Option<BitVec> {
        let mut bv = BV::from_bool(self.btor.clone(), true);
        for next_bv in bvs {
            bv = bv.or(next_bv);
        }
        Some(bv)
    }

    // surprisingly fast binary search to max
    pub fn max(&self, bv: &BitVec) -> u64 {
        self.btor.push(1);
        self.apply_assertions();

        let len = bv.get_width();
        let mut low = 0; 
        let mut high = 1 << (len-1);

        while high != low {
            bv.ugte(&self.bvv(high, len)).assume();
            while self.btor.sat() != SolverResult::Sat && high != low {
                high = low + (high - low) / 2;
                bv.ugte(&self.bvv(high, len)).assume();
            }

            let tmp = high;
            high = high + (high - low) / 2;
            low = tmp;
        }
        self.btor.pop(1);

        low
    }

    pub fn min(&self, bv: &BitVec) -> u64 {
        self.btor.push(1);
        self.apply_assertions();

        let len = bv.get_width();
        let mut low = 0; 
        let mut high = 1 << (len-1);
        
        while high != low {
            bv.ult(&self.bvv(high, len)).assume();
            while self.btor.sat() == SolverResult::Sat && high != low {
                high = low + (high - low) / 2;
                bv.ult(&self.bvv(high, len)).assume();
            }

            let tmp = high;
            high = high + (high - low) / 2;
            low = tmp;
        }
        self.btor.pop(1);
        low
    }

    pub fn max_value(&self, value: &Value) -> u64 {
        match value {
            Value::Concrete(val, _t) => *val,
            Value::Symbolic(val, _t) => self.max(val)
        }
    }

    pub fn min_value(&self, value: &Value) -> u64 {
        match value {
            Value::Concrete(val, _t) => *val,
            Value::Symbolic(val, _t) => self.min(val)
        }
    }
}