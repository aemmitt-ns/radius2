use crate::value::Value;
use boolector::{Btor, BV, SolverResult};
use boolector::option::{BtorOption, ModelGen, NumberFormat};
use std::sync::Arc;

const EVAL_MAX: u64 = 256;

#[derive(Debug, Clone)]
pub struct Solver {
    pub btor: Arc<Btor>
}

impl Solver {

    pub fn new() -> Self {
        let btor = Arc::new(Btor::new());
        btor.set_opt(BtorOption::ModelGen(ModelGen::All));
        btor.set_opt(BtorOption::Incremental(true));
        btor.set_opt(BtorOption::OutputNumberFormat(NumberFormat::Hexadecimal));

        Solver {
            btor
        }
    }

    pub fn duplicate(&self) -> Self {
        Solver {
            btor: Arc::new(self.btor.duplicate())
        }
    }

    #[inline]
    pub fn bv(&self, s: &str, n: u32) -> BV<Arc<Btor>>{
        BV::new(self.btor.clone(), n, Some(s))
    }

    #[inline]
    pub fn bvv(&self, v: u64, n: u32) -> BV<Arc<Btor>>{
        BV::from_u64(self.btor.clone(), v, n)
    }

    #[inline]
    pub fn translate(&self, bv: &BV<Arc<Btor>>) -> Option<BV<Arc<Btor>>> {
        let trans = Btor::get_matching_bv(self.btor.clone(), bv);
        trans
    }

    #[inline]
    pub fn translate_value(&self, value: &Value) -> Value {
        match value {
            Value::Concrete(val) => Value::Concrete(*val),
            Value::Symbolic(val) => Value::Symbolic(
                self.translate(val).unwrap())
        }
    }

    #[inline]
    pub fn to_bv(&self, value: &Value, length: u32) -> BV<Arc<Btor>> {
        match value {
            Value::Concrete(val) => {
                self.bvv(*val, length)
            },
            Value::Symbolic(val) => {
                let new_val = self.translate(val).unwrap();
                let szdiff = (new_val.get_width() - length) as i32;
                if szdiff == 0 {
                    new_val
                } else if szdiff > 0 {
                    new_val.slice(length-1, 0)
                } else {
                    new_val.uext(-szdiff as u32)
                }
            }
        }
    }

    #[inline]
    pub fn conditional(&self, cond: &Value, if_val: &Value, else_val: &Value) -> Value {
        match cond {
            Value::Concrete(val) => {
                if *val != 0 {
                    if_val.clone()
                } else {
                    else_val.clone()
                }
            },
            Value::Symbolic(val) => {
                Value::Symbolic(val.cond_bv(
                    &self.to_bv(if_val, 64),
                    &self.to_bv(else_val, 64)))
            }
        }
    }


    #[inline]
    pub fn evaluate(&self, bv: &BV<Arc<Btor>>) -> Option<Value> {
        let new_bv = self.translate(bv).unwrap();
        if self.btor.sat() == SolverResult::Sat {
            Some(Value::Concrete(new_bv.get_a_solution().as_u64().unwrap()))
        } else {
            None
        }
    }


    #[inline]
    pub fn eval(&self, value: &Value) -> Option<Value> {
        match value {
            Value::Concrete(val) => {
                Some(Value::Concrete(*val))
            },
            Value::Symbolic(bv) => {
                self.evaluate(&bv)
            }
        }
    }

    #[inline]
    pub fn eval_to_u64(&self, value: &Value) -> Option<u64> {
        if let Some(Value::Concrete(val)) = self.eval(value) {
            Some(val)
        } else {
            None
        }
    }

    #[inline]
    pub fn evalcon_to_u64(&self, value: &Value) -> Option<u64> {
        match value {
            Value::Concrete(val) => {
                Some(*val)
            },
            Value::Symbolic(bv) => {
                self.evalcon(&bv)
            }
        }
    }

    #[inline]
    pub fn push(&self, n: u32) {
        self.btor.push(n)
    }

    #[inline]
    pub fn pop(&self, n: u32) {
        self.btor.pop(n)
    }

    // evaluate and constrain the symbol to the value
    #[inline]
    pub fn evalcon(&self, bv: &BV<Arc<Btor>>) -> Option<u64> {
        let new_bv = self.translate(bv).unwrap();
        if self.btor.sat() == SolverResult::Sat {
            let conval = new_bv.get_a_solution().as_u64().unwrap();
            new_bv._eq(&self.bvv(conval, new_bv.get_width())).assert();
            Some(conval)
        } else {
            None
        }
    }

    #[inline]
    pub fn assert_in(&self, bv: &BV<Arc<Btor>>, values: &Vec<u64>) {
        let mut cond = self.bvv(1, 1);
        for val in values {
            let nbv = self.bvv(*val, 64);
            cond = cond.or(&bv._eq(&nbv));
        }
        cond.assert()
    }

    #[inline]
    pub fn is_sat(&self) -> bool {
        return self.btor.sat() == SolverResult::Sat 
    }

    pub fn evaluate_many(&self, bv: &BV<Arc<Btor>>) -> Vec<u64> {
        let mut solutions: Vec<u64> = vec!();
        let new_bv = self.translate(bv).unwrap();
        self.btor.push(1);
        for _i in 0..EVAL_MAX {
            if self.btor.sat() == SolverResult::Sat {
                let sol = new_bv.get_a_solution().as_u64().unwrap();
                solutions.push(sol);
                let sol_bv = BV::from_u64(
                    self.btor.clone(), sol, new_bv.get_width());

                new_bv._eq(&sol_bv).not().assert();
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

    pub fn solution(&self, bv: &BV<Arc<Btor>>) -> Option<String> {
        let new_bv = self.translate(bv).unwrap();
        if self.is_sat() {
            let solution = new_bv.get_a_solution();
            let sol_str = solution.as_01x_str(); 
            Some(sol_str.to_string())
        } else {
            None
        }
    }

    // surprisingly fast binary search to max
    pub fn max(&self, bv: &BV<Arc<Btor>>) -> u64 {
        let new_bv = self.translate(bv).unwrap();
        let len = new_bv.get_width();
        let mut low = 0; 
        let mut high = 1 << (len-1);

        while high != low {
            new_bv.ugte(&self.bvv(high, len)).assume();
            while !self.is_sat() && high != low {
                high = low + (high - low) / 2;
                new_bv.ugte(&self.bvv(high, len)).assume();
            }

            let tmp = high;
            high = high + (high - low) / 2;
            low = tmp;
        }

        low
    }

    pub fn min(&self, bv: &BV<Arc<Btor>>) -> u64 {
        let new_bv = self.translate(bv).unwrap();
        let len = new_bv.get_width();
        let mut low = 0; 
        let mut high = 1 << (len-1);
        
        while high != low {
            new_bv.ult(&self.bvv(high, len)).assume();
            while self.is_sat() && high != low {
                high = low + (high - low) / 2;
                new_bv.ult(&self.bvv(high, len)).assume();
            }

            let tmp = high;
            high = high + (high - low) / 2;
            low = tmp;
        }

        low
    }

    pub fn max_value(&self, value: &Value) -> u64 {
        match value {
            Value::Concrete(val) => *val,
            Value::Symbolic(val) => self.max(val)
        }
    }

    pub fn min_value(&self, value: &Value) -> u64 {
        match value {
            Value::Concrete(val) => *val,
            Value::Symbolic(val) => self.min(val)
        }
    }
}