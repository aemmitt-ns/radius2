use crate::value::Value;
use boolector::{Btor, BV, SolverResult};
use boolector::option::{BtorOption, ModelGen, NumberFormat};
use std::sync::Arc;

const EVAL_MAX: u64 = 256;

//type RBV = BV<Arc<Btor>>;

#[derive(Debug, Clone)]
pub struct Solver {
    pub btor: Arc<Btor>,
    pub assertions: Vec<BV<Arc<Btor>>>, // yo dawg i heard you like types
    pub indexes: Vec<usize>
}

impl Solver {

    pub fn new() -> Self {
        let btor = Arc::new(Btor::new());
        btor.set_opt(BtorOption::ModelGen(ModelGen::All));
        btor.set_opt(BtorOption::Incremental(true));
        btor.set_opt(BtorOption::OutputNumberFormat(NumberFormat::Hexadecimal));

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
            let new_assert = Btor::get_matching_bv(btor.clone(), assertion);
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
    pub fn bv(&self, s: &str, n: u32) -> BV<Arc<Btor>>{
        BV::new(self.btor.clone(), n, Some(s))
    }

    #[inline]
    pub fn bvv(&self, v: u64, n: u32) -> BV<Arc<Btor>>{
        BV::from_u64(self.btor.clone(), v, n)
    }

    #[inline]
    pub fn translate(&self, bv: &BV<Arc<Btor>>) -> Option<BV<Arc<Btor>>> {
        //Some(bv.to_owned())
        //println!("{:?}", bv);
        Btor::get_matching_bv(self.btor.clone(), bv)
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
        self.btor.push(1);
        self.apply_assertions();
        //let new_bv = self.translate(bv).unwrap();
        let sol = if self.btor.sat() == SolverResult::Sat {
            Some(Value::Concrete(bv.get_a_solution().as_u64().unwrap()))
        } else {
            None
        };
        self.btor.pop(1);
        sol
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
    pub fn eval_to_bv(&mut self, value: &Value) -> Option<BV<Arc<Btor>>> {
        match value {
            Value::Concrete(val) => {
                Some(self.bvv(*val, 64))
            },
            Value::Symbolic(bv) => {
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
            Value::Concrete(val) => {
                Some(*val)
            },
            Value::Symbolic(bv) => {
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
    pub fn evalcon(&mut self, bv: &BV<Arc<Btor>>) -> Option<u64> {
        self.push();
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
        self.pop();
        sol
    }

    #[inline]
    pub fn assert_in(&mut self, bv: &BV<Arc<Btor>>, values: &[u64]) {
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

    pub fn evaluate_many(&mut self, bv: &BV<Arc<Btor>>) -> Vec<u64> {
        let mut solutions: Vec<u64> = vec!();
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

    pub fn solution(&self, bv: &BV<Arc<Btor>>) -> Option<String> {
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

    pub fn and_all(&self, bvs: &Vec<BV<Arc<Btor>>>) -> Option<BV<Arc<Btor>>> {
        let mut bv = BV::from_bool(self.btor.clone(), true);
        for next_bv in bvs {
            bv = bv.and(next_bv);
        }
        Some(bv)
    }

    pub fn or_all(&self, bvs: &mut Vec<BV<Arc<Btor>>>) -> Option<BV<Arc<Btor>>> {
        let mut bv = BV::from_bool(self.btor.clone(), true);
        for next_bv in bvs {
            bv = bv.or(next_bv);
        }
        Some(bv)
    }

    // surprisingly fast binary search to max
    pub fn max(&self, bv: &BV<Arc<Btor>>) -> u64 {
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

    pub fn min(&self, bv: &BV<Arc<Btor>>) -> u64 {
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