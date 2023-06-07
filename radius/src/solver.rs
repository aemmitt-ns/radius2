use crate::value::Value;
use boolector::option::{BtorOption, ModelGen, NumberFormat};
use boolector::{Btor, SolverResult, BV};
use std::cmp::Ordering;
use std::sync::Arc;

const EVAL_MAX: usize = 256;

pub type BitVec = BV<Arc<Btor>>;

#[derive(Debug, Clone)]
pub struct Solver {
    pub btor: Arc<Btor>,
    pub assertions: Vec<BitVec>,
    pub indexes: Vec<usize>,
    pub eval_max: usize,
}

impl Default for Solver {
    fn default() -> Self {
        Self::new(EVAL_MAX)
    }
}

impl Solver {
    pub fn new(eval_max: usize) -> Self {
        let btor = Arc::new(Btor::new());
        //btor.set_opt(BtorOption::SatEngine(SatEngine::CaDiCaL));
        btor.set_opt(BtorOption::ModelGen(ModelGen::Disabled));
        btor.set_opt(BtorOption::Incremental(true));
        btor.set_opt(BtorOption::OutputNumberFormat(NumberFormat::Hexadecimal));
        //btor.set_opt(BtorOption::PrettyPrint(false));

        Solver {
            btor,
            assertions: Vec::with_capacity(256),
            indexes: Vec::with_capacity(256),
            eval_max,
        }
    }

    pub fn duplicate(&self) -> Self {
        let btor = Arc::new(self.btor.duplicate());

        let mut solver = Solver {
            btor,
            assertions: Vec::with_capacity(256),
            indexes: self.indexes.clone(),
            eval_max: self.eval_max,
        };

        solver.assertions = self
            .assertions
            .iter()
            .map(|a| solver.translate(a).unwrap())
            .collect();

        solver
    }

    pub fn apply_assertions(&self) {
        for assertion in &self.assertions {
            assertion.assert();
        }
    }

    #[inline]
    pub fn bv(&self, s: &str, n: u32) -> BitVec {
        // check if it already exists
        BV::new(self.btor.clone(), n, Some(s))
    }

    #[inline]
    pub fn bvv(&self, v: u64, n: u32) -> BitVec {
        if n <= 64 {
            // boolector sign extends. even though its u64...
            // what the fuck
            BV::from_u64(self.btor.clone(), v, n)
        } else {
            BV::from_u64(self.btor.clone(), v, 64).uext(n - 64)
        }
    }

    pub fn translate(&self, bv: &BitVec) -> Option<BitVec> {
        Btor::get_matching_bv(self.btor.clone(), bv)
    }

    pub fn translate_value(&self, value: &Value) -> Value {
        match value {
            Value::Concrete(val, t) => Value::Concrete(*val, *t),
            Value::Symbolic(val, t) => Value::Symbolic(self.translate(val).unwrap(), *t),
        }
    }

    pub fn to_bv(&self, value: &Value, length: u32) -> BitVec {
        match value {
            Value::Concrete(val, _t) => self.bvv(*val, length),
            Value::Symbolic(val, _t) => {
                //let new_val = self.translate(val).unwrap();
                let szdiff = val.get_width() as i32 - length as i32;
                match szdiff.cmp(&0) {
                    Ordering::Equal => val.to_owned(),
                    Ordering::Greater => val.slice(length - 1, 0),
                    Ordering::Less => val.uext((-szdiff) as u32),
                }
            }
        }
    }

    pub fn to_sym(&self, value: &Value, length: u32) -> Value {
        Value::Symbolic(self.to_bv(value, length), value.get_taint())
    }

    pub fn conditional(&self, cond: &Value, if_val: &Value, else_val: &Value) -> Value {
        let mut max_bit = 1;
        if if_val.is_symbolic() || else_val.is_symbolic() {
            if let Value::Symbolic(ifv, _) = if_val {
                max_bit = ifv.get_width();
            }

            if let Value::Symbolic(elv, _) = else_val {
                if elv.get_width() > max_bit {
                    max_bit = elv.get_width()
                }
            }
        } else {
            // add exception for if(c, y, y) for concrete y
            if let Some(x) = if_val.as_u64() {
                if let Some(y) = else_val.as_u64() {
                    if x == y {
                        return Value::Concrete(
                            if_val.as_u64().unwrap(),
                            if_val.get_taint() | else_val.get_taint(),
                        );
                    }
                }
            }
            max_bit = 64;
        }

        match cond {
            Value::Concrete(val, t) => {
                if *val != 0 {
                    if_val.with_taint(*t)
                } else {
                    else_val.with_taint(*t)
                }
            }
            Value::Symbolic(val, t) => {
                let taint = if_val.get_taint() | else_val.get_taint();
                Value::Symbolic(
                    val.slice(0, 0)
                        .cond_bv(&self.to_bv(if_val, max_bit), &self.to_bv(else_val, max_bit)),
                    taint | t,
                )
            }
        }
    }

    pub fn enable_model(&self, b: bool) {
        if b {
            self.btor.set_opt(BtorOption::ModelGen(ModelGen::All));
        } else {
            self.btor.set_opt(BtorOption::ModelGen(ModelGen::Disabled));
        }
    }

    pub fn evaluate(&self, bv: &BitVec) -> Option<Value> {
        self.enable_model(true);

        self.btor.push(1);
        self.apply_assertions();
        //let new_bv = self.translate(bv).unwrap();
        let sol = if self.btor.sat() == SolverResult::Sat {
            Some(Value::Concrete(bv.get_a_solution().as_u64().unwrap(), 0))
        } else {
            None
        };
        self.btor.pop(1);

        self.enable_model(false);

        sol
    }

    pub fn eval(&self, value: &Value) -> Option<Value> {
        match value {
            Value::Concrete(val, t) => Some(Value::Concrete(*val, *t)),
            Value::Symbolic(bv, t) => {
                self.enable_model(true);

                self.btor.push(1);
                self.apply_assertions();
                //let new_bv = self.translate(bv).unwrap();
                let sol = if self.btor.sat() == SolverResult::Sat {
                    Some(Value::Concrete(bv.get_a_solution().as_u64().unwrap(), *t))
                } else {
                    None
                };
                self.btor.pop(1);

                self.enable_model(false);

                sol
            }
        }
    }

    pub fn eval_to_u64(&self, value: &Value) -> Option<u64> {
        if let Some(Value::Concrete(val, _t)) = self.eval(value) {
            Some(val)
        } else {
            None
        }
    }

    pub fn eval_to_bv(&mut self, value: &Value) -> Option<BitVec> {
        match value {
            Value::Concrete(val, _t) => Some(self.bvv(*val, 64)),
            Value::Symbolic(bv, _t) => {
                self.enable_model(true);

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
                self.enable_model(false);

                sol_bv
            }
        }
    }

    pub fn evalcon_to_u64(&mut self, value: &Value) -> Option<u64> {
        match value {
            Value::Concrete(val, _t) => Some(*val),
            Value::Symbolic(bv, _t) => self.evalcon(bv),
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
    pub fn reset(&mut self) {
        // uhhh this might work?
        self.assertions.clear();
        self.indexes.clear();
    }

    // evaluate and constrain the symbol to the value
    pub fn evalcon(&mut self, lbv: &BitVec) -> Option<u64> {
        // TODO this is a stupid fix to 128 bit float reg evalcon-ing
        // all of this code needs to be reorganized around Values instead of
        // returning u64s, except for circumstances explicitly involving addresses
        let bv = if lbv.get_width() <= 64 {
            lbv.to_owned()
        } else {
            lbv.slice(63, 0)
        };

        self.enable_model(true);
        self.btor.push(1);
        self.apply_assertions();
        //let new_bv = self.translate(bv).unwrap();
        let sol = if self.btor.sat() == SolverResult::Sat {
            let conval = bv.get_a_solution().as_u64().unwrap();
            let assertion = bv._eq(&self.bvv(conval, bv.get_width()));
            self.assert_bv(&assertion);
            Some(conval)
        } else {
            None
        };
        self.btor.pop(1);
        self.enable_model(false);
        sol
    }

    pub fn assert_in(&mut self, bv: &BitVec, values: &[u64]) {
        let mut cond = self.bvv(1, 1);
        for val in values {
            let nbv = self.bvv(*val, 64);
            cond = cond.or(&bv._eq(&nbv));
        }
        self.assert_bv(&cond);
    }

    #[inline]
    pub fn assert_bv(&mut self, bv: &BitVec) {
        self.assertions.push(bv.to_owned());
    }

    #[inline]
    pub fn assert(&mut self, value: &Value) {
        self.assertions
            .push(self.to_bv(&!value.eq(&Value::Concrete(0, 0)), 1));
    }

    #[inline]
    pub fn is_sat(&self) -> bool {
        if self.assertions.is_empty() {
            true
        } else {
            self.btor.push(1);
            self.apply_assertions();
            let sat = self.btor.sat() == SolverResult::Sat;
            self.btor.pop(1);
            sat
        }
    }

    /// check the satisfiability of the assertion
    #[inline]
    pub fn check_sat(&mut self, assertion: &Value) -> bool {
        match assertion {
            Value::Concrete(v, _t) => *v != 0,
            Value::Symbolic(_v, _t) => {
                self.btor.push(1);
                self.assert(assertion);
                self.apply_assertions();
                let sat = self.btor.sat() == SolverResult::Sat;
                self.assertions.pop();
                self.btor.pop(1);
                sat
            }
        }
    }

    pub fn evaluate_many(&mut self, bv: &BitVec) -> Vec<u64> {
        self.enable_model(true);
        let mut solutions: Vec<u64> = Vec::with_capacity(self.eval_max);
        //let new_bv = self.translate(bv).unwrap();
        self.btor.push(1);
        self.apply_assertions();
        for _i in 0..self.eval_max {
            if self.btor.sat() == SolverResult::Sat {
                let solopt = bv.get_a_solution().as_u64();
                if let Some(sol) = solopt {
                    solutions.push(sol);
                    let sol_bv = BV::from_u64(self.btor.clone(), sol, bv.get_width());

                    bv._eq(&sol_bv).not().assert();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        self.btor.pop(1);

        if solutions.len() == self.eval_max {
            // if there are more possibilities than EVAL_MAX
            // constrain it to be in the eval subset
            self.assert_in(bv, &solutions);
        }
        self.enable_model(false);
        solutions
    }

    pub fn solution(&self, bv: &BitVec) -> Option<String> {
        self.enable_model(true);

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
        self.enable_model(false);
        sol
    }

    // workaround for dumb temp file issue on termux
    pub fn hex_solution(&self, bv: &BitVec) -> Option<String> {
        if let Some(bin) = self.solution(bv) {
            let mut hex = "".to_owned();
            for i in 0..bin.len() / 8 {
                //
                let byte = u64::from_str_radix(&bin[8 * i..8 * (i + 1)], 2);
                hex += &format!("{:02x}", byte.unwrap_or_default());
            }
            Some(hex)
        } else {
            None
        }
    }

    pub fn and_all(&self, bvs: &[BitVec]) -> BitVec {
        let mut bv = BV::from_bool(self.btor.clone(), true);
        for next_bv in bvs {
            bv = bv.and(next_bv);
        }
        bv
    }

    // this should just be called "any"
    pub fn or_all(&self, bvs: &[BitVec]) -> BitVec {
        let mut bv = BV::from_bool(self.btor.clone(), false);
        for next_bv in bvs {
            bv = bv.or(next_bv);
        }
        bv
    }

    // surprisingly fast binary search to max
    pub fn max(&self, bv: &BitVec) -> u64 {
        self.btor.push(1);
        self.apply_assertions();

        let len = bv.get_width();
        let mut low = 0;
        let mut high = 1 << (len - 1);

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
        let mut high = 1 << (len - 1);

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
            Value::Symbolic(val, _t) => self.max(val),
        }
    }

    pub fn min_value(&self, value: &Value) -> u64 {
        match value {
            Value::Concrete(val, _t) => *val,
            Value::Symbolic(val, _t) => self.min(val),
        }
    }
}
