use crate::r2_api::R2Api;
use crate::registers::Registers;
use crate::memory::Memory;
use crate::value::Value;
use boolector::{Btor, BV, SolverResult};
use boolector::option::{BtorOption, ModelGen, NumberFormat};
use std::rc::Rc;
// use backtrace::Backtrace;

const EVAL_MAX: u64 = 256;

#[derive(Debug, Clone)]
pub enum ExecMode {
    If,
    Else,
    Exec,
    NoExec,
    Uncon,
}

#[derive(Debug, Clone)]
pub struct EsilState {
    pub mode: ExecMode,
    pub previous: Value,
    pub current:  Value,
    pub last_sz:  usize,
    pub stored_address: Option<Value>,
    pub pcs: Vec<u64>
}

#[derive(Debug, Clone)]
pub enum StackItem {
    StackRegister(usize),
    StackValue(Value)
}

#[derive(Debug, Clone)]
pub struct State {
    pub solver: Rc<Btor>,
    pub stack: Vec<StackItem>,
    pub esil: EsilState,
    pub condition: Option<BV<Rc<Btor>>>,
    pub registers: Registers,
    pub memory: Memory
}

impl State {
    pub fn new(r2api: &mut R2Api) -> Self {
        let esil_state = EsilState {
            mode: ExecMode::Uncon,
            previous: Value::Concrete(0),
            current: Value::Concrete(0),
            last_sz: 64,
            stored_address: None,
            pcs: vec!()
        };
    
        let btor = Rc::new(Btor::new());
        btor.set_opt(BtorOption::ModelGen(ModelGen::All));
        btor.set_opt(BtorOption::Incremental(true));
        btor.set_opt(BtorOption::OutputNumberFormat(NumberFormat::Hexadecimal));
        //btor.set_opt(BtorOption::PrettyPrint(true));

        State {
            solver: btor.clone(),
            stack: vec!(),
            esil: esil_state,
            condition: None,
            registers: Registers::new(r2api, btor.clone()),
            memory: Memory::new(r2api, btor.clone())
        }
    }

    pub fn duplicate(&mut self) -> Self {
        let solver = Rc::new(self.solver.duplicate());

        let mut registers = self.registers.clone();
        registers.solver = solver.clone();

        let mut memory = self.memory.clone();
        memory.solver = solver.clone();

        State {
            solver: solver,
            stack: self.stack.clone(),
            esil: self.esil.clone(),
            condition: None,
            registers: registers,
            memory: memory
        }
    }

    #[inline]
    pub fn bv(&mut self, s: &str, n: u32) -> BV<Rc<Btor>>{
        BV::new(self.solver.clone(), n, Some(s))
    }

    #[inline]
    pub fn bvv(&mut self, v: u64, n: u32) -> BV<Rc<Btor>>{
        BV::from_u64(self.solver.clone(), v, n)
    }

    #[inline]
    pub fn translate(&mut self, bv: &BV<Rc<Btor>>) -> Option<BV<Rc<Btor>>> {
        //let bt = Backtrace::new();
        //println!("wtffff: {:?}", bt);
        //println!("hmmm {:?}", bv);

        let trans = Btor::get_matching_bv(self.solver.clone(), bv);
        //println!("fuck {:?}", trans);

        trans
    }

    #[inline]
    pub fn translate_value(&mut self, value: &Value) -> Value {
        match value {
            Value::Concrete(val) => Value::Concrete(*val),
            Value::Symbolic(val) => Value::Symbolic(
                self.translate(val).unwrap())
        }
    }

    pub fn evaluate(&mut self, bv: &BV<Rc<Btor>>) -> Option<Value> {
        let new_bv = self.translate(bv).unwrap();
        if self.solver.sat() == SolverResult::Sat {
            Some(Value::Concrete(new_bv.get_a_solution().as_u64().unwrap()))
        } else {
            None
        }
    }

    // evaluate and constrain the symbol to the value
    pub fn evalcon(&mut self, bv: &BV<Rc<Btor>>) -> Option<u64> {
        let new_bv = self.translate(bv).unwrap();
        if self.solver.sat() == SolverResult::Sat {
            let conval = new_bv.get_a_solution().as_u64().unwrap();
            new_bv._eq(&self.bvv(conval, new_bv.get_width())).assert();
            Some(conval)
        } else {
            None
        }
    }

    pub fn is_sat(&mut self) -> bool {
        self.solver.sat() == SolverResult::Sat
    }

    pub fn evaluate_many(&mut self, bv: &BV<Rc<Btor>>) -> Vec<u64> {
        let mut solutions: Vec<u64> = vec!();
        let new_bv = self.translate(bv).unwrap();
        self.solver.push(1);
        for _i in 0..EVAL_MAX {
            if self.solver.sat() == SolverResult::Sat {
                let sol = new_bv.get_a_solution().as_u64().unwrap();
                solutions.push(sol);
                let sol_bv = BV::from_u64(
                    self.solver.clone(), sol, new_bv.get_width());

                new_bv._eq(&sol_bv).not().assert();
            } else {
                break
            }
        }
        self.solver.pop(1);

        solutions 
    }

    pub fn evaluate_string(&mut self, bytes: Vec<Value>) -> String {
        let mut data: Vec<u8> = vec!();
        for b in bytes {
            match b {
                Value::Concrete(val) => {
                    data.push(val as u8);
                },
                Value::Symbolic(val) => {
                    let conval = self.evalcon(&val).unwrap();
                    data.push(conval as u8);
                }
            }
        }

        String::from_utf8(data).unwrap()
    }
}