use std::collections::HashMap;
use crate::r2_api;
use crate::value::Value;
use crate::boolector::{BV, Btor};
use std::rc::Rc;

const MASKS: [u64; 65] = [0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535, 131071, 262143, 524287, 1048575, 2097151, 4194303, 8388607, 16777215, 33554431, 67108863, 134217727, 268435455, 536870911, 1073741823, 2147483647, 4294967295, 8589934591, 17179869183, 34359738367, 68719476735, 137438953471, 274877906943, 549755813887, 1099511627775, 2199023255551, 4398046511103, 8796093022207, 17592186044415, 35184372088831, 70368744177663, 140737488355327, 281474976710655, 562949953421311, 1125899906842623, 2251799813685247, 4503599627370495, 9007199254740991, 18014398509481983, 36028797018963967, 72057594037927935, 144115188075855871, 288230376151711743, 576460752303423487, 1152921504606846975, 2305843009213693951, 4611686018427387903, 9223372036854775807, 18446744073709551615];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bounds {
    start: u64,
    end: u64,
    size: u64
}

#[derive(Debug, Clone)]
pub struct Register {
    pub reg_info: r2_api::RegisterInfo,
    pub bounds: Bounds,
    pub index: usize,
    pub value_index: usize,
}

#[derive(Debug, Clone)]
pub struct Registers {
    pub solver: Rc<Btor>,
    pub aliases: HashMap<String, r2_api::AliasInfo>,
    pub regs:    HashMap<String, Register>,
    pub indexes: Vec<Register>,
    pub values:  Vec<Value>
}

impl Registers {
    pub fn new(r2api: &mut r2_api::R2Api, btor: Rc<Btor>,) -> Self {
        let mut reg_info = r2api.get_registers();
        reg_info.reg_info.sort_by(|a, b| b.size.partial_cmp(&a.size).unwrap());

    
        let mut registers = Registers {
            solver: btor,
            aliases: HashMap::new(),
            regs:    HashMap::new(),
            indexes: vec!(),
            values:  vec!() //HashMap::new(),
        };
    
        for alias in reg_info.alias_info {
            registers.aliases.insert(alias.role_str.clone(), alias);
        }
    
        let mut bounds_map: HashMap<Bounds,usize> = HashMap::new();
        for reg in reg_info.reg_info {
            let mut bounds = Bounds {
                start: reg.offset,
                end: reg.offset+reg.size,
                size: reg.size
            };
    
            let old_bounds = bounds_map.keys();
            let mut in_bounds = false;

            for bound in old_bounds {
                if bounds.start >= bound.start && bounds.end <= bound.end {
                    in_bounds = true;
                    bounds = bound.clone();
                }
            }
    
            if !in_bounds {
                let val = Value::Concrete(
                    r2api.get_register_value(&reg.name)
                );
                bounds_map.insert(bounds.clone(), registers.values.len());
                registers.values.push(val);
            }
    
            let reg_obj = Register {
                reg_info: reg,
                bounds: bounds.clone(),
                value_index: bounds_map[&bounds],
                index: registers.indexes.len()
            };
    
            registers.indexes.push(reg_obj.clone());
            registers.regs.insert(reg_obj.reg_info.name.clone(), reg_obj);
        }
    
        registers
    }

    pub fn get(&mut self, reg: &str) -> Value {
        self.get_value(self.regs[reg].index)
    }

    pub fn set(&mut self, reg: &str, value: Value) {
        self.set_value(self.regs[reg].index, value)
    }

    #[inline]
    pub fn get_register(&mut self, reg: &String) -> Option<&Register> {
        self.regs.get(reg)
    }

    #[inline]
    pub fn get_value(&mut self, index: usize) -> Value {
        let register = &self.indexes[index];

        let value = &self.values[register.value_index];
        let size = register.reg_info.size;

        if size == register.bounds.size {
            match value {
                Value::Concrete(val) => {
                    return Value::Concrete(*val);
                },
                Value::Symbolic(val) => {
                    let trans_val = Btor::get_matching_bv(self.solver.clone(), val).unwrap();
                    return Value::Symbolic(trans_val);
                }
            }
        }

        let offset: u64 = register.reg_info.offset - register.bounds.start;

        match value {
            Value::Concrete(val) => {
                let mask: u64 = MASKS[size as usize];
                Value::Concrete((val >> offset) & mask)
            },
            Value::Symbolic(val) => {
                let trans_val = Btor::get_matching_bv(self.solver.clone(), val).unwrap();
                Value::Symbolic(trans_val.slice(
                    (offset+size-1) as u32, offset as u32))
            }
        }
    }

    #[inline]
    pub fn set_value(&mut self, index: usize, value: Value) {
        //println!("reg {:?} {:?}", index, value);
        let register = &self.indexes[index];
        let size = register.reg_info.size;

        if size == register.bounds.size {
            self.values[register.value_index] = value;
        } else {
            let bound_size = register.bounds.size as u32;
            let offset: u64 = register.reg_info.offset - register.bounds.start;
            let old_value = &self.values[register.value_index];

            let mut new_sym;
            let mut old_sym;
            match (value, old_value.clone()) {
                (Value::Concrete(new), Value::Concrete(old)) => {
                    let new_mask: u64 = MASKS[size as usize];
                    let mask: u64 = 0xffffffffffffffff ^ (new_mask << offset);

                    let new_value = (old & mask) + ((new & new_mask) << offset);
                    self.values[register.value_index] = Value::Concrete(new_value);
                    return;
                },
                (Value::Concrete(new), Value::Symbolic(old)) => {
                    let solv = self.solver.clone();
                    new_sym = BV::from_u64(solv.clone(), new, size as u32);
                    old_sym = Btor::get_matching_bv(solv, &old).unwrap();
                },
                (Value::Symbolic(new), Value::Concrete(old)) => {
                    let solv = self.solver.clone();
                    old_sym = BV::from_u64(solv.clone(), old, bound_size);
                    new_sym = Btor::get_matching_bv(solv, &new).unwrap();
                },
                (Value::Symbolic(new), Value::Symbolic(old)) => {
                    let solv = self.solver.clone();
                    old_sym = Btor::get_matching_bv(solv.clone(), &old).unwrap();
                    new_sym = Btor::get_matching_bv(solv, &new).unwrap();
                }
            }

            new_sym = new_sym.slice(size as u32 - 1, 0);
            old_sym = old_sym.slice(bound_size - 1, 0);

            let mut new_value;

            if offset > 0 {
                new_value = new_sym.concat(&old_sym.slice((offset-1) as u32, 0));
                let new_off = offset as u32 + size as u32;
                if bound_size - new_off > 0 {
                    new_value = old_sym.slice(bound_size-1, new_off).concat(&new_value);
                }
            } else {
                new_value = old_sym.slice(bound_size-1, size as u32).concat(&new_sym);
            }

            self.values[register.value_index] = Value::Symbolic(new_value);
        }
    }
}