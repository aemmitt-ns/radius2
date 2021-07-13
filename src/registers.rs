use std::collections::HashMap;
use crate::r2_api;
use crate::value::Value;
use crate::solver::Solver;

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

#[derive(Clone)]
pub struct Registers {
    pub solver:  Solver,
    pub r2api:   r2_api::R2Api,
    pub aliases: HashMap<String, r2_api::AliasInfo>,
    pub regs:    HashMap<String, Register>,
    pub indexes: Vec<Register>,
    pub values:  Vec<Value>
}

impl Registers {
    pub fn new(r2api: &mut r2_api::R2Api, btor: Solver) -> Self {
        let mut reg_info = r2api.get_registers();
        reg_info.reg_info.sort_by(|a, b| b.size.partial_cmp(&a.size).unwrap());

        let mut registers = Registers {
            solver: btor,
            r2api: r2api.clone(),
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
    pub fn get_register(&mut self, reg: &str) -> Option<&Register> {
        self.regs.get(reg)
    }

    pub fn get_with_alias(&mut self, alias: &str) -> Value {
        let mut reg = alias.to_owned();
        if let Some(r) = self.aliases.get(alias) {
            reg = r.reg.clone();
        }
        self.get_value(self.regs[reg.as_str()].index)
    }

    pub fn set_with_alias(&mut self, alias: &str, value: Value) {
        let mut reg = alias.to_owned();
        if let Some(r) = self.aliases.get(alias) {
            reg = r.reg.clone();
        }

        self.set_value(self.regs[reg.as_str()].index, value)
    }

    #[inline]
    pub fn is_sub(&mut self, r1: usize, r2: usize) -> bool {
        let reg1 = &self.indexes[r1];
        let reg2 = &self.indexes[r2];

        let start1 = reg1.reg_info.offset;
        let start2 = reg2.reg_info.offset;
        let end1 = reg1.reg_info.offset + reg1.reg_info.size;
        let end2 = reg2.reg_info.offset + reg2.reg_info.size;

        start2 >= start1 && end2 <= end1
    }

    #[inline]
    pub fn get_value(&mut self, index: usize) -> Value {
        let register = &self.indexes[index];

        if register.reg_info.offset as i64 == -1 {
            return Value::Concrete(0); // this is a zero register
        }

        let value = &self.values[register.value_index];
        let size = register.reg_info.size;

        if size == register.bounds.size {
            match value {
                Value::Concrete(val) => {
                    return Value::Concrete(*val);
                },
                Value::Symbolic(val) => {
                    return Value::Symbolic(val.to_owned());
                }
            }
        }

        let offset: u64 = register.reg_info.offset - register.bounds.start;

        match value {
            Value::Concrete(val) => {
                let mask: u64 = (1 << size) - 1;
                Value::Concrete((val >> offset) & mask)
            },
            Value::Symbolic(val) => {
                if val.is_const() {
                    let mask: u64 = (1 << size) - 1;
                    Value::Concrete((val.as_u64().unwrap() >> offset) & mask)
                } else {
                    Value::Symbolic(val.slice(
                        (offset+size-1) as u32, offset as u32))
                }
            }
        }
    }

    #[inline]
    pub fn set_value(&mut self, index: usize, value: Value) {
        //println!("reg {:?} {:?}", index, value);
        let register = &self.indexes[index];

        if register.reg_info.offset as i64 == -1 {
            return; // this is a zero register
        }

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
                    let new_mask: u64 = (1 << size) - 1; 
                    let mask: u64 = 0xffffffffffffffff ^ (new_mask << offset);

                    let new_value = (old & mask) + ((new & new_mask) << offset);
                    self.values[register.value_index] = Value::Concrete(new_value);
                    return;
                },
                (Value::Concrete(new), Value::Symbolic(old)) => {
                    new_sym = self.solver.bvv(new, size as u32);
                    old_sym = old; 
                },
                (Value::Symbolic(new), Value::Concrete(old)) => {
                    old_sym = self.solver.bvv(old, bound_size);
                    new_sym = new; 
                },
                (Value::Symbolic(new), Value::Symbolic(old)) => {
                    old_sym = old; 
                    new_sym = new; 
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