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
    pub fn new(r2api: &mut r2_api::R2Api, btor: Solver, blank: bool) -> Self {
        let mut reg_info = r2api.get_registers().unwrap();
        reg_info.reg_info.sort_by(|a, b| b.size.partial_cmp(&a.size).unwrap());

        let mut registers = Registers {
            solver: btor.clone(),
            r2api: r2api.clone(),
            aliases: HashMap::new(),
            regs:    HashMap::new(),
            indexes: vec!(),
            values:  vec!() //HashMap::new(),
        };
    
        for alias in reg_info.alias_info {
            registers.aliases.insert(alias.role_str.to_owned(), alias);
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
                let val = if !blank {
                    Value::Concrete(r2api.get_register_value(&reg.name).unwrap(), 0)
                } else {
                    let sym_name = format!("reg_{}", reg.name);
                    Value::Symbolic(btor.bv(sym_name.as_str(), reg.size as u32), 0)
                };

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
            reg = r.reg.to_owned();
        }
        self.get_value(self.regs[reg.as_str()].index)
    }

    pub fn set_with_alias(&mut self, alias: &str, value: Value) {
        let mut reg = alias.to_owned();
        if let Some(r) = self.aliases.get(alias) {
            reg = r.reg.to_owned();
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
            return Value::Concrete(0, 0); // this is a zero register
        }

        let value = &self.values[register.value_index];
        let size = register.reg_info.size;

        if size == register.bounds.size {
            return value.to_owned();
        }

        let offset: u64 = register.reg_info.offset - register.bounds.start;

        match value {
            Value::Concrete(val, t) => {
                let mask: u64 = (1 << size) - 1;
                Value::Concrete((val >> offset) & mask, *t)
            },
            Value::Symbolic(val, t) => {
                if val.is_const() {
                    let mask: u64 = (1 << size) - 1;
                    Value::Concrete((val.as_u64().unwrap() >> offset) & mask, *t)
                } else {
                    Value::Symbolic(val.slice(
                        (offset+size-1) as u32, offset as u32), *t)
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
            let taint;

            // TODO this may cause huge amounts of overtainting, maybe just use new
            // im pulling trig and just using new, the downside of not is too high
            match (value, old_value.to_owned()) {
                (Value::Concrete(new, t1), Value::Concrete(old, _t2)) => {
                    let new_mask: u64 = (1 << size) - 1; 
                    let mask: u64 = !(new_mask << offset);

                    taint = t1; // | t2;
                    let new_value = (old & mask) + ((new & new_mask) << offset);
                    self.values[register.value_index] = Value::Concrete(new_value, taint);
                    return;
                },
                (Value::Concrete(new, t1), Value::Symbolic(old, _t2)) => {
                    new_sym = self.solver.bvv(new, size as u32);
                    old_sym = old; 
                    taint = t1; // | t2;
                },
                (Value::Symbolic(new, t1), Value::Concrete(old, _t2)) => {
                    old_sym = self.solver.bvv(old, bound_size);
                    new_sym = new;
                    taint = t1; // | t2;
                },
                (Value::Symbolic(new, t1), Value::Symbolic(old, _t2)) => {
                    old_sym = old; 
                    new_sym = new; 
                    taint = t1; // | t2;
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

            self.values[register.value_index] = Value::Symbolic(new_value, taint);
        }
    }
}