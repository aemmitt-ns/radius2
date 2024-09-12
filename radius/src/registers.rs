use crate::r2_api::{AliasInfo, R2Api, RegisterInfo};
use crate::solver::Solver;
use crate::value::{vc, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bounds {
    tstr: String,
    start: u64,
    end: u64,
    size: u64,
}

#[derive(Debug, Clone)]
pub struct Register {
    pub reg_info: RegisterInfo,
    pub bounds: Bounds,
    pub index: usize,
    pub value_index: usize,
}

#[derive(Clone)]
pub struct Registers {
    pub solver: Solver,
    pub r2api: R2Api,
    pub aliases: HashMap<String, AliasInfo>,
    pub regs: HashMap<String, Register>,
    pub indexes: Vec<Register>,
    pub values: Vec<Value>,
    pub pc: Option<Register>,
    // clear_upper: bool
}

impl Registers {
    pub fn new(r2api: &mut R2Api, btor: Solver, blank: bool) -> Self {
        let mut reg_info = r2api.get_registers().unwrap();
        reg_info
            .reg_info
            .sort_by(|a, b| b.size.partial_cmp(&a.size).unwrap());

        //let clear_upper = r2api.clear_upper_bits();

        let mut registers = Registers {
            solver: btor.clone(),
            r2api: r2api.clone(),
            aliases: HashMap::new(),
            regs: HashMap::new(),
            indexes: vec![],
            values: vec![],
            pc: None,
            // clear_upper
        };

        let mut bounds_map: HashMap<Bounds, usize> = HashMap::new();
        for reg in reg_info.reg_info {
            let mut bounds = Bounds {
                tstr: reg.type_str.to_owned(),
                start: reg.offset,
                end: reg.offset.wrapping_add(reg.size),
                size: reg.size,
            };

            let old_bounds = bounds_map.keys();
            let mut in_bounds = false;
            for bound in old_bounds {
                let inside = bounds.start >= bound.start && bounds.end <= bound.end;
                if bound.tstr == bounds.tstr && inside {
                    in_bounds = true;
                    bounds = bound.clone();
                }
            }

            if !in_bounds {
                let val = if !blank {
                    let v = r2api.get_register_value(&reg.name).unwrap_or_default();
                    if reg.size <= 64 {
                        vc(v)
                    } else {
                        Value::Symbolic(btor.bvv(v, reg.size as u32), 0)
                    }
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
                index: registers.indexes.len(),
            };

            registers.indexes.push(reg_obj.clone());
            registers
                .regs
                .insert(reg_obj.reg_info.name.clone(), reg_obj);
        }

        for alias in &reg_info.alias_info {
            registers
                .aliases
                .insert(alias.role_str.to_owned(), alias.clone());

            if alias.role_str == "PC" {
                registers.pc = Some(registers.get_register(&alias.reg).unwrap().clone());
            }
        }

        registers
    }

    /// Returns `true` iff this register is the PC.
    pub fn is_pc(&self, reg: &Register) -> bool {
        self.pc.as_ref().unwrap().index == reg.index
    }

    /// Get the value of the register `reg`
    #[inline]
    pub fn get(&self, reg: &str) -> Value {
        self.get_value(self.regs[reg].index)
    }

    /// Set the value of the register `reg`
    #[inline]
    pub fn set(&mut self, reg: &str, value: Value) {
        self.set_value(self.regs[reg].index, value)
    }

    #[inline]
    pub fn get_register(&self, reg: &str) -> Option<&Register> {
        self.regs.get(reg)
    }

    /// Get register with name OR alias, eg. `PC`, `SP`
    #[inline]
    pub fn get_with_alias(&self, alias: &str) -> Value {
        let mut reg = alias;
        if let Some(r) = self.aliases.get(alias) {
            reg = &r.reg;
        }
        self.get_value(self.regs[reg].index)
    }

    /// Set register with name OR alias, eg. `PC`, `SP`
    #[inline]
    pub fn set_with_alias(&mut self, alias: &str, value: Value) {
        if let Some(r) = self.aliases.get(alias) {
            let t = r.reg.to_owned();
            return self.set_value(self.regs[&t].index, value);
        }
        // make set_with_alias more forgiving
        if let Some(reg) = self.regs.get(alias) {
            let creg = reg.clone();
            self.set_value(creg.index, value);
        }
    }

    /// Get the value of `PC`
    #[inline]
    pub fn get_pc(&self) -> Value {
        self.get_value(self.pc.as_ref().unwrap().index)
    }

    /// Set the value of `PC`
    #[inline]
    pub fn set_pc(&mut self, value: Value) {
        self.set_value(self.pc.as_ref().unwrap().index, value)
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

    pub fn get_value(&self, index: usize) -> Value {
        let register = &self.indexes[index];
        if register.reg_info.offset == -1i64 as u64 {
            return Value::Concrete(0, 0); // this is a zero register
        }
        let value = &self.values[register.value_index];
        if register.reg_info.size == register.bounds.size {
            value.to_owned()
        } else {
            let offset = register.reg_info.offset - register.bounds.start;
            value.slice(register.reg_info.size + offset - 1, offset)
        }
    }

    pub fn set_value(&mut self, index: usize, value: Value) {
        let register = &self.indexes[index];

        if register.reg_info.offset == -1i64 as u64 {
            return; // this is a zero register
        }

        let size = register.reg_info.size;
        if size == register.bounds.size {
            if size <= 64 {
                self.values[register.value_index] = value.slice(size - 1, 0);
            } else {
                // need to prevent size > 64 from becoming a u64
                let bv = self.solver.to_bv(&value, size as u32);
                let v = Value::Symbolic(bv, value.get_taint());
                self.values[register.value_index] = v;
            }
        } else if size == 32 {
            // this sux
            self.values[register.value_index] = value.slice(size - 1, 0).uext(&vc(32));
        } else {
            let bound_size = register.bounds.size as u32;
            let offset = register.reg_info.offset - register.bounds.start;
            let old_value = &self.values[register.value_index];

            let mut new_sym;
            let mut old_sym;
            let taint;

            // TODO this may cause huge amounts of overtainting, maybe just use new
            // im pulling trig and just using new, the downside of not is too high
            match (value, old_value.to_owned()) {
                (Value::Concrete(new, t1), Value::Concrete(old, _t2)) => {
                    let new_mask = (1 << size) - 1;
                    let mask = !(new_mask << offset);
                    let new_value = (old & mask) + ((new & new_mask) << offset);
                    self.values[register.value_index] = Value::Concrete(new_value, t1);
                    return;
                }
                (Value::Concrete(new, t1), Value::Symbolic(old, _t2)) => {
                    new_sym = self.solver.bvv(new, size as u32);
                    old_sym = old;
                    taint = t1; // | t2;
                }
                (Value::Symbolic(new, t1), Value::Concrete(old, _t2)) => {
                    old_sym = self.solver.bvv(old, bound_size);
                    new_sym = new;
                    taint = t1; // | t2;
                }
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
                new_value = new_sym.concat(&old_sym.slice((offset - 1) as u32, 0));
                let new_off = offset as u32 + size as u32;
                if bound_size - new_off > 0 {
                    new_value = old_sym.slice(bound_size - 1, new_off).concat(&new_value);
                }
            } else {
                new_value = old_sym.slice(bound_size - 1, size as u32).concat(&new_sym);
            }

            self.values[register.value_index] = Value::Symbolic(new_value, taint);
        }
    }
}
