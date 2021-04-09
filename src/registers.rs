use std::collections::HashMap;
use crate::r2_api;
use crate::value::Value;
use crate::boolector::BV;

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
    pub index: usize
}

#[derive(Debug, Clone)]
pub struct Registers {
    pub aliases: HashMap<String, r2_api::AliasInfo>,
    pub regs:    HashMap<String, Register>,
    pub indexes: Vec<Register>,
    pub values:  HashMap<Bounds, Value>
}

impl Registers {
    pub fn get(&mut self, reg: &String) -> Value {
        self.get_value(self.regs[reg].index)
    }

    pub fn set(&mut self, reg: &String, value: Value) {
        self.set_value(self.regs[reg].index, value)
    }

    pub fn get_register(&mut self, reg: &String) -> Option<&Register> {
        self.regs.get(reg)
    }

    pub fn get_value(&mut self, index: usize) -> Value {
        let register = self.indexes.get(index).unwrap();

        let value = self.values.get(&register.bounds).unwrap().clone();
        let size = register.reg_info.size;

        if size == register.bounds.size {
            return value;
        }

        let offset: u64 = register.reg_info.offset - register.bounds.start;
        let mask: u64 = *MASKS.get(register.reg_info.size as usize).unwrap();

        match &value {
            Value::Concrete(val) => {
                Value::Concrete((val >> offset) & mask)
            },
            Value::Symbolic(val) => {
                Value::Symbolic(val.slice(
                    (offset+size-1) as u32, offset as u32))
            }
        }
    }

    pub fn set_value(&mut self, index: usize, value: Value) {
        let register = self.indexes.get(index).unwrap();
        let size = register.reg_info.size;

        if size == register.bounds.size {
            self.values.insert(register.bounds.clone(), value);
        } else {
            let bounds = register.bounds.clone();
            let bound_size = register.bounds.size as u32;
            let offset: u64 = register.reg_info.offset - register.bounds.start;
            let new_mask: u64 = *MASKS.get(register.reg_info.size as usize).unwrap();
            let mask: u64 = 0xffffffffffffffff ^ (new_mask << offset);
            let old_value = self.values.get(&register.bounds).unwrap();
            
            match &value {
                Value::Concrete(val) => {
                    match &old_value {
                        Value::Concrete(old_val) => {
                            let new_value = (old_val & mask) + ((val & new_mask) << offset);
                            self.values.insert(bounds, Value::Concrete(new_value));
                        },
                        Value::Symbolic(old_val) => {
                            let btor = old_val.get_btor();
                            let new = BV::from_u64(btor.clone(), (val & new_mask) << offset, bound_size);
                            let old_mask = BV::from_u64(btor.clone(), mask, bound_size);
                            let new_value = old_val.and(&old_mask).add(&new);

                            self.values.insert(bounds, Value::Symbolic(new_value));
                        }
                    }
                },
                Value::Symbolic(val) => {
                    let btor = val.get_btor();
                    let new_mask = BV::from_u64(btor.clone(), new_mask, bound_size);
                    let new_offset = BV::from_u64(btor.clone(), offset, bound_size);
                    let new_val = val.and(&new_mask).sll(&new_offset);

                    match &old_value {
                        Value::Concrete(old_val) => {
                            let old = BV::from_u64(btor.clone(), old_val & mask, bound_size);
                            let new_value = new_val.add(&old);

                            self.values.insert(bounds, Value::Symbolic(new_value));
                        },
                        Value::Symbolic(old_val) => {
                            let old_mask = BV::from_u64(btor.clone(), mask, bound_size);
                            let new_value = new_val.add(&old_val.and(&old_mask));

                            self.values.insert(bounds, Value::Symbolic(new_value));
                        }
                    }
                }
            }
        }
    }
}

pub fn create(r2api: &mut r2_api::R2Api) -> Registers {
    let mut reg_info = r2api.get_registers();
    reg_info.reg_info.sort_by(|a, b| b.size.partial_cmp(&a.size).unwrap());

    let mut registers = Registers {
        aliases: HashMap::new(),
        regs:    HashMap::new(),
        indexes: vec!(),
        values:  HashMap::new(),
    };

    for alias in reg_info.alias_info {
        registers.aliases.insert(alias.role_str.clone(), alias);
    }

    for reg in reg_info.reg_info {
        let mut bounds = Bounds {
            start: reg.offset,
            end: reg.offset+reg.size,
            size: reg.size
        };

        let old_bounds = registers.values.keys();
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
            registers.values.insert(bounds.clone(), val);
        }

        let reg_obj = Register {
            reg_info: reg,
            bounds: bounds,
            index: registers.indexes.len()
        };

        registers.indexes.push(reg_obj.clone());
        registers.regs.insert(reg_obj.reg_info.name.clone(), reg_obj);
    }

    registers
}