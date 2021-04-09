use crate::r2_api::R2Api;
use crate::value::Value;
use crate::operations::{Operations, op_from_str, do_operation, OPS};
use std::collections::HashMap;
use crate::state::{State, StackItem, ExecMode};

#[derive(Debug, Clone)]
pub enum Word {
    Literal(Value),
    Register(usize),
    Operator(Operations),
    Unknown(String)
}

pub struct Processor {
    pub pc: Option<String>,
    pub token_cache: HashMap<u64, Vec<Word>>
}

impl Processor {
    pub fn tokenize(&mut self, state: &mut State, esil: &String) -> Vec<Word> {
        let mut tokens: Vec<Word> = vec!();
        let split_esil = esil.split(",");

        for s in split_esil {

            if let Some(literal) = self.get_literal(s) {
                tokens.push(literal)
            } else if let Some(register) = self.get_register(state, s) {
                tokens.push(register);
            } else if let Some(operator) = self.get_operator(s) {
                tokens.push(operator);

            // all this garbage is for the fuckin combo ones like ++=[8] ...
            } else if s.len() > 1 && &s[s.len()-1..s.len()] == "=" && OPS.contains(&&s[0..s.len()-1]) {
                let reg_word = tokens.pop().unwrap();
                tokens.push(reg_word.clone());
                let operator = self.get_operator(&s[0..s.len()-1]).unwrap();
                tokens.push(operator);
                tokens.push(reg_word);
                tokens.push(Word::Operator(Operations::Equal))
            } else if s.len() > 4 && &s[s.len()-1..s.len()] == "]" && OPS.contains(&&s[0..s.len()-4]) {
                tokens.push(Word::Operator(Operations::AddressStore));
                let peek = self.get_operator(&s[s.len()-3..]).unwrap();
                tokens.push(peek);
                let operator = self.get_operator(&s[0..s.len()-4]).unwrap();
                tokens.push(operator);
                let poke = self.get_operator(&s[s.len()-4..]).unwrap();
                tokens.push(poke)
            } else {
                tokens.push(Word::Unknown(String::from(s)));
            }
        }

        tokens
    }

    pub fn get_literal(&mut self, word: &str) -> Option<Word> {
        let parsed = word.parse::<i64>();
        
        if parsed.is_ok() {
            let val = Value::Concrete(parsed.unwrap() as u64);
            Some(Word::Literal(val))
        } else if word.len() > 2 && &word[0..2] == "0x" {
            let int_val = u64::from_str_radix(&word[2..word.len()], 16).unwrap();
            Some(Word::Literal(Value::Concrete(int_val)))
        } else {
            None
        }
    }

    pub fn get_register(&mut self,  state: &mut State, word: &str) -> Option<Word> {
        if let Some(reg) = state.registers.get_register(&String::from(word)) {
            Some(Word::Register(reg.index))
        } else {
            None
        }
    }

    pub fn get_operator(&mut self, word: &str) -> Option<Word> {
        let op = op_from_str(word);
        match op {
            Operations::Unknown => None,
            _ => Some(Word::Operator(op))
        }
    }

    pub fn parse(&mut self, r2api: &mut R2Api, state: &mut State, words: Vec<Word>) {
        for word in words {
            // this is weird... 
            if let ExecMode::NoExec = state.esil.mode {
                if let Word::Operator(oper) = &word {
                    match &oper {
                        Operations::Else | Operations::EndIf => {},
                        _ => continue
                    }
                }
            }

            //println!("word: {:?} {:?}", &word, &state.stack);
            match word {                
                Word::Literal(val) => {
                    state.stack.push(StackItem::StackValue(val));
                },
                Word::Register(index) => {
                    state.stack.push(StackItem::StackRegister(index));
                },
                Word::Operator(op) => {
                    do_operation(r2api, state, op);
                },
                Word::Unknown(s) => {
                    println!("Unknown word: {}", s);
                }
            }
        }
    }

    pub fn step(&mut self, r2api: &mut R2Api, mut state: State) -> Vec<State> {
        let mut states: Vec<State> = vec!();
        let pc_index = state.registers.get_register(
            &self.pc.as_ref().unwrap()).unwrap().index; // oof

        let pc = state.registers.get_value(pc_index);

        match pc {
            Value::Concrete(pc_val) => {
                let instr = r2api.disassemble(pc_val);
                //println!("step: {:?}", instr);

                let new_pc = Value::Concrete(pc_val+instr.size);
                state.registers.set_value(pc_index, new_pc);

                if self.token_cache.contains_key(&pc_val) {
                    let words = self.token_cache.get(&pc_val).unwrap().clone();
                    self.parse(r2api, &mut state, words);
                } else {
                    let words = self.tokenize(&mut state, &instr.esil);
                    self.token_cache.insert(pc_val, words.clone());
                    self.parse(r2api, &mut state, words);
                }

                states.push(state);
            },
            Value::Symbolic(_pc_val) => {}
        }

        states
    }

    pub fn run_until(&mut self, r2api: &mut R2Api, state: State, addr: u64) -> Option<State> {
        let mut states = vec!(state);
        let mut count = 0;
        while !states.is_empty() {
            let mut current_state = states.pop().unwrap();

            /*if count % 100 == 0 {
                println!("count: {} rax: {:?}", count, current_state.registers.get(&String::from("eax")));
            }*/

            if self.pc.is_none() {
                let pc_reg = &current_state.registers.aliases["PC"];
                self.pc = Some(pc_reg.reg.clone());
            }
            let pc = current_state.registers.get(&self.pc.as_ref().unwrap());

            if let Value::Concrete(pc_val) = pc {
                if pc_val == addr {
                    println!("count: {}", count);
                    return Some(current_state);
                }
            }

            let new_states = self.step(r2api, current_state);
            states.extend(new_states);
            count += 1;
        }

        None
    }
}

pub fn create() -> Processor {
    Processor {
        pc: None,
        token_cache: HashMap::new()
    }
}