use crate::r2_api::{R2Api, Instruction};
use crate::value::{Value, value_to_bv};
use crate::operations::{Operations, pop_value, pop_stack_value, do_operation, OPS};
use std::collections::HashMap;
use crate::state::{State, StackItem, ExecMode};
use std::time::SystemTime;
use boolector::BV;

const INSTR_NUM: usize = 64;

#[derive(Debug, Clone)]
pub enum Word {
    Literal(Value),
    Register(usize),
    Operator(Operations),
    Unknown(String)
}

pub struct Processor {
    pub pc: Option<usize>,
    pub instructions: HashMap<u64, InstructionEntry>
}

#[derive(Debug, Clone)]
pub struct InstructionEntry {
    instruction: Instruction,
    tokens: Vec<Word>,
    // next: Option<Rc<InstructionEntry>>
}

const DEBUG: bool = false; // show instructions
const LAZY: bool = true; // dont check sat on ite PCs

#[inline]
pub fn print_instr(instr: &Instruction) {
    if DEBUG {
        println!("{:016x}:  {:<40} |  {}", instr.offset, instr.opcode, instr.esil);
    }
}

impl Processor {
    pub fn new() -> Self {
        Processor {
            pc: None,
            instructions: HashMap::new()
        }
    }

    pub fn tokenize(&mut self, state: &mut State, esil: &String) -> Vec<Word> {
        let mut tokens: Vec<Word> = vec!();
        let split_esil = esil.split(",");

        for s in split_esil {

            if let Some(register) = self.get_register(state, s) {
                tokens.push(register);
            } else if let Some(literal) = self.get_literal(s) {
                tokens.push(literal)
            } else if let Some(operator) = self.get_operator(s) {
                tokens.push(operator);

            // all this garbage is for the fuckin combo ones like ++=[8] ...
            } else if s.len() > 1 && &s[s.len()-1..s.len()] == "="
                    && OPS.contains(&&s[0..s.len()-1]) {

                let reg_word = tokens.pop().unwrap();
                tokens.push(reg_word.clone());
                let operator = self.get_operator(&s[0..s.len()-1]).unwrap();
                tokens.push(operator);
                tokens.push(reg_word);
                tokens.push(Word::Operator(Operations::Equal))

            } else if s.len() > 4 && &s[s.len()-1..s.len()] == "]" 
                    && OPS.contains(&&s[0..s.len()-4]) {

                tokens.push(Word::Operator(Operations::AddressStore));
                let peek = self.get_operator(&s[s.len()-3..]).unwrap();
                tokens.push(peek);
                let operator = self.get_operator(&s[0..s.len()-4]).unwrap();
                tokens.push(operator);
                let poke = self.get_operator(&s[s.len()-4..]).unwrap();
                tokens.push(Word::Operator(Operations::AddressRestore));
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
        let op = Operations::from_str(word);
        match op {
            Operations::Unknown => None,
            _ => Some(Word::Operator(op))
        }
    }

    // for one off parsing of strings
    pub fn parse_expression(&mut self, r2api: &mut R2Api, state: &mut State, esil: &str) {
        if self.pc.is_none() {
            let pc_reg = &state.registers.aliases["PC"];
            self.pc = Some(state.registers.regs.get(
                &pc_reg.reg).unwrap().index);
        }
        
        let words = self.tokenize(state, &String::from(esil));
        self.parse(r2api, state, &words);
    }

    pub fn parse(&self, r2api: &mut R2Api, state: &mut State, words: &Vec<Word>) {
        state.stack.clear();
        state.esil.pcs.clear();
        
        let mut word_index = 0;
        let words_len = words.len();

        let mut temp_stack1: Vec<StackItem> = vec!();
        let mut temp_stack2: Vec<StackItem> = vec!();

        while word_index < words_len {
            let word = &words[word_index];
            word_index += 1;

            // this is weird... 
            if let ExecMode::NoExec = state.esil.mode {
                if let Word::Operator(oper) = &word {
                    match &oper {
                        Operations::Else | Operations::EndIf => {},
                        _ => continue
                    }
                } else {
                    continue
                }
            }

            //println!("word: {:?} {:?}", &word, &state.stack);
            match word {                
                Word::Literal(val) => {
                    state.stack.push(StackItem::StackValue(val.clone()));
                },
                Word::Register(index) => {
                    state.stack.push(StackItem::StackRegister(*index));
                },
                Word::Operator(op) => {
                    match op {
                        Operations::If => {
                            let arg1 = pop_value(state, false, false);
                
                            match (arg1, &state.esil.mode) {
                                (Value::Concrete(val1), ExecMode::Uncon) => {
                                    if val1 == 0 {
                                        state.esil.mode = ExecMode::NoExec;
                                    } else {
                                        state.esil.mode = ExecMode::Exec;
                                    }
                                },
                                (Value::Symbolic(val1), ExecMode::Uncon) => {
                                    //println!("if {:?}", val1);
                                    state.esil.mode = ExecMode::If;
                                    temp_stack1 = state.stack.clone();
                                    let cond_bv = val1._eq(
                                        &BV::zero(state.solver.clone(), val1.get_width())).not();

                                    state.condition = Some(cond_bv);
                                }
                                _ => {
                                    println!("Bad ESIL?");
                                }
                            }
                        },
                        Operations::Else => {
                            match &state.esil.mode {
                                ExecMode::Exec => state.esil.mode = ExecMode::NoExec,
                                ExecMode::NoExec => state.esil.mode = ExecMode::Exec,
                                ExecMode::If => {
                                    state.esil.mode = ExecMode::Else;
                                    state.condition = Some(state.condition.as_ref().unwrap().not());
                                    temp_stack2 = state.stack.clone(); // all this cloning will be slow af
                                    state.stack = temp_stack1.clone();
                                }
                                _ => {}
                            }
                        },
                        Operations::EndIf => {
                            let mut perform = false;
                            let mut new_temp = temp_stack1.clone();

                            match &state.esil.mode {
                                ExecMode::If => {
                                    perform = true;
                                },    
                                ExecMode::Else => {
                                    new_temp = temp_stack2.clone();
                                    perform = true;
                                },
                                _ => {}
                            }

                            if perform {
                                let mut new_stack: Vec<StackItem> = vec!();
                                let mut tmp = state.stack.clone();
                                while !state.stack.is_empty() && !new_temp.is_empty() {
                                    let if_val = pop_stack_value(state, &mut tmp, false, false);
                                    let else_val = pop_stack_value(state, &mut new_temp, false, false);
                                    let cond_val = state.condition.as_ref().unwrap().cond_bv(
                                        &value_to_bv(state.solver.clone(), if_val),
                                        &value_to_bv(state.solver.clone(), else_val)
                                    );

                                    new_stack.push(StackItem::StackValue(Value::Symbolic(cond_val)));
                                }

                                new_stack.reverse();
                                state.stack = new_stack;
                                state.condition = None;
                            }

                            state.esil.mode = ExecMode::Uncon;
                        },
                        _ => do_operation(r2api, state, op.clone(), self.pc.unwrap())
                    }
                },
                Word::Unknown(s) => {
                    println!("Unknown word: {}", s);
                }
            }
        }
    }

    pub fn execute(&mut self, r2api: &mut R2Api, state: &mut State, 
        pc_index: usize, pc_val: u64) {
        
        let instr_opt = self.instructions.get(&pc_val);

        if let Some(instr_entry) = instr_opt {
            print_instr(&instr_entry.instruction);
            let size = instr_entry.instruction.size;
            let new_pc = Value::Concrete(pc_val+size);
            state.registers.set_value(pc_index, new_pc);

            let words = &instr_entry.tokens;
            self.parse(r2api, state, words);
        } else {
            let mut pc_tmp = pc_val;
            let instrs = r2api.disassemble(pc_val, INSTR_NUM);

            for instr in instrs {
                let size = instr.size;
                let words = self.tokenize(state, &instr.esil);

                if pc_tmp == pc_val {
                    print_instr(&instr);
                    let new_pc = Value::Concrete(pc_tmp+size);
                    state.registers.set_value(pc_index, new_pc);
                    self.parse(r2api, state, &words);
                } 

                let instr_entry = InstructionEntry {
                    instruction: instr,
                    tokens: words,
                };

                self.instructions.insert(pc_tmp, instr_entry);
                pc_tmp += size;
            }
        }
    }

    pub fn step(&mut self, r2api: &mut R2Api, mut state: State) -> Vec<State> {
        let mut states: Vec<State> = vec!();
        let pc_index = self.pc.unwrap();

        let pc_value = state.registers.get_value(pc_index);

        if let Value::Concrete(pc_val) = pc_value {
            self.execute(r2api, &mut state, pc_index, pc_val);
        } else {
            println!("got an unexpected sym PC: {:?}", pc_value);
        }

        let new_pc = state.registers.get_value(pc_index);

        match new_pc {
            Value::Concrete(_pc_val) => {
                states.push(state);
            },
            Value::Symbolic(pc_val) => {
                // this is weird and bad
                let pcs;
                if LAZY && state.esil.pcs.len() == 2 {
                    pcs = state.esil.pcs;
                    state.esil.pcs = vec!();
                } else {
                    pcs = state.evaluate_many(&pc_val);
                }
                //println!("{:?}", pcs);

                for new_pc_val in pcs {
                    let mut new_state = state.duplicate();
                    let pc_bv = new_state.translate(&pc_val).unwrap();
                    pc_bv._eq(&new_state.bvv(new_pc_val, pc_bv.get_width())).assert();
                    new_state.registers.set_value(pc_index, Value::Concrete(new_pc_val));
                    states.push(new_state);
                }
            }
        }

        states
    }

    pub fn run_until(&mut self, r2api: &mut R2Api, state: State, addr: u64, avoid: u64) -> Option<State> {
        let mut count = 0;

        if self.pc.is_none() {
            let pc_reg = &state.registers.aliases["PC"];
            self.pc = Some(state.registers.regs.get(
                &pc_reg.reg).unwrap().index);
        }
        let pc_register = &state.registers.indexes[self.pc.unwrap()].clone();

        let now = SystemTime::now();
        let mut states = vec!(state);
        
        while let Some(current_state) = states.pop() {

            //if count % 100 == 0 {
            // println!("count: {} zf: {:?}", count, current_state.registers.get("zf"));
            //}

            let pc = &current_state.registers.values[pc_register.index];

            if let Value::Concrete(pc_val) = pc {
                if *pc_val == addr {
                    println!("count: {} ({})", count, 
                        now.elapsed().unwrap().as_micros());
                    return Some(current_state);
                } else if *pc_val == avoid {
                    continue;
                }
            } 

            let new_states = self.step(r2api, current_state);
            states.extend(new_states);
            count += 1;
        }

        None
    }
}
