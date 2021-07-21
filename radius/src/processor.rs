use crate::r2_api::{Instruction, Syscall};
use crate::value::Value;
use crate::operations::{Operations, pop_value, 
    pop_stack_value, pop_concrete, do_operation, OPS};

use std::collections::HashMap;
use crate::state::{State, StateStatus, StackItem, ExecMode};
use crate::sims::{SimMethod};
use crate::sims::syscall::syscall;
use crate::memory::CHECK_PERMS;

//use std::time::SystemTime;
//use boolector::BV;

const INSTR_NUM: usize = 64;

const CALL_TYPE: u64 = 3;
const RETN_TYPE: u64 = 5;

#[derive(Debug, Clone, PartialEq)]
pub enum Word {
    Literal(Value),
    Register(usize),
    Operator(Operations),
    Unknown(String)
}

pub type HookMethod = fn (&mut State) -> bool;

#[derive(Clone)]
pub struct Processor {
    pub pc: Option<usize>,
    pub instructions: HashMap<u64, InstructionEntry>,
    pub hooks: HashMap<u64, Vec<HookMethod>>,
    pub sims: HashMap<u64, SimMethod>,
    pub traps: HashMap<u64, SimMethod>, 
    pub syscalls: HashMap<u64, Syscall>,
    pub breakpoints: HashMap<u64, bool>,
    pub mergepoints: HashMap<u64, bool>,
    pub avoidpoints: HashMap<u64, bool>,
    pub optimized: bool,
    pub debug: bool,
    pub lazy: bool,
    pub force: bool,
    pub prune: bool
    //pub states: Vec<State>
}

#[derive(Debug, Clone, PartialEq)]
pub enum InstructionStatus {
    None,
    Hook,
    Sim,
    Merge,
    Avoid,
    Break
}

#[derive(Debug, Clone)]
pub struct InstructionEntry {
    instruction: Instruction,
    tokens: Vec<Word>,
    status: InstructionStatus
    // next: Option<Arc<InstructionEntry>>
}

//const DEBUG: bool = false; // show instructions
//const LAZY:  bool = true;  // dont check sat on ite PCs
//const OPT:   bool = true;  // optimize by removing unread flag sets
const BFS:   bool = true;    // dequeue states instead of popping

const ALLOW_INVALID: bool = true; // Allow invalid instructions (exec as NOP)

impl Processor {
    pub fn new(optimized: bool, debug: bool, lazy: bool, force: bool, prune: bool) -> Self {
        Processor {
            pc: None,
            instructions: HashMap::new(),
            hooks:        HashMap::new(),
            sims:         HashMap::new(),
            traps:        HashMap::new(),
            syscalls:     HashMap::new(),
            breakpoints:  HashMap::new(),
            mergepoints:  HashMap::new(),
            avoidpoints:  HashMap::new(),
            optimized,
            debug,
            lazy,
            force,
            prune
            //states: vec!()
        }
    }

    pub fn tokenize(&self, state: &mut State, esil: &str) -> Vec<Word> {
        let mut tokens: Vec<Word> = Vec::with_capacity(128);
        let split_esil = esil.split(',');

        for s in split_esil {

            // nice, pretty, simple
            if let Some(register) = self.get_register(state, s) {
                tokens.push(register);
            } else if let Some(literal) = self.get_literal(s) {
                tokens.push(literal);
            } else if let Some(operator) = self.get_operator(s) {
                tokens.push(operator);

            // all this garbage is for the combo ones like ++=[8] ...
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

    // attempt to tokenize word as number literal (eg. 0x8)
    pub fn get_literal(&self, word: &str) -> Option<Word> {        
        if let Ok(i) = word.parse::<u64>() {
            let val = Value::Concrete(i, 0);
            Some(Word::Literal(val))
        } else if word.len() > 2 && &word[0..2] == "0x" {
            let val = u64::from_str_radix(&word[2..word.len()], 16).unwrap();
            Some(Word::Literal(Value::Concrete(val, 0)))
        } else if let Ok(i) = word.parse::<i64>() {
            let val = Value::Concrete(i as u64, 0);
            Some(Word::Literal(val))
        } else {
            None
        }
    }

    // attempt to tokenize word as register (eg. rbx)
    pub fn get_register(&self,  state: &mut State, word: &str) -> Option<Word> {
        if let Some(reg) = state.registers.get_register(word) {
            Some(Word::Register(reg.index))
        } else {
            None
        }
    }

    // attempt to tokenize word as operation (eg. +)
    pub fn get_operator(&self, word: &str) -> Option<Word> {
        let op = Operations::from_string(word);
        match op {
            Operations::Unknown => None,
            _ => Some(Word::Operator(op))
        }
    }

    // print instruction if debug output is enabled
    #[inline]
    pub fn print_instr(&self, instr: &Instruction) {
        if self.debug {
            println!("{:016x}:  {:<40} |  {}", instr.offset, instr.disasm, instr.esil);
        }
    }

    // perform an emulated syscall using the definitions in syscall.rs
    pub fn do_syscall(&self, state: &mut State) {
        let sys_val = state.registers.get_with_alias("SN");
        let sys_num = state.solver.evalcon_to_u64(&sys_val).unwrap();
        let pc = state.registers.get_value(self.pc.unwrap()).as_u64().unwrap();

        if let Some(sys) = self.syscalls.get(&sys_num) {
            let cc = state.r2api.get_syscall_cc(pc);
            let mut args = vec!();
            for arg in cc.args {
                args.push(state.registers.get(arg.as_str()));
            }
            let ret = syscall(sys.name.as_str(), state, args);
            state.registers.set(cc.ret.as_str(), ret);
        }
    }

    // for one-off parsing of strings
    pub fn parse_expression(&self, state: &mut State, esil: &str) {
        let words = self.tokenize(state, esil);
        self.parse(state, &words);
    }

    // i'm slinging some straight shit code at this point
    pub fn parse_expression_mut(&mut self, state: &mut State, esil: &str) {
        if self.pc.is_none() {
            let pc_reg = &state.registers.aliases["PC"];
            self.pc = Some(state.registers.regs.get(
                &pc_reg.reg).unwrap().index);
        }

        let words = self.tokenize(state, esil);
        self.parse(state, &words);
    }

    /* 
     * Parse and execute the vector of tokenized ESIL words. 
     * The difficult parts here are the temporary stacks for IF/ELSE
     * When a conditional is symbolic the stack needs to be copied
     * into separate stacks for the if and else portions
     * after ENDIF (}) these stacks are unwound into a single vec of 
     * conditional bitvectors IF(cond, IF_VAL, ELSE_VAL)
     */
    pub fn parse(&self, state: &mut State, words: &[Word]) {
        state.stack.clear();
        
        let mut word_index = 0;
        let words_len = words.len();

        let mut temp_stack1: Vec<StackItem> = Vec::with_capacity(128);
        let mut temp_stack2: Vec<StackItem> = Vec::with_capacity(128);

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
                                (Value::Concrete(val1, _t), ExecMode::Uncon) => {
                                    if val1 == 0 {
                                        state.esil.mode = ExecMode::NoExec;
                                    } else {
                                        state.esil.mode = ExecMode::Exec;
                                    }
                                },
                                (Value::Symbolic(val1, _t), ExecMode::Uncon) => {
                                    //println!("if {:?}", val1);
                                    state.esil.mode = ExecMode::If;
                                    temp_stack1 = state.stack.clone();
                                    let cond_bv = val1._eq(
                                        &state.bvv(0, val1.get_width())).not();

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
                            let mut new_temp = temp_stack1.clone();

                            let perform = match &state.esil.mode {
                                ExecMode::If => true,
                                ExecMode::Else => {
                                    new_temp = temp_stack2.clone();
                                    true
                                },
                                _ => false
                            };

                            if perform {
                                let mut new_stack: Vec<StackItem> = Vec::with_capacity(128);
                                let mut tmp = state.stack.clone();
                                while !state.stack.is_empty() && !new_temp.is_empty() {
                                    let if_val = pop_stack_value(state, &mut tmp, false, false);
                                    let else_val = pop_stack_value(state, &mut new_temp, false, false);
                                    let cond_val = state.solver.conditional(
                                        &Value::Symbolic(state.condition.as_ref().unwrap().clone(), 0),
                                        &if_val,
                                        &else_val
                                    );

                                    new_stack.push(StackItem::StackValue(cond_val));
                                }

                                new_stack.reverse();
                                state.stack = new_stack;
                                state.condition = None;
                            }

                            state.esil.mode = ExecMode::Uncon;
                        },
                        Operations::GoTo => {
                            let n = pop_concrete(state, false, false);
                            if let Some(_cond) = &state.condition {
                                panic!("Hit symbolic GOTO");
                                //cond.assert();
                            }
                            state.esil.mode = ExecMode::Uncon;
                            word_index = n as usize;
                        },
                        Operations::Break => {
                            if let Some(_cond) = &state.condition {
                                panic!("Hit symbolic BREAK");
                                //cond.assert();
                            }
                            break;
                        },
                        Operations::Trap => {
                            let trap = pop_concrete(state, false, false);
                            let pc = state.registers.get_value(self.pc.unwrap()).as_u64().unwrap();

                            let sys_val = state.registers.get_with_alias("SN");                            
                            if let Some(trap_sim) = self.traps.get(&trap) {
                                // provide syscall args
                                let cc = state.r2api.get_syscall_cc(pc);
                                let mut args = vec!(sys_val);
                                for arg in cc.args {
                                    args.push(state.registers.get(arg.as_str()));
                                }
                                let ret = trap_sim(state, args);
                                state.registers.set(cc.ret.as_str(), ret);
                            }
                        },
                        Operations::Syscall => self.do_syscall(state),
                        _ => do_operation(state, op.to_owned(), self.pc.unwrap())
                    }
                },
                Word::Unknown(s) => {
                    println!("Unknown word: {}", s);
                }
            }
        }
    }

    // removes words that weak set flag values that are never read, and words that are NOPs
    pub fn optimize(&mut self, state: &mut State, prev_pc: u64, curr_instr: &InstructionEntry) {
        let prev_instr = &self.instructions[&prev_pc];
        if  !prev_instr.tokens.contains(&Word::Operator(Operations::WeakEqual)) ||
            !curr_instr.tokens.contains(&Word::Operator(Operations::WeakEqual))
        {
            return;
        }

        let mut regs_read: Vec<usize> = Vec::with_capacity(16);
        let mut regs_written: Vec<usize> = Vec::with_capacity(16);

        let len = curr_instr.tokens.len();
        for (i, word) in curr_instr.tokens.iter().enumerate() {
            if let Word::Register(index) = word {
                if i+1 < len {
                    let next = &curr_instr.tokens[i+1];
                    if let Word::Operator(op) = next {
                        if let Operations::WeakEqual = op {
                            regs_written.push(*index);
                        } else if let Operations::Equal = op {
                            regs_written.push(*index);
                        } else {
                            regs_read.push(*index);
                        }
                    } else {
                        regs_read.push(*index);
                    }
                }
            }
        }

        let mut remove: Vec<usize> = Vec::with_capacity(16);
        for (i, word) in prev_instr.tokens.iter().enumerate() {
            if let Word::Operator(op) = word {
                if let Operations::NoOperation = op {
                    remove.push(i); // remove nops
                } else if let Operations::WeakEqual = op {
                    let reg = &prev_instr.tokens[i-1];
                    
                    if let Word::Register(index) = reg {
                        // if its written but not read
                        let mut written = false;
                        let mut read = false;

                        for regr in &regs_read {
                            if state.registers.is_sub(*regr, *index) {
                                read = true;
                                break;
                            }
                        }

                        if read {
                            continue
                        }

                        for regw in &regs_written {
                            if state.registers.is_sub(*regw, *index) {
                                written = true;
                                break;
                            }
                        }

                        if written {
                            let val = &prev_instr.tokens[i-2];
                            if let Word::Operator(op) = val {
                                match op {
                                    Operations::Zero => remove.extend(vec!(i-2, i-1, i)),
                                    Operations::Carry => remove.extend(vec!(i-3, i-2, i-1, i)),
                                    Operations::Borrow => remove.extend(vec!(i-3, i-2, i-1, i)),
                                    Operations::Parity => remove.extend(vec!(i-2, i-1, i)),
                                    Operations::Overflow => remove.extend(vec!(i-3, i-2, i-1, i)),
                                    Operations::S => remove.extend(vec!(i-3, i-2, i-1, i)),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        if remove.len() > 0 {
            let mut mut_prev_instr = prev_instr.clone();
            let mut new_tokens: Vec<Word> = Vec::with_capacity(128);

            for (i, word) in prev_instr.tokens.iter().enumerate() {
                if !remove.contains(&i) {
                    new_tokens.push(word.clone());
                }
            }

            //println!("before {:?}", mut_prev_instr.tokens);
            mut_prev_instr.tokens = new_tokens;
            //println!("after {:?}", mut_prev_instr.tokens);
            self.instructions.insert(prev_pc, mut_prev_instr);
        }
    }

    /*
     * Update the status of the state and execute the instruction at PC
     * If the instruction is hooked or the method is simulated perform the
     * respective callback. Hooks returning false will skip the instruction
     */
    #[inline]
    pub fn execute(&self, state: &mut State, pc_index: usize, instr: &Instruction, 
        status: &InstructionStatus, words: &[Word]) {

        if CHECK_PERMS {
            // this is redundant but i dont want the check itself to panic
            if !state.memory.check_permission(instr.offset, instr.size, 'x') {
                state.memory.handle_segfault(instr.offset, instr.size, 'x');
            }
        }

        let pc = instr.offset;
        let new_pc = instr.offset + instr.size;

        state.esil.pcs.clear();
        if instr.jump != 0 {
            state.esil.pcs.push(instr.jump);
        } 
        if instr.fail != 0 {
            state.esil.pcs.push(instr.fail);
        }

        match instr.type_num {
            CALL_TYPE => { state.backtrace.push(new_pc); },
            RETN_TYPE => { state.backtrace.pop(); },
            _ => {}
        }

        // shit is gettin messy
        let mut new_status = status;
        if state.status == StateStatus::PostMerge {
            if *status == InstructionStatus::Merge {
                state.status = StateStatus::Active;
                new_status = &InstructionStatus::None;
            }
        }

        match new_status {
            InstructionStatus::None => {
                let pc_val = Value::Concrete(new_pc, 0);
                state.registers.set_value(pc_index, pc_val);
                self.parse(state, words);
            },
            InstructionStatus::Hook => {
                let mut skip = false;
                let pc_val = Value::Concrete(new_pc, 0);
                state.registers.set_value(pc_index, pc_val);

                let hooks = &self.hooks[&pc];
                for hook in hooks {
                    skip = !hook(state) || skip;
                }

                if !skip {
                    self.parse(state, words);
                }
            },
            InstructionStatus::Sim => {
                let sim = &self.sims[&pc];
                let pc_val = Value::Concrete(new_pc, 0);
                state.registers.set_value(pc_index, pc_val);

                let cc = state.r2api.get_cc(pc);
                let mut args = vec!();
                for arg in cc.args {
                    args.push(state.registers.get(arg.as_str()));
                }
                let ret = sim(state, args);
                state.registers.set(cc.ret.as_str(), ret);
                state.backtrace.pop();

                // don't ret if sim changes the PC value
                // this is bad hax because thats all i do
                let newer_pc_val = state.registers.get_value(pc_index);
                if let Some(newer_pc) = newer_pc_val.as_u64() {
                    if newer_pc == new_pc {
                        self.ret(state);
                    }
                }
            },
            InstructionStatus::Break => state.status = StateStatus::Break,
            InstructionStatus::Merge => state.status = StateStatus::Merge,
            InstructionStatus::Avoid => state.status = StateStatus::Inactive
        };
    }

    // weird method that just performs a return 
    pub fn ret(&self, state: &mut State) {
        let ret_esil = state.r2api.get_ret();
        self.parse_expression(state, ret_esil.as_str());
    }

    // get the instruction, set its status, tokenize if necessary
    // and optimize if enabled 
    pub fn execute_instruction(&mut self, state: &mut State, 
        pc_index: usize, pc_val: u64) {
        
        let instr_opt = self.instructions.get(&pc_val);
        
        if let Some(instr_entry) = instr_opt {
            self.print_instr(&instr_entry.instruction);
            if !ALLOW_INVALID && instr_entry.instruction.opcode == "invalid" {
                panic!("invalid instruction: {:?}", instr_entry);
            }
            //let size = instr_entry.instruction.size;
            let words = &instr_entry.tokens;
            self.execute(state, pc_index, &instr_entry.instruction, 
                &instr_entry.status, words);

        } else {
            let mut pc_tmp = pc_val;
            let instrs = state.r2api.disassemble(pc_val, INSTR_NUM);

            let mut prev: Option<u64> = None;
            for instr in instrs {
                let size = instr.size;
                let words = self.tokenize(state, &instr.esil);

                let mut status = InstructionStatus::None;
                let mut opt = self.optimized;
                if self.hooks.contains_key(&pc_tmp) {
                    status = InstructionStatus::Hook;
                } else if self.breakpoints.contains_key(&pc_tmp) {
                    status = InstructionStatus::Break;
                } else if self.mergepoints.contains_key(&pc_tmp) {
                    status = InstructionStatus::Merge;
                } else if self.avoidpoints.contains_key(&pc_tmp) {
                    status = InstructionStatus::Avoid;
                } else if self.sims.contains_key(&pc_tmp) {
                    status = InstructionStatus::Sim;
                }

                // don't optimize if hooked / bp for accuracy
                if status != InstructionStatus::None {
                    opt = false;
                }

                if pc_tmp == pc_val {
                    self.print_instr(&instr);
                    self.execute(state, pc_index, &instr, &status, &words);
                } 

                let instr_entry = InstructionEntry {
                    instruction: instr,
                    tokens: words,
                    status
                };

                if opt {
                    if let Some(prev_pc) = prev {
                        self.optimize(state, prev_pc, &instr_entry);
                    }
                    prev = Some(pc_tmp);
                }
                self.instructions.insert(pc_tmp, instr_entry);
                pc_tmp += size;
            }
        }
    }

    pub fn step(&mut self, mut state: State, duplicate: bool) -> Vec<State> {
        let pc_allocs = 32;
        let mut states: Vec<State> = Vec::with_capacity(pc_allocs);
        let pc_index = self.pc.unwrap();

        let pc_value = state.registers.get_value(pc_index);

        if let Some(pc_val) = pc_value.as_u64() {
            self.execute_instruction(&mut state, pc_index, pc_val);
        } else {
            println!("got an unexpected sym PC: {:?}", pc_value);
        }

        let new_pc = state.registers.get_value(pc_index);
        let mut pcs = Vec::with_capacity(pc_allocs);

        if self.force && state.esil.pcs.len() > 0 {
            pcs = state.esil.pcs;
            state.esil.pcs = Vec::with_capacity(pc_allocs);
        } else {
            if let Some(pc) = new_pc.as_u64() {
                pcs.push(pc)
            } else {
                let pc_val = new_pc.as_bv().unwrap();
                if self.debug {
                    println!("\nsymbolic PC: {:?}\n", pc_val);
                }
                
                if self.lazy && state.esil.pcs.len() > 0 {
                    pcs = state.esil.pcs;
                    state.esil.pcs = Vec::with_capacity(pc_allocs);
                } else {
                    pcs = state.evaluate_many(&pc_val);
                }
            }
        }

        if pcs.len() == 1 && new_pc.as_u64().is_some() {
            states.push(state);
        } else if pcs.len() > 0 {
            let last = pcs.len()-1;
            for new_pc_val in &pcs[..last] {
                let mut new_state = if duplicate { 
                    state.duplicate() 
                } else { 
                    state.clone()
                };
                if let Some(pc_val) = new_pc.as_bv() {
                    let pc_bv = new_state.translate(&pc_val).unwrap(); 
                    let a = pc_bv._eq(&new_state.bvv(*new_pc_val, pc_bv.get_width()));
                    new_state.solver.assert(&a);
                }
                new_state.registers.set_value(pc_index, Value::Concrete(*new_pc_val, 0));
                states.push(new_state);
            }
            
            let new_pc_val = pcs[last];
            if let Some(pc_val) = new_pc.as_bv() {
                let pc_bv = pc_val; 
                let a = pc_bv._eq(&state.bvv(new_pc_val, pc_bv.get_width()));
                state.solver.assert(&a);
            }
            state.registers.set_value(pc_index, Value::Concrete(new_pc_val, 0));
            states.push(state);
        }

        states
    }

    pub fn run_until(&mut self, state: State, addr: u64, avoid: Vec<u64>) -> Option<State> {
        if self.pc.is_none() {
            let pc_reg = &state.registers.aliases["PC"];
            self.pc = Some(state.registers.regs.get(
                &pc_reg.reg).unwrap().index);
        }
        let pc_register = &state.registers.indexes[self.pc.unwrap()].clone();
        let mut states = vec!(state);
        
        while !states.is_empty() {
            let current_state = if BFS {
                states.remove(0)
            } else {
                states.pop().unwrap()
            };

            let pc = &current_state.registers.values[pc_register.value_index];

            if let Some(pc_val) = pc.as_u64() {
                if pc_val == addr {
                    return Some(current_state);
                } else if avoid.contains(&pc_val) {
                    continue;
                }
            } 

            let new_states = self.step(current_state, false);
            states.extend(new_states);
        }

        None
    }

    pub fn run(&mut self, state: State, split: bool, dup: bool) -> Vec<State> {

        let mut states = vec!();
        if self.pc.is_none() {
            let pc_reg = &state.registers.aliases["PC"];
            self.pc = Some(state.registers.regs.get(
                &pc_reg.reg).unwrap().index);
        }
        states.push(state);

        // run until empty for single threaded, until split for multi
        while !states.is_empty() && (!split || states.len() == 1) {
            let current_state = if BFS {
                states.remove(0)
            } else {
                states.pop().unwrap()
            };

            match current_state.status {
                StateStatus::Active | StateStatus::PostMerge => {
                    states.extend(self.step(current_state, dup));
                },
                StateStatus::Break | StateStatus::Merge => {
                    return vec!(current_state); 
                },
                _ => {}
            }
        }

        states
    }
}
