use crate::operations::{
    do_operation, pop_concrete, pop_stack_value, pop_value, push_value, Operations, OPS,
};
use crate::r2_api::{hex_decode, CallingConvention, Instruction, Syscall};
use crate::value::Value;

use crate::state::{
    Event, EventContext, EventTrigger, ExecMode, StackItem, State, StateStatus, DO_EVENT_HOOKS,
};

use crate::sims::syscall::syscall;
use crate::sims::SimMethod;

use ahash::{AHashMap, AHashSet};
use std::collections::VecDeque;
use std::mem;
type HashMap<P, Q> = AHashMap<P, Q>;

const INSTR_NUM: usize = 64;
const COLOR: bool = false;
const CALL_TYPE: i64 = 3;
const RETN_TYPE: i64 = 5;
// const NOP_TYPE: i64 = 8;

#[derive(Debug, Clone, PartialEq)]
pub enum Word {
    Literal(Value),
    Register(usize),
    Operator(Operations),
    Unknown(String),
}

pub type HookMethod = fn(&mut State) -> bool;

#[derive(Clone)]
pub struct Processor {
    pub instructions: HashMap<u64, InstructionEntry>,
    pub hooks: HashMap<u64, Vec<HookMethod>>,
    pub esil_hooks: HashMap<u64, Vec<String>>,
    pub sims: HashMap<u64, SimMethod>,
    pub traps: HashMap<u64, SimMethod>,
    pub syscalls: HashMap<u64, Syscall>,
    pub breakpoints: AHashSet<u64>,
    pub mergepoints: AHashSet<u64>,
    pub avoidpoints: AHashSet<u64>,
    //pub visited: AHashSet<u64>,
    pub merges: HashMap<u64, State>,
    pub selfmodify: bool,
    pub optimized: bool,
    pub debug: bool,
    pub lazy: bool,
    pub force: bool,
    pub topological: bool, // execute blocks in topological sort order
    pub steps: u64,        // number of state steps
}

#[derive(Debug, Clone, PartialEq)]
pub enum InstructionStatus {
    None,
    Hook,
    ESILHook,
    Sim,
    Merge,
    Avoid,
    Break,
}

#[derive(Debug, Clone)]
pub struct InstructionEntry {
    instruction: Instruction,
    tokens: Vec<Word>,
    status: InstructionStatus, // next: Option<Arc<InstructionEntry>>
}

//const DEBUG: bool = false; // show instructions
//const LAZY:  bool = true;  // dont check sat on ite PCs
//const OPT:   bool = true;  // optimize by removing unread flag sets
//const BFS:   bool = true;    // dequeue states instead of popping

//const ALLOW_INVALID: bool = true; // Allow invalid instructions (exec as NOP)

impl Processor {
    pub fn new(
        selfmodify: bool,
        optimized: bool,
        debug: bool,
        lazy: bool,
        force: bool,
        topological: bool,
    ) -> Self {
        Processor {
            instructions: HashMap::new(),
            hooks: HashMap::new(),
            esil_hooks: HashMap::new(),
            sims: HashMap::new(),
            traps: HashMap::new(),
            syscalls: HashMap::new(),
            breakpoints: AHashSet::new(),
            mergepoints: AHashSet::new(),
            avoidpoints: AHashSet::new(),
            //visited:      AHashSet::new(),
            merges: HashMap::new(),
            selfmodify,
            optimized,
            debug,
            lazy,
            force,
            topological,
            steps: 0, //states: vec!()
        }
    }

    pub fn tokenize(&self, state: &mut State, esil: &str) -> Vec<Word> {
        let mut tokens: Vec<Word> = Vec::with_capacity(128);
        let split_esil = esil.split(',');

        for s in split_esil {
            let l = s.len();

            // nice, pretty, simple
            if let Some(register) = self.get_register(state, s) {
                tokens.push(register);
            } else if let Some(literal) = self.get_literal(s) {
                tokens.push(literal);
            } else if let Some(operator) = self.get_operator(s) {
                tokens.push(operator);

            // all this garbage is for the combo ones like ++=[8] ...
            } else if l > 1 && &s[l - 1..] == "=" && OPS.contains(&&s[..l - 1]) {
                let reg_word = tokens.pop().unwrap();
                tokens.push(reg_word.to_owned());
                let operator = self.get_operator(&s[..l - 1]).unwrap();
                tokens.push(operator);
                tokens.push(reg_word);
                tokens.push(Word::Operator(Operations::Equal));
            } else if l > 4 && &s[l - 1..] == "]" && OPS.contains(&&s[..l - 4]) {
                tokens.push(Word::Operator(Operations::AddressStore));
                let peek = self.get_operator(&s[l - 3..]).unwrap();
                tokens.push(peek);
                let operator = self.get_operator(&s[..l - 4]).unwrap();
                tokens.push(operator);
                let poke = self.get_operator(&s[l - 4..]).unwrap();
                tokens.push(Word::Operator(Operations::AddressRestore));
                tokens.push(poke);
            } else if let Some(values) = state.context.get(s) {
                tokens.extend(
                    values
                        .iter()
                        .map(|x| Word::Literal(state.translate_value(x))),
                );
            } else {
                tokens.push(Word::Unknown(String::from(s)));
            }
        }

        tokens
    }

    /// attempt to tokenize word as number literal (eg. 0x8)
    pub fn get_literal(&self, word: &str) -> Option<Word> {
        if let Ok(i) = word.parse::<u64>() {
            Some(Word::Literal(Value::Concrete(i, 0)))
        } else if word.len() > 2 && &word[0..2] == "0x" {
            let val = u64::from_str_radix(&word[2..word.len()], 16).unwrap();
            Some(Word::Literal(Value::Concrete(val, 0)))
        } else if let Ok(i) = word.parse::<i64>() {
            Some(Word::Literal(Value::Concrete(i as u64, 0)))
        } else {
            None
        }
    }

    /// attempt to tokenize word as register (eg. rbx)
    pub fn get_register(&self, state: &mut State, word: &str) -> Option<Word> {
        let name = if let Some(alias) = state.registers.aliases.get(word) {
            alias.reg.as_str()
        } else {
            word
        };
        state
            .registers
            .get_register(name)
            .map(|reg| Word::Register(reg.index))
    }

    /// attempt to tokenize word as operation (eg. +)
    pub fn get_operator(&self, word: &str) -> Option<Word> {
        match Operations::from_string(word) {
            Operations::Unknown => None,
            op => Some(Word::Operator(op)),
        }
    }

    /// print instruction if debug output is enabled
    pub fn print_instr(&self, state: &mut State, instr: &Instruction) {
        if !COLOR {
            println!(
                "{:016x}:  {:<40} |  {}",
                instr.offset, instr.disasm, instr.esil
            );
        } else {
            print!(
                "{}",
                state
                    .r2api
                    .cmd(&format!("pd 1 @ {}", instr.offset))
                    .unwrap()
            );
        }
    }

    // perform an emulated syscall using the definitions in syscall.rs
    pub fn do_syscall(&self, state: &mut State) {
        let sys_val = state.registers.get_with_alias("SN");
        let sys_num = state.solver.evalcon_to_u64(&sys_val).unwrap();
        //let pc = state.registers.get_pc().as_u64().unwrap();

        if let Some(sys) = self.syscalls.get(&sys_num) {
            let cc = state.r2api.get_syscall_cc().unwrap();
            let mut args = Vec::with_capacity(8);
            for arg in cc.args {
                args.push(state.registers.get(arg.as_str()));
            }
            let ret = syscall(sys.name.as_str(), state, &args);
            state.registers.set(cc.ret.as_str(), ret);
        }
    }

    // for one-off parsing of strings
    pub fn parse_expression(&self, state: &mut State, esil: &str) {
        let words = self.tokenize(state, esil);
        self.parse(state, &words);
    }

    /**
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

        while word_index < words_len {
            let word = &words[word_index];
            word_index += 1;

            // this is weird...
            if state.esil.mode == ExecMode::NoExec {
                match &word {
                    Word::Operator(Operations::Else) | Word::Operator(Operations::EndIf) => {}
                    _ => continue,
                }
            }

            match word {
                Word::Literal(val) => {
                    state.stack.push(StackItem::StackValue(val.to_owned()));
                }
                Word::Register(index) => {
                    state.stack.push(StackItem::StackRegister(*index));
                }
                Word::Operator(op) => {
                    match op {
                        Operations::If => {
                            let arg1 = pop_value(state, false, false);

                            match (arg1, &state.esil.mode) {
                                (Value::Concrete(val1, _t), ExecMode::Uncon) => {
                                    state.esil.mode = if val1 == 0 {
                                        ExecMode::NoExec
                                    } else {
                                        ExecMode::Exec
                                    };
                                }
                                (Value::Symbolic(val1, _t), ExecMode::Uncon) => {
                                    //println!("if {:?}", val1);
                                    state.esil.mode = ExecMode::If;
                                    state.esil.temp1 = state.stack.to_owned();
                                    let cond_bv = val1._eq(&state.bvv(0, val1.get_width())).not();

                                    state.condition = Some(cond_bv);
                                }
                                _ => {
                                    println!("Bad ESIL?");
                                }
                            }
                        }
                        Operations::Else => match &state.esil.mode {
                            ExecMode::Exec => state.esil.mode = ExecMode::NoExec,
                            ExecMode::NoExec => state.esil.mode = ExecMode::Exec,
                            ExecMode::If => {
                                state.esil.mode = ExecMode::Else;
                                state.condition = Some(state.condition.as_ref().unwrap().not());
                                state.esil.temp2 = mem::take(&mut state.stack);
                                state.stack = mem::take(&mut state.esil.temp1);
                            }
                            _ => {}
                        },
                        Operations::EndIf => {
                            match &state.esil.mode {
                                ExecMode::If | ExecMode::Else => {}
                                _ => {
                                    state.esil.mode = ExecMode::Uncon;
                                    continue;
                                }
                            };

                            let mut new_temp = match &state.esil.mode {
                                ExecMode::If => mem::take(&mut state.esil.temp1),
                                ExecMode::Else => mem::take(&mut state.esil.temp2),
                                _ => vec![], // won't happen
                            };

                            // this is weird but just a trick to not have to alloc a new vec
                            let mut new_stack = mem::take(&mut state.esil.temp1);
                            let mut old_stack = mem::take(&mut state.stack);
                            while !old_stack.is_empty() && !new_temp.is_empty() {
                                let if_val = pop_stack_value(state, &mut old_stack, false, false);
                                let else_val = pop_stack_value(state, &mut new_temp, false, false);
                                let cond_val = state.solver.conditional(
                                    &Value::Symbolic(
                                        state.condition.as_ref().unwrap().to_owned(),
                                        0,
                                    ),
                                    &if_val,
                                    &else_val,
                                );

                                new_stack.push(StackItem::StackValue(cond_val));
                            }

                            new_stack.reverse();
                            state.stack = new_stack;
                            state.condition = None;

                            state.esil.mode = ExecMode::Uncon;
                        }
                        Operations::GoTo => {
                            let n = pop_concrete(state, false, false);
                            if let Some(_cond) = &state.condition {
                                println!("Hit symbolic GOTO");
                                state.set_inactive(); // take the easy way out
                                break;
                                //cond.assert();
                            }
                            state.esil.mode = ExecMode::Uncon;
                            word_index = n as usize;
                        }
                        Operations::Break => {
                            if let Some(_cond) = &state.condition {
                                println!("Hit symbolic BREAK");
                                state.set_inactive();
                                //cond.assert();
                            }
                            state.esil.mode = ExecMode::Uncon;
                            break;
                        }
                        Operations::Trap => {
                            let trap = pop_concrete(state, false, false);
                            //let pc = state.registers.get_pc().as_u64().unwrap();

                            let sys_val = state.registers.get_with_alias("SN");
                            if let Some(trap_sim) = self.traps.get(&trap) {
                                // provide syscall args
                                let cc = state.r2api.get_syscall_cc().unwrap();
                                let mut args = vec![sys_val];
                                for arg in cc.args {
                                    args.push(state.registers.get(arg.as_str()));
                                }
                                let ret = trap_sim(state, &args);
                                state.registers.set(cc.ret.as_str(), ret);
                            }
                        }
                        Operations::Syscall => self.do_syscall(state),
                        _ => do_operation(state, op),
                    }
                }
                Word::Unknown(s) => {
                    push_value(state, Value::Concrete(0, 0));
                    println!("Unknown word: {}", s);
                }
            }
        }
    }

    /// removes words that weak set flag values that are never read, and words that are NOPs
    pub fn optimize(&mut self, state: &mut State, prev_pc: u64, curr_instr: &InstructionEntry) {
        let prev_instr = &self.instructions[&prev_pc];
        if !prev_instr
            .tokens
            .contains(&Word::Operator(Operations::WeakEqual))
            || !curr_instr
                .tokens
                .contains(&Word::Operator(Operations::WeakEqual))
        {
            return;
        }

        let mut regs_read: Vec<usize> = Vec::with_capacity(16);
        let mut regs_written: Vec<usize> = Vec::with_capacity(16);

        let len = curr_instr.tokens.len();
        for (i, word) in curr_instr.tokens.iter().enumerate() {
            if let Word::Register(index) = word {
                if i + 1 < len {
                    let next = &curr_instr.tokens[i + 1];
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

        let mut remove: Vec<usize> = Vec::with_capacity(32);
        for (i, word) in prev_instr.tokens.iter().enumerate() {
            if let Word::Operator(op) = word {
                if let Operations::NoOperation = op {
                    remove.push(i); // remove nops
                } else if let Operations::WeakEqual = op {
                    let reg = &prev_instr.tokens[i - 1];
                    if let Word::Register(index) = reg {
                        if !regs_read.iter().any(|r| state.registers.is_sub(*r, *index))
                            && regs_written
                                .iter()
                                .any(|r| state.registers.is_sub(*r, *index))
                        {
                            let val = &prev_instr.tokens[i - 2];
                            if let Word::Operator(op) = val {
                                match op {
                                    Operations::Zero => remove.extend(vec![i - 2, i - 1, i]),
                                    Operations::Carry => {
                                        remove.extend(vec![i - 3, i - 2, i - 1, i])
                                    }
                                    Operations::Borrow => {
                                        remove.extend(vec![i - 3, i - 2, i - 1, i])
                                    }
                                    Operations::Parity => remove.extend(vec![i - 2, i - 1, i]),
                                    Operations::Overflow => {
                                        remove.extend(vec![i - 3, i - 2, i - 1, i])
                                    }
                                    Operations::S => remove.extend(vec![i - 3, i - 2, i - 1, i]),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        if !remove.is_empty() {
            let mut mut_prev_instr = prev_instr.to_owned();
            let mut new_tokens: Vec<Word> = Vec::with_capacity(128);

            for (i, word) in prev_instr.tokens.iter().enumerate() {
                if !remove.contains(&i) {
                    new_tokens.push(word.to_owned());
                }
            }
            mut_prev_instr.tokens = new_tokens;
            self.instructions.insert(prev_pc, mut_prev_instr);
        }
    }

    pub fn get_args(&self, state: &mut State, cc: &CallingConvention) -> Vec<Value> {
        let mut args = Vec::with_capacity(16);

        if !cc.args.is_empty() {
            for arg in &cc.args {
                args.push(state.registers.get_with_alias(arg));
            }
        } else {
            // read args from stack?
            let mut sp = state.registers.get_with_alias("SP");
            let length = state.memory.bits as usize / 8;

            for _ in 0..8 {
                // do 8 idk?
                sp = sp + Value::Concrete(length as u64, 0);
                let value = state.memory_read_value(&sp, length);
                args.push(value);
            }
        }

        args
    }

    /**
     * Update the status of the state and execute the instruction at PC
     * If the instruction is hooked or the method is simulated perform the
     * respective callback. Hooks returning false will skip the instruction
     */
    pub fn execute(
        &self,
        state: &mut State,
        instr: &Instruction,
        status: &InstructionStatus,
        words: &[Word],
    ) {
        if state.memory.check && !state.memory.check_permission(instr.offset, instr.size, 'x') {
            state.memory.handle_segfault(instr.offset, instr.size, 'x');
        }

        let pc = instr.offset;
        let new_pc = instr.offset + instr.size;

        state.esil.pcs.clear();
        if instr.jump != 0 {
            state.esil.pcs.push(instr.jump as u64);

            if instr.fail != 0 {
                state.esil.pcs.push(instr.fail as u64);
            }
        }

        // shit is gettin messy
        let mut new_status = status;
        if state.status == StateStatus::PostMerge && *status == InstructionStatus::Merge {
            state.status = StateStatus::Active;
            new_status = &InstructionStatus::None;
        }

        match instr.type_num {
            CALL_TYPE => state.backtrace.push((instr.jump as u64, new_pc)),
            RETN_TYPE => {
                if state.backtrace.is_empty() && new_status == &InstructionStatus::None {
                    // try to avoid returning outside valid context
                    if !self.breakpoints.is_empty() {
                        new_status = &InstructionStatus::Avoid;
                    } else {
                        // break if there are no other breakpoints
                        new_status = &InstructionStatus::Break;
                    }
                } else {
                    state.backtrace.pop();
                }
            }
            _ => {}
        }

        match new_status {
            InstructionStatus::None => {
                let pc_val = Value::Concrete(new_pc, 0);
                state.registers.set_pc(pc_val);
                self.parse(state, words);
            }
            InstructionStatus::Hook => {
                let mut skip = false;
                let pc_val = Value::Concrete(new_pc, 0);
                state.registers.set_pc(pc_val);

                let hooks = &self.hooks[&pc];
                for hook in hooks {
                    skip = !hook(state) || skip;
                }

                if !skip {
                    self.parse(state, words);
                }
            }
            InstructionStatus::ESILHook => {
                let mut skip = false;
                let pc_val = Value::Concrete(new_pc, 0);
                state.registers.set_pc(pc_val);

                let esils = &self.esil_hooks[&pc];
                for esil in esils {
                    self.parse_expression(state, esil);
                    let val = pop_concrete(state, false, false);
                    skip = (val != 0) || skip;
                }

                if !skip {
                    self.parse(state, words);
                }
            }
            InstructionStatus::Sim => {
                let sim = &self.sims[&pc];
                let cc = state.r2api.get_cc(pc).unwrap_or_default();
                let args = self.get_args(state, &cc);

                let pc_val = Value::Concrete(new_pc, 0);
                state.registers.set_pc(pc_val);

                let ret = sim(state, &args);
                state.registers.set_with_alias(cc.ret.as_str(), ret);
                state.backtrace.pop();

                // don't ret if sim changes the PC value
                // this is bad hax because thats all i do
                let newer_pc_val = state.registers.get_pc();
                if let Some(newer_pc) = newer_pc_val.as_u64() {
                    if newer_pc == new_pc {
                        self.ret(state);
                    }
                }
            }
            InstructionStatus::Break => state.status = StateStatus::Break,
            InstructionStatus::Merge => state.status = StateStatus::Merge,
            InstructionStatus::Avoid => state.status = StateStatus::Inactive,
        };
    }

    // weird method that just performs a return
    pub fn ret(&self, state: &mut State) {
        let ret_esil = state.r2api.get_ret().unwrap();
        self.parse_expression(state, ret_esil.as_str());
    }

    // get the instruction, set its status, tokenize if necessary
    // and optimize if enabled. TODO this has become so convoluted, fix it
    pub fn fetch_instruction(&mut self, state: &mut State, pc_val: u64) {
        let has_instr = self.instructions.contains_key(&pc_val);
        if self.selfmodify || !has_instr {
            let mut pc_tmp = pc_val;
            let instrs = if self.selfmodify {
                let data = state.memory_read_bytes(pc_val, 32);
                // 1 at a time for selfmodify
                // check to see if bytes changed
                if has_instr {
                    let instr = &self.instructions[&pc_val];
                    let bytes = hex_decode(&instr.instruction.bytes);
                    if bytes == data[..bytes.len()].to_vec() {
                        // nothing needs to be done but this is
                        // such a weird construction. i hate this code
                        return;
                    }
                }
                state.r2api.disassemble_bytes(pc_val, &data, 1).unwrap()
            } else {
                state.r2api.disassemble(pc_val, INSTR_NUM).unwrap()
            };

            let mut prev: Option<u64> = None;
            for instr in instrs {
                let size = instr.size;
                let words = self.tokenize(state, &instr.esil);

                let mut status = InstructionStatus::None;
                let mut opt = self.optimized && !self.selfmodify;
                if self.hooks.contains_key(&pc_tmp) {
                    status = InstructionStatus::Hook;
                } else if self.esil_hooks.contains_key(&pc_tmp) {
                    status = InstructionStatus::ESILHook;
                } else if self.breakpoints.contains(&pc_tmp) {
                    status = InstructionStatus::Break;
                } else if self.mergepoints.contains(&pc_tmp) {
                    status = InstructionStatus::Merge;
                } else if self.avoidpoints.contains(&pc_tmp) {
                    status = InstructionStatus::Avoid;
                } else if self.sims.contains_key(&pc_tmp) {
                    status = InstructionStatus::Sim;
                }

                // don't optimize if hooked / bp for accuracy
                if status != InstructionStatus::None {
                    opt = false;
                }

                let instr_entry = InstructionEntry {
                    instruction: instr,
                    tokens: words,
                    status,
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

    pub fn execute_instruction(&mut self, state: &mut State, pc_val: u64) {
        self.fetch_instruction(state, pc_val);

        // the hash lookup is done twice, needs fixing
        let instr = self.instructions.get(&pc_val).unwrap();

        if self.debug {
            self.print_instr(state, &instr.instruction);
        }
        if state.strict && instr.instruction.disasm == "invalid" {
            panic!("Executed invalid instruction");
        }

        self.execute(state, &instr.instruction, &instr.status, &instr.tokens);
    }

    /// Take single step with the state provided
    pub fn step(&mut self, state: &mut State) -> Vec<State> {
        self.steps += 1;

        let pc_allocs = 32;
        let pc_value = state.registers.get_pc();

        if let Some(pc_val) = pc_value.as_u64() {
            self.execute_instruction(state, pc_val);
        } else {
            panic!("got an unexpected sym PC: {:?}", pc_value);
        }

        let new_pc = state.registers.get_pc();
        //let pcs;

        if self.force && !state.esil.pcs.is_empty() {
            // we just use the pcs in state.esil.pcs
        } else if let Some(pc) = new_pc.as_u64() {
            state.esil.pcs.clear();
            state.esil.pcs.push(pc);
        } else {
            let pc_val = new_pc.as_bv().unwrap();
            if self.debug {
                println!("\nsymbolic PC: {:?}\n", pc_val);
            }

            if DO_EVENT_HOOKS && state.has_event_hooks {
                state.do_hooked(
                    &Event::SymbolicExec(EventTrigger::Before),
                    &EventContext::ExecContext(new_pc.clone()),
                );
            }

            if !self.lazy && !state.esil.pcs.is_empty() {
                // testing sat without modelgen is a bit faster than evaluating
                state.esil.pcs = state
                    .esil
                    .pcs
                    .clone()
                    .into_iter()
                    .filter(|x| state.check(&new_pc.eq(&Value::Concrete(*x, 0))))
                    .collect();
            } else if state.esil.pcs.is_empty() {
                state.esil.pcs = state.evaluate_many(&pc_val);
            }

            if DO_EVENT_HOOKS && state.has_event_hooks {
                state.do_hooked(
                    &Event::SymbolicExec(EventTrigger::After),
                    &EventContext::ExecContext(new_pc.clone()),
                );
            }
        }

        if state.esil.pcs.len() > 1 || new_pc.as_u64().is_none() {
            let mut states: Vec<State> = Vec::with_capacity(pc_allocs);

            let last = state.esil.pcs.len() - 1;
            for new_pc_val in &state.esil.pcs[..last] {
                let mut new_state = state.clone();
                if let Some(pc_val) = new_pc.as_bv() {
                    let a = pc_val._eq(&new_state.bvv(*new_pc_val, pc_val.get_width()));
                    new_state.solver.assert(&a);
                }
                new_state.registers.set_pc(Value::Concrete(*new_pc_val, 0));
                states.push(new_state);
            }

            let new_pc_val = state.esil.pcs[last];
            if let Some(pc_val) = new_pc.as_bv() {
                let pc_bv = pc_val;
                let a = pc_bv._eq(&state.bvv(new_pc_val, pc_bv.get_width()));
                state.solver.assert(&a);
            }
            state.registers.set_pc(Value::Concrete(new_pc_val, 0));
            states
        } else {
            vec![]
        }
    }

    /// run the state until a breakpoint is hit or state split
    pub fn run(&mut self, state: State, split: bool) -> VecDeque<State> {
        let mut states = VecDeque::with_capacity(state.solver.eval_max);
        states.push_back(state);

        // run until empty for single threaded, until split for multi
        let mut index = 0;
        while !split || (states.len() == 1) {
            if states.is_empty() {
                if self.merges.is_empty() {
                    return VecDeque::new();
                } else {
                    // pop one out of mergers
                    let key = *self.merges.keys().next().unwrap();
                    let mut merge = self.merges.remove(&key).unwrap();
                    merge.status = StateStatus::PostMerge;
                    states.push_back(merge)
                }
            }

            let current_state = &mut states[index];

            match current_state.status {
                StateStatus::Active | StateStatus::PostMerge => {
                    let new_states = self.step(current_state);
                    for s in new_states {
                        states.push_front(s);
                        index += 1;
                    }
                    index += 1;
                }
                StateStatus::Merge => {
                    self.merge(states.remove(index).unwrap());
                }
                StateStatus::Break => {
                    if current_state.is_sat() {
                        return VecDeque::from(vec![states.remove(index).unwrap()]);
                    } else {
                        states.remove(index).unwrap();
                    }
                }
                _ => {
                    states.remove(index).unwrap();
                }
            }
            index = if states.is_empty() {
                0
            } else {
                index % states.len()
            };
        }

        states
    }

    pub fn merge(&mut self, mut state: State) {
        let pc = state.registers.get_with_alias("PC").as_u64().unwrap();

        let has_pc = self.merges.contains_key(&pc);
        if !has_pc {
            // trick clippy idk
            self.merges.insert(pc, state);
        } else {
            let mut merge_state = self.merges.remove(&pc).unwrap();
            let state_asserts = state.solver.assertions.clone();
            let assertion = state.solver.and_all(&state_asserts);
            let asserted = Value::Symbolic(assertion.clone(), 0);

            // merge registers
            let mut new_regs = Vec::with_capacity(256);
            let reg_count = state.registers.values.len();
            for index in 0..reg_count {
                let reg = &merge_state.registers.values[index];
                let curr_reg = state.registers.values[index].clone();
                new_regs.push(state.solver.conditional(&asserted, &curr_reg, &reg));
            }
            merge_state.registers.values = new_regs;

            // merge memory
            let mut new_mem = HashMap::new();
            let merge_addrs = merge_state.memory.addresses();
            let state_addrs = state.memory.addresses();

            let mut addrs = Vec::with_capacity(state.solver.eval_max);
            addrs.extend(merge_addrs);
            addrs.extend(state_addrs);
            for addr in addrs {
                let mem = &merge_state.memory.read_value(addr, 1);
                let curr_mem = state.memory.read_value(addr, 1);
                new_mem.insert(addr, state.solver.conditional(&asserted, &curr_mem, mem));
            }
            merge_state.memory.mem = new_mem;

            // merge solvers
            let assertions = merge_state.solver.assertions.clone();
            let current = state.solver.and_all(&assertions);
            merge_state.solver.reset();
            merge_state.assert(&current.or(&assertion));
            self.merges.insert(pc, merge_state);
        }
    }
}
