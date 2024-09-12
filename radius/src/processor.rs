use crate::operations::{do_operation, pop_concrete, pop_value, Operation, OPS};
use crate::r2_api::{hex_decode, CallingConvention, Instruction, Syscall};
use crate::sims::syscall::syscall;
use crate::sims::{Sim, SimMethod};
use crate::state::{EsilIteContext, StackItem, State, StateStatus};
use crate::value::{vc, Value};

use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::iter::Extend;
use std::mem;
use std::ops::Not;
use std::rc::Rc;

use colored::*;

/// Number of instructions to disassemble on a instruction cache miss.
const INSTR_NUM: usize = 64;
/// ESILs internal identifier for "call-like" instructions.
const CALL_TYPE: i64 = 3;
/// ESILs internal identifier for "return-like" instructions.
const RETN_TYPE: i64 = 5;

#[derive(Debug, Clone, PartialEq)]
pub enum Word {
    Literal(Value),
    Register(usize),
    Operator(Operation),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunMode {
    /// Runs until some state hits a BP.
    Single,
    /// Runs the state for a single step.
    Step,
    /// Runs the state until it splits or hits a BP.
    Parallel,
    /// Runs until there are no more states that can take a step.
    ///
    /// Does NOT immediately return if a breakpoint is hit.
    Multiple,
}

pub type HookMethod = fn(&mut State) -> bool;

/// An abstract processor that can be used to run different symbolic states.
///
/// Takes case of things like:
/// - running user-defined hooks,
/// - handling special events like breakpoints, interrupts, syscalls, traps,
/// - caching instructions,
/// - merging states,
/// - avoiding paths,
/// - some other settings
#[derive(Clone)]
pub struct Processor {
    pub instructions: BTreeMap<u64, InstructionEntry>,
    pub hooks: HashMap<u64, Vec<HookMethod>>,
    pub esil_hooks: HashMap<u64, Vec<String>>,
    pub sims: HashMap<u64, Sim>,
    pub traps: HashMap<u64, SimMethod>,
    pub interrupts: HashMap<u64, SimMethod>,
    pub syscalls: HashMap<u64, Syscall>,
    pub breakpoints: HashSet<u64>,
    pub mergepoints: HashSet<u64>,
    pub avoidpoints: HashSet<u64>,
    pub visited: HashSet<u64>,
    pub merges: BTreeMap<u64, State>,
    pub crashes: Vec<State>,
    pub selfmodify: bool,
    pub optimized: bool,
    pub debug: bool,
    pub lazy: bool,
    pub force: bool,
    pub automerge: bool,
    pub color: bool,
    pub topological: bool, // execute blocks in topological sort order
    pub steps: u64,        // number of state steps
}

/// Signals special actions to be taken when encountering a particular
/// instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InstructionFlag {
    Hook,
    ESILHook,
    Sim,
    Merge,
    Avoid,
    Break,
}

/// A particular instruction in the program.
///
/// Also includes tokenized ESIL and flags.
#[derive(Debug, Clone)]
pub struct InstructionEntry {
    pub instruction: Instruction,
    pub tokens: Vec<Word>,
    pub flags: HashSet<InstructionFlag>,
}

impl Processor {
    pub fn new(
        selfmodify: bool,
        optimized: bool,
        debug: bool,
        lazy: bool,
        force: bool,
        topological: bool,
        automerge: bool,
        color: bool,
    ) -> Self {
        Processor {
            instructions: BTreeMap::new(),
            hooks: HashMap::new(),
            esil_hooks: HashMap::new(),
            sims: HashMap::new(),
            traps: HashMap::new(),
            interrupts: HashMap::new(),
            syscalls: HashMap::new(),
            breakpoints: HashSet::new(),
            mergepoints: HashSet::new(),
            avoidpoints: HashSet::new(),
            visited: HashSet::new(),
            merges: BTreeMap::new(),
            crashes: vec![],
            selfmodify,
            optimized,
            debug,
            lazy,
            force,
            topological,
            automerge,
            color,
            steps: 0, //states: vec!()
        }
    }

    /// Parse the `esil` line into a stream of tokens that can be executed.
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
                tokens.push(Word::Operator(Operation::Equal));
            } else if l > 4 && &s[l - 1..] == "]" && OPS.contains(&&s[..l - 4]) {
                tokens.push(Word::Operator(Operation::AddressStore));
                let peek = self.get_operator(&s[l - 3..]).unwrap();
                tokens.push(peek);
                let operator = self.get_operator(&s[..l - 4]).unwrap();
                tokens.push(operator);
                let poke = self.get_operator(&s[l - 4..]).unwrap();
                tokens.push(Word::Operator(Operation::AddressRestore));
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

    /// Attempt to tokenize word as number literal (eg. 0x8).
    #[inline]
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

    /// Attempt to tokenize word as register (eg. rbx).
    #[inline]
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

    /// Attempt to tokenize word as operation (eg. +).
    #[inline]
    pub fn get_operator(&self, word: &str) -> Option<Word> {
        match Operation::from_string(word) {
            Operation::Unknown => None,
            op => Some(Word::Operator(op)),
        }
    }

    /// Print instruction if debug output is enabled.
    pub fn print_instr(&self, state: &mut State, instr: &Instruction) {
        if let Some(sim) = self.sims.get(&instr.offset) {
            println!(
                "\n0x{:08x}      ( {} {} )\n",
                instr.offset,
                "simulated",
                sim.symbol.blue()
            );
        } else if !self.color {
            println!(
                "0x{:08x}      {:<40} |  {}",
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

    /// Perform an emulated syscall using the definitions in syscall.rs.
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

    /// Parse and execute the untokenized ESIL line.
    pub fn parse_expression(&self, state: &mut State, esil: &str) {
        let words = self.tokenize(state, esil);
        self.parse(state, words.as_slice());
    }

    /// Parse and execute the vector of tokenized ESIL words.
    ///
    /// Before calling this function, PC must be set to the first byte __after__
    /// the instruction that corresponds to `words`. This is what ESIL
    /// expects.
    ///
    /// Execution of the ESIL may cause the `state` to fork. Any additional
    /// states may also generate more states. All returned states are either
    /// run till the end of the current line or became unsat along the way.
    pub fn parse(&self, state: &mut State, words: &[Word]) -> Vec<State> {
        state.stack.clear();

        // Running a state may generate additional states if there are
        // conditionals for which both branches are feasible.
        // But usually there won't be so we don't preallocate.
        let mut additional_states: Vec<(State, usize)> = Vec::with_capacity(0);

        // States that we are actively exploring via `worklist_refs`.
        let mut worklist: Vec<(State, usize)> = Vec::with_capacity(0);

        // States that were generated while driving a state down the line and
        // postponed for later exploration.
        let mut generated_states: Vec<(State, usize)> = Vec::with_capacity(0);

        // Pointers into worklist so that we can handle the initial ref and
        // generated (owned) states on the same footing.
        // (state, index of next word to be executed on this state)
        let mut worklist_refs: Vec<(&mut State, usize)> = vec![(state, 0)];

        loop {
            // Select a state to run, stop if there are no more.
            if worklist_refs.is_empty() {
                // `worklist_refs` being empty implies that we have driven all
                // states in `worklist` till the end.
                additional_states.append(&mut worklist);
                // Refill `worklist` from `generated_states`.
                mem::swap(&mut generated_states, &mut worklist);
                worklist_refs = worklist.iter_mut().map(|(s, i)| (s, *i)).collect();
                if worklist_refs.is_empty() {
                    // We are done.
                    break;
                }
            }
            let (cur_state, mut word_index) = worklist_refs.pop().unwrap();

            // Drive the selected state till the end. Collect all states that
            // are generated along the way.
            while let Some(word) = words.get(word_index) {
                word_index += 1;

                // Skips words inside conditional if we know for sure that they
                // will not be executed.
                if cur_state.esil.exec_ctx == EsilIteContext::NoExec {
                    match &word {
                        Word::Operator(Operation::Else) | Word::Operator(Operation::EndIf) => {}
                        _ => continue,
                    }
                }

                match word {
                    Word::Literal(val) => {
                        cur_state.stack.push(StackItem::StackValue(val.to_owned()));
                    }
                    Word::Register(index) => {
                        cur_state.stack.push(StackItem::StackRegister(*index));
                    }
                    Word::Operator(op) => {
                        match op {
                            Operation::If => {
                                // A GOTO got us in front of this ITE.
                                if matches!(cur_state.esil.exec_ctx, EsilIteContext::Goto) {
                                    cur_state.esil.exec_ctx = EsilIteContext::UnCon;
                                }

                                assert_eq!(
                                    cur_state.esil.exec_ctx,
                                    EsilIteContext::UnCon,
                                    "Nested conditional."
                                );

                                // Get the condition.
                                let cond_item = pop_value(cur_state, false, false);

                                // We only go down a branch if we can prove that it
                                // is possible under the current path constraints.
                                let do_if_case = cur_state.check(&cond_item.eq(&vc(0)).not());
                                let do_else_case = cur_state.check(&cond_item.eq(&vc(0)));

                                print!("[PARSE] Encountered ITE at word {}: ", word_index);
                                match (do_if_case, do_else_case) {
                                    (true, true) => {
                                        println!("both branches are feasible.");
                                        // We must fork the current state.

                                        // Use the current state to go down the
                                        // IF case,
                                        cur_state.esil.exec_ctx = EsilIteContext::Exec;

                                        // Fork state and let it go down the
                                        // ELSE case.
                                        let mut else_state = cur_state.fork(
                                            cur_state.esil.insn_address.as_u64().unwrap(),
                                            (word_index - 1) as u32,
                                            cond_item.clone(),
                                        );
                                        else_state.esil.exec_ctx = EsilIteContext::NoExec;

                                        println!(
                                            "[PARSE] Forked state: parent {:x}, child {:x}",
                                            cur_state.uid, else_state.uid
                                        );

                                        // Record path conditions.
                                        cur_state.assert(&cond_item.eq(&vc(0)).not());
                                        let tmp_cond = else_state
                                            .solver
                                            .translate_value(&cond_item.eq(&vc(0)));
                                        else_state.assert(&tmp_cond);

                                        // Postpone exploration of this branch
                                        // for later.
                                        generated_states.push((else_state, word_index));
                                    }
                                    (true, false) => {
                                        println!("only IF branch is feasible.");
                                        // Do IF. Skip over ELSE.
                                        cur_state.esil.exec_ctx = EsilIteContext::Exec;

                                        // Record path conditions.
                                        // Not redundant since ELSE case might have
                                        // timed out.
                                        cur_state.assert(&cond_item.eq(&vc(0)).not());
                                    }
                                    (false, true) => {
                                        println!("only ELSE branch is feasible.");
                                        // Skip over IF. Do ELSE.
                                        cur_state.esil.exec_ctx = EsilIteContext::NoExec;

                                        // Record path conditions.
                                        // Not redundant since IF case might have
                                        // timed out.
                                        cur_state.assert(&cond_item.eq(&vc(0)));
                                    }
                                    (false, false) => {
                                        // We cannot prove that there is a feasible
                                        // branch.
                                        cur_state.status = StateStatus::Unsat;
                                        // Stop running it.
                                        break;
                                    }
                                }
                            }
                            Operation::Else => match &cur_state.esil.exec_ctx {
                                // Current state took the IF-branch. Skip ELSE.
                                EsilIteContext::Exec => {
                                    cur_state.esil.exec_ctx = EsilIteContext::NoExec
                                }
                                // We jumped into an IF-case. Skip ELSE.
                                EsilIteContext::Goto => {
                                    cur_state.esil.exec_ctx = EsilIteContext::NoExec
                                }
                                // Current state takes the ELSE-branch.
                                EsilIteContext::NoExec => {
                                    cur_state.esil.exec_ctx = EsilIteContext::Exec
                                }
                                EsilIteContext::UnCon => {
                                    panic!("Bad ESIL?")
                                }
                            },
                            Operation::EndIf => {
                                match &cur_state.esil.exec_ctx {
                                    EsilIteContext::Goto
                                    | EsilIteContext::Exec
                                    | EsilIteContext::NoExec => {
                                        // Return to regular parsing.
                                        cur_state.esil.exec_ctx = EsilIteContext::UnCon;
                                    }
                                    EsilIteContext::UnCon => {
                                        panic!("Bad ESIL?")
                                    }
                                };
                            }
                            Operation::GoTo => {
                                // We do __not__ fork on symbolic GOTOs. We
                                // simply go down one feasible branch. We add
                                // this concretization to the path constraints.
                                // Panics if we find no solution.
                                let n = pop_concrete(cur_state, false, false);
                                word_index = n as usize;
                                cur_state.esil.exec_ctx = EsilIteContext::Goto;
                            }
                            Operation::Interrupt
                            | Operation::Trap
                            | Operation::Syscall
                            | Operation::Break => {
                                panic!("Unsupported operation: {:?}", op);
                            }
                            _ => do_operation(cur_state, op),
                        }
                    }
                    Word::Unknown(s) => {
                        panic!("Unknown word: {}", s);
                    }
                }
            }
        }

        additional_states.into_iter().map(|(s, _)| s).collect()
    }

    /// removes words that weak set flag values that are never read, and words that are NOPs
    /// really need to refactor this mess but every time i try it gets slower
    pub fn optimize(&mut self, state: &mut State, prev_pc: u64, curr_instr: &InstructionEntry) {
        let prev_instr = &self.instructions[&prev_pc];
        if !prev_instr
            .tokens
            .contains(&Word::Operator(Operation::WeakEqual))
            || !curr_instr
                .tokens
                .contains(&Word::Operator(Operation::WeakEqual))
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
                        match op {
                            Operation::WeakEqual | Operation::Equal => {
                                regs_written.push(*index);
                            }
                            _ => regs_read.push(*index),
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
                if let Operation::NoOperation = op {
                    remove.push(i); // remove nops
                } else if let Operation::WeakEqual = op {
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
                                    Operation::Zero => remove.extend(vec![i - 2, i - 1, i]),
                                    Operation::Carry => remove.extend(vec![i - 3, i - 2, i - 1, i]),
                                    Operation::Borrow => {
                                        remove.extend(vec![i - 3, i - 2, i - 1, i])
                                    }
                                    Operation::Parity => remove.extend(vec![i - 2, i - 1, i]),
                                    Operation::Overflow => {
                                        remove.extend(vec![i - 3, i - 2, i - 1, i])
                                    }
                                    Operation::S => remove.extend(vec![i - 3, i - 2, i - 1, i]),
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

    /// Update the status of the `state` according to the effects of the
    /// instruction.
    ///
    /// Returns any additional states that are generated as a consequence of
    /// the update.
    pub fn execute(
        &self,
        state: &mut State,
        instr: &Instruction,
        flags: &HashSet<InstructionFlag>,
        words: &[Word],
    ) -> Option<Vec<State>> {
        // Check memory executable permissions.
        if state.check_mem_perms && state.check_crash(&vc(instr.offset), &vc(instr.size), 'x') {
            return None;
        }

        let insn_address = instr.offset;
        state.esil.insn_address = vc(insn_address);
        // In ESIL, the PC is always directly __AFTER__ the instruction that
        // is being executed.
        let nxt_seq_insn_addr = instr.offset.wrapping_add(instr.size);

        let mut new_flags = flags.clone();
        if state.status == StateStatus::PostMerge && flags.contains(&InstructionFlag::Merge) {
            state.status = StateStatus::Active;
            new_flags.remove(&InstructionFlag::Merge);
        }

        // Update the call stack on calls.
        if instr.type_num == CALL_TYPE {
            state.backtrace.push((instr.jump as u64, instr.fail as u64));
        }

        // Run hooks before executing the instruction, PC is still pointing
        // at the instruction.
        let mut skip = false;
        let mut update = true;
        if !new_flags.is_empty() {
            // Run hooks.
            if new_flags.contains(&InstructionFlag::Hook) {
                let hooks = &self.hooks[&insn_address];
                for hook in hooks {
                    skip = !hook(state) || skip;
                }
            }
            if new_flags.contains(&InstructionFlag::ESILHook) {
                let esils = &self.esil_hooks[&insn_address];
                for esil in esils {
                    self.parse_expression(state, esil);
                    let val = pop_concrete(state, false, false);
                    skip = (val != 0) || skip;
                }
            }
            // If some hook changed PC we do not update. Else we update as
            // usual.
            if state.registers.get_pc() != vc(insn_address) {
                update = false;
            }
            // Stub functions.
            if new_flags.contains(&InstructionFlag::Sim) {
                let sim = &self.sims[&insn_address];
                let cc = state.r2api.get_cc(insn_address).unwrap_or_default();
                let args = self.get_args(state, &cc);

                let ret = (sim.function)(state, &args);
                state.registers.set_with_alias(cc.ret.as_str(), ret);

                // Don't ret if sim changes the PC value.
                // Else this stubbs the call.
                if state.registers.get_pc() == vc(insn_address) {
                    self.ret(state);
                }

                // We already handled the "effects" of this instruction.
                skip = true;
                update = false;
            }
            if new_flags.contains(&InstructionFlag::Break) {
                println!(
                    "[EXECUTE] BP hit: state {:}, bp {:x}",
                    state.uid, insn_address
                );
                state.status = StateStatus::Break;
                skip = true;
                update = false;
            }
            if new_flags.contains(&InstructionFlag::Merge) {
                state.status = StateStatus::Merge;
                skip = true;
                update = false;
            }
            if new_flags.contains(&InstructionFlag::Avoid) {
                println!(
                    "[EXECUTE] Avoided instruction: state {:}, insn {:x}",
                    state.uid, insn_address
                );
                state.status = StateStatus::Inactive;
                skip = true;
                update = false;
            }
        }

        if update {
            // Execution of ESIL expects PC to be __AFTER__ instruction that is
            // being executed.
            state.registers.set_pc(vc(nxt_seq_insn_addr));
        }

        let additional_states = if !skip {
            if state.strict && instr.disasm == "invalid" {
                panic!("Executed invalid instruction!");
            } else {
                // Update the state according to the effect of the instruction.
                // May fork the state.
                self.parse(state, words)
            }
        } else {
            Vec::with_capacity(0)
        };

        if instr.type_num == RETN_TYPE && update && !skip {
            if state.backtrace.is_empty() {
                panic!("Attempt to return out of valid context!");
            } else {
                // Remove current function from call stack.
                state.backtrace.pop();
            }
        } else if self.automerge && instr.type_num < 2 {
            state.status = StateStatus::Merge;
        }

        Some(additional_states)
    }

    /// Method that just performs a return.
    pub fn ret(&self, state: &mut State) {
        let ret_esil = state.r2api.get_ret().unwrap_or_default();
        if ret_esil != "" {
            self.parse_expression(state, ret_esil.as_str());
            state.backtrace.pop();
        } else if let Some(bt) = state.backtrace.pop() {
            state.registers.set_pc(vc(bt.1));
        }
    }

    /// Get the instruction, set its status, tokenize if necessary
    /// and optimize if enabled.
    // TODO: This has become so convoluted, fix it.
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
                state
                    .r2api
                    .disassemble_bytes(pc_val, &data, 1)
                    .unwrap_or_default()
            } else {
                state
                    .r2api
                    .disassemble(pc_val, INSTR_NUM)
                    .unwrap_or_default()
            };

            let mut prev: Option<u64> = None;
            for instr in instrs {
                let size = instr.size;
                let words = self.tokenize(state, &instr.esil);

                let mut flags = HashSet::new();
                let mut opt = self.optimized && !self.selfmodify;
                if self.hooks.contains_key(&pc_tmp) {
                    flags.insert(InstructionFlag::Hook);
                }
                if self.esil_hooks.contains_key(&pc_tmp) {
                    flags.insert(InstructionFlag::ESILHook);
                }
                if self.breakpoints.contains(&pc_tmp) {
                    flags.insert(InstructionFlag::Break);
                }
                if self.mergepoints.contains(&pc_tmp) {
                    flags.insert(InstructionFlag::Merge);
                }
                if self.avoidpoints.contains(&pc_tmp) {
                    flags.insert(InstructionFlag::Avoid);
                }
                if self.sims.contains_key(&pc_tmp) {
                    flags.insert(InstructionFlag::Sim);
                }

                // don't optimize if hooked / bp for accuracy
                if !flags.is_empty() {
                    opt = false;
                }

                let instr_entry = InstructionEntry {
                    instruction: instr,
                    tokens: words,
                    flags,
                };

                if opt {
                    if let Some(prev_pc) = prev {
                        self.optimize(state, prev_pc, &instr_entry);
                    }
                    prev = Some(pc_tmp);
                }
                self.instructions.insert(pc_tmp, instr_entry);
                pc_tmp = pc_tmp.wrapping_add(size);
            }
        }
    }

    /// Update `state` according to the effect of the instruction at `pc_val`.
    ///
    /// Any additional states due to forking are returned.
    pub fn execute_instruction(&mut self, state: &mut State, pc_val: u64) -> Option<Vec<State>> {
        self.fetch_instruction(state, pc_val);

        // The hash lookup is done twice, needs fixing.
        let instr = self.instructions.get(&pc_val).unwrap();

        if self.debug {
            self.print_instr(state, &instr.instruction);
        }

        self.execute(state, &instr.instruction, &instr.flags, &instr.tokens)
    }

    /// Run the provided `state` for a single step.
    ///
    /// Returns any additional states that were generated as a result of
    /// forking at conditionals.
    pub fn step(&mut self, state: &mut State) -> Vec<State> {
        self.steps += 1;
        state.visit();

        // At the beginning of a step the PC must be concrete. It points to the
        // instruction to be executed.
        let pc_value = state
            .registers
            .get_pc()
            .as_u64()
            .expect("Attempt to step state with symbolic PC.");
        // Tells us whether or not the instruction is to be executed in the
        // delay slot of a taken branch. This is needed to decide where to
        // continue execution after this instruction.
        let in_delay = state.esil.delay;

        if in_delay && self.debug {
            println!(
                "[STEP] State has delayed jump to: {:x}.",
                state.esil.jump_target.as_ref().unwrap().as_u64().unwrap()
            );
        }

        if self.debug {
            state.path.push(pc_value);
            print!("[STEP] History: ",);
            for pc in state.path.iter() {
                print!("->{:X}", pc);
            }
            println!("");
        }

        // Update the state according to the effect of the instruction at PC.
        let mut additional_states = self.execute_instruction(state, pc_value);

        // If we were in the delay slot of a taken branch, update PC to the
        // correct target.
        if in_delay {
            let do_delayed_jump = |state: &mut State| {
                let jump_target = state.esil.jump_target.take().unwrap();
                println!(
                    "[STEP] Executing delayed jump: state {:x}, to {:x}",
                    state.uid,
                    if let Some(target) = jump_target.as_u64() {
                        target
                    } else {
                        0
                    }
                );
                state.esil.delay = false;
                state.registers.set_pc(jump_target);
            };
            do_delayed_jump(state);
            additional_states.as_mut().map(|additional_states| {
                for s in additional_states.iter_mut() {
                    do_delayed_jump(s)
                }
            });
        } else {
            // PC already holds the address of the next instruction to be
            // executed.
        }

        // Handle symbolic PCs. May happen as the result of computed branches.
        // Currently we do not handle those at all.
        let handle_symbolic_pc = |state: &mut State| {
            let new_pc = state.registers.get_pc();
            if new_pc.is_symbolic() {
                println!("[STEP] State has symbolic PC: {:x}", state.uid);

                state.set_inactive();
            }
        };
        handle_symbolic_pc(state);
        additional_states.as_mut().map(|additional_states| {
            for s in additional_states.iter_mut() {
                handle_symbolic_pc(s)
            }
        });

        if let Some(additional_states) = additional_states {
            additional_states
        } else {
            Vec::with_capacity(0)
        }
    }

    /// Run the [`State`] until completion based on the selected [`RunMode`].
    pub fn run(&mut self, state: State, mode: RunMode) -> Vec<State> {
        // Use binary heap as priority queue to prioritize states
        // that have the lowest number of visits for the current PC.
        let mut states = BinaryHeap::new();
        let mut results = vec![];
        states.push(Rc::new(state));

        // run until empty for single, until split for parallel,
        // or until every state is at the breakpoint for multiple.
        let run_mode_is_parallel = mode == RunMode::Parallel;
        let run_mode_is_step = mode == RunMode::Step;

        loop {
            println!("\n[RUN] Got {} states to run.", states.len());

            // Select a state to run.
            if states.is_empty() {
                // Try to refill from merges.
                if self.merges.is_empty() {
                    return results;
                }
                let (_k, mut merge) = self.merges.pop_first().unwrap();
                merge.status = StateStatus::PostMerge;
                states.push(Rc::new(merge));
            }
            let mut current_state_rc = states.pop().unwrap();
            let current_state = Rc::make_mut(&mut current_state_rc);

            println!(
                "[RUN] Selected state: {:x}, {:?}, {}",
                current_state.uid, current_state.status, current_state.steps
            );

            match &current_state.status {
                StateStatus::Active | StateStatus::PostMerge => {
                    // Run the selected state for one step.
                    let new_states = self.step(current_state);
                    if current_state.status == StateStatus::Break
                        && mode != RunMode::Multiple
                        && current_state.is_sat()
                    {
                        // In all modes but `Multiple` we return as soon
                        // as a BP is hit (and the state is sat).
                        results.push(current_state.to_owned());
                        return results;
                    }
                    for mut state in new_states {
                        if state.status == StateStatus::Break
                            && mode != RunMode::Multiple
                            && state.is_sat()
                        {
                            results.push(state.to_owned());
                            return results;
                        }
                        // Add new state to the queue.
                        states.push(Rc::new(state));
                    }
                    // Return this state to the queue.
                    states.push(current_state_rc);
                }
                StateStatus::Merge => {
                    self.merge(current_state.to_owned());
                }
                StateStatus::Break => {
                    if current_state.is_sat() {
                        results.push(current_state.to_owned());
                        if mode != RunMode::Multiple {
                            return results;
                        }
                    }
                }
                StateStatus::Crash(_addr, _len) => {
                    self.crashes.push(current_state.to_owned());
                }
                _ => {}
            }

            // Single step mode always returns after single loop iteration.
            if run_mode_is_step || (run_mode_is_parallel && states.len() > 1) {
                // In `Step` mode we always return after one step.
                // In `Parallel` mode we return after generating new states.
                while let Some(mut state) = states.pop() {
                    results.push(Rc::make_mut(&mut state).to_owned());
                }
                return results;
            }
        }
    }

    pub fn merge(&mut self, mut state: State) {
        let pc = state.registers.get_pc().as_u64().unwrap();
        if let Some(merge_state) = self.merges.get_mut(&pc) {
            merge_state.merge(&mut state);
        } else {
            self.merges.insert(pc, state);
        }
    }
}
