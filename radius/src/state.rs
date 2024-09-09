use crate::memory::{Memory, READ_CACHE};
use crate::r2_api::{Endian, Information, R2Api};
use crate::registers::Registers;
use crate::sims::fs::SimFilesytem;
use crate::solver::{BitVec, Solver};
use crate::value::{byte_values, vc, Value};

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::u8;

use rand::random;

// event hooks could be a performance issue at some point
// prolly not now cuz there are 10000 slower things
// but also i hate the code for them and want to remove it
pub const DO_EVENT_HOOKS: bool = false;

/// Specifies a location relative to an event.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum EventTrigger {
    /// Call hook before event occurs.
    Before,
    /// Call hook after.
    After,
}

/// Specifies an event that can occur during symbolic execution.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Event {
    /// Read from symbolic address.
    SymbolicRead(EventTrigger),
    /// Write to symbolic address.
    SymbolicWrite(EventTrigger),
    /// Execute symbolic address.
    SymbolicExec(EventTrigger),
    /// Allocate memory (e.g., `malloc`).
    Alloc(EventTrigger),
    /// Allocate memory with a symbolic length (e.g., `malloc`).
    SymbolicAlloc(EventTrigger),
    /// Free memory (e.g., `free`).
    Free(EventTrigger),
    /// Free symbolic address (e.g., `free`).
    SymbolicFree(EventTrigger),
    /// Memory search (e.g., `strchr`, `memmem`).
    Search(EventTrigger),
    /// Memory search with symbolic addr, needle, or length.
    SymbolicSearch(EventTrigger),
    /// Compare memory (e.g., `memcmp`, `strcmp`).
    Compare(EventTrigger),
    /// Compare memory with symbolic arguments (e.g., `memcmp`, `strcmp`).
    SymbolicCompare(EventTrigger),
    /// String length check (e.g., `strlen`).
    StringLength(EventTrigger),
    /// String length check of symbolic address (e.g., `strlen`).
    SymbolicStrlen(EventTrigger),
    /// Move `len` bytes from `src` to `dst` (e.g., `memcpy`, `memmove`).
    Move(EventTrigger),
    /// Move `len` bytes from `src` to `dst` with symbolic argument
    /// (e.g., `memcpy`, `memmove`).
    SymbolicMove(EventTrigger),
    /// Gotta hook em all, ra! - di! - us!
    All(EventTrigger),
}

/// Information available to an [`Event`] hook.
#[derive(Debug, Clone, PartialEq)]
pub enum EventContext {
    ReadContext(Value, Value),
    WriteContext(Value, Value),
    ExecContext(Value, Vec<u64>),
    AllocContext(Value),
    FreeContext(Value),
    SearchContext(Value, Value, Value),
    CompareContext(Value, Value, Value),
    StrlenContext(Value, Value),
    MoveContext(Value, Value, Value),
}

/// A callback that can be attached to an [`Event`].
pub type EventHook = dyn Fn(&mut State, &EventContext);

/// State of the ESIL interpreter related to ITE statements.
#[derive(Debug, Clone, PartialEq)]
pub enum EsilIteContext {
    /// In an ITE branch that is always executed `1,?{,...,}`.
    Exec,
    /// In an ITE branch that is never executed `0,?{,...,}`.
    NoExec,
    /// Not in an ITE statement.
    UnCon,
    /// After executing a GOTO, before hitting the next IF, ELSE, or ENDIF.
    ///
    /// We essentially do not know our ITE context here.
    Goto,
}

#[derive(Debug, Clone)]
pub struct EsilState {
    /// Current ITE context.
    pub exec_ctx: EsilIteContext,
    /// Before executing the ESIL words belonging to a machine instruction we
    /// have to check whether the instruction is to be executed in a delay slot
    /// of a taken branch or not. This is necessary to deduce the address of the
    /// next instruction to be executed.
    /// During emulation, the address of next instruction is determined as
    /// follows:
    /// ```
    ///     let in_delay = state.esil.delay;
    ///     // emulate insn words
    ///     if in_delay {
    ///         let jump_target = state.esil.jump_target;
    ///         state.esil.delay = false;
    ///         state.esil.jump_target = None;
    ///         jump_target
    ///     } else {
    ///         state.registers.get_pc()
    ///     }
    /// ```
    /// If delay slots are not in use, this means that the address of the next
    /// instruction is simply `PC` after executing the instruction.
    ///
    /// The implementation relies on the following invariants:
    ///
    /// - Instructions that __may__ set `PC` or `delay` __never ever__ appear in
    ///   a delay slot. (Their ESIL __must__ include code to trap if this does
    ///   happen.)
    /// - If an instruction sets `delay`, after it finishes executing PC
    ///   __must__ be set to the address of the delay slot and the address of
    ///   the instruction to be executed after the delay slot __must__ be
    ///   recorded in `jump_target`.
    ///
    /// The current implementation is able to handle a single delay slot. It
    /// should be straight forward to extend it for multiple delay slots by
    /// making `delay` a counter.
    ///
    /// # Example: MIPS
    ///
    /// ESIL of all instructions with non-fall-through semantics is prefixed
    /// with code that traps if executed in a delay slot, e.g.,
    /// `$ds,!,!,?{TRAP}`.
    ///
    /// Direct branch:
    ///   without delay slot:   `0x1337,pc,:=`
    ///   with delay slot:      `0x1337,SETJT,1,SETD`
    /// Direct call:
    ///   without delay slot:   `pc,ra,=,0x1337,pc,:=`
    ///   with delay slot:      `pc,4,+,ra,=,0x1337,SETJT,1,SETD`
    /// Conditional direct branch:
    ///   without delay slot:   `...,?{,0x1337,pc,:=,}`
    ///   with delay slot:      `...,?{,0x1337,SETJT,1,SETD,}`
    /// Indirect (conditional) branch/call:
    ///   0x1337 -> rs
    ///
    /// # Symbolic Execution
    ///
    /// The above scheme works well for concrete execution. For symbolic
    /// execution, emulation of a single instruction may leave us with a bunch
    /// of states. The above scheme to determine the new PC has to be repeated
    /// for each new state. Afterwards, some states may end up with a symbolic
    /// PC. In this case one could try tp concretize (and fork as necessary),
    /// however, we currently just give up on this state.
    ///
    /// `$ds` flag of the ESIL VM.
    pub delay: bool,
    /// Combined `$js` and `$jt` flag of the ESIL VM.
    pub jump_target: Option<Value>,
    /// Address of the current instruction.
    ///
    /// Before executing the ESIL words belonging to a machine instruction, PC
    /// holds the address of the next __sequential__ instruction, i.e., the
    /// address of the first byte that does not belong to the instruction we
    /// are about to execute. Consequently, reading PC will __not__ give you the
    /// address of the current instruction. This also means that ESIL for
    /// instructions with fall-through semantics does not need to update PC.
    pub insn_address: Value,
    pub previous: Value,
    pub current: Value,
    pub last_sz: usize,
    pub stored_address: Option<Value>,
}

/// Item on the stack of the ESIL VM.
///
/// The stack may hold registers or values.
#[derive(Debug, Clone)]
pub enum StackItem {
    StackRegister(usize),
    StackValue(Value),
}

impl Default for StackItem {
    fn default() -> Self {
        StackItem::StackValue(Value::Concrete(0, 0))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateStatus {
    /// State is ready to take a step.
    Active,
    /// State has hit a breakpoint.
    Break,
    /// State has to be merged brefore it can take a step.
    Merge,
    /// State was just merged and may take a step.
    PostMerge,
    /// State has a not sat path condition or encountered an ITE where both
    /// branches are not sat.
    Unsat,
    /// State stepping is suspended since it hit an internal limitation of
    /// the engine.
    Inactive,
    /// State has violated memory permissions.
    Crash(u64, char),
    /// State has reached the end of the program.
    Exit,
}

/// Unique identifier of a state.
pub type StateUid = u64;

/// For states that were forked of another state, this includes information
/// about the forking event.
#[derive(Clone)]
pub struct ForkContext {
    /// State that was forked.
    pub parent: StateUid,
    /// Fork depth.
    ///
    /// How many forks relate this state to the initial state.
    pub fork_depth: u64,
    /// Address of the instruction that caused the fork.
    pub insn_address: u64,
    /// Index of the word that caused the fork.
    pub word_index: u32,
    /// Condition that caused the fork and is true for this child.
    pub condition: Value,
}

/// A symbolic program state, including memory, registers, path condition,
/// and solver data
#[derive(Clone)]
pub struct State {
    /// Handle to the boolector SMT solver.
    pub solver: Solver,
    /// Handle to r2.
    pub r2api: R2Api,
    /// Meta data about the program corresponding to this state.
    pub info: Information,
    /// Stack of the ESIL VM.
    pub stack: Vec<StackItem>,
    /// State of the ESIL VM.
    pub esil: EsilState,
    /// Map of CPU registers to bitvectors.
    pub registers: Registers,
    /// Map of memory addresses to 8-bit bitvectors.
    pub memory: Memory,
    pub filesystem: SimFilesytem,
    /// Status of this state.
    pub status: StateStatus,
    pub context: HashMap<String, Vec<Value>>,
    pub taints: HashMap<String, u64>,
    pub event_hooks: HashMap<Event, Rc<EventHook>>,
    /// Map of PC address to number of times that the corresponding instruction
    /// was visited.
    pub visits: HashMap<u64, usize>,
    /// Unique identifier of this state.
    pub uid: StateUid,
    /// If this state came to live by forking execution at a conditional, this
    /// records information about the forking event.
    pub fork_ctx: Option<Box<ForkContext>>,
    /// Call stack: (callee address, return address)
    pub backtrace: Vec<(u64, u64)>,
    /// Sequence of PCs that this state has traversed.
    pub path: Vec<u64>,
    /// Whether to symbol-fill uninitialized memory.
    pub blank: bool,
    /// Whether to print extra debugging information.
    pub debug: bool,
    /// Whether to check memory permissions.
    pub check_mem_perms: bool,
    /// Whether to panic when hitting unimplemented or not properly handled
    /// cases. Else the state is set inactive.
    pub strict: bool,
    pub has_event_hooks: bool,
    pub steps: u64,
}

impl PartialEq for State {
    /// Two states are equal iff they have the same visit count for their
    /// current PC.
    fn eq(&self, other: &Self) -> bool {
        other.get_visit() == self.get_visit()
    }
}

impl Eq for State {}

impl Ord for State {
    /// Ordering of states is based on the number of visits that they have for
    /// for their current PC value.
    ///
    /// States with lower visits are "larger".
    fn cmp(&self, other: &Self) -> Ordering {
        other.get_visit().cmp(&self.get_visit())
    }
}

impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl State {
    /// Create a new state, should generally not be called directly.
    pub fn new(
        r2api: &mut R2Api,
        eval_max: usize,
        debug: bool,
        blank: bool,
        check: bool,
        strict: bool,
    ) -> Self {
        let esil_state = EsilState {
            exec_ctx: EsilIteContext::UnCon,
            delay: false,
            jump_target: None,
            insn_address: Value::Concrete(0, 0),
            previous: Value::Concrete(0, 0),
            current: Value::Concrete(0, 0),
            last_sz: 64,
            stored_address: None,
        };

        let solver = Solver::new(eval_max);
        let registers = Registers::new(r2api, solver.clone(), blank);
        let memory = Memory::new(r2api, solver.clone(), blank);

        State {
            solver,
            r2api: r2api.clone(),
            info: r2api.info.clone(),
            stack: Vec::with_capacity(128),
            esil: esil_state,
            registers,
            memory,
            filesystem: SimFilesytem::new(),
            status: StateStatus::Active,
            context: HashMap::new(),
            taints: HashMap::new(),
            event_hooks: HashMap::new(),
            visits: HashMap::with_capacity(512),
            backtrace: Vec::with_capacity(128),
            path: Vec::with_capacity(0),
            uid: random(),
            blank,
            debug,
            check_mem_perms: check,
            strict,
            has_event_hooks: false,
            fork_ctx: None,
            steps: 0,
        }
    }

    /// duplicate state is different from clone as it creates
    /// a duplicate solver instead of another reference to the old one
    pub fn fork(&mut self, insn_address: u64, word_index: u32, condition: Value) -> Self {
        let solver = self.solver.duplicate();

        let mut registers = self.registers.clone();
        registers.solver = solver.clone();
        registers.values = registers
            .values
            .iter()
            .map(|r| solver.translate_value(r))
            .collect();

        let mut memory = self.memory.clone();
        memory.solver = solver.clone();
        let addrs = memory.addresses();
        for addr in addrs {
            let values = memory.mem.remove(&addr).unwrap();
            memory.mem.insert(
                addr,
                values.iter().map(|v| solver.translate_value(&v)).collect(),
            );
        }

        let mut context = HashMap::new();
        for key in self.context.keys() {
            let values = self.context.get(key).unwrap();
            let new_values = values.iter().map(|v| solver.translate_value(v)).collect();

            context.insert(key.to_owned(), new_values);
        }

        let mut filesystem = self.filesystem.clone();
        for f in &mut filesystem.files {
            let content = f.content.clone();
            f.content = content.iter().map(|v| solver.translate_value(v)).collect();
        }

        let esil_state = EsilState {
            exec_ctx: EsilIteContext::UnCon,
            delay: self.esil.delay,
            jump_target: self
                .esil
                .jump_target
                .clone()
                .map(|v| solver.translate_value(&v)),
            insn_address: solver.translate_value(&self.esil.insn_address),
            previous: vc(0),
            current: vc(0),
            last_sz: 64,
            stored_address: None,
        };

        State {
            solver,
            r2api: self.r2api.clone(),
            info: self.info.clone(),
            stack: Vec::with_capacity(128),
            esil: esil_state,
            registers,
            memory,
            filesystem,
            status: self.status.clone(),
            context,
            taints: self.taints.clone(),
            event_hooks: self.event_hooks.clone(),
            visits: self.visits.clone(),
            fork_ctx: Some(self.gen_fork_ctx_for_child(insn_address, word_index, condition)),
            backtrace: self.backtrace.clone(),
            path: self.path.clone(),
            uid: random(),
            blank: self.blank,
            debug: self.debug,
            check_mem_perms: self.check_mem_perms,
            strict: self.strict,
            has_event_hooks: self.has_event_hooks,
            steps: self.steps,
        }
    }

    /// Returns the fork context for a child created at the given point with
    /// the given condition.
    pub fn gen_fork_ctx_for_child(
        &self,
        insn_address: u64,
        word_index: u32,
        condition: Value,
    ) -> Box<ForkContext> {
        Box::new(ForkContext {
            parent: self.uid,
            fork_depth: if let Some(fork_ctx) = &self.fork_ctx {
                fork_ctx.fork_depth + 1
            } else {
                1
            },
            insn_address,
            word_index,
            condition,
        })
    }

    pub fn hook_event(&mut self, event: Event, hook: Rc<EventHook>) {
        self.has_event_hooks = true;
        self.event_hooks.insert(event, hook);
    }

    pub fn do_hooked(&mut self, event: &Event, event_context: &EventContext) {
        if !self.event_hooks.contains_key(event) {
            return;
        }
        let hook = self.event_hooks.get(event).unwrap().clone();
        hook(self, event_context)
    }

    /// Allocate a block of memory `length` bytes in size
    pub fn memory_alloc(&mut self, length: &Value) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if length.is_symbolic() {
                Event::SymbolicAlloc(EventTrigger::Before)
            } else {
                Event::Alloc(EventTrigger::Before)
            };
            self.do_hooked(&event, &EventContext::AllocContext(length.to_owned()));
        }

        let ret = self.memory.alloc_sym(length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if length.is_symbolic() {
                Event::SymbolicAlloc(EventTrigger::After)
            } else {
                Event::Alloc(EventTrigger::After)
            };
            self.do_hooked(&event, &EventContext::AllocContext(length.to_owned()));
        }

        ret
    }

    /// Free a block of memory at `addr`
    pub fn memory_free(&mut self, addr: &Value) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() {
                Event::SymbolicFree(EventTrigger::Before)
            } else {
                Event::Free(EventTrigger::Before)
            };
            self.do_hooked(&event, &EventContext::FreeContext(addr.to_owned()));
        }

        if self.check_mem_perms && self.check_crash(addr, &vc(1), 'r') {
            return vc(-1i64 as u64);
        }

        let ret = self.memory.free_sym(addr, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() {
                Event::SymbolicFree(EventTrigger::After)
            } else {
                Event::Free(EventTrigger::After)
            };
            self.do_hooked(&event, &EventContext::FreeContext(addr.to_owned()));
        }

        ret
    }

    /// Read `length` bytes from `address`
    pub fn memory_read(&mut self, address: &Value, length: &Value) -> Vec<Value> {
        if DO_EVENT_HOOKS && self.has_event_hooks && (address.is_symbolic() || length.is_symbolic())
        {
            self.do_hooked(
                &Event::SymbolicRead(EventTrigger::Before),
                &EventContext::ReadContext(address.to_owned(), length.to_owned()),
            );
        }

        if self.check_mem_perms && self.check_crash(address, length, 'r') {
            return vec![];
        }

        let ret = self.memory.read_sym_len(address, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks && (address.is_symbolic() || length.is_symbolic())
        {
            self.do_hooked(
                &Event::SymbolicRead(EventTrigger::After),
                &EventContext::ReadContext(address.to_owned(), length.to_owned()),
            );
        }

        ret
    }

    /// Write `length` bytes to `address`
    pub fn memory_write(&mut self, address: &Value, values: &[Value], length: &Value) {
        if DO_EVENT_HOOKS && self.has_event_hooks && (address.is_symbolic() || length.is_symbolic())
        {
            self.do_hooked(
                &Event::SymbolicWrite(EventTrigger::Before),
                &EventContext::WriteContext(address.to_owned(), length.to_owned()),
            );
        }

        if self.check_mem_perms && self.check_crash(address, length, 'r') {
            return;
        }
        let ret = self
            .memory
            .write_sym_len(address, values, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks && (address.is_symbolic() || length.is_symbolic())
        {
            self.do_hooked(
                &Event::SymbolicWrite(EventTrigger::After),
                &EventContext::WriteContext(address.to_owned(), length.to_owned()),
            );
        }

        ret
    }

    /// Read `length` byte `value` from `address`
    #[inline]
    pub fn memory_read_value(&mut self, address: &Value, length: usize) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks && address.is_symbolic() {
            self.do_hooked(
                &Event::SymbolicRead(EventTrigger::Before),
                &EventContext::ReadContext(address.to_owned(), Value::Concrete(length as u64, 0)),
            );
        }

        if self.check_mem_perms && self.check_crash(address, &vc(length as u64), 'r') {
            return vc(-1i64 as u64);
        }

        let ret = self.memory.read_sym(address, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks && address.is_symbolic() {
            self.do_hooked(
                &Event::SymbolicRead(EventTrigger::After),
                &EventContext::ReadContext(address.to_owned(), Value::Concrete(length as u64, 0)),
            );
        }

        ret
    }

    /// Write `length` byte `value` to `address`
    #[inline]
    pub fn memory_write_value(&mut self, address: &Value, value: &Value, length: usize) {
        if DO_EVENT_HOOKS && self.has_event_hooks && address.is_symbolic() {
            self.do_hooked(
                &Event::SymbolicRead(EventTrigger::Before),
                &EventContext::ReadContext(address.to_owned(), Value::Concrete(length as u64, 0)),
            );
        }

        if self.check_mem_perms && self.check_crash(address, &vc(length as u64), 'w') {
            return;
        }

        let ret = self
            .memory
            .write_sym(address, value, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks && address.is_symbolic() {
            self.do_hooked(
                &Event::SymbolicWrite(EventTrigger::After),
                &EventContext::WriteContext(address.to_owned(), Value::Concrete(length as u64, 0)),
            );
        }

        ret
    }

    /// Search for `needle` at the address `addr` for a maximum of `length` bytes
    /// Returns a `Value` containing the **address** of the needle, not index
    pub fn memory_search(
        &mut self,
        addr: &Value,
        needle: &Value,
        length: &Value,
        reverse: bool,
    ) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() || length.is_symbolic() {
                Event::SymbolicSearch(EventTrigger::Before)
            } else {
                Event::Search(EventTrigger::Before)
            };
            self.do_hooked(
                &event,
                &EventContext::SearchContext(addr.to_owned(), needle.to_owned(), length.to_owned()),
            );
        }

        if self.check_mem_perms && self.check_crash(addr, &vc(1), 'r') {
            return vc(-1i64 as u64);
        }

        let ret = self
            .memory
            .search(addr, needle, length, reverse, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() || length.is_symbolic() {
                Event::SymbolicSearch(EventTrigger::After)
            } else {
                Event::Search(EventTrigger::After)
            };
            self.do_hooked(
                &event,
                &EventContext::SearchContext(addr.to_owned(), needle.to_owned(), length.to_owned()),
            );
        }

        ret
    }

    /// Compare memory at `dst` and `src` address up to `length` bytes.
    /// This is akin to memcmp but will handle symbolic addrs and length
    pub fn memory_compare(&mut self, dst: &Value, src: &Value, length: &Value) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if dst.is_symbolic() || src.is_symbolic() || length.is_symbolic() {
                Event::SymbolicCompare(EventTrigger::Before)
            } else {
                Event::Compare(EventTrigger::Before)
            };
            self.do_hooked(
                &event,
                &EventContext::CompareContext(dst.to_owned(), src.to_owned(), length.to_owned()),
            );
        }

        if self.check_mem_perms
            && (self.check_crash(src, &vc(1), 'r') || self.check_crash(dst, &vc(1), 'r'))
        {
            return vc(-1i64 as u64);
        }

        let ret = self.memory.compare(dst, src, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if dst.is_symbolic() || src.is_symbolic() || length.is_symbolic() {
                Event::SymbolicCompare(EventTrigger::After)
            } else {
                Event::Compare(EventTrigger::After)
            };
            self.do_hooked(
                &event,
                &EventContext::CompareContext(dst.to_owned(), src.to_owned(), length.to_owned()),
            );
        }

        ret
    }

    /// Get the length of the null terminated string at `addr`
    pub fn memory_strlen(&mut self, addr: &Value, length: &Value) -> Value {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() || length.is_symbolic() {
                Event::SymbolicStrlen(EventTrigger::Before)
            } else {
                Event::StringLength(EventTrigger::Before)
            };
            self.do_hooked(
                &event,
                &EventContext::StrlenContext(addr.to_owned(), length.to_owned()),
            );
        }

        // eh don't use the length here
        if self.check_mem_perms && self.check_crash(addr, &vc(1), 'r') {
            return vc(-1i64 as u64);
        }

        let ret = self.memory.strlen(addr, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if addr.is_symbolic() || length.is_symbolic() {
                Event::SymbolicStrlen(EventTrigger::After)
            } else {
                Event::StringLength(EventTrigger::After)
            };
            self.do_hooked(
                &event,
                &EventContext::StrlenContext(addr.to_owned(), length.to_owned()),
            );
        }

        ret
    }

    /// Move `length` bytes from `src` to `dst`
    pub fn memory_move(&mut self, dst: &Value, src: &Value, length: &Value) {
        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if dst.is_symbolic() || src.is_symbolic() || length.is_symbolic() {
                Event::SymbolicMove(EventTrigger::Before)
            } else {
                Event::Move(EventTrigger::Before)
            };
            self.do_hooked(
                &event,
                &EventContext::MoveContext(dst.to_owned(), src.to_owned(), length.to_owned()),
            );
        }

        if self.check_mem_perms
            && (self.check_crash(src, length, 'r') || self.check_crash(dst, length, 'w'))
        {
            return;
        }

        self.memory.memmove(dst, src, length, &mut self.solver);

        if DO_EVENT_HOOKS && self.has_event_hooks {
            let event = if dst.is_symbolic() || src.is_symbolic() || length.is_symbolic() {
                Event::SymbolicMove(EventTrigger::After)
            } else {
                Event::Move(EventTrigger::After)
            };
            self.do_hooked(
                &event,
                &EventContext::MoveContext(dst.to_owned(), src.to_owned(), length.to_owned()),
            );
        }
    }

    /// Read pointer from `address`
    pub fn memory_read_ptr(&mut self, address: &Value) -> Value {
        let ptr_len = self.memory.bits as usize / 8;
        self.memory_read_value(address, ptr_len)
    }

    /// Write pointer `value` to `address`
    pub fn memory_write_ptr(&mut self, address: &Value, value: &Value) {
        let ptr_len = self.memory.bits as usize / 8;
        self.memory_write_value(address, value, ptr_len)
    }

    /// Read `length` bytes from `address`
    pub fn memory_read_bytes(&mut self, address: u64, length: usize) -> Vec<u8> {
        self.memory.read_bytes(address, length, &mut self.solver)
    }

    /// Read a string from `address` up to `length` bytes long
    pub fn memory_read_string(&mut self, address: u64, length: usize) -> String {
        self.memory.read_string(address, length, &mut self.solver)
    }

    /// Read a concrete c string from `address`
    pub fn memory_read_cstring(&mut self, address: u64) -> String {
        let length = self.memory_strlen(&vc(address), &vc(4096));
        let len = self.solver.evalcon_to_u64(&length).unwrap_or(0);
        self.memory
            .read_string(address, len as usize, &mut self.solver)
    }

    // this doesnt need to be here, just for consistency sake
    /// Write `string` to `address`
    pub fn memory_write_string(&mut self, address: u64, string: &str) {
        self.memory.write_string(address, string)
    }

    /// pack bytes into a single `Value`
    pub fn pack(&self, data: &[Value]) -> Value {
        self.memory.pack(data)
    }

    /// unpack `Value` into vector of bytes
    pub fn unpack(&self, data: &Value, length: usize) -> Vec<Value> {
        let mut values = vec![Value::Concrete(0, 0); length];
        self.memory.unpack(data, length, &mut values);
        values
    }

    pub fn fill_file(&mut self, fd: usize, data: &[Value]) {
        self.filesystem.fill(fd, data)
    }

    pub fn fill_file_string(&mut self, fd: usize, string: &str) {
        let data = byte_values(string);
        self.filesystem.fill(fd, &data)
    }

    pub fn dump_path(&mut self, path: &str) -> Vec<Value> {
        if let Some(fd) = self.filesystem.getfd(path) {
            self.filesystem.dump(fd)
        } else {
            vec![]
        }
    }

    pub fn dump_file(&mut self, fd: usize) -> Vec<Value> {
        self.filesystem.dump(fd)
    }

    pub fn dump_file_bytes(&mut self, fd: usize) -> Vec<u8> {
        let values = self.filesystem.dump(fd);
        let bytes = values
            .iter()
            .map(|v| self.solver.evalcon_to_u64(v).unwrap_or(0) as u8)
            .collect();

        bytes
    }

    pub fn dump_file_string(&mut self, fd: usize) -> Option<String> {
        String::from_utf8(self.dump_file_bytes(fd)).ok()
    }

    /// Apply this state to the radare2 instance. This writes all the values
    /// in the states memory back to the memory in r2 as well as the register
    /// values, evaluating any symbolic expressions.
    pub fn apply(&mut self) {
        let mut inds = Vec::with_capacity(256);
        for reg in &self.registers.indexes {
            if !inds.contains(&reg.value_index) {
                inds.push(reg.value_index);
                let rval = self.registers.values[reg.value_index].to_owned();
                let r = self.solver.evalcon_to_u64(&rval).unwrap();
                self.r2api.set_register_value(&reg.reg_info.name, r);
            }
        }

        let mut bvals = vec![Value::Concrete(0, 0); READ_CACHE];
        for addr in self.memory.addresses() {
            self.memory.read(addr, READ_CACHE, &mut bvals);
            let bytes: Vec<u8> = bvals
                .iter()
                .map(|bval| self.solver.evalcon_to_u64(&bval).unwrap() as u8)
                .collect();

            self.r2api.write(addr, bytes.clone());
        }

        // TODO: evaluate files and write to real FS? maybe a bad idea
    }

    /// Merges `state` into self
    pub fn merge(&mut self, state: &mut State) {
        let state_asserts = &state.solver.assertions;
        let assertion = state.solver.and_all(state_asserts);
        let asserted = Value::Symbolic(assertion, 0);

        // merge registers
        let reg_count = state.registers.values.len();
        for index in 0..reg_count {
            let reg = &self.registers.values[index];
            let curr_reg = &state.registers.values[index];
            //new_regs.push(state.solver.conditional(&asserted, curr_reg, reg));
            self.registers.values[index] = state.solver.conditional(&asserted, curr_reg, reg);
        }

        // merge memory
        //let mut new_mem = HashMap::with_capacity(1024);

        let merge_addrs = self.memory.addresses();
        let state_addrs = state.memory.addresses();

        let mut addrs = HashSet::with_capacity(READ_CACHE);
        addrs.extend(merge_addrs);
        addrs.extend(state_addrs);

        let mut tmp1 = Vec::with_capacity(READ_CACHE);
        let mut tmp2 = Vec::with_capacity(READ_CACHE);

        for addr in addrs {
            let newvec = if let Some(m) = self.memory.mem.get_mut(&addr) {
                m
            } else {
                self.memory.read(addr, READ_CACHE, &mut tmp1);
                &mut tmp1
            };
            let curvec = if let Some(m) = state.memory.mem.get(&addr) {
                m
            } else {
                state.memory.read(addr, READ_CACHE, &mut tmp2);
                &tmp2
            };

            for i in 0..READ_CACHE {
                if newvec.len() > i && curvec.len() > i {
                    newvec[i] = state.cond(&asserted, &curvec[i], &newvec[i]);
                }
            }
        }

        // merge context
        for (k, v) in &state.context {
            for i in 0..v.len() {
                if let Some(nv) = self.context.get_mut(k) {
                    if i < nv.len() {
                        nv[i] = state.cond(&asserted, &v[i], &nv[i]);
                    } else {
                        nv.push(state.cond(&asserted, &v[i], &vc(0)))
                    }
                }
            }
        }

        // merge filesystem
        for file in &state.filesystem.files {
            for cfile in &mut self.filesystem.files {
                if file.path == cfile.path {
                    let mlen = if file.content.len() > cfile.content.len() {
                        file.content.len()
                    } else {
                        cfile.content.len()
                    };
                    for i in 0..mlen {
                        let space = vc(0x20); // fill overflow with spaces, uhhh cuz
                        let v = file.content.get(i).unwrap_or(&space);
                        let cv = cfile.content.get(i).unwrap_or(&space);
                        if i < cfile.content.len() {
                            cfile.content[i] = state.cond(&asserted, &v, &cv);
                        } else {
                            cfile.content.push(state.cond(&asserted, &v, &cv));
                        }
                    }
                }
            }
        }

        // merge solvers
        let assertions = &self.solver.assertions;
        let current = state.solver.and_all(assertions);
        self.solver.reset();
        self.assert_bv(&current.or(&asserted.as_bv().unwrap()));
    }

    /// Use the constraints from the provided state. This is
    /// useful for constraining the data in some initial
    /// state with the assertions of some desired final state
    pub fn constrain_with_state(&mut self, state: &Self) {
        self.solver = state.solver.clone();
    }

    /// Create a bitvector from this states solver
    pub fn bv(&self, s: &str, n: u32) -> BitVec {
        self.solver.bv(s, n)
    }

    /// Create a bitvector value from this states solver
    pub fn bvv(&self, v: u64, n: u32) -> BitVec {
        self.solver.bvv(v, n)
    }

    /// Create a `Value::Concrete` from a value `v` and bit width `n`
    pub fn concrete_value(&self, v: u64, n: u32) -> Value {
        let mask = if n < 64 { (1 << n) - 1 } else { -1i64 as u64 };
        Value::Concrete(v & mask, 0)
    }

    /// Create a `Value::Symbolic` from a name `s` and bit width `n`
    pub fn symbolic_value(&self, s: &str, n: u32) -> Value {
        Value::Symbolic(self.bv(s, n), 0)
    }

    /// Create a tainted `Value::Concrete` from a value `v` and bit width `n`
    pub fn tainted_concrete_value(&mut self, t: &str, v: u64, n: u32) -> Value {
        let mask = if n < 64 { (1 << n) - 1 } else { -1i64 as u64 };
        let taint = self.get_tainted_identifier(t);
        Value::Concrete(v & mask, taint)
    }

    /// Create a tainted `Value::Symbolic` from a name `s` and bit width `n`
    pub fn tainted_symbolic_value(&mut self, t: &str, s: &str, n: u32) -> Value {
        let taint = self.get_tainted_identifier(t);
        Value::Symbolic(self.bv(s, n), taint)
    }

    /// Get the numeric identifier for the given taint name
    pub fn get_tainted_identifier(&mut self, t: &str) -> u64 {
        if let Some(taint) = self.taints.get(t) {
            *taint
        } else {
            let index = self.taints.len();
            if index < 64 {
                let new_taint = 1 << index as u64;
                self.taints.insert(t.to_owned(), new_taint);
                new_taint
            } else {
                // no need to panic
                println!("Max of 64 taints allowed!");
                0
            }
        }
    }

    /// Check if the `value` is tainted with the given `taint`
    pub fn is_tainted_with(&mut self, value: &Value, taint: &str) -> bool {
        (value.get_taint() & self.get_tainted_identifier(taint)) != 0
    }

    /// BitVectors will need to be translated if run is multithreaded
    pub fn translate(&self, bv: &BitVec) -> Option<BitVec> {
        self.solver.translate(bv)
    }

    /// Translate `value` to this states solver
    pub fn translate_value(&self, value: &Value) -> Value {
        self.solver.translate_value(value)
    }

    /// Evaluate a `Value` `val`
    pub fn eval(&mut self, val: &Value) -> Option<Value> {
        self.solver.eval(val)
    }

    /// Evaluate a bitvector `bv`
    pub fn evaluate(&mut self, bv: &BitVec) -> Option<Value> {
        self.solver.evaluate(bv)
    }

    /// Evaluate and constrain the symbol to the u64
    pub fn evalcon(&mut self, bv: &BitVec) -> Option<u64> {
        self.solver.evalcon(bv)
    }

    /// Constrain bytes of bitvector to be an exact string eg. "ABC"
    /// or use "\[...\]" to match a simple pattern eg. "\[XYZa-z0-9\]"
    pub fn constrain_bytes_bv(&mut self, bv: &BitVec, pattern: &str) {
        if &pattern[..1] != "[" {
            for (i, c) in pattern.chars().enumerate() {
                self.assert_bv(
                    &bv.slice(8 * (i as u32 + 1) - 1, 8 * i as u32)
                        ._eq(&self.bvv(c as u64, 8)),
                );
            }
        } else {
            let patlen = pattern.len();
            let newpat = &pattern[1..patlen - 1];
            let mut assertions = Vec::with_capacity(256);

            for ind in 0..bv.get_width() / 8 {
                assertions.clear();
                let s = &bv.slice(8 * (ind + 1) - 1, 8 * ind);

                let mut i = 0;
                while i < patlen - 2 {
                    let c = newpat.as_bytes()[i] as u64;
                    if patlen > 4 && i < patlen - 4 && &newpat[i + 1..i + 2] == "-" {
                        let n = newpat.as_bytes()[i + 2] as u64;
                        i += 3;
                        assertions.push(s.ugte(&self.bvv(c, 8)).and(&s.ulte(&self.bvv(n, 8))));
                    } else {
                        i += 1;
                        assertions.push(s._eq(&self.bvv(c, 8)));
                    }
                }

                self.assert_bv(&self.solver.or_all(&assertions));
            }
        }
    }

    /// Constrain bytes of bitvector to be an exact string eg. "ABC"
    /// or use "\[...\]" to match a simple pattern eg. "\[XYZa-z0-9\]"
    pub fn constrain_bytes(&mut self, bv: &Value, pattern: &str) {
        if let Value::Symbolic(s, _) = bv {
            self.constrain_bytes_bv(s, pattern)
        }
    }

    /// Constrain bytes of file with file descriptor `fd` and pattern
    pub fn constrain_fd(&mut self, fd: usize, content: &str) {
        let fbytes = self.dump_file(fd);
        let fbv = self.pack(&fbytes);
        self.constrain_bytes(&fbv, content);
    }

    /// Constrain bytes of file at `path` with pattern
    pub fn constrain_file(&mut self, path: &str, content: &str) {
        if let Some(fd) = self.filesystem.getfd(path) {
            self.constrain_fd(fd, content);
        }
    }

    // search for string in file
    pub fn search_file(&mut self, path: &str, content: &str) -> Value {
        if let Some(fd) = self.filesystem.getfd(path) {
            self.search_fd(fd, content)
        } else {
            vc(-1i64 as u64)
        }
    }

    // TODO this is hacky as fuck, make it better
    pub fn search_fd(&mut self, fd: usize, content: &str) -> Value {
        let data = self.dump_file(fd);
        let length = vc(data.len() as u64);
        let addr = self.memory_alloc(&length);
        self.memory_write(&addr, &data, &length);
        let needle = self.pack(&byte_values(content));
        let result = self.memory_search(&addr, &needle, &length, false);
        self.memory_free(&addr);
        self.cond(&result.eq(&vc(0)), &vc(-1i64 as u64), &result)
    }

    /// Check if this state is satisfiable and mark the state `Unsat` if not
    pub fn is_sat(&mut self) -> bool {
        if self.solver.is_sat() {
            true
        } else {
            self.status = StateStatus::Unsat;
            false
        }
    }

    /// Increment visit counter.
    ///
    /// The visit counter maps PC values to the number of times that the
    /// corresponding instruction was executed.
    pub fn visit(&mut self) {
        self.steps += 1;
        if let Some(pc) = self.registers.get_pc().as_u64() {
            self.visits.entry(pc).and_modify(|c| *c += 1).or_insert(1);
        }
    }

    /// Get visit counter
    pub fn get_visit(&self) -> usize {
        if let Some(pc) = self.registers.get_pc().as_u64() {
            *self.visits.get(&pc).unwrap_or(&0)
        } else {
            0
        }
    }

    /// Print backtrace
    pub fn print_backtrace(&mut self) {
        for (i, bt) in self.backtrace.iter().rev().enumerate() {
            let name = self.r2api.get_flag(bt.1).unwrap_or_default();
            println!("\n#{} 0x{:08x} ({})\n", i, bt.1, name.trim());
        }
    }

    /// Set status of state (active, inactive, merge, unsat...)
    pub fn set_status(&mut self, status: StateStatus) {
        self.status = status;
    }

    /// Get status of state (active, inactive, merge, unsat...)
    pub fn get_status(&mut self) -> StateStatus {
        self.status.clone()
    }

    /// Convenience method to mark state inactive
    pub fn set_inactive(&mut self) {
        self.set_status(StateStatus::Inactive);
    }

    /// Convenience method to mark state crashed
    pub fn set_crash(&mut self, addr: u64, perm: char) {
        self.set_status(StateStatus::Crash(addr, perm));
    }

    pub fn check_crash(&mut self, addr: &Value, len: &Value, perm: char) -> bool {
        let length = self.solver.max_value(len);
        match addr {
            Value::Concrete(address, _t) => {
                let crash = !self.memory.check_permission(*address, length, perm);
                if crash {
                    self.set_crash(*address, perm);
                }
                crash
            }
            Value::Symbolic(address, _t) => {
                let min = self.solver.min(address);
                let max = self.solver.max(address);
                let min_crash = !self.memory.check_permission(min, length, perm);
                let max_crash = !self.memory.check_permission(max, length, perm);
                if min_crash {
                    self.set_crash(min, perm);
                } else if max_crash {
                    self.set_crash(max, perm);
                }
                min_crash || max_crash
            }
        }
    }

    /// convenience method to break
    pub fn set_break(&mut self) {
        self.set_status(StateStatus::Break);
    }

    /// Get the argument values for the current function
    pub fn get_args(&mut self) -> Vec<Value> {
        let pc = self.registers.get_pc().as_u64().unwrap();
        let cc = self.r2api.get_cc(pc).unwrap_or_default();
        let mut args = Vec::with_capacity(16);

        if !cc.args.is_empty() {
            for arg in &cc.args {
                args.push(self.registers.get_with_alias(arg));
            }
        } else {
            // read args from stack?
            let mut sp = self.registers.get_with_alias("SP");
            let length = self.memory.bits as usize / 8;

            for _ in 0..8 {
                // do 8 idk?
                sp = sp + Value::Concrete(length as u64, 0);
                let value = self.memory_read_value(&sp, length);
                args.push(value);
            }
        }

        args
    }

    /// get the return value from the right register
    pub fn get_ret(&mut self) -> Value {
        let pc = self.registers.get_pc().as_u64().unwrap();
        let cc = self.r2api.get_cc(pc).unwrap_or_default();
        self.registers.get(&cc.ret)
    }

    /// Set the argument values for the current function
    pub fn set_args(&mut self, mut values: Vec<Value>) {
        let pc = self.registers.get_pc().as_u64().unwrap();
        let cc = self.r2api.get_cc(pc).unwrap_or_default();

        if !cc.args.is_empty() {
            for arg in &cc.args {
                if !values.is_empty() {
                    self.registers.set_with_alias(arg, values.remove(0));
                }
            }
        } else {
            // read args from stack?
            let mut sp = self.registers.get_with_alias("SP");
            let length = self.memory.bits as usize / 8;

            for _ in 0..8 {
                // do 8 idk?
                sp = sp + Value::Concrete(length as u64, 0);
                if !values.is_empty() {
                    self.memory_write_value(&sp, &values.remove(0), length);
                }
            }
        }
    }

    /// Assert the truth of the given bitvector (value != 0)
    pub fn assert_bv(&mut self, bv: &BitVec) {
        self.solver.assert_bv(bv)
    }

    /// Assert the truth of the given `Value` (value != 0)
    pub fn assert(&mut self, value: &Value) {
        self.solver.assert(value)
    }

    /// Check the satisfiability of the given value
    pub fn check(&mut self, val: &Value) -> bool {
        self.solver.check_sat(val)
    }

    /// Get a conditional value
    pub fn cond(&self, condition: &Value, if_val: &Value, else_val: &Value) -> Value {
        self.solver.conditional(condition, if_val, else_val)
    }

    /// Evaluate multiple solutions to bv
    pub fn evaluate_many(&mut self, bv: &BitVec) -> Vec<u64> {
        self.solver.evaluate_many(bv)
    }

    /// Evaluate bytes from bitvector `bv`
    pub fn evaluate_bytes_bv(&mut self, bv: &BitVec) -> Option<Vec<u8>> {
        let new_bv = bv; //self.translate(bv).unwrap();
        let mut data: Vec<u8> = vec![];
        if self.solver.is_sat() {
            //let one_sol = new_bv.get_a_solution().disambiguate();
            let solution_opt = self.solver.solution(new_bv);
            if let Some(solution) = solution_opt {
                for i in 0..(new_bv.get_width() / 8) as usize {
                    let sol = u8::from_str_radix(&solution[i * 8..(i + 1) * 8], 2);
                    data.push(sol.unwrap());
                }
                if self.memory.endian == Endian::Little {
                    data.reverse();
                }
                Some(data)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Evaluate bytes from bitvector `bv`
    pub fn evaluate_string_bv(&mut self, bv: &BitVec) -> Option<String> {
        if let Some(bytes) = self.evaluate_bytes_bv(bv) {
            String::from_utf8(bytes).ok()
        } else {
            None
        }
    }

    /// Evaluate bytes from value
    pub fn evaluate_bytes(&mut self, value: &Value) -> Option<Vec<u8>> {
        self.evaluate_bytes_bv(value.as_bv().as_ref().unwrap())
    }

    /// Evaluate string from value
    pub fn evaluate_string(&mut self, value: &Value) -> Option<String> {
        self.evaluate_string_bv(value.as_bv().as_ref().unwrap())
    }
}
