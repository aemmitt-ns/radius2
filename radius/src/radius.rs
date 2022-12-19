pub use crate::processor::{HookMethod, Processor, RunMode};
use crate::r2_api::{BasicBlock, FunctionInfo, Information, Instruction, R2Api, R2Result};
use crate::state::State;
//use crate::value::Value;
use crate::sims::syscall::indirect;
use crate::sims::{get_sims, zero, SimMethod, Sim};
use crate::value::{vc, Value};

// use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// use std::thread;

#[derive(Debug, Clone, PartialEq)]
pub enum RadiusOption {
    /// Use simulated syscalls
    Syscalls(bool),
    /// Use simulated imports     
    Sims(bool),
    /// Sim all imports, with stub if missing
    SimAll(bool),
    /// Optimize executed ESIL expressions
    Optimize(bool),
    /// Enable debug output
    Debug(bool),
    /// panic! on unimplemented
    Strict(bool),
    /// Don't check sat on symbolic pcs
    Lazy(bool),
    /// Check memory permissions
    Permissions(bool),
    /// Force execution of all branches
    Force(bool),
    /// Execute blocks in topological order
    Topological(bool),
    /// Maximum values to evaluate for sym PCs
    EvalMax(usize),
    /// Radare2 argument, must be static
    R2Argument(&'static str),
    /// Handle self-modifying code (poorly)
    SelfModify(bool),
    /// Load plugins
    LoadPlugins(bool),
    /// Load libraries
    LoadLibs(bool),
    /// use color output from r2
    ColorOutput(bool),
    /// Path to load library from
    LibPath(String),
}

/**
 * Main Radius struct that coordinates and configures
 * the symbolic execution of a binary.
 *
 * Radius can be instantiated using either `Radius::new(filename: &str)`
 * or `Radius::new_with_options(...)`
 *
 * **Example**
 *
 * ```
 * use radius2::radius::Radius;
 * let mut radius = Radius::new("../tests/r200");
 * ```
 *
 */
pub struct Radius {
    pub r2api: R2Api,
    pub processor: Processor,
    processors: Arc<Mutex<Vec<Processor>>>,
    pub eval_max: usize,
    pub check: bool,
    pub debug: bool,
    pub strict: bool,
}

impl Radius {
    /**
     * Create a new Radius instance for the provided binary
     *
     * **Example**
     *
     * ```
     * use radius2::radius::Radius;
     * let mut radius = Radius::new("../tests/r100");
     * ```
     */
    pub fn new<T: AsRef<str>>(filename: T) -> Self {
        // no radius options and no r2 errors by default
        Radius::new_with_options(Some(filename), &[])
    }

    /**
     * Create a new Radius instance for the provided binary with a vec of `RadiusOption`
     *
     * **Example**
     *
     * ```
     * use radius2::radius::{Radius, RadiusOption};
     * let options = [RadiusOption::Optimize(false), RadiusOption::Sims(false)];
     * let mut radius = Radius::new_with_options(Some("../tests/baby-re"), &options);
     * ```
     */
    pub fn new_with_options<T: AsRef<str>>(filename: Option<T>, options: &[RadiusOption]) -> Self {
        let mut argv = vec!["-2"];
        let mut eval_max = 256;
        let mut paths = vec![];
        for o in options {
            if let RadiusOption::R2Argument(arg) = o {
                argv.push(*arg);
            } else if let RadiusOption::EvalMax(m) = o {
                eval_max = *m;
            } else if let RadiusOption::LibPath(p) = o {
                paths.push(p.to_owned());
            }
        }

        let debug = options.contains(&RadiusOption::Debug(true));
        let color = options.contains(&RadiusOption::ColorOutput(true));
        let use_sims = !options.contains(&RadiusOption::Sims(false));

        if !options.contains(&RadiusOption::LoadPlugins(true)) {
            argv.push("-NN");
        }

        if debug && color {
            // pretty print disasm + esil
            argv.push("-e scr.color=3");
            argv.push("-e asm.cmt.esil=true");
            argv.push("-e asm.lines=false");
            argv.push("-e asm.emu=false");
            argv.push("-e asm.xrefs=false");
            argv.push("-e asm.functions=false");
        }

        let args = if !argv.is_empty() || filename.is_none() { Some(argv) } else { None };

        let mut r2api = R2Api::new(filename, args);
        r2api.set_option("io.cache", "true").unwrap();
        // r2api.cmd("eco darkda").unwrap(); // i like darkda

        let arch = &r2api.info.bin.arch;

        // don't optimize dalvik & arm
        let opt = !options.contains(&RadiusOption::Optimize(false))
            && arch.as_str() != "arm"
            && arch.as_str() != "dalvik";

        let lazy = !options.contains(&RadiusOption::Lazy(false));
        let force = options.contains(&RadiusOption::Force(true));
        let topo = options.contains(&RadiusOption::Topological(true));
        let check = options.contains(&RadiusOption::Permissions(true));
        let sim_all = options.contains(&RadiusOption::SimAll(true));
        let selfmod = options.contains(&RadiusOption::SelfModify(true));
        let strict = options.contains(&RadiusOption::Strict(true));

        let mut processor = Processor::new(selfmod, opt, debug, lazy, force, topo, color);
        let processors = Arc::new(Mutex::new(vec![]));

        if !options.contains(&RadiusOption::Syscalls(false)) {
            let syscalls = r2api.get_syscalls().unwrap();
            if let Some(sys) = syscalls.get(0) {
                processor.traps.insert(sys.swi, indirect);
            }
            for sys in &syscalls {
                processor.syscalls.insert(sys.num, sys.to_owned());
            }
        }

        let _libs = if options.contains(&RadiusOption::LoadLibs(true)) {
            r2api.load_libraries(&paths).unwrap()
        } else {
            vec![]
        };

        // this is weird, idk
        if use_sims {
            Radius::register_sims(&mut r2api, &mut processor, sim_all);
        }

        Radius {
            r2api,
            processor,
            processors,
            eval_max,
            check,
            debug,
            strict,
        }
    }

    /**
     * Initialized state at the provided function address with an initialized stack
     * (if applicable)
     *
     * **Example**
     *
     * ```
     * use radius2::radius::Radius;
     * let mut radius = Radius::new("../tests/r100");
     * let mut state = radius.call_state(0x004006fd);
     * ```
     */
    pub fn call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        let mut state = self.init_state();
        state.memory.add_stack();
        state.memory.add_heap();
        state.memory.add_std_streams();
        state
    }

    /**
     * Initialized state at the provided function name with an initialized stack
     * equivalent to `call_state(get_address(sym))`
     *
     * **Example**
     *
     * ```
     * use radius2::radius::Radius;
     * let mut radius = Radius::new("../tests/r100");
     * let mut state = radius.callsym_state("sym.imp.printf");
     * ```
     */
    pub fn callsym_state<T: AsRef<str>>(&mut self, sym: T) -> State {
        let addr = self.get_address(sym).unwrap_or_default();
        self.call_state(addr)
    }

    /// Initialize state from a debugger breakpoint
    /// the program will block until bp is hit
    pub fn debug_state(&mut self, addr: u64, args: &[String]) -> State {
        // set cache to false to set breakpoint
        self.r2api.set_option("io.cache", "false").unwrap();
        self.r2api.init_debug(addr, args);
        self.init_state()
    }

    /// Initialize state from a frida hook
    /// the program will block until the hook is hit
    pub fn frida_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        let mut state = self.init_state();
        self.processor.fetch_instruction(&mut state, addr); // cache real instrs
        let context = self.r2api.init_frida(addr).unwrap();

        for reg in context.keys() {
            if state.registers.regs.contains_key(reg) {
                state.registers.set(reg, vc(context[reg]));
            }
        }
        state
    }

    /**
     * Initialized state at the program entry point (the first if multiple).
     *
     * **Example**
     *
     * ```
     * use radius2::radius::Radius;
     * let mut radius = Radius::new("../tests/r100");
     * let mut state = radius.entry_state();
     * ```
     */
    pub fn entry_state(&mut self) -> State {
        // get the entrypoint
        let entrypoints = self.r2api.get_entrypoints().unwrap_or_default();
        if !entrypoints.is_empty() {
            self.r2api.seek(entrypoints[0].vaddr);
        }
        self.r2api.init_vm();
        let mut state = self.init_state();
        state.memory.add_stack();
        state.memory.add_heap();
        state.memory.add_std_streams();

        let start_main_reloc = self.r2api.get_address("reloc.__libc_start_main").unwrap();

        self.hook(start_main_reloc, __libc_start_main);
        state
    }

    /// Set argv and env with values instead of the dumb string way
    pub fn set_argv_env(&mut self, state: &mut State, args: &[Value], env: &[Value]) {
        // we write args to both regs and stack
        // i think this is ok
        let sp = state.registers.get_with_alias("SP");
        let ptrlen = (state.memory.bits / 8) as usize;
        let argc = Value::Concrete(args.len() as u64, 0);
        state.memory_write_value(&sp, &argc, ptrlen);
        state.registers.set_with_alias("A0", argc);

        let types = ["argv", "env"];
        let mut current = sp + Value::Concrete(ptrlen as u64, 0);
        for (i, strings) in [args, env].iter().enumerate() {
            state
                .context
                .insert(types[i].to_owned(), vec![current.clone()]);
            let alias = format!("A{}", i + 1);
            state.registers.set_with_alias(&alias, current.clone());
            for string in strings.iter() {
                let addr = state
                    .memory
                    .alloc(&Value::Concrete((string.size() / 8) as u64 + 1, 0));

                state.memory_write_value(
                    &Value::Concrete(addr, 0),
                    string,
                    string.size() as usize / 8,
                );

                state.memory.write_value(
                    addr + (string.size() / 8) as u64,
                    &Value::Concrete(0, 0),
                    1,
                );

                state.memory_write_value(&current, &Value::Concrete(addr, 0), ptrlen);
                current = current + Value::Concrete(ptrlen as u64, 0);
            }
            state.memory_write_value(&current, &Value::Concrete(0, 0), ptrlen);
            current = current + Value::Concrete(ptrlen as u64, 0);
        }
    }

    pub fn init_state(&mut self) -> State {
        State::new(
            &mut self.r2api,
            self.eval_max,
            self.debug,
            false,
            self.check,
            self.strict,
        )
    }

    pub fn blank_state(&mut self) -> State {
        State::new(
            &mut self.r2api,
            self.eval_max,
            self.debug,
            true,
            self.check,
            self.strict,
        )
    }

    /// Blank except for PC and SP
    pub fn blank_call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        let mut state = self.blank_state();
        let sp = self.r2api.get_register_value("SP").unwrap();
        state
            .registers
            .set_with_alias("PC", Value::Concrete(addr, 0));
        state.registers.set_with_alias("SP", Value::Concrete(sp, 0));
        state.memory.add_stack();
        state.memory.add_heap();
        state.memory.add_std_streams();
        state
    }

    /// Hook an address with a callback that is passed the `State`
    pub fn hook(&mut self, addr: u64, hook_callback: HookMethod) {
        self.processor
            .hooks
            .entry(addr)
            .or_insert(vec![])
            .push(hook_callback);
    }

    /// Hook an address with an esil expression
    pub fn esil_hook(&mut self, addr: u64, esil: &str) {
        self.processor
            .esil_hooks
            .entry(addr)
            .or_insert(vec![])
            .push(esil.to_owned());
    }

    /// Hook a symbol with a callback that is passed each state that reaches it
    pub fn hook_symbol(&mut self, sym: &str, hook_callback: HookMethod) {
        let addr = self.get_address(sym).unwrap();
        self.hook(addr, hook_callback);
    }

    // internal method to register import sims
    fn register_sims(r2api: &mut R2Api, processor: &mut Processor, sim_all: bool) {
        let sims = get_sims();
        let files = r2api.get_files().unwrap();

        for file in files {
            if file.uri.starts_with("null://") {
                continue;
            }

            r2api.set_file_fd(file.fd);
            let symbols = r2api.get_imports().unwrap();
            let mut symmap: HashMap<String, u64> = HashMap::new();

            for symbol in symbols {
                symmap.insert(symbol.name, symbol.plt);
            }

            // TODO expand this to handle other symbols
            for sim in &sims {
                let addropt = symmap.remove(&sim.symbol);
                if let Some(addr) = addropt {
                    processor.sims.insert(addr, sim.to_owned());
                }
            }

            if sim_all {
                for name in symmap.keys() {
                    // we are gonna go with zero by default
                    processor.sims.insert(symmap[name], Sim {
                        symbol: name.to_owned(),
                        function: zero,
                        arguments: 0,
                    });
                }
            }
        }

        // back to main file
        r2api.set_file_fd(3);
    }

    /// Register a trap to call the provided `SimMethod`
    pub fn trap(&mut self, trap_num: u64, sim: SimMethod) {
        self.processor.traps.insert(trap_num, sim);
    }

    /// Register a `SimMethod` for the provided function address
    pub fn simulate(&mut self, addr: u64, sim: Sim) {
        self.processor.sims.insert(addr, sim);
    }

    /// Add a breakpoint at the provided address.
    /// This is where execution will stop after `run` is called
    pub fn breakpoint(&mut self, addr: u64) {
        self.processor.breakpoints.insert(addr);
    }

    /// Add a mergepoint, an address where many states will be combined
    /// into a single state with the proper constraints
    pub fn mergepoint(&mut self, addr: u64) {
        self.processor.mergepoints.insert(addr);
    }

    /// Add addresses that will be avoided during execution. Any
    /// `State` that reaches these addresses will be marked inactive
    pub fn avoid(&mut self, addrs: &[u64]) {
        for addr in addrs {
            self.processor.avoidpoints.insert(*addr);
        }
    }

    pub fn get_steps(&self) -> u64 {
        self.processor.steps
            + self
                .processors
                .lock()
                .unwrap()
                .iter()
                .map(|p| p.steps)
                .sum::<u64>()
    }

    /// execute function
    pub fn call_function(&mut self, sym: &str, state: State, args: Vec<Value>) -> Option<State> {
        let addr = self.r2api.get_address(sym).unwrap_or_default();
        self.call_address(addr, state, args)
    }

    /// execute function at address
    pub fn call_address(&mut self, addr: u64, mut state: State, args: Vec<Value>) -> Option<State> {
        state.set_args(args);
        state.registers.set_pc(vc(addr));
        self.processor.run(state, RunMode::Single).pop()
    }

    /// Simple way to execute until a given target address while avoiding a vec of other addrs
    pub fn run_until(&mut self, state: State, target: u64, avoid: &[u64]) -> Option<State> {
        self.breakpoint(target);
        self.avoid(avoid);
        self.processor.run(state, RunMode::Single).pop()
    }

    /// execute until every state has reached an end
    pub fn run_all(&mut self, state: State) -> Vec<State> {
        self.processor.run(state, RunMode::Multiple)
    }

    /**
     * Main run method, start or continue a symbolic execution
     *
     * More words
     *
     */
    pub fn run(&mut self, state: State, _threads: usize) -> Option<State> {
        // we are gonna scrap threads for now cuz theyre currently useless.
        self.processor.run(state, RunMode::Single).pop()

        // if there are multiple threads we need to duplicate solvers
        // else there will be race conditions. Unfortunately this
        // will prevent mergers from happening. this sucks

        /*if threads == 1 || !self.processor.mergepoints.is_empty() {
            return self.processor.run(state, RunMode::Single).pop();
        }

        let mut handles = Vec::with_capacity(threads);
        let statevector = Arc::new(Mutex::new(VecDeque::with_capacity(threads * self.eval_max)));
        statevector.lock().unwrap().push_back(state);

        loop {
            let mut count = 0;
            let _state_count = statevector.lock().unwrap().len();
            while count < threads && !statevector.lock().unwrap().is_empty() {
                //println!("on thread {}!", thread_count);
                let procs = self.processors.clone();
                let states = statevector.clone();
                let state = states.lock().unwrap().pop_front().unwrap().duplicate();

                let mut processor = if !procs.lock().unwrap().is_empty() {
                    procs.lock().unwrap().pop().unwrap()
                } else {
                    self.processor.clone()
                };

                let handle = thread::spawn(move || {
                    let new_states = processor.run(state, RunMode::Single);
                    states.lock().unwrap().extend(new_states);
                    procs.lock().unwrap().push(processor);
                });
                handles.push(handle);
                count += 1;
            }

            while !handles.is_empty() {
                handles.pop().unwrap().join().unwrap();
            }

            if statevector.lock().unwrap().is_empty() {
                break None;
            }

            if let Some(state) = statevector
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.status == StateStatus::Break)
            {
                break Some(state.to_owned());
            }
        }*/
    }

    /// Run radare2 analysis
    pub fn analyze(&mut self, n: usize) {
        let _r = self.r2api.analyze(n);
    }

    /// Get information about the binary and radare2 session
    pub fn get_info(&mut self) -> R2Result<Information> {
        self.r2api.get_info()
    }

    /// Get address of symbol
    pub fn get_address<T: AsRef<str>>(&mut self, symbol: T) -> R2Result<u64> {
        self.r2api.get_address(symbol.as_ref())
    }

    /// Get all functions
    pub fn get_functions(&mut self) -> R2Result<Vec<FunctionInfo>> {
        self.r2api.get_functions()
    }

    /// Get function information at this address
    pub fn get_function(&mut self, address: u64) -> R2Result<FunctionInfo> {
        self.r2api.get_function_info(address)
    }

    /// Get basic blocks of a function
    pub fn get_blocks(&mut self, address: u64) -> R2Result<Vec<BasicBlock>> {
        self.r2api.get_blocks(address)
    }

    /// Disassemble at the provided address
    pub fn disassemble(&mut self, address: u64, num: usize) -> R2Result<Vec<Instruction>> {
        self.r2api.disassemble(address, num)
    }

    /// Disassemble function at the provided address
    pub fn disassemble_function(&mut self, address: u64) -> R2Result<Vec<Instruction>> {
        self.r2api.disassemble_function(address)
    }

    /// Assemble the given instruction
    pub fn assemble(&mut self, instruction: &str) -> R2Result<Vec<u8>> {
        self.r2api.assemble(instruction)
    }

    /// Read directly from binary
    pub fn read(&mut self, address: u64, length: usize) -> R2Result<Vec<u8>> {
        self.r2api.read(address, length)
    }

    /// Patch binary
    pub fn write(&mut self, address: u64, data: Vec<u8>) {
        self.r2api.write(address, data)
    }

    /// write string to binary / real memory
    pub fn write_string(&mut self, address: u64, string: &str) {
        self.r2api
            .write(address, string.chars().map(|c| c as u8).collect::<Vec<_>>())
    }

    /// set option
    pub fn set_option(&mut self, key: &str, value: &str) {
        self.r2api.set_option(key, value).unwrap();
    }

    /// Run any r2 command
    pub fn cmd(&mut self, cmd: &str) -> R2Result<String> {
        self.r2api.cmd(cmd)
    }

    /// close r2
    pub fn close(&mut self) {
        self.r2api.close()
    }

    // clear cached data from r2api and processors
    pub fn clear(&mut self) {
        self.r2api.clear();
        self.processors.lock().unwrap().clear();
    }
}

pub fn __libc_start_main(state: &mut State) -> bool {
    let mut args = state.get_args();
    let main = args.remove(0);

    // TODO go to init then main
    // but we need a nice arch neutral way to push ret
    // so until then

    // go to main
    state.registers.set_with_alias("PC", main);
    state.set_args(args);

    false
}
