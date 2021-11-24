use crate::r2_api::{R2Api, R2Result, FunctionInfo, BasicBlock, Instruction, Information};
use crate::processor::{Processor, HookMethod};
use crate::state::{State, StateStatus};
//use crate::value::Value;
use crate::sims::{get_sims, SimMethod, zero};
use crate::sims::syscall::{indirect};
use crate::value::Value;

use std::sync::{Arc, Mutex};
use std::thread;
use std::collections::VecDeque;

use ahash::AHashMap;
type HashMap<P, Q> = AHashMap<P, Q>;

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
    /// Load libraries
    LoadLibs(bool),
    /// Path to load library from
    LibPath(String)
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
    pub strict: bool
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
    pub fn new_with_options<T: AsRef<str>>(
        filename: Option<T>, 
        options: &[RadiusOption]) -> Self {

        let mut argv = vec!();
        let mut eval_max = 256;
        let mut paths = vec!();
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
        let use_sims = !options.contains(&RadiusOption::Sims(false));

        if debug {
            // pretty print disasm + esil
            argv.push("-e scr.color=3");
            argv.push("-e asm.cmt.esil=true");
            argv.push("-e asm.lines=false");
            argv.push("-e asm.emu=false");
        }

        argv.push("-2");

        // need this for sims
        if use_sims {
            argv.push("-e io.cache=true");
            argv.push("-e bin.cache=true");
        }

        let args = if argv.len() > 0 {
            Some(argv)
        } else {
            None
        };

        let mut r2api = R2Api::new(filename, args);

        let opt = !options.contains(&RadiusOption::Optimize(false));
        let lazy = !options.contains(&RadiusOption::Lazy(false));
        let force = options.contains(&RadiusOption::Force(true));
        let topological = options.contains(&RadiusOption::Topological(true));
        let check = options.contains(&RadiusOption::Permissions(true));
        let sim_all = options.contains(&RadiusOption::SimAll(true));
        let selfmod = options.contains(&RadiusOption::SelfModify(true));
        let strict = options.contains(&RadiusOption::Strict(true));
        let mut processor = Processor::new(selfmod, opt, debug, lazy, force, topological);
        let processors = Arc::new(Mutex::new(vec!()));

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
            vec!()
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
            strict
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

    pub fn frida_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        let mut state = self.init_state();
        self.processor.fetch_instruction(&mut state, addr); // cache real instrs
        let context = self.r2api.init_frida(addr).unwrap();

        for reg in context.keys() {
            let val = u64::from_str_radix(&context[reg][2..], 16).unwrap();
            state.registers.set(reg, vc(val));
        }

        state
    }

    /**
     * Initialized state at the program entry point (the first if multiple).
     * Can also be passed concrete args and env variables
     * 
     * **Example**
     * 
     * ```
     * use radius2::radius::Radius;
     * let mut radius = Radius::new("../tests/r100");
     * let mut state = radius.entry_state(&["r100"], &[]);
     * ```
     */
    pub fn entry_state(&mut self) -> State {
        // get the entrypoint
        let entry = self.r2api.get_entrypoints().unwrap()[0].vaddr;
        self.r2api.seek(entry);
        self.r2api.init_vm();
        let mut state = self.init_state();
        state.memory.add_stack();
        state.memory.add_heap();
        state.memory.add_std_streams();

        // we write args to both regs and stack
        // i think this is ok
        /*let sp = state.registers.get_with_alias("SP");
        let ptrlen = (state.memory.bits/8) as usize;
        let argc = Value::Concrete(args.len() as u64, 0);
        state.memory_write_value(
            &sp, &argc, ptrlen);

        state.registers.set_with_alias("A0", argc);

        let types = ["argv", "env"];
        let mut current = sp+Value::Concrete(ptrlen as u64, 0);
        for (i, strings) in [args, env].iter().enumerate() {
            state.context.insert(types[i].to_owned(), vec!(current.clone()));
            let alias = format!("A{}", i+1);
            state.registers.set_with_alias(&alias, current.clone());
            for (j, string) in strings.iter().enumerate() {
                let addr = state.memory.alloc(
                    &Value::Concrete(string.as_ref().len() as u64 +1, 0));

                let mut esc = false;
                for (k, c) in string.as_ref().chars().enumerate() {
                    if c == '\\' {
                        esc = true;
                    } else {
                        let v;
                        if !esc && c == '~' { // ~ become symbolic bytes
                            let sym = format!("{}[{}][{}]", types[i], j, k);
                            v = state.symbolic_value(&sym, 8);
                        } else {
                            v = state.concrete_value(c as u64, 8);
                        }
                        state.memory.write_value(addr+k as u64, &v, 1);
                        esc = false
                    }
                }
                state.memory.write_value(
                    addr+string.as_ref().len() as u64, &Value::Concrete(0,0), 1);

                state.memory_write_value(
                    &current, &Value::Concrete(addr, 0), ptrlen);

                current = current + Value::Concrete(ptrlen as u64, 0); 
            }
            state.memory_write_value(
                &current, &Value::Concrete(0, 0), ptrlen); // write a long null
                
            current = current + Value::Concrete(ptrlen as u64, 0); 
        }*/

        let start_main_reloc = self.r2api.get_address(
            "reloc.__libc_start_main").unwrap();

        self.hook(start_main_reloc, __libc_start_main);

        //state.memory.add_std_streams();
        state
    }

    /// Set argv and env with values instead of the dumb string way
    pub fn set_argv_env(&mut self, state: &mut State, args: &[Value], env: &[Value]) {

        // we write args to both regs and stack
        // i think this is ok
        let sp = state.registers.get_with_alias("SP");
        let ptrlen = (state.memory.bits/8) as usize;
        let argc = Value::Concrete(args.len() as u64, 0);
        state.memory_write_value(&sp, &argc, ptrlen);
        state.registers.set_with_alias("A0", argc);

        let types = ["argv", "env"];
        let mut current = sp+Value::Concrete(ptrlen as u64, 0);
        for (i, strings) in [args, env].iter().enumerate() {
            state.context.insert(types[i].to_owned(), vec!(current.clone()));
            let alias = format!("A{}", i+1);
            state.registers.set_with_alias(&alias, current.clone());
            for string in strings.iter() {
                let addr = state.memory.alloc(
                    &Value::Concrete((string.size()/8) as u64 +1, 0));

                state.memory_write_value(
                    &Value::Concrete(addr, 0), string, string.size() as usize/8);

                state.memory.write_value(
                    addr+(string.size()/8) as u64, &Value::Concrete(0,0), 1);

                state.memory_write_value(
                    &current, &Value::Concrete(addr, 0), ptrlen);

                current = current + Value::Concrete(ptrlen as u64, 0); 
            }
            state.memory_write_value(&current, &Value::Concrete(0, 0), ptrlen); 
            current = current + Value::Concrete(ptrlen as u64, 0); 
        }
    }

    pub fn init_state(&mut self) -> State {
        State::new(&mut self.r2api, self.eval_max, self.debug, false, self.check, self.strict)
    }

    pub fn blank_state(&mut self) -> State {
        State::new(&mut self.r2api, self.eval_max, self.debug, true, self.check, self.strict)
    }

    /// Blank except for PC and SP
    pub fn blank_call_state(&mut self, addr: u64) -> State {
        self.r2api.seek(addr);
        self.r2api.init_vm();
        let mut state = self.blank_state();
        let sp = self.r2api.get_register_value("SP").unwrap();
        state.registers.set_with_alias("PC", Value::Concrete(addr, 0));
        state.registers.set_with_alias("SP", Value::Concrete(sp, 0));
        state.memory.add_stack();
        state.memory.add_heap();
        state.memory.add_std_streams();
        state
    }

    /// Hook an address with a callback that is passed the `State`
    pub fn hook(&mut self, addr: u64, hook_callback: HookMethod) {
        let mut hooks = self.processor.hooks.remove(&addr).unwrap_or_default();
        hooks.push(hook_callback);
        self.processor.hooks.insert(addr, hooks);
    }

    /// Hook an address with an esil expression
    pub fn esil_hook(&mut self, addr: u64, esil: &str) {
        let mut esils = self.processor.esil_hooks.remove(&addr).unwrap_or_default();
        esils.push(esil.to_owned());
        self.processor.esil_hooks.insert(addr, esils);
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
                    processor.sims.insert(addr, sim.function);
                }
            }

            if sim_all {
                for addr in symmap.values() {
                    // we are gonna go with unconstrained by default
                    processor.sims.insert(*addr, zero);
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
    pub fn simulate(&mut self, addr: u64, sim: SimMethod) {
        self.processor.sims.insert(addr, sim);
    }

    /// Add a breakpoint at the provided address. 
    /// This is where execution will stop after `run` is called
    pub fn breakpoint(&mut self, addr: u64) {
        self.processor.breakpoints.insert(addr, true);
    }

    /// Add a mergepoint, an address where many states will be combined
    /// into a single state with the proper constraints
    pub fn mergepoint(&mut self, addr: u64) {
        self.processor.mergepoints.insert(addr, true);
    }

    /// Add addresses that will be avoided during execution. Any
    /// `State` that reaches these addresses will be marked inactive
    pub fn avoid(&mut self, addrs: &[u64]) {
        for addr in addrs {
            self.processor.avoidpoints.insert(*addr, true);
        }
    }

    /// Simple way to execute until a given target address while avoiding a vec of other addrs
    pub fn run_until(&mut self, state: State, target: u64, avoid: &[u64]) -> Option<State> {
        self.breakpoint(target);
        self.avoid(avoid);
        self.processor.run(state, false).pop_front()
    }

    /**
     * Main run method, start or continue a symbolic execution
     * 
     * More words 
     * 
     */
    pub fn run(&mut self, state: State, mut threads: usize) -> Option<State> {
        if threads == 1 {
            return self.processor.run(state, false).pop_front();
        }

        let mut handles = Vec::with_capacity(threads);
        let statevector = Arc::new(Mutex::new(VecDeque::with_capacity(self.eval_max)));
        statevector.lock().unwrap().push_back(state);

        // if there are multiple threads we need to duplicate solvers
        // else there will be race conditions. Unfortunately this 
        // will prevent mergers from happening. this sucks 
        if !self.processor.mergepoints.is_empty() {
            threads = 1;
        }

        loop {
            let mut count = 0;
            while count < threads && !statevector.lock().unwrap().is_empty() {
                //println!("on thread {}!", thread_count);
                let procs = self.processors.clone();
                let states = statevector.clone();
                let state = if threads > 1 {
                    states.lock().unwrap().pop_front().unwrap().duplicate()
                } else {
                    states.lock().unwrap().pop_front().unwrap()
                };

                let mut processor = if !procs.lock().unwrap().is_empty() {
                    procs.lock().unwrap().pop().unwrap()
                } else {
                    self.processor.clone()
                };

                if state.status == StateStatus::Break {
                    return Some(state);
                }

                let handle = thread::spawn(move || {
                    let new_states = processor.run(state, threads > 1);
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

            if let Some(state) = statevector.lock().unwrap().iter() 
                .find(|s| s.status == StateStatus::Break) {
                break Some(state.to_owned()); 
            }
        }
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
    pub fn get_address(&mut self, symbol: &str) -> R2Result<u64> {
        self.r2api.get_address(symbol)
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
        self.r2api.write(address, 
            string.chars().map(|c| c as u8).collect::<Vec<_>>())
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
        //self.processor = Processor::new();
    }
}

pub fn __libc_start_main(state: &mut State) -> bool {
    let main = state.registers.get_with_alias("A0");
    let argc = state.registers.get_with_alias("A1");
    let argv = state.registers.get_with_alias("A2");
    let env  = state.registers.get_with_alias("A3");

    // TODO go to init then main 
    // but we need a nice arch neutral way to push ret 
    // so until then 

    // go to main 
    state.registers.set_with_alias("PC", main);
    state.registers.set_with_alias("A0", argc);
    state.registers.set_with_alias("A1", argv);

    // TODO set env
    state.registers.set_with_alias("A2", env);

    false
}

/// convenience method for making an untainted `Value::Concrete`
pub fn vc(v: u64) -> Value {
    Value::Concrete(v, 0)
}