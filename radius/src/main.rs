use clap::{Arg, App};
use boolector::BV;
use crate::radius::{Radius, RadiusOption};
use crate::processor::Word;
use crate::r2_api::hex_encode;

// use crate::state::State;
use crate::value::Value;

use ahash::AHashMap;
type HashMap<P, Q> = AHashMap<P, Q>;

pub mod r2_api;
pub mod registers;
pub mod value;
pub mod processor;
pub mod state;
pub mod operations;
pub mod memory;
pub mod radius;
pub mod solver;
pub mod sims;
pub mod test;

fn main() {
    let matches = App::new("radius2")
        .version("1.0.5")
        .author("Austin Emmitt <aemmitt@nowsecure.com>")
        .about("Symbolic Execution tool using r2 and boolector")
        .arg(Arg::with_name("path")
            .short("p")
            .long("path")
            .takes_value(true)
            .required(true)
            .help("Path to the target binary"))
        .arg(Arg::with_name("libs")
            .short("L")
            .long("libs")
            .takes_value(true)
            .help("Load libraries from path"))
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .value_names(&["PATH", "SYMBOL"])
            .multiple(true)
            .help("Add a symbolic file"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Show verbose / debugging output"))
        .arg(Arg::with_name("lazy")
            .short("z")
            .long("lazy")
            .help("Evaluate symbolic PC values lazily"))
        .arg(Arg::with_name("strict")
            .long("strict")
            .help("Panic on invalid instructions and ESIL"))
        .arg(Arg::with_name("no_sims")
            .long("no-sims")
            .help("Do not simulate imports"))
        .arg(Arg::with_name("frida")
            .short("F")
            .long("frida")
            .help("Create initial state from frida hook"))
        .arg(Arg::with_name("stdin")
            .short("0")
            .long("stdin")
            .help("Use stdin for target program"))
        .arg(Arg::with_name("stdout")
            .short("1")
            .long("stdout")
            .help("Show stdout output"))
        .arg(Arg::with_name("stderr")
            .short("2")
            .long("stderr")
            .help("Show stderr output"))
        // gonna have it all sim by default if libs not loaded
        /*.arg(Arg::with_name("all_sims")
            .long("all-sims")
            .help("Simulate all imports (nop unimplemented)"))*/
        .arg(Arg::with_name("address")
            .short("a")
            .long("address")
            .takes_value(true)
            .help("Address to begin execution at"))
        .arg(Arg::with_name("threads")
            .short("t")
            .long("threads")
            .takes_value(true)
            .default_value("1")
            .help("Number of threads to execute"))
        .arg(Arg::with_name("breakpoint")
            .short("b")
            .long("break")
            .takes_value(true)
            .multiple(true)
            .help("Breakpoint at some target address"))
        .arg(Arg::with_name("break_strings")
            .short("B")
            .long("break-strings")
            .takes_value(true)
            .multiple(true)
            .help("Breakpoint code xrefs to strings"))
        .arg(Arg::with_name("avoid")
            .short("x")
            .long("avoid")
            .takes_value(true)
            .multiple(true)
            .help("Avoid addresses"))
        .arg(Arg::with_name("avoid_strings")
            .short("X")
            .long("avoid-strings")
            .takes_value(true)
            .multiple(true)
            .help("Avoid code xrefs to strings"))
        .arg(Arg::with_name("merge")
            .short("m")
            .long("merge")
            .takes_value(true)
            .multiple(true)
            .help("Set address as a mergepoint"))
        .arg(Arg::with_name("arg")
            .long("arg")
            .takes_value(true)
            .multiple(true)
            .help("Argument for the target program"))
        .arg(Arg::with_name("env")
            .long("env")
            .takes_value(true)
            .multiple(true)
            .help("Environment variable for the target program"))
        .arg(Arg::with_name("symbol")
            .short("s")
            .long("symbol")
            .value_names(&["NAME", "BITS"])
            .multiple(true)
            .help("Create a symbolic value"))
        .arg(Arg::with_name("set")
            .short("S")
            .long("set")
            .value_names(&["REG/ADDR", "VALUE", "BITS"])
            .multiple(true)
            .help("Set memory or register values"))
        .arg(Arg::with_name("constrain")
            .short("c")
            .long("constrain")
            .value_names(&["SYMBOL", "EXPR"])
            .multiple(true)
            .help("Constrain symbol values with string or pattern"))
        .arg(Arg::with_name("hook")
            .short("H")
            .long("hook")
            .value_names(&["ADDR", "EXPR"])
            .multiple(true)
            .help("Hook the provided address with an ESIL expression"))
        .arg(Arg::with_name("r2_command")
            .short("r")
            .long("r2-cmd")
            .value_names(&["CMD"])
            .multiple(true)
            .help("Run r2 command on launch"))
        .arg(Arg::with_name("evaluate")
            .short("e")
            .long("eval")
            .value_names(&["ESIL"])
            .multiple(true)
            .help("Evaluate ESIL expression"))
        .arg(Arg::with_name("evaluate_after")
            .short("E")
            .long("eval-after")
            .value_names(&["ESIL"])
            .multiple(true)
            .help("Evaluate ESIL expression after execution"))
        .get_matches();

    let libpaths: Vec<&str> = matches.values_of("libs").unwrap_or_default().collect();

    let no_sims = matches.occurrences_of("no_sims") > 0;
    let all_sims = !no_sims && libpaths.is_empty();

    let mut options = vec!(
        RadiusOption::Debug(matches.occurrences_of("verbose") > 0),
        RadiusOption::Lazy(matches.occurrences_of("lazy") > 0),
        RadiusOption::Strict(matches.occurrences_of("strict") > 0),
        RadiusOption::Sims(!no_sims),
        RadiusOption::SimAll(all_sims),
        RadiusOption::LoadLibs(!libpaths.is_empty())
    );
    
    for lib in libpaths {
        options.push(RadiusOption::LibPath(lib.to_owned()));
    }

    let mut radius = Radius::new_with_options(matches.value_of("path"), &options);
    let threads: usize = matches.value_of("threads").unwrap_or_default().parse().unwrap();

    // execute provided r2 commands
    let cmds: Vec<&str> = matches.values_of("r2_command").unwrap_or_default().collect();
    for cmd in cmds {
        let r = radius.cmd(cmd);
        if matches.occurrences_of("verbose") > 0 && r.is_ok() {
            println!("{}", r.unwrap());
        }
    }
    
    let mut state = if let Some(address) = matches.value_of("address") {
        let addr = radius.get_address(address).unwrap();
        if matches.occurrences_of("frida") > 0 {
            radius.frida_state(addr)
        } else {
            radius.call_state(addr)
        }
    } else {
        radius.entry_state()
    };

    // collect the symbol declarations
    let mut files: Vec<&str> = matches.values_of("file").unwrap_or_default().collect();
    let mut symbol_map = HashMap::new();
    let symbols: Vec<&str> = matches.values_of("symbol").unwrap_or_default().collect();
    for i in 0..matches.occurrences_of("symbol") as usize {
        let length: u32 = symbols[2*i+1].parse().unwrap();
        let sym_value = state.symbolic_value(symbols[2*i], length);
        let sym_name = symbols[2*i];
        symbol_map.insert(sym_name, sym_value.as_bv().unwrap());
        state.context.insert(sym_name.to_owned(), vec!(sym_value));

        if sym_name.to_lowercase() == "stdin" {
            files.extend(vec!("0", sym_name));
        }
    }

    if matches.occurrences_of("arg") > 0 || matches.occurrences_of("env") > 0{
        let argvs: Vec<&str> = matches.values_of("arg").unwrap_or_default().collect();
        let envs: Vec<&str> = matches.values_of("env").unwrap_or_default().collect();
        let mut argv = vec!();
        let mut envv = vec!();

        for (t, args) in [argvs, envs].iter().enumerate() {
            for i in 0..args.len() as usize {
                let value = if let Some(sym) = symbol_map.get(args[i]) {
                    Value::Symbolic(sym.clone(), 0)
                } else {
                    let bytes: Vec<Value> = args[i].as_bytes().iter()
                        .map(|b| Value::Concrete(*b as u64, 0)).collect();

                    state.memory.pack(&bytes)
                };

                if t == 0 {
                    argv.push(value);
                } else {
                    envv.push(value);
                }
            }
        }

        radius.set_argv_env(&mut state, &argv, &envv);
    }

    // collect the symbol constraints
    let cons: Vec<&str> = matches.values_of("constrain").unwrap_or_default().collect();
    for i in 0..matches.occurrences_of("constrain") as usize {
        let bv = &symbol_map[cons[2*i]];
        state.constrain_bytes(bv, cons[2*i+1]);
    }

    // collect the ESIL hooks
    let hooks: Vec<&str> = matches.values_of("hook").unwrap_or_default().collect();
    for i in 0..matches.occurrences_of("hook") as usize {
        if let Ok(addr) = radius.get_address(hooks[2*i]) {
            radius.esil_hook(addr, hooks[2*i+1]);
        }
    }

    // collect the added files
    for i in 0..files.len()/2 as usize {
        let file = files[2*i];
        let name = files[2*i+1];
        if let Some(sym) = symbol_map.get(name) {
            let length = symbol_map[name].get_width() as usize;
            let value = Value::Symbolic(sym.clone(), 0);
            let bytes = state.memory.unpack(&value, length/8);
            if let Ok(fd) = files[2*i].parse() {
                state.filesystem.fill(fd, &bytes);
            } else {
                state.filesystem.add_file(files[2*i], &bytes);
            }
        } else {
            let content = files[2*i+1];
            if let Ok(fd) = file.parse() {
                state.fill_file_string(fd, content)
            } else {
                let bytes: Vec<Value> = content.as_bytes().iter()
                    .map(|b| Value::Concrete(*b as u64, 0)).collect();

                state.filesystem.add_file(file, &bytes);
            }
        }
    }

    // set provided address and register values
    let sets: Vec<&str> = matches.values_of("set").unwrap_or_default().collect();
    for i in 0..matches.occurrences_of("set") as usize {
        // easiest way to interpret the stuff is just to use 
        let ind = 3*i;
        let length: u32 = sets[ind+2].parse().unwrap();

        let value = if let Some(Word::Literal(val)) = 
            radius.processor.get_literal(sets[ind+1]) {
            val
        } else if let Some(bv) = symbol_map.get(sets[ind+1]) {
            Value::Symbolic(bv.slice(length-1, 0), 0)
        } else {
            // this is a real workaround of the system
            // i need a better place for these kinds of utils
            let bytes = sets[ind+1].as_bytes();
            let bv = BV::from_hex_str(state.solver.btor.clone(), 
                hex_encode(bytes).as_str(), length);

            Value::Symbolic(bv, 0)
        };

        if let Some(Word::Literal(address)) = 
            radius.processor.get_literal(sets[ind]) {
            state.memory_write_value(&address, &value, (length/8) as usize);
        } else if let Some(Word::Register(index)) = 
            radius.processor.get_register(&mut state, sets[ind]) {
            state.registers.set_value(index, value);
        }
    }

    // set breakpoints, avoids, and merges
    let mut bps: Vec<u64> = matches.values_of("bp").unwrap_or_default()
        .map(|x| radius.get_address(x).unwrap()).collect();
    let mut avoid: Vec<u64> = matches.values_of("avoid").unwrap_or_default()
        .map(|x| radius.get_address(x).unwrap()).collect();
    let merges: Vec<u64> = matches.values_of("merge").unwrap_or_default()
        .map(|x| radius.get_address(x).unwrap()).collect();

    // get code references to strings and add them to the avoid list
    if matches.occurrences_of("avoid_strings") > 0 {
        // need to analyze to get string refs
        radius.analyze(3);
        for string in matches.values_of("avoid_strings").unwrap_or_default() {
            for location in radius.r2api.search_strings(string).unwrap() {
                avoid.extend(radius.r2api.get_references(location)
                    .unwrap_or_default().iter().map(|x| x.from));
            }
        }
    }
    
    // get code references to strings and add them to the breakpoints
    if matches.occurrences_of("break_strings") > 0 {
        // need to analyze to get string refs
        radius.analyze(3);
        for string in matches.values_of("break_strings").unwrap_or_default() {
            for location in radius.r2api.search_strings(string).unwrap() {
                bps.extend(radius.r2api.get_references(location)
                    .unwrap_or_default().iter().map(|x| x.from));
            }
        }
    }

    for bp in bps {
        radius.breakpoint(bp);
    }

    radius.avoid(&avoid);

    for merge in merges {
        radius.mergepoint(merge);
    }

    // collect the ESIL strings to evaluate
    let evals: Vec<&str> = matches.values_of("evaluate").unwrap_or_default().collect();
    for eval in evals {
        radius.processor.parse_expression(&mut state, eval);
    }

    // run the thing
    if let Some(mut end_state) = radius.run(state, threads) {
        // collect the ESIL strings to evaluate after running
        let evals: Vec<&str> = matches.values_of("evaluate_after")
            .unwrap_or_default().collect();

        for eval in evals {
            radius.processor.parse_expression(&mut end_state, eval);
        }

        for symbol in symbol_map.keys() {
            let val = Value::Symbolic(symbol_map[symbol].clone(), 0);
            if let Some(bv) = end_state.solver.eval_to_bv(&val) {
                if let Some(string) = end_state.evaluate_string(&bv) {
                    println!("{} : {:?} {:?}", symbol, bv, string);
                } else {
                    println!("{} : {:?}", symbol, bv);
                }
            } else {
                println!("{} : no satisfiable value", symbol);
            }
        }

        // dump program output 
        if matches.occurrences_of("stdout") > 0 { 
            print!("{}", end_state.dump_file_string(1).unwrap_or("".to_string()));
        }
        if matches.occurrences_of("stderr") > 0 { 
            print!("{}", end_state.dump_file_string(2).unwrap_or("".to_string()));
        }
    }

    radius.close();
}