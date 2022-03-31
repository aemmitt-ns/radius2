use crate::processor::Word;
use crate::r2_api::hex_encode;
use crate::radius::{Radius, RadiusOption, RunMode};
use boolector::BV;
use clap::{App, Arg};
use std::path::Path;
use std::time::Instant;
use std::{fs, process};

use crate::state::StateStatus;
use crate::value::Value;

use std::collections::HashMap;

//use ahash::AHashMap;
//type HashMap<P, Q> = AHashMap<P, Q>;
use std::collections::VecDeque;
use serde::{Deserialize, Serialize};

pub mod memory;
pub mod operations;
pub mod processor;
pub mod r2_api;
pub mod radius;
pub mod registers;
pub mod sims;
pub mod solver;
pub mod state;
pub mod value;

macro_rules! occurs {
    ($m:expr, $s:expr) => {
        $m.occurrences_of($s) > 0
    };
}

macro_rules! collect {
    ($m:expr, $s:expr) => {
        $m.values_of($s).unwrap_or_default().collect::<Vec<_>>()
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonOutput {
    pub symbols: HashMap<String, String>,
    pub stdout: String,
    pub stderr: String
}

fn main() {
    let matches = App::new("radius2")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Austin Emmitt (@alkalinesec) <aemmitt@nowsecure.com>")
        .about("A symbolic execution tool using r2 and boolector
        
                             ooo  o88                           ooooooo   
 oo oooooo   ooooooo    ooooo888  oooo oooo  oooo   ooooooo88 o88     888 
  888   888  ooooo888 888    888   888  888   888  888ooooooo       o888  
  888      888    888 888    888   888  888   888          888   o888     
 o888o      88ooo88 8o  88ooo888o o888o  888o88 8o 88oooooo88 o8888oooo88 
        ")
        .arg(
            Arg::with_name("path")
                .short("p")
                .long("path")
                .takes_value(true)
                .required(true)
                .help("Path to the target binary"),
        )
        .arg(
            Arg::with_name("libs")
                .short("L")
                .long("libs")
                .takes_value(true)
                .multiple(true)
                .help("Load libraries from path"),
        )
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_names(&["PATH", "SYMBOL"])
                .multiple(true)
                .help("Add a symbolic file"),
        )
        .arg(
            Arg::with_name("json")
                .short("j")
                .long("json")
                .help("Output JSON"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Show verbose / debugging output"),
        )
        .arg(
            Arg::with_name("plugins")
                .long("plugins")
                .help("Load r2 plugins"),
        )
        .arg(
            Arg::with_name("lazy")
                .short("z")
                .long("lazy")
                .help("Evaluate symbolic PC values lazily"),
        )
        .arg(
            Arg::with_name("crash")
                .long("crash")
                .help("Execution stops on invalid memory access"),
        )
        .arg(
            Arg::with_name("selfmodify")
                .short("M")
                .long("selfmodify")
                .help("Allow selfmodifying code (slower)"),
        )
        .arg(
            Arg::with_name("strict")
                .long("strict")
                .help("Panic on invalid instructions and ESIL"),
        )
        .arg(
            Arg::with_name("no_sims")
                .long("no-sims")
                .help("Do not simulate imports"),
        )
        .arg(
            Arg::with_name("fuzz")
                .short("F")
                .long("fuzz")
                .takes_value(true)
                .help("Generate testcases and write to supplied dir"),
        )
        .arg(
            Arg::with_name("max")
                .long("max")
                .takes_value(true)
                .help("Maximum number of states to keep at a time"),
        )
        .arg(
            Arg::with_name("profile")
                .short("P")
                .long("profile")
                .help("Get performance and runtime information"),
        )
        .arg(
            Arg::with_name("color")
                .short("V")
                .long("color")
                .help("Use color output"),
        )
        .arg(
            Arg::with_name("stdin")
                .short("0")
                .long("stdin")
                .help("Use stdin for target program"),
        )
        .arg(
            Arg::with_name("stdout")
                .short("1")
                .long("stdout")
                .help("Show stdout output"),
        )
        .arg(
            Arg::with_name("stderr")
                .short("2")
                .long("stderr")
                .help("Show stderr output"),
        )
        .arg(
            Arg::with_name("address")
                .short("a")
                .long("address")
                .takes_value(true)
                .help("Address to begin execution at"),
        )
        .arg(
            Arg::with_name("threads")
                .short("t")
                .long("threads")
                .takes_value(true)
                .default_value("1")
                .help("Number of threads to execute"),
        )
        .arg(
            Arg::with_name("breakpoint")
                .short("b")
                .long("break")
                .takes_value(true)
                .multiple(true)
                .help("Breakpoint at some target address"),
        )
        .arg(
            Arg::with_name("break_strings")
                .short("B")
                .long("break-strings")
                .takes_value(true)
                .multiple(true)
                .help("Breakpoint code xrefs to strings"),
        )
        .arg(
            Arg::with_name("avoid")
                .short("x")
                .long("avoid")
                .takes_value(true)
                .multiple(true)
                .help("Avoid addresses"),
        )
        .arg(
            Arg::with_name("avoid_strings")
                .short("X")
                .long("avoid-strings")
                .takes_value(true)
                .multiple(true)
                .help("Avoid code xrefs to strings"),
        )
        .arg(
            Arg::with_name("merge")
                .short("m")
                .long("merge")
                .takes_value(true)
                .multiple(true)
                .help("Set address as a mergepoint"),
        )
        .arg(
            Arg::with_name("arg")
                .short("A")
                .long("arg")
                .takes_value(true)
                .multiple(true)
                .help("Argument for the target program"),
        )
        .arg(
            Arg::with_name("env")
                .long("env")
                .takes_value(true)
                .multiple(true)
                .help("Environment variable for the target program"),
        )
        .arg(
            Arg::with_name("symbol")
                .short("s")
                .long("symbol")
                .value_names(&["NAME", "BITS"])
                .multiple(true)
                .help("Create a symbolic value"),
        )
        .arg(
            Arg::with_name("set")
                .short("S")
                .long("set")
                .value_names(&["REG/ADDR", "VALUE", "BITS"])
                .multiple(true)
                .help("Set memory or register values"),
        )
        .arg(
            Arg::with_name("constrain")
                .short("c")
                .long("constrain")
                .value_names(&["SYMBOL", "EXPR"])
                .multiple(true)
                .help("Constrain symbol values with string or pattern"),
        )
        .arg(
            Arg::with_name("constrain_after")
                .short("C")
                .long("constrain-after") // post-constrain
                .value_names(&["SYMBOL", "EXPR"])
                .multiple(true)
                .help("Constrain symbol or file values after execution"),
        )
        .arg(
            Arg::with_name("hook")
                .short("H")
                .long("hook")
                .value_names(&["ADDR", "EXPR"])
                .multiple(true)
                .help("Hook the provided address with an ESIL expression"),
        )
        .arg(
            Arg::with_name("r2_command")
                .short("r")
                .long("r2-cmd")
                .value_names(&["CMD"])
                .multiple(true)
                .help("Run r2 command on launch"),
        )
        .arg(
            Arg::with_name("evaluate")
                .short("e")
                .long("eval")
                .value_names(&["ESIL"])
                .multiple(true)
                .help("Evaluate ESIL expression"),
        )
        .arg(
            Arg::with_name("evaluate_after")
                .short("E")
                .long("eval-after")
                .value_names(&["ESIL"])
                .multiple(true)
                .help("Evaluate ESIL expression after execution"),
        )
        .get_matches();

    let libpaths: Vec<&str> = collect!(matches, "libs");

    let debug = occurs!(matches, "verbose") || occurs!(matches, "color");
    let no_sims = occurs!(matches, "no_sims");
    let profile = occurs!(matches, "profile");
    let fuzz = occurs!(matches, "fuzz");
    let all_sims = !no_sims && libpaths.is_empty();
    let mut json_out = JsonOutput {
        symbols: HashMap::new(),
        stdout: String::from(""),
        stderr: String::from(""),
    };

    let do_json = occurs!(matches, "json");

    let plugins = occurs!(matches, "plugins")
        || matches
            .value_of("path")
            .unwrap_or_default()
            .starts_with("frida:"); // load plugins for r2frida

    let mut options = vec![
        RadiusOption::Debug(debug),
        RadiusOption::Lazy(occurs!(matches, "lazy")),
        RadiusOption::Strict(occurs!(matches, "strict")),
        RadiusOption::SelfModify(occurs!(matches, "selfmodify")),
        RadiusOption::ColorOutput(occurs!(matches, "color")),
        RadiusOption::Permissions(occurs!(matches, "crash")),
        RadiusOption::Sims(!no_sims),
        RadiusOption::SimAll(all_sims),
        RadiusOption::LoadLibs(!libpaths.is_empty()),
        RadiusOption::LoadPlugins(plugins),
    ];

    for lib in libpaths {
        options.push(RadiusOption::LibPath(lib.to_owned()));
    }

    let threads: usize = matches
        .value_of("threads")
        .unwrap_or_default()
        .parse()
        .unwrap();

    let start = Instant::now();

    let path = matches.value_of("path").unwrap_or_default();
    let dir = Path::new(matches.value_of("fuzz").unwrap_or("."));

    // just a guardrail cuz the error otherwise is vv unclear
    if path != "-" && !path.contains(':') && fs::metadata(path).is_err() {
        println!("'{}' not found", path);
        process::exit(1);
    }

    let mut radius = Radius::new_with_options(matches.value_of("path"), &options);

    if !dir.exists() {
        fs::create_dir(&dir).unwrap();
    }

    let max_states = matches
        .value_of("max")
        .unwrap_or("256")
        .parse()
        .unwrap_or(256);

    // execute provided r2 commands
    let cmds: Vec<&str> = collect!(matches, "r2_command");
    for cmd in cmds {
        let r = radius.cmd(cmd);
        if occurs!(matches, "verbose") && r.is_ok() {
            println!("{}", r.unwrap());
        }
    }

    // set breakpoints, avoids, and merges
    let mut bps: Vec<u64> = collect!(matches, "breakpoint")
        .iter()
        .map(|x| radius.get_address(x).unwrap())
        .collect();
    let mut avoid: Vec<u64> = collect!(matches, "avoid")
        .iter()
        .map(|x| radius.get_address(x).unwrap())
        .collect();
    let merges: Vec<u64> = collect!(matches, "merge")
        .iter()
        .map(|x| radius.get_address(x).unwrap())
        .collect();

    let mut analyzed = false;
    // get code references to strings and add them to the avoid list
    if occurs!(matches, "avoid_strings") {
        // need to analyze to get string refs
        radius.analyze(3);
        analyzed = true;
        for string in collect!(matches, "avoid_strings") {
            for location in radius.r2api.search_strings(string).unwrap() {
                avoid.extend(
                    radius
                        .r2api
                        .get_references(location)
                        .unwrap_or_default()
                        .iter()
                        .map(|x| x.from),
                );
            }
        }
    }

    // get code references to strings and add them to the breakpoints
    if occurs!(matches, "break_strings") {
        // need to analyze to get string refs
        if !analyzed {
            radius.analyze(3);
        }
        for string in collect!(matches, "break_strings") {
            for location in radius.r2api.search_strings(string).unwrap() {
                bps.extend(
                    radius
                        .r2api
                        .get_references(location)
                        .unwrap_or_default()
                        .iter()
                        .map(|x| x.from),
                );
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

    let mut state = if let Some(address) = matches.value_of("address") {
        let addr = radius.get_address(address).unwrap_or(0);
        if path.starts_with("frida:") {
            radius.frida_state(addr)
        } else if path.starts_with("gdb:") || path.starts_with("dbg:") {
            radius.debug_state(addr)
        } else {
            radius.call_state(addr)
        }
    } else {
        // workaround for stupid reloc.__libc_start_main issue
        let addr = radius.get_address("main").unwrap_or(0);
        if addr != 0 {
            radius.call_state(addr)
        } else {
            radius.entry_state()
        }
    };

    // collect the symbol declarations
    let mut files: Vec<&str> = collect!(matches, "file");
    let mut symbol_map = HashMap::new();
    let mut symbol_types = HashMap::new();
    let symbols: Vec<&str> = collect!(matches, "symbol");
    for i in 0..matches.occurrences_of("symbol") as usize {
        // use get_address so hex / simple ops can be used
        let sym_name = symbols[2 * i];
        let mut len = symbols[2 * i + 1];

        if len.ends_with('n') {
            len = &len[..len.len() - 1];
            symbol_types.insert(sym_name, "num");
        } else {
            symbol_types.insert(sym_name, "str");
        }

        let length = radius.get_address(len).unwrap_or(8) as u32;
        let sym_value = state.symbolic_value(sym_name, length);
        //symbol_types.insert(sym_name, symbols[3 * i + 2]);
        symbol_map.insert(sym_name, sym_value.as_bv().unwrap());
        state.context.insert(sym_name.to_owned(), vec![sym_value]);

        if sym_name.to_lowercase() == "stdin" {
            files.extend(vec!["0", sym_name]);
        }
    }

    if occurs!(matches, "arg") || occurs!(matches, "env") {
        let argvs: Vec<&str> = collect!(matches, "arg");
        let envs: Vec<&str> = collect!(matches, "env");
        let mut argv = vec![];
        let mut envv = vec![];

        for (t, args) in [argvs, envs].iter().enumerate() {
            for arg in args {
                let value = if let Some(sym) = symbol_map.get(arg) {
                    Value::Symbolic(sym.clone(), 0)
                } else {
                    // @ signs to prevent parsing as radius args
                    let narg = if arg.starts_with("@") {
                        &arg[1..]
                    } else {
                        &arg[..]
                    };

                    let bytes: Vec<Value> = narg
                        .as_bytes()
                        .iter()
                        .map(|b| Value::Concrete(*b as u64, 0))
                        .collect();

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
    let cons: Vec<&str> = collect!(matches, "constrain");
    for i in 0..matches.occurrences_of("constrain") as usize {
        let bv = &symbol_map[cons[2 * i]];
        let cons = if cons[2 * i + 1].starts_with('@') {
            &cons[2 * i + 1][1..]
        } else {
            &cons[2 * i + 1]
        };

        state.constrain_bytes_bv(bv, cons);
    }

    // collect the ESIL hooks
    let hooks: Vec<&str> = collect!(matches, "hook");
    for i in 0..matches.occurrences_of("hook") as usize {
        if let Ok(addr) = radius.get_address(hooks[2 * i]) {
            radius.esil_hook(addr, hooks[2 * i + 1]);
        }
    }

    // collect the added files
    for i in 0..files.len() / 2usize {
        let file = files[2 * i];
        let name = files[2 * i + 1];
        if let Some(sym) = symbol_map.get(name) {
            let length = symbol_map[name].get_width() as usize;
            let value = Value::Symbolic(sym.clone(), 0);
            let bytes = state.memory.unpack(&value, length / 8);
            if let Ok(fd) = files[2 * i].parse() {
                state.filesystem.fill(fd, &bytes);
            } else {
                state.filesystem.add_file(files[2 * i], &bytes);
            }
        } else {
            let content = files[2 * i + 1];
            if let Ok(fd) = file.parse() {
                state.fill_file_string(fd, content)
            } else {
                let bytes: Vec<Value> = content
                    .as_bytes()
                    .iter()
                    .map(|b| Value::Concrete(*b as u64, 0))
                    .collect();

                state.filesystem.add_file(file, &bytes);
            }
        }
    }

    // set provided address and register values
    let sets: Vec<&str> = collect!(matches, "set");
    for i in 0..matches.occurrences_of("set") as usize {
        // easiest way to interpret the stuff is just to use
        let ind = 3 * i;
        let length: u32 = sets[ind + 2].parse().unwrap();

        let lit = radius.processor.get_literal(sets[ind + 1]);
        let value = if let Some(Word::Literal(val)) = lit {
            val
        } else if let Some(bv) = symbol_map.get(sets[ind + 1]) {
            Value::Symbolic(bv.slice(length - 1, 0), 0)
        } else {
            // this is a real workaround of the system
            // i need a better place for these kinds of utils
            let bytes = sets[ind + 1].as_bytes();
            let bv = BV::from_hex_str(
                state.solver.btor.clone(),
                hex_encode(bytes).as_str(),
                length,
            );

            Value::Symbolic(bv, 0)
        };

        let lit = radius.processor.get_literal(sets[ind]);
        if let Some(Word::Literal(address)) = lit {
            state.memory_write_value(&address, &value, (length / 8) as usize);
        } else if let Some(Word::Register(index)) =
            radius.processor.get_register(&mut state, sets[ind])
        {
            state.registers.set_value(index, value);
        }
    }

    // collect the ESIL strings to evaluate
    let evals: Vec<&str> = collect!(matches, "evaluate");
    for eval in evals {
        radius.processor.parse_expression(&mut state, eval);
    }

    if profile {
        println!("init time:\t{}", start.elapsed().as_micros());
    }
    // run the thing
    let run_start = Instant::now();

    if !fuzz {
        let result = radius.run(state, threads);

        if profile {
            let usecs = run_start.elapsed().as_micros();
            let steps = radius.get_steps();
            println!(
                "run time:\t{}\ninstructions:\t{}\ninstr/usec:\t{:0.6}",
                usecs,
                steps,
                (steps as f64 / usecs as f64)
            );
        }

        if let Some(mut end_state) = result {

            // collect the ESIL strings to evaluate after running
            let constraints: Vec<&str> = collect!(matches, "constrain_after");
            for i in 0..matches.occurrences_of("constrain_after") as usize {
                let name = constraints[2 * i];
                let con = constraints[2 * i + 1];

                let cons = if con.starts_with('@') {
                    &con[1..]
                } else {
                    con
                };

                if symbol_map.contains_key(name) {
                    let bv = &symbol_map[name];
                    end_state.constrain_bytes_bv(bv, cons);
                } else if files.contains(&name) {
                    end_state.constrain_file(name, cons);
                } else if let Ok(fd) = name.parse::<usize>() {
                    end_state.constrain_fd(fd, cons);
                }
            }

            // collect the ESIL strings to evaluate after running
            let evals: Vec<&str> = collect!(matches, "evaluate_after");
            for eval in evals {
                radius.processor.parse_expression(&mut end_state, eval);
            }
            let solve_start = Instant::now();

            if !do_json { println!() };
            for symbol in symbol_map.keys() {
                let val = Value::Symbolic(end_state.translate(&symbol_map[symbol]).unwrap(), 0);

                if let Some(bv) = end_state.solver.eval_to_bv(&val) {
                    let str_opt = end_state.evaluate_string_bv(&bv);
                    let sym_type = symbol_types[symbol];
                    let hex = &format!("{:?}", bv)[2..];
                    if !do_json {
                        if sym_type == "str" && str_opt.is_some() {
                            println!("  {} : {:?}", symbol, str_opt.unwrap());
                        } else {
                            println!("  {} : 0x{}", symbol, hex);
                        }
                    } else {
                        json_out.symbols.insert(symbol.to_owned().to_owned(), hex.to_owned());
                    }
                } else if !do_json {
                    println!("  {} : no satisfiable value", symbol);
                } else {
                    json_out.symbols.insert(symbol.to_owned().to_owned(), "unsat".to_owned());
                }   
            }
            if !do_json { println!() };

            if profile {
                println!("solve time:\t{}", solve_start.elapsed().as_micros());
            }

            // dump program output
            let head = "=".repeat(37);
            if occurs!(matches, "stdout") {
                let out = end_state.dump_file_string(1).unwrap_or_default();
                if !do_json {
                    println!("{}stdout{}\n{}\n{}======{}", head, head, out, head, head);
                } else {
                    json_out.stdout = out;
                }
            }
            if occurs!(matches, "stderr") {
                let out = end_state.dump_file_string(2).unwrap_or_default();
                if !do_json {
                    println!("\n{}stderr{}\n{}\n{}======{}", head, head, out, head, head);
                } else {
                    json_out.stderr = out;
                }
            }
        }
        
        if do_json {
            println!("{}", serde_json::to_string(&json_out).unwrap_or_default());
        }
    } else {
        let mut pcs: HashMap<u64, usize> = HashMap::new();
        let mut states = VecDeque::new();
        let mut solutions: HashMap<Vec<u8>, usize> = HashMap::new();
        states.push_back(state);

        let mut file_counts: HashMap<&str, usize> = HashMap::new();

        for symbol in symbol_map.keys() {
            file_counts.insert(symbol, 0);
        }

        while !states.is_empty() {
            let num_states = states.len();
            let mut s = states.pop_front().unwrap();
            let cpc = s.registers.get_pc().as_u64().unwrap();

            radius.processor.fetch_instruction(&mut s, cpc);
            let tn = radius.processor.instructions[&cpc].instruction.type_num;

            let new_states = radius.processor.run(s, RunMode::Step);
            //new_states.push(s);

            for mut new_state in new_states {
                let pc = new_state.registers.get_pc().as_u64().unwrap();
                let active = new_state.status == StateStatus::Active;
                if pcs.entry(pc).and_modify(|c| *c += 1).or_insert(1) > &mut 1 {
                    if active && num_states <= max_states {
                        states.push_back(new_state);
                    }
                    continue;
                }
                // after (conditional) calls and jumps
                if tn & 0xf == 1 || tn & 0xf == 4 {
                    for symbol in symbol_map.keys() {
                        let val = new_state.translate(&symbol_map[symbol]).unwrap();

                        if let Some(bytes) = new_state.evaluate_bytes_bv(&val) {
                            if !solutions.contains_key(&bytes) {
                                let c = file_counts[symbol];
                                let filename = &format!("{}{:04}", symbol, c);
                                fs::write(dir.join(filename), &bytes).unwrap();
                                file_counts.insert(symbol, c + 1);
                                solutions.insert(bytes, 1);
                            }
                        }
                    }
                }
                if active {
                    states.push_front(new_state);
                }
            }
        }

        if profile {
            let usecs = run_start.elapsed().as_micros();
            let steps = radius.get_steps();
            println!(
                "run time:\t{}\ninstructions:\t{}\ninstr/usec:\t{:0.6}\ngenerated:\t{}",
                usecs,
                steps,
                (steps as f64 / usecs as f64),
                file_counts.values().sum::<usize>()
            );
        }
    }

    if profile {
        println!("total time:\t{}", start.elapsed().as_micros());
    }

    radius.close();
}
