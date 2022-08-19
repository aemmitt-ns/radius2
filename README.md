## radius2 - fast symbolic execution with r2

radius2 is symbolic execution and taint analysis framework using radare2 and its ESIL intermediate representation. It is essentially a rust rewrite of ESILSolve with some architectural improvements. It uses boolector as the SMT solver rather than z3. It executes about 1000x faster than ESILSolve on average. radius2 gains additional speed over other rust based symbex tools by using u64 primitives for concrete values instead of constant valued bitvectors which incur significant overhead for all operations. 

### Building

Install radare2 with 
```
git clone https://github.com/radareorg/radare2.git
radare2/sys/install.sh 
```

Include radius2 as a dependency using `radius2 = "1.0.17"` or build locally with `cargo build --release`

### Supported Architectures

- **x86**
- **amd64**
- **ARM**
- **AArch64**

### "Supported" Architectures

radius2 also "supports" **MIPS**, **PowerPC**, and **Gameboy** but they are almost entirely untested. Additionally radius2 supports execution of **cBPF** and **eBPF** programs.

radius2 can execute **Dalvik** bytecode only involving static methods and variables. 

Finally there is also a varying amount of support for **6502**, **8051**, **AVR**, **h8300**, **PIC**, **RISCV**, **SH-4**, **V810**, **V850**, **Xtensa**.

Also PCode can be translated to ESIL with r2ghidra with `pdgp` (currently broken, actually maybe fixed now) so potentially more archs could be supported that way.

### Example

```rust
use radius2::Radius;

fn main() {
    let mut radius = Radius::new("tests/r100");
    let mut state = radius.call_state(0x004006fd);
    let addr: u64 = 0x100000;
    let flag_val = state.symbolic_value("flag", 12*8);
    state.memory_write_value(addr, &flag_val, 12);
    state.registers.set("rdi", state.concrete_value(addr, 64));

    radius.breakpoint(0x004007a1);
    radius.avoid(&[0x00400790]);
    let mut new_state = radius.run(state, 1).unwrap();
    let flag = new_state.evaluate_string(&flag_val).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "Code_Talkers");
}
```

### radius2 CLI tool

radius2 can also be installed from crates.io and easily included in packages. radius2 also has a CLI tool that can be installed with `cargo install radius2`

```
radius2 1.0.17
Austin Emmitt (@alkalinesec) <aemmitt@nowsecure.com>
A symbolic execution tool using r2 and boolector

USAGE:
    radius2 [FLAGS] [OPTIONS] --path <path>

FLAGS:
    -V, --color         Use color output
        --crash         Execution stops on invalid memory access
    -h, --help          Prints help information
    -j, --json          Output JSON
    -z, --lazy          Evaluate symbolic PC values lazily
        --no-sims       Do not simulate imports
        --plugins       Load r2 plugins
    -P, --profile       Get performance and runtime information
    -M, --selfmodify    Allow selfmodifying code (slower)
    -2, --stderr        Show stderr output
    -0, --stdin         Use stdin for target program
    -1, --stdout        Show stdout output
        --strict        Panic on invalid instructions and ESIL
        --version       Prints version information
    -v, --verbose       Show verbose / debugging output

OPTIONS:
    -a, --address <address>                   Address to begin execution at
    -A, --arg <arg>...                        Argument for the target program
    -x, --avoid <avoid>...                    Avoid addresses
    -X, --avoid-strings <avoid_strings>...    Avoid code xrefs to strings
    -B, --break-strings <break_strings>...    Breakpoint code xrefs to strings
    -b, --break <breakpoint>...               Breakpoint at some target address
    -c, --constrain <SYMBOL> <EXPR>           Constrain symbol values with string or pattern
    -C, --constrain-after <SYMBOL> <EXPR>     Constrain symbol or file values after execution
        --env <env>...                        Environment variable for the target program
    -e, --eval <ESIL>...                      Evaluate ESIL expression
    -E, --eval-after <ESIL>...                Evaluate ESIL expression after execution
    -f, --file <PATH> <SYMBOL>                Add a symbolic file
    -F, --fuzz <fuzz>                         Generate testcases and write to supplied dir
    -H, --hook <ADDR> <EXPR>                  Hook the provided address with an ESIL expression
    -L, --libs <libs>...                      Load libraries from path
        --max <max>                           Maximum number of states to keep at a time
    -m, --merge <merge>...                    Set address as a mergepoint
    -p, --path <path>                         Path to the target binary
    -r, --r2-cmd <CMD>...                     Run r2 command on launch
    -S, --set <REG/ADDR> <VALUE> <BITS>       Set memory or register values
    -s, --symbol <NAME> <BITS>                Create a symbolic value
    -t, --threads <threads>                   Number of threads to execute [default: 1]
```

This tool can be used to solve the same `r100` crackme as above like 

```
$ radius2 -p tests/r100 -a 0x4006fd -x 0x400790 -s flag 96 -S A0 0x100000 64 -S 0x100000 flag 96
  flag : "Code_Talkers"
```
Or even more quickly with strings using 

```
$ radius2 -p tests/r100 -s stdin 96 -X Incorrect
  stdin : "Code_Talkers"
```