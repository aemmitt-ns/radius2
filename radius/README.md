## radius - fast symbolic execution with r2

radius is a rust rewrite of ESILSolve with some architectural improvements. It uses boolector as the SMT solver rather than z3. It executes about 1000x faster than ESILSolve on average. radius gains additional speed over other rust based symbex tools by using u64 primitives for concrete values instead of constant valued bitvectors which incur significant overhead for all operations. 

### Building

Install radare2 with 
```
git clone https://github.com/radareorg/radare2.git
radare2/sys/install.sh 
```
Then clone and build radius with `cargo build --release`

### Example

```rust
use radius2::radius::Radius;

fn main() {
    let mut radius = Radius::new("tests/r100");
    let mut state = radius.call_state(0x004006fd);
    let addr: u64 = 0x100000;
    let flag_val = state.symbolic_value("flag", 12*8);
    state.memory.write_value(addr, &flag_val, 12);
    state.registers.set("rdi", state.concrete_value(addr, 64));

    radius.breakpoint(0x004007a1);
    radius.avoid(&[0x00400790]);
    let mut new_state = radius.run(state, 1).unwrap();
    let flag = new_state.evaluate_string_value(&flag_val).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "Code_Talkers");
}
```

### radius CLI tool

radius can also be installed from crates.io and easily included in packages. radius also has a CLI tool that can be installed with `cargo install radius2`

```
radius2 1.0.2
Austin Emmitt <aemmitt@nowsecure.com>
Symbolic Execution tool using r2 and boolector

USAGE:
    radius2 [FLAGS] [OPTIONS] --path <path>

FLAGS:
    -h, --help       Prints help information
    -z, --lazy       Evaluate symbolic PC values lazily
        --no-sims    Do not simulate imports
    -V, --version    Prints version information
    -v, --verbose    Show verbose / debugging output

OPTIONS:
    -a, --address <address>                Address to begin execution at
        --arg <arg>...                     Argument for the target program
    -x, --avoid <avoid>...                 Avoid addresses
    -b, --break <breakpoint>...            Breakpoint at some target address
    -c, --constrain <SYMBOL> <EXPR>        Constrain symbol values with string or pattern
        --env <env>...                     Environment variable for the target program
    -e, --eval <ESIL>...                   Evaluate ESIL expression
    -E, --eval-after <ESIL>...             Evaluate ESIL expression after execution
    -f, --file <PATH> <SYMBOL>             Add a symbolic file
    -L, --libs <libs>                      Load libraries from path
    -m, --merge <merge>...                 Set address as a mergepoint
    -p, --path <path>                      Path to the target binary
        --set <REG/ADDR> <VALUE> <BITS>    Set memory or register values
    -s, --symbol <NAME> <BITS>             Create a symbolic value
    -t, --threads <threads>                Number of threads to execute [default: 1]
```

This tool can be used to solve the same `r100` crackme as above like 

```
$ radius2 -p tests/r100 -a 0x4006fd -x 0x400790 -s flag 96 --set A0 0x100000 64 --set 0x100000 flag 96
flag : #x7372656b6c61545f65646f43 "Code_Talkers"
```