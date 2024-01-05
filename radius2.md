# The `radius2` command line tool 

The `radius2` symbolic execution framework includes a command line utility that can be installed with `cargo install radius2`. It allows users to solve reversing problems quickly using symbolic execution and aims to be both user friendly and flexible enough to do nearly any task straight from the terminal. Many complex reversing CTF challenges can be solved with a short command like 

```bash
$ radius2 -p crackme -s flag 320 -X Wrong -B Correct

  flag : "grey{d1d_y0u_s0lv3_by_emul4t1ng?_1e4b8a}"

```

In this example from GreyCTF2023 `radius2` analyzes the binary with `r2`, executes 295293 instructions, and solves the final constraints, all in under 6 seconds. This binary also contains self-modifying code based on the input, which is handled seemlessly by the symbolic execution engine. 

This document will cover the many different ways `radius2` can be used to perform automated reverse engineering with symbolic execution. 

`radius2 -h` outputs the usage information:

```
radius2 1.0.27
Austin Emmitt (@alkalinesec) <alkali@alkalinesecurity.com>
A symbolic execution tool using r2 and boolector

USAGE:
    radius2 [FLAGS] [OPTIONS] --path <path>

FLAGS:
    -M, --automerge    Automatically merge states
    -V, --color        Use color output
        --crash        Execution stops on invalid memory access
    -h, --help         Prints help information
    -j, --json         Output JSON
    -z, --lazy         Evaluate symbolic PC values lazily
    -K, --merge-all    Merge all finished states
        --no-sims      Do not simulate imports
    -N, --no-modify    Disallow self-modifying code (faster sometimes)
        --no-strict    Don't avoid invalid instructions and ESIL
        --plugins      Load r2 plugins
    -P, --profile      Get performance and runtime information
    -2, --stderr       Show stderr output
    -0, --stdin        Use stdin for target program
    -1, --stdout       Show stdout output
        --version      Prints version information
    -v, --verbose      Show verbose / debugging output

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
    -i, --include <SYMBOL> <EXPR>             Assert symbol contains a string
    -L, --libs <libs>...                      Load libraries from path
        --max <max>                           Maximum number of states to keep at a time
    -m, --merge <merge>...                    Set address as a mergepoint
    -I, --not-include <SYMBOL> <EXPR>         Assert symbol does not contain a string
    -p, --path <path>                         Path to the target binary
    -r, --r2-cmd <CMD>...                     Run r2 command on launch
    -S, --set <REG/ADDR> <VALUE> <BITS>       Set memory or register values
    -s, --symbol <NAME> <BITS>                Create a symbolic value
```

The only required argument is `--path` (or `-p`) and the default behaviour of `radius2` is simply to begin execution from an `entry_state`, a state at the entrypoint of the program and run until the program exits, so `radius2 -p /bin/ls` will run, print nothing, and finish. To see what is "going on" the `-v` option can be used to view the instructions as they execute (`-V` will output with color)

```
$ radius2 -p /bin/ls -v
0000000100003f00:  pacibsp                                  |  
0000000100003f04:  stp x28, x27, [sp,  -0x60]!              |  96,sp,-=,x28,sp,=[8],x27,sp,8,+,=[8]
...
0000000100007154:  mov w0,  0x1                             |  0x1,w0,=
0000000100007158:  bl sym.imp.exit                          |  pc,lr,=,4294997208,pc,=
00000001000074d8:  adrp x17, 0x100008000                    |  4295000064,x17,=

```

The string on the right is ESIL, the intermediate language that is actually being executed by radius. It will be explained more below. By default no libraries are loaded and standard c functions are emulated (see the contents of `radius/sims/libc.rs`).

## Symbolic Values

Symbolic values can be defined with `-s <name> <length in bits>[n]` where n is appended to the bits in order to force printing the value as a number after evaluation. 

`stdin` is a special name that is automatically treated as the content of stdin, equivalent to `-s stdin 32 -f 0 stdin` (numeric file names are treated as file descriptors). See below for more information on input. A simple crackme can be solved as easily as 

```
$ radius2 -p r100 -s stdin 96 -X Incorrect

  stdin : "Code_Talkers"

```

## Guiding Execution

In order to reach a desired program state the user can set places to avoid or to complete execution. The user can also provide hooks to manipulate the state when it reaches an address. If no breakpoints or hooks are provided the symbolic execution will return the first state that finishes execution (eg. returns from `main`). 

The `-X` option tells radius2 to avoid any addresses that contain XREFs to a string containing the argument. States that reach avoided address are discarded and the first state to finish execution without being discarded is used to evaluate the symbolic values. Addresses to avoid can be manually set like `-x 0x400855`, the addresses can be in decimal or hex (or octal or binary if you wanna get real nuts), can include symbols and even be offsets from symbols like 

```
$ radius2 -p r100 -s stdin 96 -x main+109
```

Conversely breakpoints, target addresses where execution should stop and evaluate, can be set with `-b` and string xref breakpoints with `-B` so `radius2 -p r100 -s stdin 96 -B Nice` also works.  

## Program Input and Output

The user can set symbolic `argv` values using the symbol name, like `sym` in `-A progname sym`. Additionally symbolic file contents are created using `-s sym 4096 -f /path/to/file sym`. For both `-f` and `-A` any string which has not been defined as a symbol name will simply be that string. Files that are not supplied will be read from the real filesystem, but will never be written to. An example of these and other features is the solution to `unbreakable`

```bash
$ radius2 -p unbreakable -s flag 408 -c flag 'CTF{' -B 'Thank you' -z -A . flag

  flag : "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}"

```

This example also constrains the first four bytes of `flag` to be "CTF{" with `-c` and passes `-z` to enable lazy solving, which will significantly speed up runtime (from 1 second down to 0.4 or so). In some cases string XREFs may not be found, in this case try passing `-r aae` which will tell r2 to emulate the program to find additional references. 

In this example the `-A . flag` arguments are actually not necessary as by default if a symbolic value hasn't been written into the program somehow it will be automatically set as `argv[1]`.

It is also possible to directly set register and memory values with `-S <reg or addr> <value> <length in bits>`.

The output of the program to `stdout` and `stderr` can also be dumped after the execution finishes using the `-1` and `-2` options respectively. This is helpful when checking whether the output of the program matches the expected result corresponding to the evaluated symbols. 

## State Merging

More complicated code may require state merging to finish in a reasonable time like in this example where `0x004007ba` is designated as a merge point

```
$ radius2 -p r200 -s stdin 48 -X Incorrect -m 0x004007ba

  stdin : "rotors"

```

State merging is the process of taking multiple program states that have reached the same point in code and combining them in order to prevent "state explosion". This occurs when eg. loops with symbolic conditions lead to exponential growth in the number of states being executed by the engine. In the example above this is prevented by setting a mergepoint at `0x004007ba` so that when a state reaches this address it is merged with the previous states at this address. The values of this state are combined based on the path constraints so if `eax` was `x` in state `s1` and `y` in state `s2` then the merged `eax` will now have the symbolic value `if(<s1 constraints>, x, if(<s2 constraints>, y, ...))`

In general state merging is often helpful in between loops where both loops have a symbolic condition that will result in `n` new states, for a total of `n**2` states after the second loop. When `n` is large this can result in huge numbers of states that will exhaust the memory of the host and take forever to execute one at a time. 

This is the case for the `r200` example above. Without state merging the execution will not complete in any reasonable time, but with a mergepoint between the two loops at `0x004007ba` it takes ~0.1 seconds!

```c
                  |    do {
    0x00400811    |        if (iStack_58 != 5 && SBORROW4(iStack_58, 5) == iStack_58 + -5 < 0) {
    0x00400813    |            iStack_58 = 0;
    0x00400830    |            while( true ) {
    0x00400841    |                if (iStack_58 != 5 && SBORROW4(iStack_58, 5) == iStack_58 + -5 < 0) {
    0x00400849    |                    return 0;
                  |                }
    0x00400830    |                if (*(aiStack_48 + iStack_58 * 4) != *(aiStack_28 + iStack_58 * 4)) break;
    0x00400839    |                iStack_58 = iStack_58 + 1;
                  |            }
    0x00400849    |            return 1;
                  |        }
    0x004007ba    |        uStack_54 = 0;
    0x004007fb    |        for (puStack_50 = *0x601080; puStack_50 != NULL; puStack_50 = *(puStack_50 + 2)) {
    0x004007dd    |            if (*(puStack_50 + 1) == *(iStack_60 + iStack_58)) {
    0x004007e3    |                uStack_54 = *puStack_50;
    0x004007e8    |                break;
                  |            }
                  |        }
    0x00400805    |        *(aiStack_48 + iStack_58 * 4) = uStack_54;
    0x00400809    |        iStack_58 = iStack_58 + 1;
    0x00400809    |    } while( true );
```

The above code is from `r2ghidra`, specifically the `pdgo` command which shows the offsets along with the decompiler output

Sometimes it will be clear when state merging can help, like this example. Other times its less clear and I generally just try random addresses that I think might work. 

## Test case generation 

`radius2` also has a basic testcase generation option, `-F <dir>` which will generate files containing values of the defined symbols for each different execution path. 

```
$ radius2 -p ais3 -s flag 256 -A . flag -F testcases -P
init time:      74039
run time:       194957
instructions:   2226
instr/usec:     0.011418
generated:      5
total time:     269024
$ ls testcases 
flag0000 flag0001 flag0002 flag0003 flag0004 flag0005
$ cat testcases/flag0005
ais3{I_tak3_g00d_n0t3s}
```

Here the `-P` option causes `radius2` to print out some profiling information. Times are measured in microseconds so it took 0.27 seconds to explore every path of the program and generate the 5 unique testcases that traverse each one. The flag value is contained in the last one (it usually is). 

## Adding Constraints

In the `unbreakable` example above we added an additional constraint onto the `flag` value with `-c flag 'CTF{'`. This argument constrains the first four characters of `flag` to be `CTF{`, however its also possible to use `-c` to constrain the bytes of a symbol to ranges, with eg. `-c flag '[a-zA-Z]'`. The syntax should look familiar as it is the same as the `[...]` regular expression. For example this IDA ctf challenge had the additional requirement that the bytes be printable, which can be quickly accomplished with the range `[ -~]`

```bash
$ radius2 -p chal -s flag 192 -c flag '[ -~]' -b 0x1610  

  flag : "Fr33_M4dam3-De/M4inten0n"

```

In addition to a symbolic value provided by the user, `-c` and `-C` can constrain register and file contents. This is particularly useful when a desired value should be found in a file or standard out after the symbolic execution finishes, as in the example of `ollvm`

```bash
$ radius2 -Np ollvm -s hex 128 -C1 'Output: 875cd4f2e18f8fc4'

  hex : "6d6972726F725f6d"

$ rax2 -s 6d6972726F725f6d # hex decode for flag bytes
mirror_m
```

The `-C` argument adds a constraint **after** execution. Here the first argument is a file descriptor `1` which denotes `stdout` and can be used to constrain the symbolic bytes of the output to the desired string. 

This example in particular shows the power of `radius2`. It has symbolic function summaries of many common functions, including `scanf` and `printf` which allows it to read the symbol as hex, transform it with 17k obfuscated instructions, and then print the reencoded bytes to `stdout`. Even with all of these operations the total time to execute and solve is less than 4 seconds. 

## Hooking with ESIL

Potentially the most powerful feature of `radius2` is the ability to quickly write arbitrary hooks with ESIL, the Evaluable String Intermediate Language of `radare2`. The `r200` example could also be solved using 

```bash
$ radius2 -p r200 -s stdin 48 -m 0x4007ba -H 0x400849 'eax,!,?{,stdin,.,}'
000000000040084a: 0x000073726f746f72 "rotors\u{0}\u{0}"
```

Instead of placing breakpoints or avoidpoints, this example hooks the address `0x400849` so that when reached by a state the expression `eax,!,?{,stdin,.,}` will be executed. This address is at the end of the validation function which is 0 when the input is correct. ESIL is a simple stack based VM that pushes values to a stack and has operators that pop them off and push the results. Here `eax` is pushed to the stack, then `!` pops it off and pushes its boolean negation (so pushing 1 if `eax` is 0, 0 otherwise). Next `?{` is a conditional that executes the expression between the brackets if the popped value is nonzero, and `stdin,.` simply evaluates and prints `stdin`. A table of ESIL operators can be viewed by running `ae??` in r2 and is reproduced below 


```
 =       assign updating internal flags
 :=      assign without updating internal flags
 +=      A+=B => B,A,+=
 +       A=A+B => B,A,+,A,=
 ++      increment, 2,A,++ == 3 (see rsi,--=[1], ... )
 --      decrement, 2,A,-- == 1
 *=      A*=B => B,A,*=
 /=      A/=B => B,A,/=
 %=      A%=B => B,A,%=
 &=      and ax, bx => bx,ax,&=
 |       or r0, r1, r2 => r2,r1,|,r0,=
 !=      negate all bits
 ^=      xor ax, bx => bx,ax,^=
 []      mov eax,[eax] => eax,[],eax,=
 =[]     mov [eax+3], 1 => 1,3,eax,+,=[]
 =[1]    mov byte[eax],1 => 1,eax,=[1]
 =[8]    mov [rax],1 => 1,rax,=[8]
 []      peek from random position
 [N]     peek word of N bytes from popped address
 [*]     peek some from random position
 =[*]    poke some at random position
 $       int 0x80 => 0x80,$
 $$      simulate a hardware trap
 ==      pops twice, compare and update esil flags
 <       compare for smaller
 <=      compare for smaller or equal
 >       compare for bigger
 >=      compare bigger for or equal
 >>=     shr ax, bx => bx,ax,>>=  # shift right
 <<=     shl ax, bx => bx,ax,<<=  # shift left
 >>>=    ror ax, bx => bx,ax,>>>=  # rotate right
 <<<=    rol ax, bx => bx,ax,<<<=  # rotate left
 ?{      if popped value != 0 run the block until }
 POP     drops last element in the esil stack
 DUP     duplicate last value in stack
 NUM     evaluate last item in stack to number
 SWAP    swap last two values in stack
 TRAP    stop execution
 BITS    16,BITS  # change bits, useful for arm/thumb
 TODO    the instruction is not yet esilized
 STACK   show contents of stack
 CLEAR   clears the esil stack
 REPEAT  repeat n times
 BREAK   terminates the string parsing
 SETJT   set jump target
 SETJTS  set jump target set
 SETD    set delay slot
 GOTO    jump to the Nth word popped from the stack
 $       esil interrupt
 $z      internal flag: zero
 $c      internal flag: carry
 $b      internal flag: borrow
 $p      internal flag: parity
 $s      internal flag: sign
 $o      internal flag: overflow
 $ds     internal flag: delay-slot
 $jt     internal flag: jump-target
 $js     internal flag: jump-target-set
 $$      internal flag: pc address
```

In addition to these operators `radius2` adds a few special ones

```
 .       print an evaluated value
 ..      print a debug value (unevaluated AST)
 _       constrain popped value to be nonzero
 _+      push solver constraints
 _-      pop solver contraints
 !!      set the state as if a breakpoint was hit
 !_      set the state as if an avoidpoint was hit
```

As noted above ESIL is also what all instructions are lifted into so it can be instructive to read the expressions in the verbose output. Since ESIL can define any instruction it is essentially possible to do nearly anything with an ESIL hook. 

## Faster Execution

The defaults of the `radius2` rust API are set so that the symbolic execution is as fast as possible. On the other hand the `radius2` CLI utility has defaults that are more reliable but may be a bit slower. 

In order to speed up execution the `-z` option will set the engine to check satisfiability as little as possible. This can often lead to significantly reduced run times but may also increase the chance of state explosion.

Additionally if the target does not include self-modifying code the `-N` argument can be used which will allow reading many instructions at a time and optimizing the instructions by performing some dead code elimination. 

Finally it is often useful to add more avoidpoints than is strictly necessary. By adding more and by placing them as early as possible in execution it can cut down on wasted execution of undesired states. 

## Other stuff 

Uhhhhhhh what else? `radius2` can initialize states from a process running in a local or remote debugger so `radius2 -p dbg://192.168.1.123:5555 -a addr -s sym 64 num -S x0 sym 64` will place a breakpoint and once hit will initiallize the state with the current context of the debuggee, set the register `x0` to a symbolic value, and then start symbolic execution. This can also be done with frida so `radius2 -p frida://usb/attach//wpa_supplicant -a free ...` will set a hook on `free` and when the hook is hit will initialize an exact state of the current process. You can even use `radius2` on a process running in `qemu` or attached via JTAG with `gdb://`.

## Conclusion

In a blog post Trail of Bits described its symbolic execution tool `manticore` with the expression "there's more than one way to skin a cat" and called `manticore` a "cat skinning machine". As `radius2` is orders of magnitude faster, works on more architectures and file formats, and is even more flexible than `manticore`, `radius2` should be thought of as a Cat-Skinning Optimus Prime. 


