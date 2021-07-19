## radius - fast symbolic execution with r2

radius is a rust rewrite of ESILSolve with some architectural improvements. It uses boolector as the SMT solver rather than z3. It executes about 1000x faster than ESILSolve on average. radius gains additional speed over other rust based symbex tools by using u64 primitives for concrete values instead of constant valued bitvectors which incur significant overhead for all operations. 

As always, r100 as an example:
```rust
fn r100() {
    let mut radius = Radius::new("tests/r100");
    let mut state = radius.call_state(0x004006fd);
    let bv = state.bv("flag", 12*8);
    let addr: u64 = 0x100000;
    state.memory.write_value(addr, Value::Symbolic(bv.clone()), 12);
    state.registers.set("rdi", Value::Concrete(addr));
    
    // run until 0x004007a1 avoiding 0x00400790
    let mut new_state = radius.run_until(state, 
        0x004007a1, vec!(0x00400790)).unwrap();

    let flag = new_state.evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "Code_Talkers");
}
```
