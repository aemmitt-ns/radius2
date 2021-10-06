use radius2::radius::Radius;

fn main() {
    let mut radius = Radius::new("tests/r200");
    let mut state = radius.call_state(0x00400886);
    let bv = state.symbolic_value("flag", 6*8);

    let addr = state.registers.get("rsp").as_u64().unwrap();
    state.memory.write_value(addr-0x18, &bv, 6);

    radius.breakpoint(0x00400843);
    radius.mergepoint(0x004007fd);
    radius.avoid(&[0x00400832]);

    let mut new_state = radius.run(state, 1).unwrap();
    let flag = new_state.evaluate_string_value(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "rotors");
}
