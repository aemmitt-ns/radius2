use radius2::Radius;

fn main() {
    let mut radius = Radius::new("tests/r100");
    let mut state = radius.call_state(0x004006fd);
    let addr: u64 = 0x100000;
    let flag_val = state.symbolic_value("flag", 12 * 8);
    state.memory.write_value(addr, &flag_val, 12);
    state.registers.set("rdi", state.concrete_value(addr, 64));

    radius.breakpoint(0x004007a1);
    radius.avoid(&[0x00400790]);
    let mut new_state = radius.run(state, 1).unwrap();
    let flag = new_state.evaluate_string_value(&flag_val).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "Code_Talkers");
}
