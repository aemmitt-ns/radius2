use radius::radius::{Radius, RadiusOption};

fn main() {
    let options = vec!(RadiusOption::Debug(true));
    let mut radius = Radius::new_with_options("tests/r100", options);
    let mut state = radius.call_state(0x004006fd);
    let addr: u64 = 0x100000;
    let flag_val = state.symbolic_value("flag", 12*8);
    state.memory.write_value(addr, flag_val.clone(), 12);
    state.registers.set("rdi", state.concrete_value(addr, 64));

    radius.breakpoint(0x004007a1);
    radius.avoid(vec!(0x00400790));
    let mut new_state = radius.run(Some(state), 1).unwrap();
    let flag = new_state.evaluate_string_value(&flag_val).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "Code_Talkers");
}