use radius::radius::Radius;
use radius::value::Value;

fn main() {
    let mut radius = Radius::new("tests/r200");
    let mut state = radius.call_state(0x00400886);
    let bv = state.bv("flag", 6*8);

    let addr = state.registers.get("rsp").as_u64().unwrap();
    state.memory.write_value(addr-0x18, &Value::Symbolic(bv.clone(), 0), 6);

    radius.breakpoint(0x00400843);
    radius.mergepoint(0x004007fd);
    radius.avoid(vec!(0x00400832));

    let mut new_state = radius.run(Some(state), 1).unwrap();
    let flag = new_state.evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "rotors");
}
