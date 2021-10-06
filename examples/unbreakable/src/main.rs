use radius2::radius::Radius;
use radius2::value::Value;

fn main() {
    let mut radius = Radius::new("tests/unbreakable");
    let mut state = radius.call_state(0x004005bd);
    let len: usize = 0x33;
    let bv = state.bv("flag", 8*len as u32);

    // add "CTF{" constraint
    let assertion = bv.slice(31, 0)._eq(&state.bvv(0x7b465443, 32));
    state.assert(&assertion);

    let addr: u64 = 0x6042c0;
    state.memory.write_value(addr, &Value::Symbolic(bv.clone(), 0), len);
    let new_state = radius.run_until(state, 0x00400830, &[0x00400850]);

    let flag = new_state.unwrap().evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}");
}
