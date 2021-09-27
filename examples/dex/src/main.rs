use radius::radius::{Radius, RadiusOption};

fn main() {
    // doesnt work yet
    let options = [RadiusOption::Debug(true), RadiusOption::Sims(false)];
    let mut radius = Radius::new_with_options(Some("apk://tests/escrackme.apk"), &options);
    let mut state = radius.call_state(0x001b7fec);
    let _bv = state.symbolic_value("flag", 32);

    state.registers.set("v7", state.concrete_value(0xcafebabe, 32));
    let new_state = radius.run_until(state, 0x001b8000, &[0x001b8040]).unwrap();
    println!(": {}", new_state.registers.get_with_alias("PC").as_u64().unwrap());
    /*let flag = new_state.eval(&bv).unwrap().as_u64().unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, 0xcafebabe);*/
}
