use radius2::{Radius, RadiusOption};

fn main() {
    let options = [RadiusOption::Debug(true), RadiusOption::Sims(false)];
    let mut radius = Radius::new_with_options(Some("apk://tests/escrackme.apk"), &options);
    let mut state = radius.call_state(0x001bd1cc);
    let bv = state.symbolic_value("flag", 32);

    state.registers.set("v7", bv.clone());
    let mut new_state = radius.run_until(state, 0x001bd21e, &[]).unwrap();
    let flag = new_state.eval(&bv).unwrap().as_u64().unwrap();

    println!("FLAG: {:x}", flag);
    assert_eq!(flag, 0xcafebabe);
}
