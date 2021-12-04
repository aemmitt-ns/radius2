use radius2::radius::{Radius, RadiusOption};
use radius2::state::State;
use radius2::value::Value;

// simulates the scanf("%d", dst) calls with sym inputs
fn scanf_sim(state: &mut State, args: &[Value]) -> Value {
    let input_len = state
        .context
        .entry("ints".to_owned())
        .or_insert_with(Vec::new)
        .len();

    let new_int = state.symbolic_value(&format!("int{}", input_len), 32);
    state.memory_write_value(&args[1], &new_int, 4);
    state.context.get_mut("ints").unwrap().push(new_int);
    state.concrete_value(1, 64)
}

fn main() {
    // runs better without opt and default sims
    let options = [RadiusOption::Optimize(false), RadiusOption::Sims(false)];
    let mut radius = Radius::new_with_options(Some("tests/baby-re"), &options);
    let main = radius.get_address("main").unwrap();
    let scanf = radius.get_address("sym.imp.__isoc99_scanf").unwrap();

    // register the custom sim
    radius.simulate(scanf, scanf_sim);

    let state = radius.call_state(main); // start at main
    let new_state = radius.run_until(state, 0x004028e9, &[0x00402941]).unwrap();

    // solving takes the majority of the ~5 sec runtime
    let mut flag_bytes = vec![]; // the hook writes the flag bytes, collect them
    for input in new_state.context.get("ints").unwrap() {
        flag_bytes.push(new_state.solver.eval_to_u64(&input).unwrap() as u8);
    }
    let flag = String::from_utf8(flag_bytes).unwrap();

    println!("FLAG: {}", flag);
    assert_eq!(flag, "Math is hard!");
}
