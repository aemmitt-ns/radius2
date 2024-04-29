use radius2::sims::{libc, make_sim};
use radius2::{vc, Radius, RadiusOption};

fn main() {
    let mut radius = Radius::new_with_options(
        Some("tests/statically-linked"),
        &[RadiusOption::Debug(true)],
    );

    // Hooking library functions can save a lot of time
    radius.simulate(0x40145e, make_sim("strcmp", libc::strcmp, 2));

    let mut state = radius.call_state(0x40102b); // start at main
    let flag = state.symbolic_value("flag", 15 * 8); // flag is 15 bytes long
    radius.set_argv_env(&mut state, &[vc(0), flag.clone()], &[]); // argv[1] = flag
    radius.avoid(&[0x401047]);

    let mut desired_state = radius.run(state, 1).unwrap();
    println!("flag: {}", desired_state.evaluate_string(&flag).unwrap());
}
