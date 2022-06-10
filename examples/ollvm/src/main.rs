use radius2::{Radius, State, Value, vc};

// output: 
// FLAG: mirror_mirror_on_the_wall_whos_the_ugliest_handler_of_them_all?!
// target/release/ollvm  0.92s user 0.04s system 99% cpu 0.964 total

const HASHES:[u64; 8] = [
    0x875cd4f2e18f8fc4, 0xbb093e17e5d3fa42, 0xada5dd034aae16b4, 0x97322728fea51225,
    0x4124799d72188d0d, 0x2b3e3fbbb4d44981, 0xdfcac668321e4daa, 0xeac2137a35c8923a
];

fn main() {
    let mut radius = Radius::new("tests/ollvm");
    fn flag_hook(state: &mut State) -> bool {
        state.registers.set("rax", state.context["flag"][0].clone()); 
        true
    }
    radius.hook(0x00400899, flag_hook);

    let main = radius.get_address("main").unwrap();
    let mut state = radius.call_state(main);
    radius.set_argv_env(&mut state, &[vc(0x58), vc(0x31)], &[]);
    let flag = state.symbolic_value("flag", 64);
    state.context.insert("flag".to_owned(), vec!(flag.clone()));

    let mut end_state = radius.run(state, 1).unwrap();
    let rcx = end_state.registers.get("rcx");
    let mut solution = "".to_owned();

    for hash in HASHES {
        end_state.solver.push();
        end_state.assert(&rcx.eq(&Value::Concrete(hash, 0)));
        let reved = end_state.evaluate_string(&flag).unwrap();
        solution += &reved.chars().rev().collect::<String>();
        end_state.solver.pop();
    }
    println!("FLAG: {}", solution);
}
