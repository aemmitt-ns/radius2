use radius2::{Radius, RadiusOption};
use radius2::state::StateStatus;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let options = [RadiusOption::Debug(true), RadiusOption::Sims(false)];
    let mut radius = Radius::new_with_options(Some(args[1].to_owned()), &options);
    let addr = radius.get_address(&args[2]).unwrap_or_default();
    let mut state = radius.debug_state(addr, &args[3..]);
    let mut prev = radius.r2api.cmd("dr").unwrap();
    let mut cont = true;
    
    while state.status == StateStatus::Active && cont {
        for register in &state.registers.indexes {
            let reg = &register.reg_info;
            if reg.type_str == "gpr" || reg.type_str == "flg" {
                let name = reg.name.to_owned();
                let dbg_value = radius.r2api.get_register_value(&name).unwrap();
                let rad_value = state.registers.get(&name).as_u64().unwrap();
                if dbg_value != rad_value {
                    println!("{} {:x} {:x}", name, dbg_value, rad_value);
                    cont = reg.type_str == "flg"; // continue for flags
                } 
            }
        }
        if cont {
            prev = radius.r2api.cmd("dr;ds").unwrap();
            radius.processor.step(&mut state);
        } else {
            println!("\nprevious:\n{}", prev);
            println!("\ncurrent:\n{}", radius.r2api.cmd("dr").unwrap());
        }
    }
}
