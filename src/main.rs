#[macro_use]
extern crate r2pipe;
extern crate serde_json;
extern crate boolector;
extern crate hex;

mod r2_api;
mod registers;
mod value;
mod processor;
mod state;
mod operations;
mod memory;

fn main() {
    let filename = String::from("/home/alkali/hacking/looper");
    let mut r2api = r2_api::create(Some(filename));
    r2api.r2p.cmd("s 0x0000112d; aei; aeim");
    let state = state::create(&mut r2api);
    let mut processor = processor::create();
    let mut new_state = processor.run_until(&mut r2api, state, 0x00001168).unwrap();

    println!("{:?}", new_state.registers.get(&String::from("eax")))
}