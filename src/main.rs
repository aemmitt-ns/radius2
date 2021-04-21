#[macro_use]
extern crate r2pipe;
extern crate serde_json;
extern crate boolector;
extern crate hex;
extern crate backtrace;

pub mod r2_api;
pub mod registers;
pub mod value;
pub mod processor;
pub mod state;
pub mod operations;
pub mod memory;
pub mod radius;

use crate::radius::Radius;
use crate::value::Value;

#[test]
fn looper() {
    let mut radius = Radius::new("/home/alkali/hacking/looper");
    let state = radius.call_state(0x112d);
    let mut new_state = radius.run_until(state, 0x00001168, 0).unwrap();

    println!("{:?}", new_state.registers.get("eax"))
}

#[test]
fn simple() {
    let mut radius = Radius::new("/home/alkali/hacking/simple");
    let mut state = radius.call_state(0x5fa);

    let bv = state.bv("num", 32);
    state.registers.set("edi", Value::Symbolic(bv.clone()));
    let mut new_state = radius.run_until(state, 0x60b, 0x612).unwrap();

    if let Value::Concrete(val) = new_state.evaluate(&bv).unwrap() {
        assert_eq!(val, 2);
    }
}

#[test]
fn r100() {
    let mut radius = Radius::new("/home/alkali/hacking/r100");
    let mut state = radius.call_state(0x004006fd);
    let bv = state.bv("flag", 12*8);
    let addr: u64 = 0x1000000;
    let len = 12;
    state.memory.write_value(addr, Value::Symbolic(bv.clone()), len);
    state.registers.set("rdi", Value::Concrete(addr));
    let mut new_state = radius.run_until(state, 0x004007a1, 0x00400790).unwrap();

    //println!("hmmm {:?}", new_state);
    let flag_vec = new_state.memory.read(&mut radius.r2api, addr, len);
    let flag = new_state.evaluate_string(flag_vec);
    println!("FLAG: {}", flag);

    assert_eq!(flag, "Code_Talkers");
    radius.r2api.close();
}

//#[test]
fn unbreakable() {
    let mut radius = Radius::new("/home/alkali/hacking/unbreakable");
    let mut state = radius.call_state(0x004005bd);
    let len: usize = 0x33;
    let bv = state.bv("flag", 8*len as u32);

    // add "CTF{" constraint
    bv.slice(31, 0)._eq(&state.bvv(0x7b465443, 32)).assert();

    let addr: u64 = 0x6042c0;
    state.memory.write_value(addr, Value::Symbolic(bv.clone()), len);
    let mut new_state = radius.run_until(state, 0x00400830, 0x00400850).unwrap();

    //println!("hmmm {:?}", new_state);
    let flag_vec = new_state.memory.read(&mut radius.r2api, addr, len);
    let flag = new_state.evaluate_string(flag_vec);
    println!("FLAG: {}", flag);
    assert_eq!(flag, "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}");

    radius.r2api.close();
}

fn main() {
    /*let c = Value::Concrete(0b110100);
    let rot = Value::Concrete(3);
    println!("{:?}", c.ror(rot, 6));*/
    unbreakable();
}