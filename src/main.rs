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
pub mod solver;
pub mod sims;

use crate::radius::{Radius, RadiusOption};
use crate::value::Value;
//use crate::state::State;

//#[test]
fn looper() {
    let options = vec!(); // RadiusOption::Debug(true));
    let mut radius = Radius::new_with_options("tests/looper", options);
    let state = radius.call_state(0x112d);
    //let state = radius.entry_state(&vec!("looper".to_owned()), &vec!());
    let mut new_state = radius.run_until(state, 0x00001168, vec!()).unwrap();
    println!("{:?}", new_state.registers.get("eax"));
}

#[test]
fn hello() {
    let mut radius = Radius::new("tests/hello");
    let state = radius.call_state(0x00001149);
    let mut new_state = radius.run_until(state, 0x00001163, vec!()).unwrap();
    println!("{:?}", new_state.registers.get("eax"))
}

#[test]
fn strstuff() {
    let mut radius = Radius::new("tests/strstuff");
    let main = radius.r2api.get_address("main");
    let mut state = radius.call_state(main);

    let bv = state.bv("flag", 10*8);
    let addr: u64 = 0x100000;
    let len = 10;
    state.memory.write_value(addr+8, Value::Concrete(addr+24), 8);
    state.memory.write_value(addr+24, Value::Symbolic(bv.clone()), len);
    state.memory.write_value(addr+34, Value::Concrete(0), 8);
    state.registers.set("rsi", Value::Concrete(addr));

    let mut new_state = radius.run_until(state, 0x00001208, 
        vec!(0x0000120f)).unwrap();
    println!("{:?}", new_state.evaluate_string(&bv))
}

#[test]
fn simple() {
    let mut radius = Radius::new("tests/simple");
    let mut state = radius.call_state(0x5fa);

    let bv = state.bv("num", 32);
    state.registers.set("edi", Value::Symbolic(bv.clone()));
    let mut new_state = radius.run_until(state, 0x60b, vec!(0x612)).unwrap();

    if let Value::Concrete(val) = new_state.evaluate(&bv).unwrap() {
        assert_eq!(val, 2);
    }
}

#[test]
fn multi() {
    let mut radius = Radius::new("tests/multi");
    let check = radius.r2api.get_address("sym.check");
    let mut state = radius.call_state(check);

    let bv = state.bv("num", 64);
    state.registers.set("rdi", Value::Symbolic(bv.clone()));
    let new_state = radius.run_until(state, 0x11c2, vec!(0x11c9)).unwrap();

    println!("{:?}", new_state.solver.evaluate(&bv));
}

//#[test]
fn r100() {
    let options = vec!(RadiusOption::Debug(true));
    let mut radius = Radius::new_with_options("tests/r100", options);
    let mut state = radius.call_state(0x004006fd);
    let bv = state.bv("flag", 12*8);
    let addr: u64 = 0x100000;
    state.memory.write_value(addr, Value::Symbolic(bv.clone()), 12);
    state.registers.set("rdi", Value::Concrete(addr));

    radius.breakpoint(0x004007a1);
    radius.avoid(vec!(0x00400790));
    let mut new_state = radius.run(Some(state), 2).unwrap();
    let flag = new_state.evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "Code_Talkers");
}

//#[test]
fn r200() {
    let options = vec!(RadiusOption::Debug(false));
    let mut radius = Radius::new_with_options("tests/r200", options);
    let mut state = radius.call_state(0x00400886);
    let bv = state.bv("flag", 6*8);

    let addr = state.registers.get("rsp").as_u64().unwrap();
    state.memory.write_value(addr-0x18, Value::Symbolic(bv.clone()), 6);

    radius.breakpoint(0x00400843);
    radius.mergepoint(0x004007fd);
    radius.avoid(vec!(0x00400832));

    let mut new_state = radius.run(Some(state), 2).unwrap();
    let flag = new_state.evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "rotors");
}

//#[test]
fn unbreakable() {
    let mut radius = Radius::new("tests/unbreakable");
    let mut state = radius.call_state(0x004005bd);
    let len: usize = 0x33;
    let bv = state.bv("flag", 8*len as u32);

    // add "CTF{" constraint
    let assertion = bv.slice(31, 0)._eq(&state.bvv(0x7b465443, 32));
    state.assert(&assertion);

    let addr: u64 = 0x6042c0;
    state.memory.write_value(addr, Value::Symbolic(bv.clone()), len);
    let mut new_state = radius.run_until(
        state, 0x00400830, vec!(0x00400850)).unwrap();

    let flag = new_state.evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}");
}

/*fn callback(state: &mut State) -> bool {
    //println!("state: {:?}", state);
    true
}*/

//#[test]
fn symmem() {
    let mut radius = Radius::new_with_options("tests/symmem", vec!(RadiusOption::Debug(true)));
    let main = radius.r2api.get_address("main");
    let mut state = radius.call_state(main);

    let x = state.bv("x", 64);
    //x.ult(&state.bvv(-1 as i64 as u64, 64)).assert();
    //x.ugt(&state.bvv(40, 64)).assert();
    //println!("x: {:?}", state.solver.max(&x));

    let sentence = String::from("this is my string it is a good string I think");
    state.memory.write_string(0x100000, sentence.as_str());
    state.memory.write_value(0x100008, Value::Symbolic(x.clone()), 8);

    let index = state.memory_search(
        &Value::Concrete(0x100000), 
        &Value::Concrete(0x646f6f67), 
        &Value::Concrete(64), false);

    //println!("index is {:?}", index);

    if let Value::Symbolic(ind) = index {
        state.solver.push();
        ind._eq(&state.bvv(0x10000a, 64)).assert();
        //println!("{:?}", state.memory.read_string(0x100000, 48));
        state.solver.pop();
    }

    //return;

    let sentence1 = "elephant";
    let sentence2 = "alephant";

    state.memory.write_string(0x100000, sentence1);
    state.memory.write_value(0x100010, Value::Symbolic(x.clone()), 8);

    let cmp = state.memory_compare(
        &Value::Concrete(0x100000),
        &Value::Concrete(0x100010),
        &Value::Concrete(8));

    if let Value::Symbolic(c) = cmp {
        c._eq(&state.bvv(0, 64)).assert();
        println!("{}", state.evaluate_string(&x).unwrap());
    }

    //println!("cmp: {:?}", cmp);

    /*println!("good: {:?}", index);
    if let Value::Concrete(good) = index {
        println!("good: {:?}, {:?}", index, sentence.get(..good as usize));
    }*/

    let len: usize = 8;
    let bv = state.bv("flag", 8*len as u32);
    //bv._eq(&state.bvv(3, 64)).not().assert();

    state.registers.set("rdi", Value::Symbolic(bv.clone()));

    let mut new_state = radius.run_until(
        state, 0x119c, vec!(0x119e)).unwrap();

    let eax = new_state.registers.get("rax");

    //println!("eax: {:?}", eax);
    //eax.as_bv().unwrap()._eq(&new_state.bvv(7, 64)).assert();
    println!("val: {:?} {:?}", new_state.eval(&eax), eax);

    radius.r2api.close();
}

//#[test]
fn ioscrackme() {
    let mut radius = Radius::new("ipa://tests/ioscrackme.ipa");
    //radius.r2api.r2p.cmd("e asm.arch=arm.v35");
    let len: usize = 16;

    let validate = radius.r2api.get_address("sym._validate");
    let mut state = radius.call_state(validate);
    let bv = state.bv("flag", 8*len as u32);

    // add "[a-zA-Z]" constraint
    for i in 0..len {
        let gteca = bv.slice(8*(i+1) as u32 -1, 8*i as u32).ugte(&state.bvv(0x41, 8));
        let ltecz = bv.slice(8*(i+1) as u32 -1, 8*i as u32).ulte(&state.bvv(0x5A, 8));
        let gtea  = bv.slice(8*(i+1) as u32 -1, 8*i as u32).ugte(&state.bvv(0x61, 8));
        let ltez  = bv.slice(8*(i+1) as u32 -1, 8*i as u32).ulte(&state.bvv(0x7A, 8));
        gteca.and(&ltecz).or(&gtea.and(&ltez)).assert();
    }

    let buf_addr: u64 = 0x100000;
    state.registers.set("x0", Value::Concrete(buf_addr));
    state.memory.write_value(buf_addr, Value::Symbolic(bv.clone()), len);


    let mut new_state = radius.run_until(
        state, 0x10000600c, vec!(0x100006044)).unwrap();

    let flag = new_state.evaluate_string(&bv);
    println!("FLAG: {}", flag.unwrap());
    radius.r2api.close();
}

fn main() {
    r100();
}