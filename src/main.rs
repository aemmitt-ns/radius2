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

use crate::radius::Radius;
use crate::value::Value;
use crate::state::State;

//#[test]
fn looper() {
    let mut radius = Radius::new("tests/looper");
    let state = radius.call_state(0x112d);
    let mut new_state = radius.run_until(state, 0x00001168, vec!()).unwrap();
    println!("{:?}", new_state.registers.get("eax"))
}

fn hello() {
    let mut radius = Radius::new("tests/hello");
    let mut state = radius.call_state(0x00001149);
    let mut new_state = radius.run_until(state, 0x00001163, vec!()).unwrap();
    //println!("{:?}", new_state.registers.get("eax"))
}

fn strstuff() {
    let mut radius = Radius::new("tests/strstuff");
    let main = radius.r2api.get_address("main");
    let mut state = radius.call_state(main);

    let bv = state.bv("flag", 10*8);
    let addr: u64 = 0x1000000;
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
    let mut radius = Radius::new("tests/r100");
    let mut state = radius.call_state(0x004006fd);
    let bv = state.bv("flag", 12*8);
    let addr: u64 = 0x1000000;
    let len = 12;
    state.memory.write_value(addr, Value::Symbolic(bv.clone()), len);
    state.registers.set("rdi", Value::Concrete(addr));

    radius.breakpoint(0x004007a1);
    radius.avoid(vec!(0x00400790));
    let mut new_state = radius.run(Some(state), 2).unwrap();
    let flag = new_state.evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);

    assert_eq!(flag, "Code_Talkers");
    radius.r2api.close();
}

#[test]
fn unbreakable() {
    let mut radius = Radius::new("tests/unbreakable");
    let mut state = radius.call_state(0x004005bd);
    let len: usize = 0x33;
    let bv = state.bv("flag", 8*len as u32);

    // add "CTF{" constraint
    bv.slice(31, 0)._eq(&state.bvv(0x7b465443, 32)).assert();

    let addr: u64 = 0x6042c0;
    state.memory.write_value(addr, Value::Symbolic(bv.clone()), len);
    let mut new_state = radius.run_until(
        state, 0x00400830, vec!(0x00400850)).unwrap();

    let flag = new_state.evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}");

    radius.r2api.close();
}

/*fn callback(state: &mut State) -> bool {
    //println!("state: {:?}", state);
    true
}*/

//#[test]
fn symmem() {
    let mut radius = Radius::new("tests/symmem");
    let main = radius.r2api.get_address("main");
    let mut state = radius.call_state(main);

    let x = state.bv("x", 64);
    //x.ult(&state.bvv(-1 as i64 as u64, 64)).assert();
    //x.ugt(&state.bvv(40, 64)).assert();
    //println!("x: {:?}", state.solver.max(&x));

    let sentence = String::from("this is my string it is a good string I think");
    state.memory.write_string(0x1000000, sentence.as_str());
    state.memory.write_value(0x1000008, Value::Symbolic(x.clone()), 8);

    let index = state.memory.search(
        &Value::Concrete(0x1000000), 
        &Value::Concrete(0x646f6f67), 
        &Value::Concrete(64), false);

    if let Value::Symbolic(ind) = index {
        //ind._eq(&state.bvv(0x1000008, 64)).assert();
        println!("{:?}", state.memory.read_string(0x1000000, 30));
    }

    let sentence1 = "elephant";
    let sentence2 = "alephant";

    state.memory.write_string(0x1000000, sentence1);
    state.memory.write_value(0x1000010, Value::Symbolic(x.clone()), 8);

    let cmp = state.memory.compare(
        &Value::Concrete(0x1000000),
        &Value::Concrete(0x1000010),
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

    let eax = new_state.registers.get("eax");
    //println!("eax: {:?}", eax);
    println!("val: {:?}", new_state.eval(&eax));

    radius.r2api.close();
}

#[test]
fn ioscrackme() {
    let mut radius = Radius::new("ipa://tests/ioscrackme.ipa");
    //radius.r2api.r2p.cmd("e asm.arch=arm.v35");
    let len: usize = 16;

    let validate = radius.r2api.get_address("sym._validate");
    // radius.hook(0x100005e34, callback);
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

    //radius.breakpoint(0x10000600c);
    //radius.avoid(vec!(0x100006044));
    let mut new_state = radius.run_until(
        state, 0x10000600c, vec!(0x100006044)).unwrap();
    //let mut new_state = radius.run(Some(state), 2).unwrap();
    let flag = new_state.evaluate_string(&bv);
    println!("FLAG: {}", flag.unwrap());
    radius.r2api.close();
}

fn main() {
    /*let c = Value::Concrete(0b110100);
    let rot = Value::Concrete(3);
    println!("{:?}", c.ror(rot, 6));*/
    r100();
}