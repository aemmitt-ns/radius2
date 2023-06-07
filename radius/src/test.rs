//use crate::state::State;

// #[test]
// looper is broken cuz of the weird disassembly crash
// fn looper() {
//     use crate::radius::{Radius, RadiusOption};

//     let options = [RadiusOption::Sims(false)]; // RadiusOption::Debug(true));
//     let mut radius = Radius::new_with_options(Some("../tests/looper"), &options);
//     let state = radius.call_state(0x100003f4c);
//     //let state = radius.entry_state(&vec!("looper".to_owned()), &vec!());
//     let new_state = radius.run_until(state, 0x100003fb4, &[]).unwrap();
//     let x0 = new_state.registers.get("x0");
//     println!("{:?}", x0);
//     assert_eq!(x0.as_u64(), Some(1837180037));
// }

#[test]
fn hello() {
    use crate::radius::{Radius, RadiusOption};
    let options = [RadiusOption::Debug(true)];
    let mut radius = Radius::new_with_options(Some("../tests/hello"), &options);
    let state = radius.call_state(0x00001149);
    let new_state = radius.run_until(state, 0x1163, &[]).unwrap();
    println!("{:?}", new_state.registers.get("eax"))
}

#[test]
fn strstuff() {
    use crate::radius::Radius;
    use crate::value::Value;

    let mut radius = Radius::new("../tests/strstuff");
    let main = radius.r2api.get_address("main").unwrap();
    let mut state = radius.call_state(main);

    let bv = state.bv("flag", 10 * 8);
    let addr: u64 = 0x100000;
    let len = 10;
    state
        .memory
        .write_value(addr + 8, &Value::Concrete(addr + 24, 0), 8);
    state
        .memory
        .write_value(addr + 24, &Value::Symbolic(bv.clone(), 0), len);
    state
        .memory
        .write_value(addr + 34, &Value::Concrete(0, 0), 8);
    state.registers.set("rsi", Value::Concrete(addr, 0));

    let mut new_state = radius.run_until(state, 0x1208, &[0x120f]).unwrap();
    println!("{:?}", new_state.evaluate_string_bv(&bv))
}

#[test]
fn simple() {
    use crate::radius::Radius;
    use crate::value::Value;

    let mut radius = Radius::new("../tests/simple");
    let mut state = radius.call_state(0x5fa);

    let bv = state.bv("num", 32);
    state.registers.set("edi", Value::Symbolic(bv.clone(), 0));
    let mut new_state = radius.run_until(state, 0x60b, &[0x612]).unwrap();

    if let Value::Concrete(val, _t) = new_state.evaluate(&bv).unwrap() {
        assert_eq!(val, 2);
    }
}

// this takes a really long time now (3s)
// cuz its doing the atoi also
#[test]
fn multi() {
    use crate::radius::{Radius, RadiusOption};

    let options = [RadiusOption::Debug(true)];
    let mut radius = Radius::new_with_options(Some("../tests/multi"), &options);
    let mut state = radius.entry_state();

    let arg1 = state.symbolic_value("arg1", 40);
    let name = state.concrete_value(0, 0);

    radius.set_argv_env(&mut state, &[name, arg1], &[]);
    let mut new_state = radius.run_until(state, 0x11c2, &[0x11c9]).unwrap();

    let arg = new_state.registers.get_with_alias("A0");
    println!("arg: {}", new_state.eval(&arg).unwrap().as_u64().unwrap());
}

#[test]
fn r100() {
    use crate::radius::{Radius, RadiusOption};
    use crate::value::Value;

    let options = vec![RadiusOption::Debug(false)];
    let mut radius = Radius::new_with_options(Some("../tests/r100"), &options);
    let mut state = radius.call_state(0x004006fd);
    let bv = state.bv("flag", 12 * 8);
    let addr: u64 = 0x100000;
    state
        .memory
        .write_value(addr, &Value::Symbolic(bv.clone(), 0), 12);
    state.registers.set("rdi", Value::Concrete(addr, 0));

    radius.breakpoint(0x004007a1);
    radius.avoid(&[0x00400790]);
    let mut new_state = radius.run(state, 1).unwrap();
    let flag = new_state.evaluate_string_bv(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "Code_Talkers");
}

#[test]
fn r200() {
    use crate::radius::{Radius, RadiusOption};
    use crate::value::Value;

    let options = vec![RadiusOption::Debug(false)];
    let mut radius = Radius::new_with_options(Some("../tests/r200"), &options);
    let mut state = radius.call_state(0x00400886);
    let bv = state.bv("flag", 6 * 8);

    let addr = state.registers.get("rsp").as_u64().unwrap();
    state
        .memory
        .write_value(addr - 0x18, &Value::Symbolic(bv.clone(), 0), 6);

    radius.breakpoint(0x00400843);
    radius.mergepoint(0x004007fd);
    radius.avoid(&[0x00400832]);

    let mut new_state = radius.run(state, 1).unwrap();
    let flag = new_state.evaluate_string_bv(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "rotors");
}

#[test]
fn unbreakable() {
    use crate::radius::Radius;
    use crate::value::Value;

    let mut radius = Radius::new("../tests/unbreakable");
    let mut state = radius.call_state(0x004005bd);
    let len: usize = 0x33;
    let bv = state.bv("flag", 8 * len as u32);

    // add "CTF{" constraint
    let assertion = bv.slice(31, 0)._eq(&state.bvv(0x7b465443, 32));
    state.assert_bv(&assertion);

    let addr: u64 = 0x6042c0;
    state
        .memory
        .write_value(addr, &Value::Symbolic(bv.clone(), 0), len);
    let mut new_state = radius.run_until(state, 0x00400830, &[0x00400850]).unwrap();

    let flag = new_state.evaluate_string_bv(&bv).unwrap();
    println!("FLAG: {}", flag);
    assert_eq!(flag, "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}");
}

/*fn callback(state: &mut State) -> bool {
    //println!("state: {:?}", state);
    true
}*/

#[test]
fn fileread() {
    use crate::radius::{Radius, RadiusOption};
    use crate::value::byte_values;

    let options = vec![RadiusOption::Debug(true)];
    let mut radius = Radius::new_with_options(Some("../tests/fileread"), &options);
    radius.analyze(2); // necessary for sims for some reason
    let mut state = radius.call_state(0x100003e7c);
    let data = byte_values("hmmmmmm");
    state.filesystem.add_file("test.txt", &data);
    let mut new_state = radius.run_until(state, 0x100003f14, &[]).unwrap();

    // dump stdout
    let data = new_state.filesystem.dump(1);

    let mut str_bytes = vec![];
    for d in data {
        str_bytes.push(new_state.solver.eval_to_u64(&d).unwrap() as u8);
    }
    let string = String::from_utf8(str_bytes).unwrap();
    assert_eq!(string, "hmmm\n");
}

#[test]
fn format() {
    use crate::radius::Radius;
    use crate::sims::format;
    use crate::value::vc;

    let mut radius = Radius::new("../tests/hello");
    let main = radius.r2api.get_address("main").unwrap();
    let mut state = radius.call_state(main);

    //let buf_addr = state.memory_alloc(&vc(100));
    let fmt_addr = state.memory_alloc(&vc(100));

    let dx = state.symbolic_value("dx", 8);
    //state.assert_value(&dx.eq(&vc('x' as u64)));

    // symbolic format
    let fmt = [vc('%' as u64), dx, vc(0)];
    state.memory_write(&fmt_addr, &fmt, &vc(8));

    //state.memory_write_string(fmt_addr.as_u64().unwrap(), "%02x");
    //state.memory_write_string(buf_addr.as_u64().unwrap(), "cool");

    //state.memory_write_value(&buf_addr, &vc(17492), 4);
    let data = format::format(&mut state, &[fmt_addr, vc(17499)]);
    let value = state.pack(&data);
    state.assert(&value.slice(31, 0).eq(&vc(0x62353434)));
    let result = state.evaluate_string(&value).unwrap();
    println!("result: {}", result);
    assert_eq!(&result[0..4], "445b");
}

#[test]
fn symmem() {
    use crate::radius::{Radius, RadiusOption};
    use crate::sims::format::{atoi_helper, itoa_helper};
    use crate::state::{Event, EventTrigger};
    use crate::value::Value;
    use std::rc::Rc;

    let mut radius =
        Radius::new_with_options(Some("../tests/symmem"), &vec![RadiusOption::Debug(false)]);

    let main = radius.r2api.get_address("main").unwrap();
    let mut state = radius.call_state(main);
    state.hook_event(
        Event::SymbolicRead(EventTrigger::Before),
        Rc::new(|_s, _e| {
            println!("hit event hook");
        }),
    );

    let x = state.bv("x", 64);
    //x.ult(&state.bvv(-1 as i64 as u64, 64)).assert();
    //x.ugt(&state.bvv(40, 64)).assert();
    //println!("x: {:?}", state.solver.max(&x));

    let sentence = String::from("this is my string it is a good string I think");
    state.memory.write_string(0x100000, sentence.as_str());
    state
        .memory
        .write_value(0x100008, &Value::Symbolic(x.clone(), 0), 8);

    let index = state.memory_search(
        &Value::Concrete(0x100000, 0),
        &Value::Concrete(0x646f6f67, 0),
        &Value::Concrete(64, 0),
        false,
    );

    //println!("index is {:?}", index);

    if let Value::Symbolic(ind, _t) = index {
        state.solver.push();
        ind._eq(&state.bvv(0x10000a, 64)).assert();
        //println!("{:?}", state.memory.read_string(0x100000, 48));
        state.solver.pop();
    }

    //return;

    let sentence1 = "elephant";
    let _sentence2 = "alephant";

    state.memory.write_string(0x100000, sentence1);
    state
        .memory
        .write_value(0x100010, &Value::Symbolic(x.clone(), 0), 8);

    let cmp = state.memory_compare(
        &Value::Concrete(0x100000, 0),
        &Value::Concrete(0x100010, 0),
        &Value::Concrete(8, 0),
    );

    if let Value::Symbolic(c, _t) = cmp {
        c._eq(&state.bvv(0, 64)).assert();
        println!("{}", state.evaluate_string_bv(&x).unwrap());
    }

    let len = 8;
    state.memory.write_string(0x200000, "00000110");
    let atoi_addr = Value::Concrete(0x200000, 0);
    let numstr = state.symbolic_value("numstr", 8 * len);
    state.memory_write_value(&atoi_addr, &numstr, len as usize);
    let num = atoi_helper(&mut state, &atoi_addr, &Value::Concrete(2, 0), 32); //numstr);
    state.assert(&num.sgt(&Value::Concrete(110i64 as u64, 0)));
    //println!("num: {:?}", num);
    println!("atoi: {:?}", state.evaluate_string(&numstr));

    let itoa_addr = Value::Concrete(0x300000, 0);
    let citoa_val = Value::Concrete(0x003239343731, 0);
    //let itoa_val = Value::Concrete(0x4454, 0);
    let itoa_val = state.symbolic_value("itoa", 32);
    itoa_helper(
        &mut state,
        &itoa_val,
        &itoa_addr,
        &Value::Concrete(10, 0),
        true,
        32,
    );
    let ibv = state.memory_read_value(&itoa_addr, 7);
    state.assert(&ibv.eq(&citoa_val));
    println!("itoa: {:?}", state.eval(&itoa_val));

    //println!("cmp: {:?}", cmp);

    /*println!("good: {:?}", index);
    if let Value::Concrete(good) = index {
        println!("good: {:?}, {:?}", index, sentence.get(..good as usize));
    }*/

    let len: usize = 8;
    let bv = state.bv("flag", 8 * len as u32);
    //bv._eq(&state.bvv(3, 64)).not().assert();

    state.registers.set("rdi", Value::Symbolic(bv.clone(), 0));

    let mut new_state = radius.run_until(state, 0x119c, &[0x119e]).unwrap();

    let eax = new_state.registers.get("rax");

    //println!("eax: {:?}", eax);
    //eax.as_bv().unwrap()._eq(&new_state.bvv(7, 64)).assert();
    println!("val: {:?} {:?}", new_state.eval(&eax), eax);

    radius.r2api.close();
}

#[test]
fn ioscrackme() {
    use crate::radius::{Radius, RadiusOption};
    use crate::value::Value;

    let mut radius = Radius::new_with_options(
        Some("ipa://../tests/ioscrackme.ipa"),
        &[RadiusOption::Debug(true)],
    );

    //radius.set_option("asm.arch", "arm.v35");
    let len: usize = 16;

    let validate = radius.r2api.get_address("sym._validate").unwrap();
    let mut state = radius.call_state(validate);
    let bv = state.bv("flag", 8 * len as u32);

    // add "[a-zA-Z]" constraint
    state.constrain_bytes_bv(&bv, "[a-zA-Z]");

    let buf_addr: u64 = 0xfff00000;
    state.registers.set("x0", Value::Concrete(buf_addr, 0));
    state
        .memory
        .write_value(buf_addr, &Value::Symbolic(bv.clone(), 0), len);

    let mut new_state = radius
        .run_until(state, 0x10000600c, &[0x100006044])
        .unwrap();

    let flag = new_state.evaluate_string_bv(&bv);
    println!("FLAG: {}", flag.unwrap());
    radius.r2api.close();
}
