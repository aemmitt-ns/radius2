use radius::radius::{Radius, RadiusOption};
use radius::value::Value;

fn main() {
    let options = [RadiusOption::Debug(true), RadiusOption::Sims(false)];
    let mut radius = Radius::new_with_options(
        Some("frida://attach/usb//iOSCrackMe"), &options);

    // turn off cache to write value back to real mem
    radius.set_option("io.cache", "false"); 
    let validate = radius.get_address("validate").unwrap();
    let mut state = radius.frida_state(validate); // hook addr and suspend when hit

    let len: usize = 16;
    let bv = state.bv("flag", 8*len as u32);

    // add "[a-zA-Z]" constraint
    for i in 0..len as u32 {
        let gteca = bv.slice(8*(i+1)-1, 8*i).ugte(&state.bvv(0x41, 8));
        let ltecz = bv.slice(8*(i+1)-1, 8*i).ulte(&state.bvv(0x5A, 8));
        let gtea  = bv.slice(8*(i+1)-1, 8*i).ugte(&state.bvv(0x61, 8));
        let ltez  = bv.slice(8*(i+1)-1, 8*i).ulte(&state.bvv(0x7A, 8));
        gteca.and(&ltecz).or(&gtea.and(&ltez)).assert();
    }

    let buf_addr = state.registers.get("x0");
    state.memory_write_value(&buf_addr, &Value::Symbolic(bv.clone(), 0), len);

    let mut new_state = radius.run_until(
        state, validate+0x210, &[validate+0x218]).unwrap();

    let flag = new_state.evaluate_string(&bv).unwrap();
    println!("FLAG: {}", flag);

    // write solution back to app memory
    radius.write_string(buf_addr.as_u64().unwrap(), &flag);
    radius.close(); // closing lets app continue
}

