use radius2::value::Value;
use radius2::{Radius, RadiusOption};

fn main() {
    let options = [
        RadiusOption::Debug(true),
        RadiusOption::Sims(false),
        RadiusOption::LoadPlugins(true),
    ];

    let mut radius = Radius::new_with_options(Some("frida://attach/usb//iOSCrackMe"), &options);

    // turn off cache to write value back to real mem
    radius.set_option("io.cache", "false");
    let validate = radius.get_address("validate").unwrap();
    let mut state = radius.frida_state(validate); // hook addr and suspend when hit

    let len: usize = 16;
    let bv = state.bv("flag", 8 * len as u32);

    // add "[a-zA-Z]" constraint
    state.constrain_bytes_bv(&bv, "[a-zA-Z]");
    let buf_addr = state.registers.get("x0");
    state.memory_write_value(&buf_addr, &Value::Symbolic(bv.clone(), 0), len);

    let mut new_state = radius
        .run_until(state, validate + 0x210, &[validate + 0x218])
        .unwrap();

    let flag = new_state.evaluate_string_bv(&bv).unwrap();
    println!("FLAG: {}", flag);

    // write solution back to app memory
    radius.write_string(buf_addr.as_u64().unwrap(), &flag);
    radius.close(); // closing lets app continue
}
