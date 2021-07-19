use crate::value::Value;
use crate::state::{State, StateStatus};
use crate::sims::fs::FileMode;

const MAX_LEN: u64 = 8192;

pub fn syscall(syscall_name: &str, state: &mut State, args: Vec<Value>) -> Value {
    match syscall_name {
        "indirect_syscall" => indirect(state, args),  // fuq

        "open"     => open(state, args),
        "close"    => close(state, args),
        "read"     => read(state, args),
        "write"    => write(state, args),
        "access"   => access(state, args),
        "lseek"    => lseek(state, args),
        "mprotect" => mmap(state, args),
        "mmap"     => mmap(state, args),
        "munmap"   => munmap(state, args),
        "brk"      => brk(state, args),
        "sbrk"     => sbrk(state, args),
        "fork"     => fork(state, args),
        "exit"     => exit(state, args),
         _         => error(state, args)

        // this is literally every syscall
        // the rest arent real
        // you have been played for a fool
    }
}

// get actual syscall and recall .. 
pub fn indirect(state: &mut State, mut args: Vec<Value>) -> Value {
    let sn = state.solver.evalcon_to_u64(&args.remove(0)).unwrap();
    let sys_str = state.r2api.get_syscall_str(sn);
    syscall(sys_str.as_str(), state, args)
}

pub fn open(state: &mut State, args: Vec<Value>) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let len = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN));
    let length = state.solver.evalcon_to_u64(&len).unwrap();
    let path = state.memory_read_string(addr, length as usize);
    if let Some(fd) = state.filesystem.open(path.as_str(), FileMode::Read) {
        Value::Concrete(fd as u64)
    } else {
        Value::Concrete(-1i64 as u64)
    }
}

pub fn close(state: &mut State, args: Vec<Value>) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]);
    state.filesystem.close(fd.unwrap() as usize);
    Value::Concrete(0)
}


pub fn read(state: &mut State, args: Vec<Value>) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let length = state.solver.max_value(&args[2]);
    let data = state.filesystem.read(fd as usize, length as usize);
    let len = data.len();
    state.memory_write(&args[1], data, &args[2]);
    Value::Concrete(len as u64)
}

pub fn write(state: &mut State, args: Vec<Value>) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let data = state.memory_read(&args[1], &args[2]);
    let len = data.len();
    state.filesystem.write(fd as usize, data);
    Value::Concrete(len as u64)
}

pub fn access(state: &mut State, args: Vec<Value>) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let len = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN));
    let length = state.solver.evalcon_to_u64(&len).unwrap();
    let path = state.memory_read_string(addr, length as usize);
    state.filesystem.access(path.as_str())
}

pub fn lseek(state: &mut State, args: Vec<Value>) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let pos = state.solver.evalcon_to_u64(&args[1]).unwrap();
    state.filesystem.seek(fd as usize, pos as usize);
    Value::Concrete(pos)
}

// TODO the stat structure stuff ugh
// error til then
pub fn error(_state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(-1i64 as u64)
}

// TODO success dummy
pub fn success(_state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(0)
}

// TODO fd backed mem
pub fn mmap(state: &mut State, args: Vec<Value>) -> Value {
    // we can't do symbolic mmaps
    // this is beyond science
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let size = state.solver.evalcon_to_u64(&args[1]).unwrap();
    let prot = state.solver.evalcon_to_u64(&args[2]).unwrap();

    let perms = state.memory.prot_to_str(prot);
    state.memory.add_segment("", addr, size, perms.as_str());
    Value::Concrete(addr)
}

pub fn munmap(state: &mut State, args: Vec<Value>) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();

    let mut ind = -1i32 as usize;
    for (i, seg) in state.memory.segs.iter().enumerate() {
        if seg.addr == addr {
            ind = i;
        }
    }

    if ind as i32 != -1 {
        state.memory.segs.remove(ind);
        Value::Concrete(0)
    } else {
        Value::Concrete(-1i64 as u64)
    }
}

pub fn brk(state: &mut State, args: Vec<Value>) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let ret = state.memory.brk(addr);

    if ret {
        Value::Concrete(0)
    } else {
        Value::Concrete(-1i64 as u64)
    }
}

pub fn sbrk(state: &mut State, args: Vec<Value>) -> Value {
    let inc = state.solver.evalcon_to_u64(&args[0]).unwrap();
    Value::Concrete(state.memory.sbrk(inc))
}

// returning a symbolic pid+1 | 0 | -1
// will result in a split state when used to branch
// essentially recreating a fork. pretty cool!
pub fn fork(state: &mut State, _args: Vec<Value>) -> Value {
    let cpid = state.pid+1;
    state.pid = cpid;
    let pid = state.bv(format!("pid_{}", cpid).as_str(), 64);
    let a = pid._eq(&state.bvv(cpid, 64)).or(&pid._eq(&state.bvv(0, 64)))
        .or(&pid._eq(&state.bvv(-1i64 as u64, 64)));

    state.solver.assert(&a);

    Value::Symbolic(pid)
}

pub fn exit(state: &mut State, _args: Vec<Value>) -> Value {
    state.status = StateStatus::Inactive;
    Value::Concrete(0)
}