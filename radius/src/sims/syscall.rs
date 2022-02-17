use crate::sims::fs::FileMode;
use crate::state::{State, StateStatus};
use crate::value::Value;

const MAX_LEN: u64 = 8192;

pub fn syscall(syscall_name: &str, state: &mut State, args: &[Value]) -> Value {
    match syscall_name {
        "indirect_syscall" => indirect(state, args), // fuq

        "open" => open(state, args),
        "openat" => openat(state, args),
        "close" => close(state, args),
        "read" => read(state, args),
        "write" => write(state, args),
        "access" => access(state, args),
        "stat" => stat(state, args),
        "fstat" => fstat(state, args),
        "lstat" => lstat(state, args),
        "lseek" => lseek(state, args),
        "mprotect" => mmap(state, args),
        "mmap" => mmap(state, args),
        "munmap" => munmap(state, args),
        "brk" => brk(state, args),
        "sbrk" => sbrk(state, args),
        "getpid" => getpid(state, args),
        "getuid" => getuid(state, args),
        "geteuid" => getuid(state, args),
        "getgid" => getuid(state, args),
        "getegid" => getuid(state, args),
        "fork" => fork(state, args),
        "exit" => exit(state, args),
        "ptrace" => ptrace(state, args),
        _ => error(state, args), // this is literally every syscall
                                 // the rest arent real
                                 // you have been played for a fool
    }
}

// get actual syscall and recall ..
pub fn indirect(state: &mut State, args: &[Value]) -> Value {
    let sn = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let sys_str = state.r2api.get_syscall_str(sn).unwrap();
    syscall(sys_str.as_str(), state, &args[1..])
}

pub fn open(state: &mut State, args: &[Value]) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let len = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0));
    let length = state.solver.evalcon_to_u64(&len).unwrap();
    let path = state.memory_read_string(addr, length as usize);
    if let Some(fd) = state.filesystem.open(path.as_str(), FileMode::Read) {
        Value::Concrete(fd as u64, 0)
    } else {
        Value::Concrete(-1i64 as u64, 0)
    }
}

// ignore dir for now idk
pub fn openat(state: &mut State, args: &[Value]) -> Value {
    open(state, &args[1..])
}

pub fn close(state: &mut State, args: &[Value]) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]);
    state.filesystem.close(fd.unwrap() as usize);
    Value::Concrete(0, 0)
}

pub fn read(state: &mut State, args: &[Value]) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let length = state.solver.max_value(&args[2]);
    let data = state.filesystem.read(fd as usize, length as usize);
    let len = data.len();
    state.memory_write(&args[1], &data, &args[2]);
    Value::Concrete(len as u64, args[2].get_taint())
}

pub fn write(state: &mut State, args: &[Value]) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let data = state.memory_read(&args[1], &args[2]);
    let len = data.len();
    state.filesystem.write(fd as usize, data);
    Value::Concrete(len as u64, 0)
}

pub fn access(state: &mut State, args: &[Value]) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let len = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0));
    let length = state.solver.evalcon_to_u64(&len).unwrap();
    let path = state.memory_read_string(addr, length as usize);
    state.filesystem.access(path.as_str())
}

/*

/* offset    |  size */  type = struct stat {
/*    0      |     8 */    __dev_t st_dev;
/*    8      |     8 */    __ino_t st_ino;
/*   16      |     8 */    __nlink_t st_nlink;
/*   24      |     4 */    __mode_t st_mode;
/*   28      |     4 */    __uid_t st_uid;
/*   32      |     4 */    __gid_t st_gid;
/*   36      |     4 */    int __pad0;
/*   40      |     8 */    __dev_t st_rdev;
/*   48      |     8 */    __off_t st_size;
/*   56      |     8 */    __blksize_t st_blksize;
/*   64      |     8 */    __blkcnt_t st_blocks;
/*   72      |    16 */    struct timespec {
/*   72      |     8 */        __time_t tv_sec;
/*   80      |     8 */        __syscall_slong_t tv_nsec;

                               /* total size (bytes):   16 */
                           } st_atim;
/*   88      |    16 */    struct timespec {
/*   88      |     8 */        __time_t tv_sec;
/*   96      |     8 */        __syscall_slong_t tv_nsec;

                               /* total size (bytes):   16 */
                           } st_mtim;
/*  104      |    16 */    struct timespec {
/*  104      |     8 */        __time_t tv_sec;
/*  112      |     8 */        __syscall_slong_t tv_nsec;

                               /* total size (bytes):   16 */
                           } st_ctim;
/*  120      |    24 */    __syscall_slong_t __glibc_reserved[3];

                           /* total size (bytes):  144 */
                         }

*/

pub fn stat(state: &mut State, args: &[Value]) -> Value {
    let path_addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let path_len = state.memory_strlen(&args[0], &Value::Concrete(4096, 0)); // idk
    let path = state.memory_read_string(path_addr, path_len.as_u64().unwrap() as usize);
    let statopt = state.filesystem.stat(&path);
    let statbuf = state.solver.evalcon_to_u64(&args[1]).unwrap();

    if let Some(statdata) = statopt {
        // oof this is just one case, any different bits, arch, or os could be different
        // this definitely sucks.
        state
            .memory
            .write_value(statbuf, &Value::Concrete(statdata.st_dev, 0), 8);
        state
            .memory
            .write_value(statbuf + 8, &Value::Concrete(statdata.st_ino, 0), 8);
        state.memory.write_value(
            statbuf + 16,
            &Value::Concrete(statdata.st_mode as u64, 0),
            8,
        );
        state.memory.write_value(
            statbuf + 24,
            &Value::Concrete(statdata.st_nlink as u64, 0),
            4,
        );
        state
            .memory
            .write_value(statbuf + 28, &Value::Concrete(statdata.st_uid as u64, 0), 4);
        state
            .memory
            .write_value(statbuf + 32, &Value::Concrete(statdata.st_gid as u64, 0), 4);
        state
            .memory
            .write_value(statbuf + 36, &Value::Concrete(statdata.__pad0 as u64, 0), 4);
        state
            .memory
            .write_value(statbuf + 40, &Value::Concrete(statdata.st_rdev, 0), 8);
        state.memory.write_value(
            statbuf + 48,
            &Value::Concrete(statdata.st_size as u64, 0),
            8,
        );
        state.memory.write_value(
            statbuf + 56,
            &Value::Concrete(statdata.st_blksize as u64, 0),
            8,
        );
        //state.memory.write_value(statbuf, &Value::Concrete(statdata.__pad2 as u64, 0), 4);
        state.memory.write_value(
            statbuf + 64,
            &Value::Concrete(statdata.st_blocks as u64, 0),
            8,
        );
        state
            .memory
            .write_value(statbuf + 72, &Value::Concrete(statdata.st_atime, 0), 8);
        state
            .memory
            .write_value(statbuf + 80, &Value::Concrete(statdata.st_atimensec, 0), 8);
        state
            .memory
            .write_value(statbuf + 88, &Value::Concrete(statdata.st_mtime, 0), 8);
        state
            .memory
            .write_value(statbuf + 96, &Value::Concrete(statdata.st_mtimensec, 0), 8);
        state
            .memory
            .write_value(statbuf + 104, &Value::Concrete(statdata.st_ctime, 0), 8);
        state
            .memory
            .write_value(statbuf + 112, &Value::Concrete(statdata.st_ctimensec, 0), 8);
        state.memory.write_value(
            statbuf + 120,
            &Value::Concrete(statdata.__glibc_reserved[0] as u64, 0),
            4,
        );
        state.memory.write_value(
            statbuf + 124,
            &Value::Concrete(statdata.__glibc_reserved[1] as u64, 0),
            4,
        );
        Value::Concrete(0, 0)
    } else {
        Value::Concrete(-1i64 as u64, 0)
    }
}

pub fn fstat(state: &mut State, args: &[Value]) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let path = state.filesystem.getpath(fd as usize);
    state.filesystem.stat(path.unwrap().as_str());
    Value::Concrete(0, 0)
}

// TODO handle symbolic links
pub fn lstat(state: &mut State, args: &[Value]) -> Value {
    stat(state, args)
}

pub fn lseek(state: &mut State, args: &[Value]) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let pos = state.solver.evalcon_to_u64(&args[1]).unwrap();
    state.filesystem.seek(fd as usize, pos as usize);
    Value::Concrete(pos, 0)
}

pub fn error(_state: &mut State, _args: &[Value]) -> Value {
    Value::Concrete(-1i64 as u64, 0)
}

// TODO success dummy
pub fn success(_state: &mut State, _args: &[Value]) -> Value {
    Value::Concrete(0, 0)
}

// TODO fd backed mem
pub fn mmap(state: &mut State, args: &[Value]) -> Value {
    // we can't do symbolic mmaps
    // this is beyond science
    let mut addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let size = state.solver.evalcon_to_u64(&args[1]).unwrap();
    let prot = state.solver.evalcon_to_u64(&args[2]).unwrap();

    if addr == 0 {
        addr = state.memory_alloc(&args[1]).as_u64().unwrap();
    }

    let perms = state.memory.prot_to_str(prot);
    state
        .memory
        .add_segment("mmapped", addr, size, perms.as_str());
    Value::Concrete(addr, 0)
}

pub fn munmap(state: &mut State, args: &[Value]) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();

    let mut ind = -1i32 as usize;
    for (i, seg) in state.memory.segs.iter().enumerate() {
        if seg.addr == addr {
            ind = i;
            break;
        }
    }

    if ind as i32 != -1 {
        state.memory.segs.remove(ind);
        Value::Concrete(0, 0)
    } else {
        Value::Concrete(-1i64 as u64, 0)
    }
}

pub fn brk(state: &mut State, args: &[Value]) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    Value::Concrete(state.memory.brk(addr), 0)
}

pub fn sbrk(state: &mut State, args: &[Value]) -> Value {
    let inc = state.solver.evalcon_to_u64(&args[0]).unwrap();
    Value::Concrete(state.memory.sbrk(inc), 0)
}

// returning a symbolic pid+1 | 0 | -1
// will result in a split state when used to branch
// essentially recreating a fork. pretty cool!
pub fn fork(state: &mut State, _args: &[Value]) -> Value {
    let cpid = state.pid + 1;
    state.pid = cpid;
    let pid = state.bv(format!("pid_{}", cpid).as_str(), 64);
    let a = pid
        ._eq(&state.bvv(cpid, 64))
        .or(&pid._eq(&state.bvv(0, 64)))
        .or(&pid._eq(&state.bvv(-1i64 as u64, 64)));

    state.solver.assert_bv(&a);
    Value::Symbolic(pid, 0)
}

pub fn getpid(state: &mut State, _args: &[Value]) -> Value {
    Value::Concrete(state.pid, 0)
}

pub fn getuid(_state: &mut State, _args: &[Value]) -> Value {
    Value::Concrete(0, 0)
}

pub fn ptrace(_state: &mut State, _args: &[Value]) -> Value {
    Value::Concrete(0, 0) // antidebug checks for -1
}

pub fn exit(state: &mut State, args: &[Value]) -> Value {
    state.status = StateStatus::Inactive;
    args[0].to_owned()
}
