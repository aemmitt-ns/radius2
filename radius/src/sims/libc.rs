use crate::value::Value;
use crate::state::State;
// use crate::sims::fs::FileMode;
use crate::sims::syscall;

const MAX_LEN: u64 = 8192;

// TODO everything that interacts with errno in any way
// I forget how errno works, i know its weird 

// now using sim fs
pub fn puts(state: &mut State, args: Vec<Value>) -> Value {
    let addr = &args[0];
    let length = strlen(state, vec!(addr.to_owned()));
    let mut data = state.memory_read(addr, &length);
    data.push(Value::Concrete('\n' as u64, 0)); // add newline
    //println!("{}", value);
    state.filesystem.write(1, data);
    length
}

// TODO you know, all this
pub fn printf(state: &mut State, args: Vec<Value>) -> Value {
    puts(state, args)
}

pub fn memmove(state: &mut State, args: Vec<Value>) -> Value {
    state.memory_move(&args[0], &args[1], &args[2]);
    args[0].to_owned()
}

pub fn memcpy(state: &mut State, args: Vec<Value>) -> Value {
    // TODO make actual memcpy that does overlaps right
    // how often do memcpys actually do that? next to never probably
    state.memory_move(&args[0], &args[1], &args[2]);
    args[0].to_owned()
}

pub fn bcopy(state: &mut State, args: Vec<Value>) -> Value {
    state.memory_move(&args[0], &args[1], &args[2]);
    Value::Concrete(0, 0)
}

pub fn bzero(state: &mut State, args: Vec<Value>) -> Value {
    memset(state, vec!(args[0].to_owned(), 
        Value::Concrete(0, 0), args[1].to_owned()));

    Value::Concrete(0, 0)
}

pub fn mempcpy(state: &mut State, args: Vec<Value>) -> Value {
    memcpy(state, args.clone()).add(&args[2])
}

pub fn memccpy(state: &mut State, args: Vec<Value>) -> Value {
    memcpy(state, args)
}

pub fn memfrob(state: &mut State, args: Vec<Value>) -> Value {
    //state.proc.parse_expression( // this is the fun way to do it
    //"0,A1,-,DUP,DUP,?{,A1,-,A0,+,DUP,[1],0x2a,^,SWAP,=[1],1,+,1,GOTO,}", state)
    let addr = &args[0];
    let num = &args[1];

    let x = Value::Concrete(0x2a, 0);
    let data = state.memory_read(&addr, &num);
    let mut new_data = vec!();
    for d in data {
        new_data.push(d.to_owned() ^ x.to_owned());
    }

    state.memory_write(addr, &new_data, &num);
    //state.mem_copy(addr, data, num)
    Value::Concrete(0, 0)
}

pub fn strlen(state: &mut State, args: Vec<Value>) -> Value {
    state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0))
}

pub fn strnlen(state: &mut State, args: Vec<Value>) -> Value {
    state.memory_strlen(&args[0], &args[1])
}

// TODO implement this with sim fs
pub fn gets(state: &mut State, args: Vec<Value>) -> Value {
    let bv = state.bv(format!("gets_{:?}", &args[0]).as_str(), 256*8);
    state.memory_write_value(&args[0], &Value::Symbolic(bv, 0), 256);
    args[0].to_owned()
}

// TODO this idk why don't you do it? huh?
pub fn fgets(_state: &mut State, args: Vec<Value>) -> Value {
    //let bv = state.bv(format!("fgets_{:?}", &args[0]).as_str(), 256*8);
    //state.memory.write_sym(&args[0], Value::Symbolic(bv), 256);
    args[0].to_owned()
}

pub fn strcpy(state: &mut State, args: Vec<Value>) -> Value {
    let length = state.memory_strlen(&args[1], &Value::Concrete(MAX_LEN, 0))
        +Value::Concrete(1, 0);
    state.memory_move(&args[0], &args[1], &length);
    args[0].to_owned()
}

pub fn stpcpy(state: &mut State, args: Vec<Value>) -> Value {
    let length = state.memory_strlen(&args[1], &Value::Concrete(MAX_LEN, 0));
    strcpy(state, args) + length
}

pub fn strdup(state: &mut State, args: Vec<Value>) -> Value {
    let length = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0))
        +Value::Concrete(1, 0);
    let new_addr = Value::Concrete(state.memory.alloc(&length), 0);
    state.memory_move(&new_addr, &args[0], &length);
    new_addr
}

pub fn strdupa(state: &mut State, args: Vec<Value>) -> Value {
    let length = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0))
        +Value::Concrete(1, 0);
    strdup(state, args) + length
}

// TODO for strn stuff I may need to add a null?
pub fn strndup(state: &mut State, args: Vec<Value>) -> Value {
    let length = state.memory_strlen(&args[0], &args[1]);
    let new_addr = Value::Concrete(state.memory.alloc(&length), 0);
    state.memory_move(&new_addr, &args[0], &length);
    new_addr
}

pub fn strndupa(state: &mut State, args: Vec<Value>) -> Value {
    let length = state.memory_strlen(&args[0], &args[1]);
    strndup(state, args) + length
}

pub fn strfry(_state: &mut State, args: Vec<Value>) -> Value {
    /*length, last = state.mem_search(addr, [BZERO])
    data = state.mem_read(addr, length)
    // random.shuffle(data) // i dont actually want to do this?
    state.mem_copy(addr, data, length)*/
    args[0].to_owned()
}

pub fn strncpy(state: &mut State, args: Vec<Value>) -> Value {
    let length = state.memory_strlen(&args[1], &args[2]);
    state.memory_move(&args[0], &args[1], &length);
    args[0].to_owned()
}

pub fn strcat(state: &mut State, args: Vec<Value>) -> Value {
    let length1 = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0));
    let length2 = state.memory_strlen(&args[1], &Value::Concrete(MAX_LEN, 0))+Value::Concrete(1, 0);
    state.memory_move(&(args[0].to_owned() + length1), &args[1], &length2);
    args[0].to_owned()
}

pub fn strncat(state: &mut State, args: Vec<Value>) -> Value {
    let length1 = state.memory_strlen(&args[0], &args[2]);
    let length2 = state.memory_strlen(&args[1], &args[2])+Value::Concrete(1, 0);
    state.memory_move(&(args[0].to_owned() + length1), &args[1], &length2);
    args[0].to_owned()
}

pub fn memset(state: &mut State, args: Vec<Value>) -> Value {
    let mut data = vec!();
    let length = state.solver.max_value(&args[2]);

    for _ in 0..length {
        data.push(args[1].to_owned());
    }

    state.memory_write(&args[0], &data, &args[2]);
    args[0].to_owned()
}

pub fn memchr_help(state: &mut State, args: Vec<Value>, reverse: bool) -> Value {
    state.memory_search(&args[0], &args[1], &args[2], reverse)
}

pub fn memchr(state: &mut State, args: Vec<Value>) -> Value {
    memchr_help(state, args, false)
}

pub fn memrchr(state: &mut State, args: Vec<Value>) -> Value {
    memchr_help(state, args, true)
}

pub fn strchr_help(state: &mut State, args: Vec<Value>, reverse: bool) -> Value {
    let length = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0));
    memchr_help(state, vec!(args[0].to_owned(), args[1].to_owned(), length), reverse)
}

pub fn strchr(state: &mut State, args: Vec<Value>) -> Value {
    strchr_help(state, args, false)
}

pub fn strrchr(state: &mut State, args: Vec<Value>) -> Value {
    strchr_help(state, args, true)
}

pub fn memcmp(state: &mut State, args: Vec<Value>) -> Value {
    state.memory_compare(&args[0], &args[1], &args[2])
}

pub fn strcmp(state: &mut State, args: Vec<Value>) -> Value {    
    let len1 = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0));
    let len2 = state.memory_strlen(&args[1], &Value::Concrete(MAX_LEN, 0));
    let length  = state.solver.conditional(&(len1.ult(&len2)), 
        &len1, &len2)+Value::Concrete(1, 0);

    state.memory_compare(&args[0], &args[1], &length)
}

pub fn strncmp(state: &mut State, args: Vec<Value>) -> Value {
    let len1 = state.memory_strlen(&args[0], &args[2]);
    let len2 = state.memory_strlen(&args[1], &args[2]);
    let length  = state.solver.conditional(&(len1.ult(&len2)), 
        &len1, &len2)+Value::Concrete(1, 0);

    state.memory_compare(&args[0], &args[1], &length)
}

// TODO properly handle sym slens
// idk if I will ever do this ^. it is super complicated
// and the performance would likely be shit anyway
pub fn memmem(state: &mut State, args: Vec<Value>) -> Value {
    let len = state.solver.evalcon_to_u64(&args[3]).unwrap() as usize;
    let mut needle_val = state.memory_read_value(&args[2], len);

    // necessary as concrete values will not search for end nulls
    needle_val = Value::Symbolic(state.solver.to_bv(&needle_val, 8*len as u32), needle_val.get_taint());
    memchr_help(state, vec!(args[0].to_owned(), needle_val, args[1].to_owned()), false)
}

pub fn strstr(state: &mut State, args: Vec<Value>) -> Value {
    let dlen = state.memory_strlen(&args[0], &Value::Concrete(MAX_LEN, 0));
    let slen = state.memory_strlen(&args[1], &Value::Concrete(MAX_LEN, 0));
    let len = state.solver.evalcon_to_u64(&slen).unwrap() as usize;
    let needle_val = state.memory_read_value(&args[0], len);
    memchr_help(state, vec!(args[0].to_owned(), needle_val, dlen), false)
}

pub fn malloc(state: &mut State, args: Vec<Value>) -> Value {
    Value::Concrete(state.memory.alloc(&args[0]), 0)
}

pub fn calloc(state: &mut State, args: Vec<Value>) -> Value {
    Value::Concrete(state.memory.alloc(&args[0].mul(&args[1])), 0)
}

pub fn free(state: &mut State, args: Vec<Value>) -> Value {
    state.memory.free(&args[0]);
    Value::Concrete(0, 0)
}

pub fn c_syscall(state: &mut State, args: Vec<Value>) -> Value {
    syscall::syscall("indirect_syscall", state, args)
}

// This is not going to be a real version of this func
// because otherwise all execution would have to take place 
// within this sim which would be weird and bad
pub fn __libc_start_main(state: &mut State, args: Vec<Value>) -> Value {
    let main = args[0].to_owned();
    let argc = args[1].to_owned();
    let argv = args[2].to_owned();

    // TODO go to init then main 
    // but we need a nice arch neutral way to push ret 
    // so until then 

    // go to main 
    state.registers.set_with_alias("PC", main);
    state.registers.set_with_alias("A0", argc);
    state.registers.set_with_alias("A1", argv);

    // TODO set env
    state.registers.set_with_alias("A2", Value::Concrete(0, 0));

    // uh in case we are overwriting A0
    args[1].to_owned()
}

/*
pub fn atoi_helper(state: &mut State, addr, size=SIZE): // still sucks
    string, length = state.symbolic_string(addr)

    if z3.is_bv_value(string):
        cstr = state.evaluate_string(string)
        return BV(int(cstr), size)
    else:
        length = state.evalcon(length).as_long() // unfortunate

        result = BV(0, size)
        is_neg = z3.BoolVal(False)
        m = BV(ord("-"), 8)
        for i in range(length):
            d = state.mem_read_bv(addr+i, 1)
            is_neg = z3.If(d == m, z3.BoolVal(True), is_neg)
            c = z3.If(d == m, BV(0, size), z3.ZeroExt(size-8, d-BV_0))
            result = result+(c*BV(10**(length-(i+1)), size))

        result = z3.If(is_neg, -result, result)
        return result

pub fn atoi(state: &mut State, addr):
    return atoi_helper(state: &mut State, addr, 32)

pub fn atol(state: &mut State, addr):
    return atoi_helper(state: &mut State, addr, state.bits)

pub fn atoll(state: &mut State, addr):
    return atoi_helper(state: &mut State, addr, 64)

pub fn digit_to_char(digit):
    if digit < 10:
        return str(digit)

    return chr(ord('a') + digit - 10)

pub fn str_base(number, base):
    if number < 0:
        return '-' + str_base(-number, base)

    (d, m) = divmod(number, base)
    if d > 0:
        return str_base(d, base) + digit_to_char(m)

    return digit_to_char(m)

pub fn bvpow(bv, ex):
    nbv = BV(1, 128)
    for i in range(ex):
        nbv = nbv*bv
    
    return z3.simplify(nbv)

pub fn itoa_helper(state: &mut State, value, string, base, sign=True):
    // ok so whats going on here is... uhh it works
    data = [BZERO]
    nvalue = z3.SignExt(96, z3.Extract(31, 0, value))
    pvalue = z3.ZeroExt(64, value)
    do_neg = z3.And(nvalue < 0, base == 10, z3.BoolVal(sign))
    base = z3.ZeroExt(64, base)
    new_value = z3.If(do_neg, -nvalue, pvalue)
    shift = BV(0, 128)
    for i in range(32):
        d = (new_value % bvpow(base, i+1)) / bvpow(base, i)
        c = z3.Extract(7, 0, d)
        shift = z3.If(c == BZERO, shift+BV(8, 128), BV(0, 128))
        data.append(z3.If(c < 10, c+BV_0, (c-10)+BV_a))

    pbv = z3.Concat(*data)
    szdiff = pbv.size()-shift.size()
    pbv = pbv >> z3.ZeroExt(szdiff, shift)
    nbv = z3.simplify(z3.Concat(pbv, BV(ord("-"),8)))
    pbv = z3.simplify(z3.Concat(BV(0,8), pbv)) // oof
    state.mem_write(string, z3.If(do_neg, nbv, pbv))
        
    return string

pub fn itoa(state: &mut State, value, string, base):
    return itoa_helper(state: &mut State, value, string, base)
*/

pub fn islower(_state: &mut State, args: Vec<Value>) -> Value {
    let c = args[0].slice(7, 0);
    c.ult(&Value::Concrete(0x7b, 0)) & !c.ult(&Value::Concrete(0x61, 0))
}

pub fn isupper(_state: &mut State, args: Vec<Value>) -> Value {
    let c = args[0].slice(7, 0);
    c.ult(&Value::Concrete(0x5b, 0)) & !c.ult(&Value::Concrete(0x41, 0))
}

pub fn isalpha(state: &mut State, args: Vec<Value>) -> Value {
    isupper(state, args.clone()) | islower(state, args)
}

pub fn isdigit(_state: &mut State, args: Vec<Value>) -> Value {
    let c = args[0].slice(7, 0);
    c.ult(&Value::Concrete(0x3a, 0)) & !c.ult(&Value::Concrete(0x30, 0))
}

pub fn isalnum(state: &mut State, args: Vec<Value>) -> Value {
    isalpha(state, args.clone()) | isdigit(state, args)
}

pub fn isblank(_state: &mut State, args: Vec<Value>) -> Value {
    let c = args[0].slice(7, 0);
    c.eq(&Value::Concrete(0x20, 0)) | c.eq(&Value::Concrete(0x09, 0))
}

pub fn iscntrl(_state: &mut State, args: Vec<Value>) -> Value {
    let c = args[0].slice(7, 0);
    (c.ugte(&Value::Concrete(0, 0)) & c.ulte(&Value::Concrete(0x1f, 0)))
        | c.eq(&Value::Concrete(0x7f, 0))
}

pub fn toupper(state: &mut State, args: Vec<Value>) -> Value {
    let islo = islower(state, args.clone());
    state.solver.conditional(&islo, 
        &(args[0].to_owned()-Value::Concrete(0x20, 0)), &args[0])
}

pub fn tolower(state: &mut State, args: Vec<Value>) -> Value {
    let isup = isupper(state, args.clone());
    state.solver.conditional(&isup, 
    &(args[0].to_owned()+Value::Concrete(0x20, 0)), &args[0])
}

pub fn zero(_state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
}

/*pub fn rand(state: &mut State, _args: Vec<Value>) -> Value {
    let mut rng = rand::thread_rng();
    let rn: u64 = rng.gen();
    Value::Symbolic(state.bv(format!("rand_{}", rn), 32))
}

pub fn srand(state: &mut State, _args: Vec<Value>) -> Value {
    //s = state.evaluate(s).as_long()
    //random.seed(s)
    Value::Concrete(1, 0)
}

pub fn abs(state: &mut State, args: Vec<Value>) -> Value {
    state.solver.conditional(i.sext(
        Value::Concrete(32)).slt(Value::Concrete(0, 0)), -i, i)
}

pub fn labs(state: &mut State, args: Vec<Value>) -> Value {
    state.solver.conditional(args[0].clone().slt(Value::Concrete(0, 0)), -args[0], i)
}

pub fn div(state: &mut State, args: Vec<Value>) -> Value {
    let nn = args[0].clone().slice(31, 0);
    let nd = args[1].clone().slice(31, 0);
    nn / nd
}

pub fn ldiv(state: &mut State, n: Value, d: Value) -> Value {
    n / d 
}
*/

pub fn fflush(_state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
}

pub fn getpid(state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(state.pid, 0)
}

pub fn fork(state: &mut State, args: Vec<Value>) -> Value {
    syscall::fork(state, args)
}

pub fn getpagesize(_state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(0x1000, 0)
}

pub fn gethostname(state: &mut State, args: Vec<Value>) -> Value {
    let len = state.solver.max_value(&args[1]);
    let bv = state.bv("hostname", 8*len as u32);
    let data = state.memory.unpack(&Value::Symbolic(bv, 0), len as usize);
    state.memory_write(&args[0], &data, &args[1]);
    Value::Concrete(0, 0)
}

/*
pub fn getenv(state: &mut State, addr):
    name, length = state.symbolic_string(addr)
    con_name = state.evaluate_string(name)
    data = state.os.getenv(con_name)

    if data == None:
        return 0
    else:
        val_addr = state.mem_alloc(len(data)+1)
        state.memory[val_addr] = data
        return val_addr
*/

pub fn sleep(_state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
}

/*
pub fn fileno(state: &mut State, f):
    // this isn't how its really done so ima leave this
    addr = state.evalcon(f).as_long()
    bv = state.memory[addr]
    return state.evalcon(bv).as_long()
*/

pub fn open(state: &mut State, args: Vec<Value>) -> Value {
    syscall::open(state, args)
}

/*
pub fn mode_to_int(mode):
    m = 0

    if "rw" in mode:
        m |= os.O_RDWR
    elif "r" in mode:
        m |= os.O_RDONLY
    elif "w" in mode:
        m |= os.O_WRONLY
    elif "a" in mode:
        m |= os.O_APPEND

    if "+" in mode:
        m |= os.O_CREAT

    return m


pub fn fopen(state: &mut State, path, mode):
    f = state.mem_alloc(8)
    mode = state.evaluate_string(state.symbolic_string(path)[0])
    flags = mode_to_int(mode)
    fd = open(state: &mut State, path, BV(flags), BV(0o777))
    state.memory[f] = fd
    return f
*/

pub fn close(state: &mut State, args: Vec<Value>) -> Value {
    syscall::close(state, args)
}

/*
pub fn fclose(state: &mut State, f):
    fd = fileno(state: &mut State, f)
    return close(state: &mut State, BV(fd))
*/

pub fn read(state: &mut State, args: Vec<Value>) -> Value {
    syscall::read(state, args)
}

/*
pub fn fread(state: &mut State, addr, sz, length, f):
    fd = fileno(state: &mut State, f)
    return read(state: &mut State, BV(fd), addr, sz*length)
*/

pub fn write(state: &mut State, args: Vec<Value>) -> Value {
    syscall::write(state, args)
}

/*
pub fn fwrite(state: &mut State, addr, sz, length, f):
    fd = fileno(state: &mut State, f)
    return write(state: &mut State, BV(fd), addr, sz*length)
*/

pub fn lseek(state: &mut State, args: Vec<Value>) -> Value {
    syscall::lseek(state, args)
}

pub fn access(state: &mut State, args: Vec<Value>) -> Value {
    syscall::access(state, args)
}

pub fn stat(state: &mut State, args: Vec<Value>) -> Value {
    syscall::stat(state, args)
}

pub fn fstat(state: &mut State, args: Vec<Value>) -> Value {
    syscall::fstat(state, args)
}

pub fn lstat(state: &mut State, args: Vec<Value>) -> Value {
    syscall::lstat(state, args)
}

pub fn exit(state: &mut State, args: Vec<Value>) -> Value {
    syscall::exit(state, args)
}
