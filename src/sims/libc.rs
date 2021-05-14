use crate::value::Value;
use crate::state::State;
use rand::Rng;

pub fn puts(state: &mut State, addr: Value) -> Value {
    let length = strlen(state, addr.clone());
    let minlen = state.solver.min_value(length) as usize;
    let value = state.memory.read_string(addr, minlen);
    println!("{}", value);
    Value::Concrete(value.len() as u64)
}

pub fn printf(state: &mut State, addr: Value, a1, a2, a3, a4, a5, a6, a7) -> Value {
    puts(state, addr)
}

const MAX_LEN: u64 = 9192;

pub fn memmove(state: &mut State, dst: Value, src: Value, num: Value) -> Value {
    state.memory.memmove(&dst, &src, &num);
    dst
}

pub fn memcpy(state: &mut State, dst: Value, src: Value, num: Value) -> Value {
    // TODO make actual memcpy that does overlaps right
    // how often do memcpys actually do that? next to never probably
    state.memory.memmove(&dst, &src, &num);
    dst
}

pub fn bcopy(state: &mut State, src: Value, dst: Value, num: Value) -> Value {
    state.memory.memmove(&dst, &src, &num);
    Value::Concrete(0)
}

pub fn bzero(state: &mut State, dst: Value, num: Value) -> Value {
    memset(state, dst, Value::Concrete(0), num);
    Value::Concrete(0)
}

pub fn mempcpy(state: &mut State, dst: Value, src: Value, num: Value) -> Value {
    memcpy(state, dst, src, num.clone()) + num
}

pub fn memccpy(state: &mut State, dst: Value, src: Value, ch: Value, num: Value) -> Value {
    c = z3.Extract(7, 0, ch)
    length, last = state.mem_search(src, [c], num)
    newlen = z3.If(length < num, length, num)
    result = mempcpy(state: &mut State, dst, src, newlen)
    return z3.If(length == state.memory.error, ZERO, result)
}

pub fn memfrob(state: &mut State, addr: Value, num: Value) -> Value {
    //state.proc.parse_expression( // this is the fun way to do it
    //"0,A1,-,DUP,DUP,?{,A1,-,A0,+,DUP,[1],0x2a,^,SWAP,=[1],1,+,1,GOTO,}", state)

    let x = Value::Concrete(0x2a);
    let data = state.memory.read_sym_len(&addr, &num);
    let new_data = vec!();
    for d in data {
        new_data.push(d.clone() ^ x.clone());
    }

    state.memory.write_sym_len(addr, new_data, &num);
    //state.mem_copy(addr, data, num)
    Value::Concrete(0)
}

pub fn strlen(state: &mut State, addr: Value) -> Value {
    state.memory.strlen(&src, &Value::Concrete(MAX_LEN))
}

pub fn strnlen(state: &mut State, addr: Value, n: Value) -> Value {
    state.memory.strlen(&src, &n)
}

/*pub fn gets(state: &mut State, addr: Value): // just a maybe useful default
    length = state.fs.stdin_chunk
    read(state: &mut State, STDIN, addr, length)
    return addr

pub fn fgets(state: &mut State, addr: Value, length: Value, f: Value):
    fd = fileno(state: &mut State, f)
    read(state: &mut State, BV(fd), addr, length)
    return addr*/

pub fn strcpy(state: &mut State, dst: Value, src: Value) -> Value {
    let length = state.memory.strlen(&src, &Value::Concrete(MAX_LEN));
    state.memory.memmove(&dst, &src, &length);
    dst
}

pub fn stpcpy(state: &mut State, dst: Value, src: Value) -> Value {
    let length = state.memory.strlen(&src, &Value::Concrete(MAX_LEN));
    strcpy(state, dst, src) + length
}

pub fn strdup(state: &mut State, addr: Value) -> Value {
    let length = state.memory.strlen(&addr, &Value::Concrete(MAX_LEN));
    let new_addr = Value::Concrete(malloc(state, length));
    state.memory.memmove(new_addr.clone(), addr, length);
    new_addr
}

pub fn strdupa(state: &mut State, addr: Value) -> Value {
    let length = state.memory.strlen(&addr, &Value::Concrete(MAX_LEN));
    strdup(state, addr) + length
}

pub fn strndup(state: &mut State, addr: Value, num: Value) -> Value {
    let length = state.memory.strlen(&addr, &num);
    let new_addr = Value::Concrete(malloc(state, length));
    state.memory.memmove(new_addr.clone(), addr, length);
    new_addr
}

pub fn strndupa(state: &mut State, addr: Value, num: Value) -> Value {
    let length = state.memory.strlen(&addr, &num);
    strndup(state, addr, num) + length
}

pub fn strfry(state: &mut State, addr: Value) -> Value {
    /*length, last = state.mem_search(addr, [BZERO])
    data = state.mem_read(addr, length)
    // random.shuffle(data) // i dont actually want to do this?
    state.mem_copy(addr, data, length)*/
    addr
}

pub fn strncpy(state: &mut State, dst: Value, src: Value, num: Value) -> Value {
    let length = state.memory.strlen(&src, &num);
    state.memory.memmove(&dst, &src, &length);
    dst
}

pub fn strcat(state: &mut State, dst: Value, src: Value) -> Value {
    let length1 = state.memory.strlen(&dst, &Value::Concrete(MAX_LEN));
    let length2 = state.memory.strlen(&src, &Value::Concrete(MAX_LEN));
    state.memory.memmove(&(dst.clone() + length1), &src, &length2);
    dst
}

pub fn strncat(state: &mut State, dst: Value, src: Value, num: Value) -> Value {
    let length1 = state.memory.strlen(&dst, &num);
    let length2 = state.memory.strlen(&src, &num);
    state.memory.memmove(&(dst.clone() + length1), &src, &length2);
    dst
}
 
pub fn memset(state: &mut State, dst: Value, ch: Value, num: Value) -> Value {
    let data = vec!();
    let length = state.solver.max_value(&num);

    for _ in 0..length {
        data.push(ch.clone());
    }

    state.memory.write_sym_len(&dst, data, &num);
    dst
}

pub fn memchr_help(state: &mut State, dst: Value, ch: Value, num: Value, reverse: bool) -> Value {
    state.memory.search(&dst, &ch, &num, reverse)
}

pub fn memchr(state: &mut State, dst: Value, ch: Value, num: Value) -> Value {
    memchr_help(state, dst, ch, num, false)
}

pub fn memrchr(state: &mut State, dst: Value, ch: Value, num: Value) -> Value {
    memchr_help(state, dst, ch, num, true)
}

pub fn strchr_help(state: &mut State, dst: Value, ch: Value, reverse: bool) -> Value {
    let length = state.memory.strlen(&dst, &Value::Concrete(MAX_LEN));
    memchr_help(state, dst, ch, length, reverse)
}

pub fn strchr(state: &mut State, dst: Value, ch: Value) -> Value {
    strchr_help(state: &mut State, dst, ch, false)
}

pub fn strrchr(state: &mut State, dst: Value, ch: Value) -> Value {
    strchr_help(state: &mut State, dst, ch, true)
}

pub fn memcmp(state: &mut State, dst: Value, src: Value, num: Value) -> Value {
    state.memory.compare(&dst, &src, &num)
}

pub fn strcmp(state: &mut State, dst: Value, src: Value) -> Value {
    let length = state.memory.strlen(&dst, &Value::Concrete(MAX_LEN));
    state.memory.compare(&dst, &src, &length)
}

pub fn strncmp(state: &mut State, dst: Value, src: Value, num: Value) -> Value {
    let length = state.memory.strlen(&dst, &num);
    state.memory.compare(&dst, &src, &length)
}

// TODO properly handle sym slens
pub fn memmem(state: &mut State, addr: Value, dlen: Value, needle: Value, slen: Value) -> Value {
    let len = state.solver.min_value(&slen) as usize;
    let needle_val = state.memory.read_sym(&needle, len);
    memchr_help(state, addr, needle_val, dlen, false)
}

pub fn strstr(state: &mut State, addr: Value, needle: Value) -> Value {
    let dlen = state.memory.strlen(&addr, &Value::Concrete(MAX_LEN))
    let slen = state.memory.strlen(&needle, &Value::Concrete(MAX_LEN));
    let len = state.solver.min_value(&slen) as usize;
    let needle_val = state.memory.read_sym(&needle, len);
    memchr_help(state, addr, needle_val, dlen, false)
}

pub fn malloc(state: &mut State, length: Value) -> Value {
    Value::Concrete(state.memory.alloc(length))
}

pub fn calloc(state: &mut State, n: Value, sz: Value) -> Value {
    Value::Concrete(state.memory.alloc(n*sz))
}

pub fn free(state: &mut State, addr: Value) -> Value {
    state.memory.free(addr);
    Value::Concrete(0)
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
pub fn islower(state: &mut State, ch: Value) -> Value {
    let c = ch.slice(7, 0);
    c.clone().ult(Value::Concrete(0x7b)) & !c.ult(Value::Concrete(0x61))
}

pub fn isupper(state: &mut State, ch: Value) -> Value {
    let c = ch.slice(7, 0);
    c.clone().ult(Value::Concrete(0x5b)) & !c.ult(Value::Concrete(0x41))
}

pub fn isalpha(state: &mut State, ch: Value) -> Value {
    isupper(state, ch.clone()) | islower(state, ch)
}

pub fn isdigit(state: &mut State, ch: Value) -> Value {
    let c = ch.slice(7, 0);
    c.clone().ult(Value::Concrete(0x3a)) & !c.ult(Value::Concrete(0x30))
}

pub fn isalnum(state: &mut State, ch: Value) -> Value {
    isalpha(state, ch.clone()) | isdigit(state, ch)
}

pub fn isblank(state: &mut State, ch: Value) -> Value {
    let c = ch.slice(7, 0);
    c.eq(Value::Concrete(0x20)) | c.eq(Value::Concrete(0x09))
}

pub fn iscntrl(state: &mut State, ch: Value) -> Value {
    let c = ch.slice(7, 0);
    (c.ugte(Value::Concrete(0)) & c.ulte(Value::Concrete(0x1f)))
        | c.eq(Value::Concrete(0x7f))
}

pub fn toupper(state: &mut State, ch: Value) -> Value {
    state.solver.conditional(islower(state, ch.clone()), 
        ch.clone()-Value::Concrete(0x20), ch)
}

pub fn tolower(state: &mut State, ch) -> Value {
    state.solver.conditional(isupper(state, ch.clone()), 
        ch.clone()+Value::Concrete(0x20), ch)
}

pub fn rand(state: &mut State) -> Value {
    let mut rng = rand::thread_rng();
    let rn: u64 = rng.gen();
    Value::Symbolic(state.bv(format!("rand_{}", rn), 32))
}

pub fn srand(state: &mut State, s: Value) -> Value {
    //s = state.evaluate(s).as_long()
    //random.seed(s)
    Value::Concrete(1)
}

pub fn abs(state: &mut State, i: Value) -> Value {
    state.solver.conditional(i.sext(
        Value::Concrete(32)).slt(Value::Concrete(0)), -i, i)
}

pub fn labs(state: &mut State, i: Value) -> Value {
    state.solver.conditional(i.slt(Value::Concrete(0)), -i, i)
}

pub fn div(state: &mut State, n: Value, d: Value) -> Value {
    let nn = n.slice(31, 0);
    let nd = d.slice(31, 0);
    nn / nd
}

pub fn ldiv(state: &mut State, n: Value, d: Value) -> Value {
    n / d 
}

/*
pub fn fflush(state: &mut State, f):
    sys.stdout.flush()
    return 0

pub fn getpid(state):
    return state.pid

pub fn fork(state):
    if state.fork_mode ==  "child":
        state.pid += 1
        return 0
    else:
        return state.pid+1

pub fn getpagesize(state):
    return 0x1000 //idk

pub fn gethostname(state: &mut State, addr, size):
    size = state.evalcon(size).as_long()
    hostname = socket.gethostname()
    state.mem_write(addr, hostname[:size])
    return 0

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

pub fn sleep(state: &mut State, secs: Value) -> Value {
    Value::Concrete(0)
}

/*
pub fn fileno(state: &mut State, f):
    // this isn't how its really done so ima leave this
    addr = state.evalcon(f).as_long()
    bv = state.memory[addr]
    return state.evalcon(bv).as_long()

pub fn open(state: &mut State, path, flags, mode):
    path = state.symbolic_string(path)[0]
    path_str = state.evaluate_string(path)
    flags = state.evalcon(flags).as_long()
    mode = state.evalcon(mode).as_long()
    return state.fs.open(path_str, flags, mode)

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

pub fn close(state: &mut State, fd):
    fd = state.evalcon(fd).as_long()
    return state.fs.close(fd)

pub fn fclose(state: &mut State, f):
    fd = fileno(state: &mut State, f)
    return close(state: &mut State, BV(fd))

pub fn read(state: &mut State, fd, addr, length):
    fd = state.evalcon(fd).as_long()
    //length = state.evalcon(length).as_long()
    length = z3.simplify(length)

    if z3.is_bv_value(length):
        rlen = length.as_long()
    else:
        rlen = len(state.mem_read(addr, length)) // hax

    data = state.fs.read(fd, rlen)
    dlen = BV(len(data))
    state.mem_copy(addr, data, length)
    return z3.If(dlen < length, dlen, length)

pub fn fread(state: &mut State, addr, sz, length, f):
    fd = fileno(state: &mut State, f)
    return read(state: &mut State, BV(fd), addr, sz*length)

pub fn write(state: &mut State, fd, addr, length):
    fd = state.evalcon(fd).as_long()
    length = state.evalcon(length).as_long()
    data = state.mem_read(addr, length)
    return state.fs.write(fd, data)

pub fn fwrite(state: &mut State, addr, sz, length, f):
    fd = fileno(state: &mut State, f)
    return write(state: &mut State, BV(fd), addr, sz*length)

pub fn lseek(state: &mut State, fd, offset, whence):
    fd = state.evalcon(fd).as_long()
    offset = state.evalcon(offset).as_long()
    whence = state.evalcon(whence).as_long()
    return state.fs.seek(fd, offset, whence)

pub fn fseek(state: &mut State, f, offset, whence):
    fd = fileno(state: &mut State, f)
    return lseek(state: &mut State, BV(fd), offset, whence)

pub fn access(state: &mut State, path, flag): // TODO: complete this
    path = state.symbolic_string(path)[0]
    path = state.evaluate_string(path)
    return state.fs.exists(path)

pub fn stat(state: &mut State, path, data): // TODO: complete this
    path = state.symbolic_string(path)[0]
    path = state.evaluate_string(path)
    return state.fs.exists(path)

pub fn system(state: &mut State, cmd):
    string, length = state.symbolic_string(cmd)
    logger.warning("system(%s)" % state.evaluate_string(string)) // idk
    return 0

pub fn abort(state):
    logger.info("process aborted")
    state.exit = 0
    return 0

pub fn simexit(state: &mut State, status):
    logger.info("process exited")
    state.exit = status
    return 0

pub fn print_stdout(s: str):
    try:
        from colorama import Fore, Style
        sys.stdout.write(Fore.YELLOW+s+Style.RESET_ALL)
    except:
        sys.stdout.write(s)

pub fn nothin(state):
    return 0
    
pub fn ret_one(state):
    return 1

pub fn ret_negone(state):
    return BV(-1)

pub fn ret_arg1(state: &mut State, a):
    return a

pub fn ret_arg2(state: &mut State, a, b):
    return b

pub fn ret_arg3(state: &mut State, a, b, c):
    return c

pub fn ret_arg4(state: &mut State, a, b, c, d):
    return d

UINT = 0
SINT = 1
FLOAT = 2
PTR = 3

pub fn ieee_to_float(endian, v, size=64):
    e = "<"
    if endian == "big":
        e = ">"

    o = e+"d"
    i = e+"Q"
    if size == 32:
        o = e+"f"
        i = e+"I"

    return unpack(o, pack(i, v))[0]

pub fn convert_arg(state: &mut State, arg, typ, size, base):

    szdiff = size-arg.size()

    if szdiff > 0:
        if typ == SINT:
            arg = z3.SignExt(szdiff, arg)
        else:
            arg = z3.ZeroExt(szdiff, arg)
    elif szdiff < 0:
        arg = z3.Extract(size-1, 0, arg)

    arg = state.evalcon(arg)
    if typ == UINT:
        return arg.as_long()
    elif typ == SINT:
        return arg.as_signed_long()
    elif typ == FLOAT:
        argl = arg.as_long()
        return ieee_to_float(state.endian, argl, size)
    else:
        addr = arg.as_long()
        string = state.symbolic_string(addr)[0]
        return state.evaluate_string(string)

// this sucks 
pub fn format_writer(state: &mut State, fmt, vargs):
    fmts = {
        "c":   ["c",  UINT,  8, 10],
        "d":   ["d",  SINT,  32, 10],
        "i":   ["i",  SINT,  32, 10],
        "u":   ["u",  UINT,  32, 10],
        "e":   ["e",  FLOAT, 64, 10],
        "E":   ["E",  FLOAT, 64, 10],
        "f":   ["f",  FLOAT, 32, 10],
        "lf":  ["lf", FLOAT, 64, 10],
        "Lf":  ["Lf", FLOAT, 64, 10],
        "g":   ["g",  FLOAT, 64, 10],
        "G":   ["G",  FLOAT, 64, 10],
        "hi":  ["hi", SINT,  16, 10],
        "hu":  ["hu", UINT,  16, 10],
        "lu":  ["lu", UINT,  state.bits, 10],
        "ld":  ["ld", SINT,  state.bits, 10],
        "li":  ["li", SINT,  state.bits, 10],
        "p":   ["x",  UINT,  state.bits, 16],
        "llu": ["lu", UINT,  64, 10],
        "lld": ["ld", SINT,  64, 10],
        "lli": ["li", SINT,  64, 10],
        "x":   ["x",  UINT,  32, 16],
        "hx":  ["x",  UINT,  16, 16],
        "lx":  ["x",  UINT,  state.bits, 16],
        "llx": ["x",  UINT,  64, 16],
        "o":   ["o",  UINT,  32, 8],
        "s":   ["s",  PTR,   state.bits, 10],
        //"n":   ["",  PTR,   state.bits, 10],
    }

    '''if fmt.count("%") == 1:
        r_str = ""
        p_ind = fmt.index("%")

        i = p_ind+1
        shiftstr = ""
        while not fmt[i].isalpha():
            shiftstr += fmt[i]
            i += 1'''

    new_args = []
    new_fmt = ""

    ind = 0
    argc = 0
    while ind < len(fmt):
        new_fmt += fmt[ind]
        if fmt[ind] != "%":  
            ind += 1
        else:  
            ind += 1
            nextc = fmt[ind:ind+1]
            if nextc == "%":
                new_fmt += nextc

            else:
                arg = vargs[argc]
                argc += 1

                while not nextc.isalpha():
                    new_fmt += nextc
                    ind += 1
                    nextc = fmt[ind:ind+1]
                
                next3fmt = fmt[ind:ind+3]
                next2fmt = fmt[ind:ind+2]
                next1fmt = fmt[ind:ind+1]

                if next3fmt in fmts:
                    rep, typ, sz, base = fmts[next3fmt]
                    new_args += [convert_arg(state: &mut State, arg, typ, sz, base)]
                    new_fmt += rep
                    ind += 3

                elif next2fmt in fmts:
                    rep, typ, sz, base = fmts[next2fmt]
                    new_args += [convert_arg(state: &mut State, arg, typ, sz, base)]
                    new_fmt += rep
                    ind += 2

                elif next1fmt in fmts:
                    rep, typ, sz, base = fmts[next1fmt]
                    new_args += [convert_arg(state: &mut State, arg, typ, sz, base)]
                    new_fmt += rep
                    ind += 1
                
                elif next1fmt == "n":
                    lastind = len(new_fmt)-new_fmt[::-1].index("%")-1
                    n = len(new_fmt[:lastind]%tuple(new_args))
                    state.mem_write(arg, n)

    return new_fmt % tuple(new_args)

*/