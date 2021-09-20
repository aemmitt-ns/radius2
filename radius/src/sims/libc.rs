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
    state.memory_move(&args[0].add(&length1), &args[1], &length2);
    args[0].to_owned()
}

pub fn strncat(state: &mut State, args: Vec<Value>) -> Value {
    let length1 = state.memory_strlen(&args[0], &args[2]);
    let length2 = state.memory_strlen(&args[1], &args[2])+Value::Concrete(1, 0);
    state.memory_move(&args[0].add(&length1), &args[1], &length2);
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
type = struct _IO_FILE {
/*    0      |     4 */    int _flags;
/* XXX  4-byte hole  */
/*    8      |     8 */    char *_IO_read_ptr;
/*   16      |     8 */    char *_IO_read_end;
/*   24      |     8 */    char *_IO_read_base;
/*   32      |     8 */    char *_IO_write_base;
/*   40      |     8 */    char *_IO_write_ptr;
/*   48      |     8 */    char *_IO_write_end;
/*   56      |     8 */    char *_IO_buf_base;
/*   64      |     8 */    char *_IO_buf_end;
/*   72      |     8 */    char *_IO_save_base;
/*   80      |     8 */    char *_IO_backup_base;
/*   88      |     8 */    char *_IO_save_end;
/*   96      |     8 */    struct _IO_marker *_markers;
/*  104      |     8 */    struct _IO_FILE *_chain;
/*  112      |     4 */    int _fileno;
/*  116      |     4 */    int _flags2;
/*  120      |     8 */    __off_t _old_offset;
/*  128      |     2 */    unsigned short _cur_column;
/*  130      |     1 */    signed char _vtable_offset;
/*  131      |     1 */    char _shortbuf[1];
/* XXX  4-byte hole  */
/*  136      |     8 */    _IO_lock_t *_lock;
/*  144      |     8 */    __off64_t _offset;
/*  152      |     8 */    struct _IO_codecvt *_codecvt;
/*  160      |     8 */    struct _IO_wide_data *_wide_data;
/*  168      |     8 */    struct _IO_FILE *_freeres_list;
/*  176      |     8 */    void *_freeres_buf;
/*  184      |     8 */    size_t __pad5;
/*  192      |     4 */    int _mode;
/*  196      |    20 */    char _unused2[20];

                           /* total size (bytes):  216 */
                         }
*/

// beginning of shitty FILE function support

// _fileno offset from above linux x86_64
pub const FILENO_OFFSET: u64 = 112;

pub fn fileno(state: &mut State, args: Vec<Value>) -> Value {
    let fd_addr = args[0].add(&Value::Concrete(FILENO_OFFSET, 0));
    state.memory_read_value(&(fd_addr), 4) 
}

pub fn fopen(state: &mut State, args: Vec<Value>) -> Value {
    // we are reaching levels of shit code previously undreamt
    let fd = syscall::open(state, args.clone());
    let file_struct = state.memory.alloc(&Value::Concrete(216, 0));
    state.memory.write_value(file_struct+FILENO_OFFSET, &fd, 4);
    Value::Concrete(file_struct, 0)
}

pub fn fclose(state: &mut State, args: Vec<Value>) -> Value {
    let fd = fileno(state, args.clone());
    syscall::close(state, vec!(fd))
}

pub fn fread(state: &mut State, args: Vec<Value>) -> Value {
    let fd = fileno(state, args.clone());
    syscall::read(state, vec!(fd, args[1].to_owned(), args[2].to_owned()))
}

pub fn fwrite(state: &mut State, args: Vec<Value>) -> Value {
    let fd = fileno(state, args.clone());
    syscall::write(state, vec!(fd, args[1].to_owned(), args[2].to_owned()))
}

pub fn fseek(state: &mut State, args: Vec<Value>) -> Value {
    let fd = fileno(state, args.clone());
    syscall::lseek(state, vec!(fd, args[1].to_owned(), args[2].to_owned()))
}

/*
 * From SO
 * atoi reads digits from the buffer until it can't any more. It stops when it 
 * encounters any character that isn't a digit, except whitespace (which it skips)
 * or a '+' or a '-' before it has seen any digits (which it uses to select the 
 * appropriate sign for the result). It returns 0 if it saw no digits.
 */

 fn vc(n: u64) -> Value {
    Value::Concrete(n, 0)
 }

 // is digit
fn isdig(c: &Value) -> Value {
    c.ult(&Value::Concrete(0x3a, 0)) & !c.ult(&Value::Concrete(0x30, 0))
}

// is whitespace
fn _isws(c: &Value) -> Value {
    c.eq(&Value::Concrete(0x09, 0)) | 
    c.eq(&Value::Concrete(0x20, 0)) | 
    c.eq(&Value::Concrete(0x0d, 0)) | 
    c.eq(&Value::Concrete(0x0a, 0))
}

fn bv_pow(bv: &Value, exp: u32) -> Value {
    let mut result = vc(1);
    for _ in 0..exp {
        result = result * bv.clone();
    }
    result
}

// is valid digit of base
fn isbasedigit(state: &State, c: &Value, base: &Value) -> Value {
    state.solver.conditional(
        &base.ult(&vc(11)),
        &(c.ult(&(vc('0' as u64)+base.clone())) & !c.ult(&vc('0' as u64))),
        &(isdig(c) | (c.ult(&(vc('a' as u64)+base.sub(&vc(10)))) & !c.ult(&vc('a' as u64))) |
        (c.ult(&(vc('A' as u64)+base.sub(&vc(10)))) & !c.ult(&vc('A' as u64)))))
}

fn tonum(state: &State, c: &Value) -> Value {
    let alpha = state.solver.conditional(
        &c.ulte(&vc('Z' as u64)),
        &c.sub(&vc('A' as u64 - 10)),
        &c.sub(&vc('a' as u64 - 10))
    );

    state.solver.conditional(
        &c.ulte(&vc('9' as u64)),
        &c.sub(&vc('0' as u64)),
        &alpha
    )
}

fn atoi_concrete(state: &mut State, addr: &Value, base: &Value, len: usize) -> Value {
    let numstr = state.memory_read_string(addr.as_u64().unwrap(), len);
    let numstr = numstr.trim_start(); // trim whitespace

    let start = if &numstr[0..2] == "0x" { 2 } else { 0 }; // offset
    // oof this is rough, atoi / strtol stop at first nondigit, from_str_radix gives 0
    let end = if let Some(n) = numstr[start+1..].chars().position(|c| isbasedigit(
        state, &vc(c as u64), base).as_u64().unwrap() != 1) { start+n+1 } else { len }; // oof

    let numopt = u64::from_str_radix(&numstr[start..end], base.as_u64().unwrap() as u32);
    return if let Ok(n) = numopt { vc(n) } else { vc(0) };
}

// for now and maybe forever this only works for strings that 
// don't have garbage in them. so only strings with digits or +/- 
pub fn atoi_helper(state: &mut State, addr: &Value, base: &Value) -> Value {
    let length = state.memory_strlen(&addr, &Value::Concrete(64, 0)); 
    let data = state.memory_read(&addr, &length);
    let len = data.len();

    state.assert_value(&length.eq(&vc(len as u64)));
    if len == 0 {
        return Value::Concrete(0, 0);
    }

    // gonna take the easy way out and special case out all concrete
    if addr.is_concrete() && base.is_concrete() 
        && data.iter().all(|x| x.is_concrete()) {
        return atoi_concrete(state, addr, base, len);
    }

    let mut result = Value::Concrete(0, 0);

    // multiplier for negative nums
    let neg_mul = state.solver.conditional(
        &data[0].eq(&vc('-' as u64)),
        &Value::Concrete(-1i64 as u64, 0),
        &Value::Concrete(1, 0));

    for (i, d) in data.iter().enumerate() {
        let dx = d.uext(&vc(8)); 
        let exp = (len-i-1) as u32;

        // digit or + / - 
        let cond = if i == 0 {
            isbasedigit(state, &dx, base) | 
            dx.eq(&vc('-' as u64)) | dx.eq(&vc('+' as u64))
        } else {
            isbasedigit(state, &dx, base)
        };
        state.assert_value(&cond);

        // add d*10**n to result
        result = result + state.solver.conditional(
            &!isbasedigit(state, &dx, base), &vc(0),
            &(bv_pow(base, exp) * tonum(state, &dx))
        );
    }
    result * neg_mul
}

pub fn atoi(state: &mut State, args: Vec<Value>) -> Value {
    atoi_helper(state, &args[0], &vc(10)).slice(31, 0)
}

pub fn atol(state: &mut State, args: Vec<Value>) -> Value {
    let bits = state.memory.bits;
    atoi_helper(state, &args[0], &vc(10)).slice(bits-1, 0)
}

pub fn atoll(state: &mut State, args: Vec<Value>) -> Value {
    atoi_helper(state, &args[0], &vc(10))
}

pub fn strtoll(state: &mut State, args: Vec<Value>) -> Value {
    // not perfect but idk
    if let Value::Concrete(addr, _) = args[1] {
        if addr != 0 {
            let length = state.memory_strlen(&args[0], &Value::Concrete(64, 0)); 
            state.memory_write_value(&args[1], &args[0].add(&length), 
                state.memory.bits as usize / 8);
        }
    }

    atoi_helper(state, &args[0], &args[2])
}

pub fn strtod(state: &mut State, args: Vec<Value>) -> Value {
    strtoll(state, args).slice(31, 0)
}

pub fn strtol(state: &mut State, args: Vec<Value>) -> Value {
    let bits = state.memory.bits;
    strtoll(state, args).slice(bits-1, 0)
}

pub fn itoa_helper(state: &mut State, value: &Value, 
    string: &Value, base: &Value, sign: bool, size: usize) -> Value {

    let mut data = vec!();

    // condition to add a minus sign -
    let neg_cond = &(value.slt(&vc(0)) & base.eq(&vc(10)) & vc(sign as u64));

    let uval = state.solver.conditional(
        &neg_cond, &value.mul(&vc(-1i64 as u64)), &value);

    let uval = Value::Symbolic(state.solver.to_bv(&uval, 128), 0); 
    let ubase = Value::Symbolic(state.solver.to_bv(&base, 128), 0); 
    let mut shift = Value::Symbolic(state.solver.bvv(0, 64), 0); 

    for i in 0..size as u32 {
        let dx = uval.rem(&bv_pow(&ubase, i+1)).div(&bv_pow(&ubase, i));

        // shift that will be applied to remove 00000...
        shift = state.solver.conditional(
            &!dx.clone(), &shift.add(&vc(8)), &vc(0));

        data.push(state.solver.conditional(
            &dx.ult(&vc(10)),
            &dx.add(&vc('0' as u64)),
            &dx.sub(&vc(10)).add(&vc('a' as u64))
        ));
    }

    data.reverse();

    let bv = state.memory.pack(&data).as_bv().unwrap();
    let shift_bits = 31 - bv.get_width().leading_zeros(); // log2(n)
    let bv = bv.srl(&shift.as_bv().unwrap().slice(shift_bits-1, 0));
    let mut new_addr = string.clone();

    if sign { 
        let b = state.solver.conditional(
            &neg_cond, &vc('-' as u64), &vc('+' as u64));
        
        state.memory_write_value(&string, &b, 1);

        // if we add a minus, write number to addr+1 
        new_addr = state.solver.conditional(
            &neg_cond, &(new_addr.clone()+vc(1)), &new_addr);
    }
    state.memory_write_value(&new_addr, &Value::Symbolic(bv,0), data.len());

    string.to_owned()
}

pub fn itoa(state: &mut State, args: Vec<Value>) -> Value {
    itoa_helper(state, &args[0], &args[1], &args[2], true, 32)
}

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

pub fn rand(state: &mut State, _args: Vec<Value>) -> Value {
    state.symbolic_value("rand", 32)
}

pub fn srand(_state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
}

pub fn fflush(_state: &mut State, _args: Vec<Value>) -> Value {
    Value::Concrete(0, 0)
}

pub fn getpid(state: &mut State, args: Vec<Value>) -> Value {
    syscall::getpid(state, args)
}

pub fn getuid(state: &mut State, args: Vec<Value>) -> Value {
    syscall::getuid(state, args)
}

pub fn getgid(state: &mut State, args: Vec<Value>) -> Value {
    syscall::getuid(state, args)
}

pub fn geteuid(state: &mut State, args: Vec<Value>) -> Value {
    syscall::getuid(state, args)
}

pub fn getegid(state: &mut State, args: Vec<Value>) -> Value {
    syscall::getuid(state, args)
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

pub fn open(state: &mut State, args: Vec<Value>) -> Value {
    syscall::open(state, args)
}

pub fn close(state: &mut State, args: Vec<Value>) -> Value {
    syscall::close(state, args)
}

pub fn read(state: &mut State, args: Vec<Value>) -> Value {
    syscall::read(state, args)
}

pub fn write(state: &mut State, args: Vec<Value>) -> Value {
    syscall::write(state, args)
}

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
