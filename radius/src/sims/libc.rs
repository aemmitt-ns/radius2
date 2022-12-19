use crate::sims::format;
use crate::sims::syscall;
use crate::state::State;
use crate::value::{vc, Value};
use rand::Rng;

const MAX_LEN: u64 = 8192;

// TODO everything that interacts with errno in any way

// now using sim fs
pub fn puts(state: &mut State, args: &[Value]) -> Value {
    put_helper(state, args, true)
}

fn put_helper(state: &mut State, args: &[Value], nl: bool) -> Value {
    let addr = &args[0];
    let length = strlen(state, &args[0..1]);
    let mut data = state.memory_read(addr, &length);
    if nl {
        data.push(vc('\n' as u64))
    } // add newline
    state.filesystem.write(1, data);
    length
}

pub fn putchar(state: &mut State, args: &[Value]) -> Value {
    let c = args[0].slice(7, 0);
    state.filesystem.write(1, vec![c.clone()]);
    c
}

fn readline(state: &mut State, args: &[Value]) -> Value {
    let fd = state.solver.evalcon_to_u64(&args[0]).unwrap_or(0) as usize;
    let mut p = args[1].to_owned();

    loop {
        let c = state
            .filesystem
            .read(fd, 1)
            .get(0)
            .unwrap_or(&vc(-1i64 as u64))
            .to_owned();

        if c.as_u64() != Some(-1i64 as u64) {
            // uhhh idk we cant do symbolic file pos yet so
            // this is where we are at
            if c.as_u64() == Some('\n' as u64) {
                break;
            } else if c.is_symbolic() {
                state.assert(&!c.eq(&vc('\n' as u64)));
            }
            state.memory_write_value(&p, &c, 1);
            p = p + vc(1);
        } else {
            break;
        }
    }
    state.memory_write_value(&p, &vc(0), 1);
    args[1].to_owned()
}

pub fn getchar(state: &mut State, _args: &[Value]) -> Value {
    state
        .filesystem
        .read(0, 1)
        .get(0)
        .unwrap_or(&vc(-1i64 as u64))
        .to_owned()
}

pub fn fprintf(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &args[0..1]);
    let fdn = state.solver.evalcon_to_u64(&fd).unwrap_or(1);
    let formatted = format::format(state, args);
    let ret = vc(formatted.len() as u64);
    state.filesystem.write(fdn as usize, formatted);
    ret
}

pub fn sprintf(state: &mut State, args: &[Value]) -> Value {
    let formatted = format::format(state, &args[1..]);
    let ret = vc(formatted.len() as u64);
    state.memory_write(&args[0], &formatted, &vc(formatted.len() as u64));
    ret
}

pub fn printf(state: &mut State, args: &[Value]) -> Value {
    let formatted = format::format(state, args);
    let ret = vc(formatted.len() as u64);
    state.filesystem.write(1, formatted);
    ret
}

pub fn scanf(state: &mut State, args: &[Value]) -> Value {
    let buf = state.memory_alloc(&vc(MAX_LEN));
    gets(state, &[buf.clone()]);
    let result = format::scan(state, &[&[buf.clone()], args].concat());
    state.memory_free(&buf);
    result
}

pub fn sscanf(state: &mut State, args: &[Value]) -> Value {
    format::scan(state, args)
}

pub fn memmove(state: &mut State, args: &[Value]) -> Value {
    state.memory_move(&args[0], &args[1], &args[2].slice(31, 0));
    args[0].to_owned()
}

pub fn memcpy(state: &mut State, args: &[Value]) -> Value {
    // TODO make actual memcpy that does overlaps right
    // how often do memcpys actually do that? next to never probably
    state.memory_move(&args[0], &args[1], &args[2].slice(31, 0));
    args[0].to_owned()
}

pub fn bcopy(state: &mut State, args: &[Value]) -> Value {
    state.memory_move(&args[0], &args[1], &args[2].slice(31, 0));
    vc(0)
}

pub fn bzero(state: &mut State, args: &[Value]) -> Value {
    memset(state, &[args[0].to_owned(), vc(0), args[1].to_owned()]);
    vc(0)
}

pub fn mempcpy(state: &mut State, args: &[Value]) -> Value {
    memcpy(state, args).add(&args[2])
}

pub fn memccpy(state: &mut State, args: &[Value]) -> Value {
    memcpy(state, args)
}

pub fn memfrob(state: &mut State, args: &[Value]) -> Value {
    let addr = &args[0];
    let num = &args[1];

    let x = vc(0x2a);
    let data = state.memory_read(addr, num);
    let mut new_data = vec![];
    for d in data {
        new_data.push(d.to_owned() ^ x.to_owned());
    }
    state.memory_write(addr, &new_data, num);
    vc(0)
}

pub fn strlen(state: &mut State, args: &[Value]) -> Value {
    state.memory_strlen(&args[0], &vc(MAX_LEN))
}

pub fn strnlen(state: &mut State, args: &[Value]) -> Value {
    state.memory_strlen(&args[0], &args[1].slice(31, 0))
}

pub fn gets(state: &mut State, args: &[Value]) -> Value {
    readline(state, &[&[vc(0)], args].concat())
}

pub fn fgets(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &args[2..3]);
    let buf = args[0].to_owned();
    let len = args[1].to_owned() - vc(1);
    syscall::read(state, &[fd, buf, len]);
    args[0].to_owned()
}

pub fn fputs(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &args[1..2]);
    let length = strlen(state, &args[0..1]);
    syscall::write(state, &[fd, args[0].to_owned(), length]);
    vc(0)
}

pub fn perror(state: &mut State, args: &[Value]) -> Value {
    let length = strlen(state, &args[0..1]);
    syscall::write(state, &[vc(2), args[0].to_owned(), length]);
    vc(0)
}

pub fn fputc(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &args[1..2]);
    let fdn = state.solver.evalcon_to_u64(&fd).unwrap_or(1) as usize;
    state.filesystem.write(fdn, vec![args[0].to_owned()]);
    vc(0)
}

pub fn feof(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &args[1..2]);
    let fdn = state.solver.evalcon_to_u64(&fd).unwrap_or(1) as usize;
    let f = &state.filesystem.files[fdn];
    vc((f.position != f.content.len() - 1) as u64)
}

pub fn strcpy(state: &mut State, args: &[Value]) -> Value {
    let length = state.memory_strlen(&args[1], &vc(MAX_LEN)) + vc(1);
    state.memory_move(&args[0], &args[1], &length);
    args[0].to_owned()
}

pub fn stpcpy(state: &mut State, args: &[Value]) -> Value {
    let length = state.memory_strlen(&args[1], &vc(MAX_LEN));
    strcpy(state, args) + length
}

pub fn strdup(state: &mut State, args: &[Value]) -> Value {
    let length = state.memory_strlen(&args[0], &vc(MAX_LEN)) + vc(1);
    let new_addr = vc(state.memory.alloc(&length));
    state.memory_move(&new_addr, &args[0], &length);
    new_addr
}

// what a weird function
pub fn strdupa(state: &mut State, args: &[Value]) -> Value {
    let length = state.memory_strlen(&args[0], &vc(MAX_LEN)) + vc(1);
    strdup(state, args) + length
}

// TODO for strn stuff I may need to add a null?
pub fn strndup(state: &mut State, args: &[Value]) -> Value {
    let length = state.memory_strlen(&args[0], &args[1].slice(31, 0));
    let new_addr = vc(state.memory.alloc(&length));
    state.memory_move(&new_addr, &args[0], &length);
    new_addr
}

pub fn strndupa(state: &mut State, args: &[Value]) -> Value {
    let length = state.memory_strlen(&args[0], &args[1]);
    strndup(state, args) + length
}

pub fn strfry(_state: &mut State, args: &[Value]) -> Value {
    args[0].to_owned() // don't shuffle anything
}

pub fn strncpy(state: &mut State, args: &[Value]) -> Value {
    let length = state.memory_strlen(&args[1], &args[2].slice(31, 0));
    state.memory_move(&args[0], &args[1], &length);
    args[0].to_owned()
}

pub fn strcat(state: &mut State, args: &[Value]) -> Value {
    let length1 = state.memory_strlen(&args[0], &vc(MAX_LEN));
    let length2 = state.memory_strlen(&args[1], &vc(MAX_LEN)) + vc(1);
    state.memory_move(&args[0].add(&length1), &args[1], &length2);
    args[0].to_owned()
}

pub fn strncat(state: &mut State, args: &[Value]) -> Value {
    let length1 = state.memory_strlen(&args[0], &args[2].slice(31, 0));
    let length2 = state.memory_strlen(&args[1], &args[2].slice(31, 0)) + vc(1);
    state.memory_move(&args[0].add(&length1), &args[1], &length2);
    args[0].to_owned()
}

pub fn memset(state: &mut State, args: &[Value]) -> Value {
    let mut data = vec![];
    let length = state.solver.max_value(&args[2]) & 0xffffffff;
    for _ in 0..length {
        data.push(args[1].to_owned());
    }

    state.memory_write(&args[0], &data, &args[2]);
    args[0].to_owned()
}

fn memchr_helper(state: &mut State, args: &[Value], reverse: bool) -> Value {
    state.memory_search(&args[0], &args[1], &args[2], reverse)
}

pub fn memchr(state: &mut State, args: &[Value]) -> Value {
    memchr_helper(state, args, false)
}

pub fn memrchr(state: &mut State, args: &[Value]) -> Value {
    memchr_helper(state, args, true)
}

fn strchr_helper(state: &mut State, args: &[Value], reverse: bool) -> Value {
    let length = state.memory_strlen(&args[0], &vc(MAX_LEN));
    let string = args[0].to_owned();
    let c = args[1].and(&vc(0xff));

    memchr_helper(state, &[string, c, length], reverse)
}

pub fn strchr(state: &mut State, args: &[Value]) -> Value {
    strchr_helper(state, args, false)
}

pub fn strrchr(state: &mut State, args: &[Value]) -> Value {
    strchr_helper(state, args, true)
}

pub fn memcmp(state: &mut State, args: &[Value]) -> Value {
    state.memory_compare(&args[0], &args[1], &args[2])
}

pub fn strcmp(state: &mut State, args: &[Value]) -> Value {
    let len1 = state.memory_strlen(&args[0], &vc(MAX_LEN));
    let len2 = state.memory_strlen(&args[1], &vc(MAX_LEN));
    let length = state.cond(&(len1.ult(&len2)), &len1, &len2) + vc(1);

    state.memory_compare(&args[0], &args[1], &length)
}

pub fn strncmp(state: &mut State, args: &[Value]) -> Value {
    let len1 = state.memory_strlen(&args[0], &args[2]);
    let len2 = state.memory_strlen(&args[1], &args[2]);
    let length = state.cond(&(len1.ult(&len2)), &len1, &len2) + vc(1);

    state.memory_compare(&args[0], &args[1], &length)
}

// TODO properly handle sym slens
// idk if I will ever do this ^. it is super complicated
// and the performance would likely be bad anyway
pub fn memmem(state: &mut State, args: &[Value]) -> Value {
    let len = state.solver.evalcon_to_u64(&args[3]).unwrap() as usize;
    let mut needle_val = state.memory_read_value(&args[2], len);

    // necessary as concrete values will not search for end nulls
    needle_val = Value::Symbolic(
        state.solver.to_bv(&needle_val, 8 * len as u32),
        needle_val.get_taint(),
    );

    let mem = args[0].to_owned();
    let length = args[1].to_owned();
    memchr_helper(state, &[mem, needle_val, length], false)
}

pub fn strstr(state: &mut State, args: &[Value]) -> Value {
    let dlen = state.memory_strlen(&args[0], &vc(MAX_LEN));
    let slen = state.memory_strlen(&args[1], &vc(MAX_LEN));
    let len = state.solver.evalcon_to_u64(&slen).unwrap() as usize;
    let needle_val = state.memory_read_value(&args[0], len);
    memchr_helper(state, &[args[0].to_owned(), needle_val, dlen], false)
}

pub fn malloc(state: &mut State, args: &[Value]) -> Value {
    state.memory_alloc(&args[0])
}

pub fn realloc(state: &mut State, args: &[Value]) -> Value {
    malloc(state, &args[1..])
}

pub fn calloc(state: &mut State, args: &[Value]) -> Value {
    state.memory_alloc(&args[0].mul(&args[1]))
}

pub fn free(state: &mut State, args: &[Value]) -> Value {
    state.memory_free(&args[0]);
    vc(0)
}

pub fn mmap(state: &mut State, args: &[Value]) -> Value {
    syscall::mmap(state, args)
}

pub fn munmap(state: &mut State, args: &[Value]) -> Value {
    syscall::munmap(state, args)
}

pub fn c_syscall(state: &mut State, args: &[Value]) -> Value {
    syscall::syscall("indirect_syscall", state, args)
}

// This is not going to be a real version of this func
// because otherwise all execution would have to take place
// within this sim which would be weird and bad
pub fn __libc_start_main(state: &mut State, args: &[Value]) -> Value {
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
    state.registers.set_with_alias("A2", vc(0));

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

// beginning of bad FILE function support

// _fileno offset from above linux x86_64
pub const LINUX_FILENO_OFFSET: u64 = 112;

// _file offset from macos aarch64
pub const MACOS_FILENO_OFFSET: u64 = 18;

pub fn fileno(state: &mut State, args: &[Value]) -> Value {
    let fd_addr = if state.info.bin.os == "darwin" {
        args[0].add(&vc(MACOS_FILENO_OFFSET))
    } else {
        args[0].add(&vc(LINUX_FILENO_OFFSET))
    };
    state.memory_read_value(&(fd_addr), 4)
}

pub fn fopen(state: &mut State, args: &[Value]) -> Value {
    // we are reaching levels of jank code previously undreamt
    let fd = syscall::open(state, args);
    let file_struct = state.memory.alloc(&vc(216));

    let fd_addr = if state.info.bin.os == "darwin" {
        vc(file_struct).add(&vc(MACOS_FILENO_OFFSET))
    } else {
        vc(file_struct).add(&vc(LINUX_FILENO_OFFSET))
    };
    state.memory_write_value(&fd_addr, &fd, 4);
    vc(file_struct)
}

pub fn fclose(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &[args[0].to_owned()]);
    syscall::close(state, &[fd])
}

pub fn fread(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &[args[3].to_owned()]);
    syscall::read(state, &[fd, args[0].to_owned(), args[1].mul(&args[2]).to_owned()])
}

pub fn fwrite(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &[args[3].to_owned()]);
    syscall::write(state, &[fd, args[0].to_owned(), args[1].mul(&args[2]).to_owned()])
}

pub fn fseek(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &[args[0].to_owned()]);
    syscall::lseek(state, &[fd, args[1].to_owned(), args[2].to_owned()])
}

pub fn ftell(state: &mut State, args: &[Value]) -> Value {
    let fd = fileno(state, &[args[0].to_owned()]);
    let fdn = state.solver.evalcon_to_u64(&fd).unwrap_or_default() as usize;
    vc(state.filesystem.files[fdn].position as u64)
}

// is whitespace
fn _isws(c: &Value) -> Value {
    c.eq(&vc(0x09)) | c.eq(&vc(0x20)) | c.eq(&vc(0x0d)) | c.eq(&vc(0x0a))
}

pub fn atoi(state: &mut State, args: &[Value]) -> Value {
    format::atoi_helper(state, &args[0], &vc(10), 32)
}

pub fn atol(state: &mut State, args: &[Value]) -> Value {
    let bits = state.memory.bits;
    format::atoi_helper(state, &args[0], &vc(10), bits)
}

pub fn atoll(state: &mut State, args: &[Value]) -> Value {
    format::atoi_helper(state, &args[0], &vc(10), 64)
}

pub fn strto_helper(state: &mut State, args: &[Value], bits: u64) -> Value {
    // not perfect but idk
    if let Value::Concrete(addr, _) = args[1] {
        if addr != 0 {
            let length = state.memory_strlen(&args[0], &vc(64));
            state.memory_write_value(
                &args[1],
                &args[0].add(&length),
                state.memory.bits as usize / 8,
            );
        }
    }
    
    format::atoi_helper(state, &args[0], &args[2], bits)
}

pub fn strtoll(state: &mut State, args: &[Value]) -> Value {
    strto_helper(state, args, 64)
}

// this is string to double not int... do something horrific for now
pub fn strtod(state: &mut State, args: &[Value]) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap_or_default();
    vc(state.memory_read_cstring(addr).parse::<f64>().unwrap_or_default().to_bits())
}

pub fn strtol(state: &mut State, args: &[Value]) -> Value {
    let bits = state.memory.bits;
    strto_helper(state, args, bits)
}

pub fn strtoul(state: &mut State, args: &[Value]) -> Value {
    let bits = state.memory.bits;
    strto_helper(state, args, bits)
}

pub fn itoa(state: &mut State, args: &[Value]) -> Value {
    format::itoa_helper(state, &args[0], &args[1], &args[2], true, 32)
}

pub fn islower(_state: &mut State, args: &[Value]) -> Value {
    let c = args[0].slice(7, 0);
    c.ult(&vc(0x7b)) & !c.ult(&vc(0x61))
}

pub fn isupper(_state: &mut State, args: &[Value]) -> Value {
    let c = args[0].slice(7, 0);
    c.ult(&vc(0x5b)) & !c.ult(&vc(0x41))
}

pub fn isalpha(state: &mut State, args: &[Value]) -> Value {
    isupper(state, args) | islower(state, args)
}

pub fn isdigit(_state: &mut State, args: &[Value]) -> Value {
    let c = args[0].slice(7, 0);
    c.ult(&vc(0x3a)) & !c.ult(&vc(0x30))
}

pub fn isalnum(state: &mut State, args: &[Value]) -> Value {
    isalpha(state, args) | isdigit(state, args)
}

pub fn isblank(_state: &mut State, args: &[Value]) -> Value {
    let c = args[0].slice(7, 0);
    c.eq(&vc(0x20)) | c.eq(&vc(0x09))
}

pub fn iscntrl(_state: &mut State, args: &[Value]) -> Value {
    let c = args[0].slice(7, 0);
    (c.ugte(&vc(0)) & c.ulte(&vc(0x1f))) | c.eq(&vc(0x7f))
}

pub fn toupper(state: &mut State, args: &[Value]) -> Value {
    let islo = islower(state, args);
    state.cond(&islo, &args[0].sub(&vc(0x20)), &args[0])
}

pub fn tolower(state: &mut State, args: &[Value]) -> Value {
    let isup = isupper(state, args);
    state.cond(&isup, &args[0].add(&vc(0x20)), &args[0])
}

pub fn zero(_state: &mut State, _args: &[Value]) -> Value {
    vc(0)
}

pub fn rand(state: &mut State, _args: &[Value]) -> Value {
    let r = rand::thread_rng().gen::<u64>();
    let rand = state.symbolic_value(&format!("rand_{}", r), 64);

    let rand_vec = &mut state
        .context
        .entry("rand".to_string())
        .or_insert_with(Vec::new);

    rand_vec.push(rand.clone());
    rand
}

pub fn srand(_state: &mut State, _args: &[Value]) -> Value {
    vc(0)
}

pub fn fflush(_state: &mut State, _args: &[Value]) -> Value {
    vc(0)
}

pub fn getpid(state: &mut State, args: &[Value]) -> Value {
    syscall::getpid(state, args)
}

pub fn getuid(state: &mut State, args: &[Value]) -> Value {
    syscall::getuid(state, args)
}

pub fn getgid(state: &mut State, args: &[Value]) -> Value {
    syscall::getuid(state, args)
}

pub fn geteuid(state: &mut State, args: &[Value]) -> Value {
    syscall::getuid(state, args)
}

pub fn getegid(state: &mut State, args: &[Value]) -> Value {
    syscall::getuid(state, args)
}

pub fn fork(state: &mut State, args: &[Value]) -> Value {
    syscall::fork(state, args)
}

pub fn brk(state: &mut State, args: &[Value]) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap();
    let current = syscall::sbrk(state, &[vc(0)]).as_u64();
    let new = syscall::brk(state, args).as_u64();
    if current.unwrap() == addr || new.unwrap() != addr {
        vc(0)
    } else {
        vc(-1i64 as u64)
    }
}

pub fn sbrk(state: &mut State, args: &[Value]) -> Value {
    syscall::sbrk(state, args)
}

pub fn getpagesize(_state: &mut State, _args: &[Value]) -> Value {
    vc(0x1000)
}

pub fn gethostname(state: &mut State, args: &[Value]) -> Value {
    let addr = state.solver.evalcon_to_u64(&args[0]).unwrap_or(0);
    state.memory_write_string(addr, "radius");
    vc(0)
}

// hardcode these for now idk
const OPTIND: u64 = 0xfffd0000;
const OPTARG: u64 = 0xfffd0004;

fn getopt_setup(state: &mut State) {
    let relocs = state.r2api.get_relocations().unwrap_or_default();

    let optind_addr = relocs
        .iter()
        .find(|r| r.name == "optind")
        .map(|r| r.vaddr)
        .unwrap_or(0);

    let optarg_addr = relocs
        .iter()
        .find(|r| r.name == "optarg")
        .map(|r| r.vaddr)
        .unwrap_or(0);

    let optind_ptr = state.memory_read_value(&vc(optind_addr), 4);

    if let Some(ind) = optind_ptr.as_u64() {
        if ind != OPTIND {
            state.memory_write_ptr(&vc(optind_addr), &vc(OPTIND));
            state.memory_write_ptr(&vc(optarg_addr), &vc(OPTARG));
            state.memory_write_value(&vc(OPTIND), &vc(1), 4);
            state.memory_write_ptr(&vc(OPTARG), &vc(0));
        }
    }
}

/*
from the man pages

"By default, getopt() permutes the contents of argv as it scans,
so that eventually all the nonoptions are at the end."

uhhhh i am not gonna do that for right now? also wat
*/

// this is not even close to being a faithful representation
// of the actual (insane) semantics of getopt
pub fn getopt(state: &mut State, args: &[Value]) -> Value {
    getopt_setup(state);

    let ptr = state.memory.bits / 8;
    let optind_val = state.memory_read_value(&vc(OPTIND), 4);
    let optind = state.solver.evalcon_to_u64(&optind_val).unwrap_or(1);
    let argc = state.solver.evalcon_to_u64(&args[0]).unwrap_or(1);

    if optind >= argc {
        vc(-1i64 as u64)
    } else {
        let optstr_addr = state.solver.evalcon_to_u64(&args[2]).unwrap_or(0);
        let optstr = state.memory_read_cstring(optstr_addr);

        let argv_addr = state.memory_read_ptr(&args[1].add(&vc(optind * ptr)));
        let argv_len = strlen(state, &[argv_addr.clone()]);

        let arg = state.memory_read(&argv_addr, &argv_len);
        let mut result = vc(-1i64 as u64);
        if arg.len() < 2 {
            return result;
        }

        let is_opt = arg[0].eq(&vc('-' as u64));
        result = state.cond(&is_opt, &vc('?' as u64), &result);
        let mut optarg = state.memory_read_ptr(&vc(OPTARG));

        for index in 0..optstr.len() {
            let c = vc(optstr.as_bytes()[index] as u64);
            let is_c = arg[1].eq(&c);
            result = state.cond(&is_opt.and(&is_c), &c, &result);

            if arg.len() > 2 && index + 1 < optstr.len() && &optstr[index + 1..index + 2] == ":" {
                // argument may be next argv, nvmd disallow
                //let newarg_addr = args[1].add(&vc((optind+1)*ptr));

                // if opt is c which has arg, arg must be in same argv (eg -xfoo)
                let arg_cond = (!is_c.clone()).or(&is_c.and(&!arg[2].eq(&vc(0))));
                state.assert(&arg_cond);

                optarg = state.cond(&is_c, &argv_addr.add(&vc(2)), &optarg);
                state.memory_write_ptr(&vc(OPTARG), &optarg);
            }
        }

        state.memory_write_value(&vc(OPTIND), &vc(optind + 1), 4);
        result
    }
}

// fully symbolic getenv
pub fn getenv(state: &mut State, args: &[Value]) -> Value {
    if state.context.get("env").is_none() {
        return vc(0);
    }

    let arg_ptr = args[0].to_owned();
    let arg_length = state.memory_strlen(&arg_ptr, &vc(MAX_LEN));

    let bits = state.memory.bits as usize;
    let mut env_ptr = state.context["env"][0].clone();
    let mut result = vc(0);
    let eqs = vc('=' as u64);
    loop {
        let var_ptr = state.memory_read_value(&env_ptr, bits / 8);

        if state.solver.check_sat(&var_ptr.eq(&vc(0))) {
            state.assert(&var_ptr.eq(&vc(0)));
            break;
        }

        let full_length = state.memory_strlen(&var_ptr, &vc(MAX_LEN));
        let name_end = state.memory_search(&var_ptr, &eqs, &full_length, false);

        let name_length = state.cond(&name_end.eq(&vc(0)), &full_length, &name_end.sub(&var_ptr));

        let value_ptr = var_ptr.add(&name_length).add(&vc(1));
        let long_len = state.cond(&arg_length.ugte(&name_length), &arg_length, &name_length);

        let cmp = state.memory_compare(&arg_ptr, &var_ptr, &long_len);
        result = state.cond(&cmp.eq(&vc(0)), &value_ptr, &result);

        env_ptr = env_ptr + vc(bits as u64 / 8);
    }
    result
}

// the first arg is always the real path idk
pub fn realpath(state: &mut State, args: &[Value]) -> Value {
    let length = state.memory_strlen(&args[0], &vc(MAX_LEN));
    state.memory_move(&args[1], &args[0], &length);
    args[1].to_owned()
}

pub fn sleep(_state: &mut State, _args: &[Value]) -> Value {
    vc(0)
}

pub fn __errno_location(state: &mut State, _args: &[Value]) -> Value {
    let addr = state.memory_alloc(&vc(8));
    state.memory_write_value(&addr, &vc(0), 8);
    addr
}

pub fn open(state: &mut State, args: &[Value]) -> Value {
    syscall::open(state, args)
}

pub fn close(state: &mut State, args: &[Value]) -> Value {
    syscall::close(state, args)
}

pub fn read(state: &mut State, args: &[Value]) -> Value {
    syscall::read(state, args)
}

pub fn write(state: &mut State, args: &[Value]) -> Value {
    syscall::write(state, args)
}

pub fn lseek(state: &mut State, args: &[Value]) -> Value {
    syscall::lseek(state, args)
}

pub fn access(state: &mut State, args: &[Value]) -> Value {
    syscall::access(state, args)
}

pub fn stat(state: &mut State, args: &[Value]) -> Value {
    syscall::stat(state, args)
}

pub fn fstat(state: &mut State, args: &[Value]) -> Value {
    syscall::fstat(state, args)
}

pub fn lstat(state: &mut State, args: &[Value]) -> Value {
    syscall::lstat(state, args)
}

pub fn ptrace(state: &mut State, args: &[Value]) -> Value {
    syscall::ptrace(state, args)
}

pub fn exit(state: &mut State, args: &[Value]) -> Value {
    syscall::exit(state, args)
}
