use crate::state::State;
use crate::value::Value;

pub mod format;
pub mod fs;
pub mod libc;
pub mod syscall;

pub type SimMethod = fn(&mut State, &[Value]) -> Value;

pub struct Sim {
    pub symbol: String,
    pub function: SimMethod,
    pub arguments: usize,
}

pub fn make_sim(symbol: &str, function: SimMethod, arguments: usize) -> Sim {
    Sim {
        symbol: String::from(symbol),
        function,
        arguments,
    }
}

pub fn error(_state: &mut State, _args: &[Value]) -> Value {
    Value::Concrete(-1i64 as u64, 0)
}

pub fn zero(_state: &mut State, _args: &[Value]) -> Value {
    Value::Concrete(0, 0)
}

pub fn ret(state: &mut State, _args: &[Value]) -> Value {
    state.registers.get_with_alias("R0")
}

// this isn't great
/*pub fn unconstrained(state: &mut State, _args: &[Value]) -> Value {
    let mut uncon_vec = state.context.entry("uncon".to_owned()).or_insert(vec!()).clone();
    let uncon = state.symbolic_value(&format!("uncon_{}", uncon_vec.len()), 64);
    uncon_vec.push(uncon.clone());
    state.context.insert("uncon".to_owned(), uncon_vec);
    uncon
}*/

// get a vec of all available Sims
pub fn get_sims() -> Vec<Sim> {
    vec![
        make_sim("puts", libc::puts, 1),
        make_sim("gets", libc::gets, 1),
        make_sim("putchar", libc::putchar, 1),
        make_sim("putwchar", libc::putchar, 1),
        make_sim("getchar", libc::getchar, 0),
        make_sim("fgets", libc::fgets, 1),
        make_sim("fgetc", libc::fgets, 1),
        make_sim("fputs", libc::fputs, 2),
        make_sim("fputc", libc::fputc, 2),
        make_sim("feof", libc::feof, 1),
        make_sim("fprintf", libc::fprintf, 2),
        make_sim("printf", libc::printf, 1),
        make_sim("sprintf", libc::sprintf, 1),
        make_sim("vprintf", libc::printf, 1),   // fix
        make_sim("vsprintf", libc::sprintf, 1), // fix
        make_sim("perror", libc::perror, 1),
        make_sim("fflush", libc::fflush, 0),
        make_sim("scanf", libc::scanf, 1),
        make_sim("sscanf", libc::sscanf, 1),
        make_sim("__isoc99_scanf", libc::scanf, 1),
        make_sim("fopen", libc::fopen, 2),
        make_sim("freopen", libc::fopen, 3),
        make_sim("fread", libc::fread, 4),
        make_sim("fwrite", libc::fwrite, 4),
        make_sim("ferror", libc::zero, 1),
        make_sim("fseek", libc::fseek, 2),
        make_sim("ftell", libc::ftell, 1),
        make_sim("fclose", libc::fgets, 1),
        make_sim("strlen", libc::strlen, 1),
        make_sim("strnlen", libc::strnlen, 2),
        make_sim("strstr", libc::strstr, 2),
        make_sim("strcpy", libc::strcpy, 2),
        make_sim("stpcpy", libc::stpcpy, 2),
        make_sim("strncpy", libc::strncpy, 3),
        make_sim("strxfrm", libc::strncpy, 3),
        make_sim("strcat", libc::strcat, 2),
        make_sim("strncat", libc::strncat, 3),
        make_sim("strdup", libc::strdup, 1),
        make_sim("strndup", libc::strndup, 2),
        make_sim("strdupa", libc::strdupa, 1),
        make_sim("strndupa", libc::strndupa, 2),
        make_sim("strfry", libc::strfry, 1),
        make_sim("strchr", libc::strchr, 2),
        make_sim("strrchr", libc::strrchr, 2),
        make_sim("strstr", libc::strstr, 2),
        make_sim("strcmp", libc::strcmp, 2),
        make_sim("strcoll", libc::strcmp, 2),
        make_sim("strncmp", libc::strncmp, 3),
        make_sim("memmove", libc::memmove, 3),
        make_sim("memcpy", libc::memcpy, 3),
        make_sim("memccpy", libc::memccpy, 3),
        make_sim("mempcpy", libc::mempcpy, 3),
        make_sim("memfrob", libc::memfrob, 2),
        make_sim("memset", libc::memset, 3),
        make_sim("memchr", libc::memchr, 3),
        make_sim("memrchr", libc::memrchr, 3),
        make_sim("memcmp", libc::memcmp, 3),
        make_sim("memmem", libc::memmem, 3),
        make_sim("bcopy", libc::bcopy, 3),
        make_sim("bzero", libc::bzero, 2),
        make_sim("malloc", libc::malloc, 1),
        make_sim("realloc", libc::realloc, 1),
        make_sim("calloc", libc::calloc, 2),
        make_sim("free", libc::strnlen, 1),
        make_sim("mmap", libc::mmap, 4),
        make_sim("munmap", libc::munmap, 2),
        make_sim("brk", libc::brk, 1),
        make_sim("sbrk", libc::sbrk, 1),
        make_sim("atoi", libc::atoi, 1),
        make_sim("atol", libc::atol, 1),
        make_sim("itoa", libc::itoa, 3),
        make_sim("strtol", libc::strtol, 3),
        make_sim("strtoul", libc::strtoul, 3),
        make_sim("strtoll", libc::strtoll, 3),
        make_sim("strtod", libc::strtod, 3),
        make_sim("islower", libc::islower, 1),
        make_sim("isupper", libc::isupper, 1),
        make_sim("isalpha", libc::isalpha, 1),
        make_sim("isdigit", libc::isdigit, 1),
        make_sim("isalnum", libc::isalnum, 1),
        make_sim("iscntrl", libc::iscntrl, 1),
        make_sim("isblank", libc::isblank, 1),
        make_sim("tolower", libc::tolower, 1),
        make_sim("toupper", libc::toupper, 1),
        make_sim("open", libc::open, 3),
        make_sim("close", libc::close, 1),
        make_sim("read", libc::read, 3),
        make_sim("write", libc::write, 3),
        make_sim("lseek", libc::lseek, 2),
        make_sim("access", libc::access, 1),
        make_sim("stat", libc::stat, 2),
        make_sim("fstat", libc::fstat, 2),
        make_sim("lstat", libc::lstat, 2),
        make_sim("getopt", libc::getopt, 3),
        make_sim("getopt_long", libc::getopt, 4),
        make_sim("getuid", libc::getuid, 0),
        make_sim("getgid", libc::getgid, 0),
        make_sim("geteuid", libc::geteuid, 0),
        make_sim("getegid", libc::getegid, 0),
        make_sim("sleep", libc::sleep, 1),
        make_sim("getpid", libc::getpid, 0),
        make_sim("fork", libc::fork, 0),
        make_sim("ptrace", libc::ptrace, 0),
        make_sim("syscall", libc::c_syscall, 0),
        make_sim("getenv", libc::getenv, 1),
        make_sim("abort", libc::exit, 1),
        make_sim("exit", libc::exit, 1),
        make_sim("xexit", libc::exit, 1),
        make_sim("ioctl", error, 1),
        make_sim("sysctl", zero, 1),
        make_sim("setbuf", zero, 2),
        make_sim("rand", libc::rand, 0),
        make_sim("arc4random", libc::rand, 0),
        make_sim("srand", libc::srand, 1),
        make_sim("gethostname", libc::gethostname, 0),
        make_sim("getpagesize", libc::getpagesize, 0),
        make_sim("__stack_chk_fail", ret, 0),
        make_sim("__libc_start_main", libc::__libc_start_main, 5),
        make_sim("__cfi_slowpath", zero, 0),
        make_sim("__errno_location", libc::__errno_location, 0),
    ]
}
