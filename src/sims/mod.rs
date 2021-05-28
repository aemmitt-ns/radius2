use crate::value::Value;
use crate::state::State;

pub mod libc;
pub mod fs;

pub type SimMethod = fn (&mut State, Vec<Value>) -> Value;

pub struct Sim {
    pub symbol: String,
    pub function: SimMethod,
    pub arguments: usize
}

pub fn make_sim(symbol: &str, function: SimMethod,
    arguments: usize) -> Sim {
    
    Sim {symbol: String::from(symbol), function, arguments}
}

// get a vec of all available Sims
pub fn get_sims() -> Vec<Sim> {
    let mut simuvec = vec!();

    simuvec.push(make_sim("puts",    libc::puts, 1));
    simuvec.push(make_sim("printf",  libc::printf, 1)); // fix

    simuvec.push(make_sim("strlen",  libc::strlen, 1));
    simuvec.push(make_sim("strnlen", libc::strnlen, 2));
    simuvec.push(make_sim("strstr",  libc::strstr, 2));
    simuvec.push(make_sim("strcpy",  libc::strcpy, 2));
    simuvec.push(make_sim("strncpy", libc::strncpy, 3));
    simuvec.push(make_sim("strcat",  libc::strcat, 2));
    simuvec.push(make_sim("strncat", libc::strncat, 3));
    simuvec.push(make_sim("strdup",  libc::strdup, 1));
    simuvec.push(make_sim("strndup", libc::strndup, 2));
    simuvec.push(make_sim("strdupa", libc::strdupa, 1));
    simuvec.push(make_sim("strndupa",libc::strndupa, 2));
    simuvec.push(make_sim("strfry",  libc::strfry, 1));
    simuvec.push(make_sim("strchr",  libc::strchr, 2));
    simuvec.push(make_sim("strrchr", libc::strrchr, 2));
    simuvec.push(make_sim("strstr",  libc::strstr, 2));
    simuvec.push(make_sim("strcmp",  libc::strcmp, 2));
    simuvec.push(make_sim("strncmp", libc::strncmp, 3));

    simuvec.push(make_sim("memmove", libc::memmove, 3));
    simuvec.push(make_sim("memcpy",  libc::memcpy, 3));
    simuvec.push(make_sim("memccpy", libc::memccpy, 3));
    simuvec.push(make_sim("mempcpy", libc::mempcpy, 3));
    simuvec.push(make_sim("memfrob", libc::memfrob, 2));
    simuvec.push(make_sim("memset",  libc::memset, 3));
    simuvec.push(make_sim("memchr",  libc::memchr, 3));
    simuvec.push(make_sim("memrchr", libc::memrchr, 3));
    simuvec.push(make_sim("memcmp",  libc::memcmp, 3));
    simuvec.push(make_sim("memmem",  libc::memmem, 3));

    simuvec.push(make_sim("bcopy",   libc::bcopy, 3));
    simuvec.push(make_sim("bzero",   libc::bzero, 2));

    simuvec.push(make_sim("malloc",  libc::malloc, 1));
    simuvec.push(make_sim("calloc",  libc::calloc, 2));
    simuvec.push(make_sim("free",    libc::strnlen, 1));

    simuvec.push(make_sim("islower", libc::islower, 1));
    simuvec.push(make_sim("isupper", libc::isupper, 1));
    simuvec.push(make_sim("isalpha", libc::isalpha, 1));
    simuvec.push(make_sim("isdigit", libc::isdigit, 1));
    simuvec.push(make_sim("isalnum", libc::isalnum, 1));
    simuvec.push(make_sim("iscntrl", libc::iscntrl, 1));
    simuvec.push(make_sim("isblank", libc::isblank, 1));
    simuvec.push(make_sim("tolower", libc::tolower, 1));
    simuvec.push(make_sim("toupper", libc::toupper, 1));

    simuvec.push(make_sim("open",    libc::open, 3));
    simuvec.push(make_sim("close",   libc::close, 1));
    simuvec.push(make_sim("read",    libc::read, 3));
    simuvec.push(make_sim("write",   libc::write, 3));
    simuvec.push(make_sim("lseek",   libc::lseek, 2));
    simuvec.push(make_sim("access",  libc::access, 1));

    simuvec.push(make_sim("sleep",   libc::sleep, 1));
    simuvec.push(make_sim("getpid",  libc::getpid, 0));
    simuvec.push(make_sim("fork",    libc::fork, 0));

    simuvec.push(make_sim("gethostname", libc::gethostname, 0));
    simuvec.push(make_sim("getpagesize", libc::getpagesize, 0));

    simuvec
}