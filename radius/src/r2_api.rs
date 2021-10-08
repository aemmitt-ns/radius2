
use r2pipe::{R2Pipe, R2PipeSpawnOptions};
use serde::{Deserialize, Serialize};
use std::u64;
use std::u8;
use std::sync::{Arc, Mutex};
//use ahash::AHashMap;
//type HashMap<P, Q> = AHashMap<P, Q>;

use std::collections::HashMap;
use std::path::Path;
use std::{thread, time};

pub const STACK_START: u64 = 0xff000000;
pub const STACK_SIZE:  u64 = 0x780000*2;

#[derive(Debug, Clone, PartialEq)]
pub enum Endian {
    Little,
    Big,
    Mixed,
    Unknown
}

#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Default,
    Debugger,
    Frida
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallingConvention {
    pub ret:  String,
    pub args: Vec<String>
}

impl Endian {
    pub fn from_string(end: &str) -> Endian {
        match end {
            "little" => Endian::Little,
            "big" => Endian::Big,
            "mixed" => Endian::Mixed,
            _ => Endian::Unknown
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub offset: u64,
    pub size: u64,

    #[serde(default="invalid")]
    pub opcode: String,

    #[serde(default="invalid")]
    pub disasm: String,

    #[serde(default="blank")]
    pub esil: String,

    pub bytes: String,

    #[serde(default="invalid")]
    pub r#type: String,

    #[serde(default="zero")]
    pub type_num: i64,

    #[serde(default="zero")]
    pub jump: i64,

    #[serde(default="zero")]
    pub fail: i64  
}

fn invalid() -> String {
    "invalid".to_string()
}

fn blank() -> String {
    "".to_string()
}

fn zero() -> i64 {
    0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub name:  String,
    pub size:  u64,
    pub vsize: u64,
    pub perm:  String,
    pub paddr: u64,
    pub vaddr: u64
}

#[derive(Debug)]
pub struct Permission {
    pub initialized: bool,
    pub read: bool,
    pub write: bool,
    pub execute: bool
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasInfo {
    pub reg: String,
    pub role: u64,
    pub role_str: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInfo {
    pub name: String,
    pub r#type: u64,
    pub type_str: String,
    pub size: u64,
    pub offset: u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInformation {
    pub alias_info: Vec<AliasInfo>,
    pub reg_info: Vec<RegisterInfo>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreInfo {
    pub file: String,

    #[serde(default="zero")]
    pub size: i64,
    pub mode: String,
    pub format: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinInfo {
    pub arch: String,
    pub bintype: String,
    pub bits: u64,
    pub canary: bool,
    pub endian: String,
    pub os: String,
    pub nx: bool
}

fn binfo() -> BinInfo{
    BinInfo {
        arch: "".to_string(),
        bintype: "".to_string(),
        bits: 64,
        canary: false,
        endian: "little".to_string(),
        os: "".to_string(),
        nx: false
    }
}

fn core() -> CoreInfo {
    CoreInfo {
        file: "".to_string(),
        size: 0,
        mode: "".to_string(),
        format: "".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Information {
    #[serde(default="core")]
    pub core: CoreInfo,

    #[serde(default="binfo")]
    pub bin: BinInfo
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Syscall {
    pub name: String,
    pub swi: u64,
    pub num: u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRef {
    pub addr: u64,
    pub r#type: String,
    pub at: u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarRef {
    pub base: String,
    pub offset: u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub kind: String,
    pub r#type: String,
    pub r#ref: VarRef
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub offset: u64,
    pub name: String,
    pub size: u64,
    pub realsz: u64,
    pub noreturn: bool,
    pub stackframe: u64,
    pub calltype: String,
    pub cost: u64,
    pub cc: u64,
    pub bits: u64,
    pub r#type: String,
    pub nbbs: u64, // number of basic blocks
    pub edges: u64,
    pub ebbs: u64, 
    pub signature: String,
    pub minbound: u64,
    pub maxbound: u64,
    pub callrefs: Vec<CrossRef>,
    pub datarefs: Vec<u64>,
    pub codexrefs: Vec<CrossRef>,
    pub dataxrefs: Vec<CrossRef>,
    pub indegree: u64,
    pub outdegree: u64,
    pub nlocals: u64,
    pub nargs: u64,
    pub bpvars: Vec<Variable>,
    pub spvars: Vec<Variable>,
    pub regvars: Vec<Variable>,
    pub difftype: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub opaddr: u64,
    pub addr: u64,
    pub size: u64,
    pub inputs: u64,
    pub outputs: u64,
    pub ninstr: u64,
    pub traced: bool,

    #[serde(default="zero")]
    pub jump: i64,

    #[serde(default="zero")]
    pub fail: i64  
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub flagname: String,
    pub realname: String,
    pub ordinal: usize,
    pub bind: String,
    pub size: usize,
    pub r#type: String,
    pub vaddr: u64,
    pub paddr: u64,
    pub is_imported: bool
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub ordinal: usize,
    pub bind: String,
    pub r#type: String,
    pub name: String,
    pub plt: u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    name: String,
    flagname: String,
    realname: String,
    ordinal: usize,
    bind: String,
    size: usize,
    r#type: String,
    vaddr: u64,
    paddr: u64,
    is_imported: bool
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassMethod {
    pub name: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassField {
    pub name: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relocation {
    #[serde(default="blank")]
    pub name: String,
    pub vaddr: u64,
    pub paddr: u64,
    pub r#type: String,
    pub demname: String,
    pub is_ifunc: bool
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    pub raised: bool,
    pub fd: usize,
    pub uri: String,
    pub from: u64,
    pub writable: bool,
    pub size: usize

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entrypoint {
    pub vaddr: u64,
    pub paddr: u64,
    pub baddr: u64,
    pub laddr: u64,
    pub haddr: u64,
    pub r#type: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassInfo {
    pub classname: String,
    pub addr: u64,
    pub index: i64, 
    //pub r#super: String,
    pub methods: Vec<ClassMethod>,
    pub fields: Vec<ClassField>,

    #[serde(rename = "super")]
    pub superclass: String
}

pub type R2Result<T> = Result<T, String>;
pub fn r2_result<T, E>(result: Result<T, E>) -> R2Result<T> {
    if let Ok(res) = result {
        Ok(res)
    } else {
        Err("Deserialization error".to_owned())
    }
}

pub fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|d| {format!("{:02x}", *d)})
        .collect::<Vec<_>>()
        .join("")
}

pub fn hex_decode(data: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    for i in 0..data.len()/2 {
        result.push(u8::from_str_radix(&data[2*i..2*i+2], 16).unwrap());
    }
    result
}

// #[derive(DerefMut)]
#[derive(Clone)]
pub struct R2Api {
    pub r2p: Arc<Mutex<R2Pipe>>,
    //pub instructions: HashMap<u64, Instruction>,
    //pub permissions: HashMap<u64, Permission>,
    pub info: Option<Information>,
    pub mode: Mode
}

impl R2Api {
    pub fn new<T: AsRef<str>>(filename: Option<T>, opts: Option<Vec<&'static str>>) -> R2Api {
        let options = if let Some(o) = &opts {
            Some(R2PipeSpawnOptions { 
                exepath: "r2".to_owned(), 
                args: o.to_owned()
            })
        } else {
            None
        };

        let r2pipe = match (filename, opts) {
            (None, None) => R2Pipe::open(),
            (Some(name), _) => R2Pipe::spawn(name, options),
            _ => Err("cannot have options for non-spawned")
        };

        let mut r2api = R2Api {
            r2p: Arc::new(Mutex::new(r2pipe.unwrap())),
            info: None,
            mode: Mode::Default
        };
    
        let info = r2api.get_info().unwrap();
        r2api.mode = if info.core.file.starts_with("frida:") {
            let _ = r2api.cmd("s `:il~[0]`"); // seek to first module
            Mode::Frida
        } else if info.core.file.starts_with("dbg:") {
            Mode::Debugger
        } else {
            Mode::Default
        };

        r2api
    }

    pub fn cmd(&mut self, cmd: &str) -> R2Result<String> {
        self.r2p.lock().unwrap().cmd(cmd)
    }

    pub fn get_info(&mut self) -> R2Result<Information> {
        if self.info.is_none() {
            let json = self.cmd("ij")?;
            self.info = serde_json::from_str(json.as_str()).unwrap()
        }
        Ok(self.info.as_ref().unwrap().clone())
    }

    pub fn get_registers(&mut self) -> R2Result<RegisterInformation> {
        let json = self.cmd("aerpj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_cc(&mut self, pc: u64) -> R2Result<CallingConvention> {
        let json = self.cmd(format!("af @ {}; afcrj @ {}", pc, pc).as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    /*
        arch/ABI      arg1  arg2  arg3  arg4  arg5  arg6  arg7  Notes
    ──────────────────────────────────────────────────────────────
    alpha         a0    a1    a2    a3    a4    a5    -
    arc           r0    r1    r2    r3    r4    r5    -
    arm/OABI      a1    a2    a3    a4    v1    v2    v3
    arm/EABI      r0    r1    r2    r3    r4    r5    r6
    arm64         x0    x1    x2    x3    x4    x5    -
    blackfin      R0    R1    R2    R3    R4    R5    -
    i386          ebx   ecx   edx   esi   edi   ebp   -
    ia64          out0  out1  out2  out3  out4  out5  -
    m68k          d1    d2    d3    d4    d5    a0    -
    microblaze    r5    r6    r7    r8    r9    r10   -
    mips/o32      a0    a1    a2    a3    -     -     -     [1]
    mips/n32,64   a0    a1    a2    a3    a4    a5    -
    nios2         r4    r5    r6    r7    r8    r9    -
    parisc        r26   r25   r24   r23   r22   r21   -
    powerpc       r3    r4    r5    r6    r7    r8    r9
    riscv         a0    a1    a2    a3    a4    a5    -
    s390          r2    r3    r4    r5    r6    r7    -
    s390x         r2    r3    r4    r5    r6    r7    -
    superh        r4    r5    r6    r7    r0    r1    r2
    sparc/32      o0    o1    o2    o3    o4    o5    -
    sparc/64      o0    o1    o2    o3    o4    o5    -
    tile          R00   R01   R02   R03   R04   R05   -
    x86-64        rdi   rsi   rdx   r10   r8    r9    -
    x32           rdi   rsi   rdx   r10   r8    r9    -
    xtensa        a6    a3    a4    a5    a8    a9    -
    */
    
    pub fn get_syscall_cc(&mut self) -> R2Result<CallingConvention> {
        let bin = self.info.as_ref().unwrap().bin.clone();
        // this sucks, need a central place for arch shit
        match (bin.arch.as_str(), bin.bits) {
            ("x86", 32) => Ok(CallingConvention {
                args: vec!(
                    "ebx".to_string(), 
                    "ecx".to_string(), 
                    "edx".to_string(), 
                    "esi".to_string(), 
                    "edi".to_string(), 
                    "ebp".to_string()
                ),
                ret: "eax".to_string()
            }),
            ("x86", 64) => Ok(CallingConvention {
                args: vec!(
                    "rdi".to_string(), 
                    "rsi".to_string(), 
                    "rdx".to_string(), 
                    "r10".to_string(), 
                    "r8".to_string(), 
                    "r9".to_string()
                ),
                ret: "rax".to_string()
            }),
            // 16 is thumb mode, need to handle better
            ("arm", 16) | ("arm", 32) => Ok(CallingConvention {
                args: vec!(
                    "r0".to_string(), 
                    "r1".to_string(), 
                    "r2".to_string(), 
                    "r3".to_string(), 
                    "r4".to_string(), 
                    "r5".to_string(),
                    "r6".to_string()
                ),
                ret: "r0".to_string()
            }),
            ("arm", 64) => Ok(CallingConvention {
                args: vec!(
                    "x0".to_string(), 
                    "x1".to_string(), 
                    "x2".to_string(), 
                    "x3".to_string(), 
                    "x4".to_string(), 
                    "x5".to_string(),
                    "x6".to_string(),
                    "x7".to_string(),
                    "x8".to_string() // supposedly xnu/ios can have up 9 args
                ),
                ret: "x0".to_string()
            }),
            ("riscv", _) | ("mips", _) => Ok(CallingConvention {
                args: vec!(
                    "a0".to_string(), 
                    "a1".to_string(), 
                    "a2".to_string(), 
                    "a3".to_string(), 
                    "a4".to_string(), 
                    "a5".to_string()
                ),
                ret: "a0".to_string()
            }),
            ("sparc", _) => Ok(CallingConvention {
                args: vec!(
                    "o0".to_string(), 
                    "o1".to_string(), 
                    "o2".to_string(), 
                    "o3".to_string(), 
                    "o4".to_string(), 
                    "o5".to_string()
                ),
                ret: "o0".to_string()
            }),
            ("ppc", _) => Ok(CallingConvention {
                args: vec!(
                    "r3".to_string(), 
                    "r4".to_string(), 
                    "r5".to_string(),
                    "r6".to_string(), 
                    "r7".to_string(), 
                    "r8".to_string(), 
                    "r9".to_string()
                ),
                ret: "r3".to_string() // TODO errors are in r0
            }),
            _ => Err("calling convention not found".to_owned())
        }
    }

    pub fn get_classes(&mut self) -> R2Result<Vec<ClassInfo>> {
        let json = self.cmd(format!("icj").as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_class_map(&mut self) -> R2Result<HashMap<String, ClassInfo>> {
        let classes = self.get_classes()?;
        let mut class_map = HashMap::new();
        for c in &classes {
            class_map.insert(c.classname.clone(), c.to_owned());
        }    
        Ok(class_map)
    }

    pub fn get_segments(&mut self) -> R2Result<Vec<Segment>> {
        let json = self.cmd("iSj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn analyze(&mut self, n: usize) -> R2Result<String> { 
        // n = 14 automatically wins flareon
        self.cmd("a".repeat(n).as_str())
    }

    pub fn get_function_info(&mut self, addr: u64) -> R2Result<FunctionInfo> {
        let json = self.cmd(format!("afij @ {}", addr).as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_functions(&mut self) -> R2Result<Vec<FunctionInfo>> {
        let json = self.cmd("aflj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_blocks(&mut self, addr: u64) -> R2Result<Vec<BasicBlock>> {
        let cmd = format!("af @ {}; afbj @ {}", addr, addr);
        let json = self.cmd(cmd.as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_ret(&mut self) -> R2Result<String> {
        // simple as that?
        let ret = self.cmd("pae ret")?;
        Ok(ret[0..ret.len()-1].to_owned())
    }

    pub fn get_register_value(&mut self, reg: &str) -> R2Result<u64> {
        let cmd = format!("aer {}", reg);
        let val = self.cmd(cmd.as_str())?;
        // println!("val: {}", val);
        Ok(u64::from_str_radix(&val[2..val.len()-1], 16).unwrap())
    }

    pub fn set_register_value(&mut self, reg: &str, value: u64) {
        let cmd = format!("aer {}={}", reg, value);
        let _r = self.cmd(cmd.as_str());
    }

    pub fn get_syscall_str(&mut self, sys_num: u64) -> R2Result<String> {
        let cmd = format!("asl {}", sys_num);
        let ret = self.cmd(cmd.as_str())?;
        Ok(ret[0..ret.len()-1].to_owned())
    }

    pub fn get_syscall_num(&mut self, sys_str: &str) -> R2Result<u64> {
        let cmd = format!("asl {}", sys_str);
        let ret = self.cmd(cmd.as_str())?;
        Ok((&ret[0..ret.len()-1]).parse::<u64>().unwrap())
    }
    
    pub fn get_syscalls(&mut self) -> R2Result<Vec<Syscall>> {
        let json = self.cmd("asj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn seek(&mut self, addr: u64) {
        let _r = self.cmd(format!("s {}", addr).as_str());
    }

    pub fn breakpoint(&mut self, addr: u64) -> R2Result<String> {
        match self.mode {
            Mode::Debugger => self.cmd(format!("db {}", addr).as_str()),
            Mode::Frida => self.cmd(format!(":db {}", addr).as_str()),
            _ => Ok("idk".to_string())
        }
    }

    pub fn cont(&mut self) -> R2Result<String> {
        match self.mode {
            Mode::Debugger => self.cmd("dc"),
            Mode::Frida => self.cmd(":dc"),
            _ => Ok("idk".to_string())
        }
    }

    pub fn init_vm(&mut self) {
        let _r = self.cmd(format!("aei; aeim {} {}", 
            STACK_START, STACK_SIZE).as_str());
    }

    pub fn init_entry(&mut self, args: &[String], vars: &[String]) {
        let argc = args.len();
        let argv = args.join(" ");
        let env = vars.join(" ");
        self.init_vm();
        // this is very weird but this is how it works
        let _r = self.cmd(format!(".aeis {} {} {} @ SP", argc, argv, env).as_str());
    }

    pub fn init_frida(&mut self, addr: u64) -> R2Result<HashMap<String, String>> {
        // we are reaching levels of jankiness previously thought to be impossible
        let alloc = self.cmd(":dma 4096").unwrap();
        let func = format!("{{ptr('{}').writeUtf8String(JSON.stringify(this.context))}}",
            alloc.trim());

        let script_data = format!(": Interceptor.attach(ptr('0x{:x}'),function(){});:db {}", 
            addr, func, addr);

        self.cmd(&script_data).unwrap();
        loop {
            thread::sleep(time::Duration::from_millis(100));
            let out = self.cmd(&format!("psz 4096 @ {}", alloc))?;
            if out.starts_with("{") {
                self.cmd(&format!(":dma- {}", alloc)).unwrap();
                break r2_result(serde_json::from_str(&out));
            }
        }
    }

    pub fn set_option(&mut self, key: &str, value: &str) -> R2Result<String> {
        self.cmd(format!("e {}={}", key, value).as_str())
    }

    pub fn get_symbols(&mut self) -> R2Result<Vec<Symbol>> {
        let json = self.cmd("isj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_imports(&mut self) -> R2Result<Vec<Import>> {
        let json = self.cmd("iij")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_exports(&mut self) -> R2Result<Vec<Export>> {
        let json = self.cmd("iEj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn disassemble(&mut self, addr: u64, num: usize) -> R2Result<Vec<Instruction>> {
        let cmd = format!("pdj {} @ {}", num, addr);
        let json = self.cmd(cmd.as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn disassemble_bytes(&mut self, addr: u64, data: &[u8], num: usize) -> R2Result<Vec<Instruction>> {
        let cmd = format!("wx {} @ {}; pij {} @ {}", 
            hex_encode(data), addr, num, addr);

        let json = self.cmd(cmd.as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn assemble(&mut self, instruction: &str) -> R2Result<Vec<u8>> {
        let cmd = format!("pa {}", instruction);
        let hexpairs = self.cmd(cmd.as_str())?;
        Ok(hex_decode(&hexpairs))
    }

    pub fn read(&mut self, addr: u64, length: usize) -> R2Result<Vec<u8>> {
        let cmd = format!("xj {} @ {}", length, addr);
        let json = self.cmd(cmd.as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn write(&mut self, addr: u64, data: Vec<u8>) {
        let cmd = format!("wx {} @ {}", hex_encode(&data), addr);
        let _r = self.cmd(cmd.as_str());
    }

    pub fn get_address(&mut self, symbol: &str) -> R2Result<u64> {
        let cmd = if self.mode != Mode::Frida {
            format!("?v {}", symbol)
        } else {
            format!(":isa {}", symbol)
        };

        let val = self.cmd(cmd.as_str())?;
        r2_result(u64::from_str_radix(&val[2..val.len()-1], 16))
    }

    pub fn get_files(&mut self) -> R2Result<Vec<File>> {
        let json = self.cmd("oj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn set_file(&mut self, path: &str) {
        if let Some(file) = self.get_files().unwrap().iter().find(|f| f.uri == path) {
            self.cmd(format!("op {}", file.fd).as_str()).unwrap();   
        }
    }

    pub fn set_file_fd(&mut self, fd: usize) {
        self.cmd(format!("op {}", fd).as_str()).unwrap();   
    }

    pub fn get_libraries(&mut self) -> R2Result<Vec<String>> {
        let json = self.cmd("ilj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_relocations(&mut self) -> R2Result<Vec<Relocation>> {
        let json = self.cmd("irj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_entrypoints(&mut self) -> R2Result<Vec<Entrypoint>> {
        let json = self.cmd("iej")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    // load libraries, return list of full loaded paths
    pub fn load_libraries(&mut self, lib_paths: &[String]) -> R2Result<Vec<String>> {
        let paths = self.load_library_helper(lib_paths, &[])?;
        self.cmd("op 3")?; // usually the main module is 3 idk
        Ok(paths)
    }

    // this got a little nuts
    pub fn load_library_helper(&mut self, lib_paths: &[String], loaded_paths: &[String]) -> R2Result<Vec<String>> {
        let bits = self.info.as_ref().unwrap().bin.bits;
        let mut sections = self.get_segments().unwrap();
        let relocations = self.get_relocations().unwrap();

        let mut relocation_map = HashMap::new();
        for reloc in &relocations {
            relocation_map.insert(reloc.name.clone(), reloc);
        }

        let mut high_addr = sections.iter().map(|s| s.vaddr).max().unwrap();

        let libs = self.get_libraries()?;

        let mut paths = lib_paths.to_owned();
        paths.push("".to_owned()); // add cur dir ?

        let mut full_paths = loaded_paths.to_owned();

        for lib in &libs {
            for path in &paths {
                let lib_path = path.to_owned() + lib;
                let loaded = full_paths.iter().any(|x| x == &lib_path);

                //println!("{}", lib_path);

                if !loaded && Path::new(&lib_path).exists() {
                    let load_addr = (high_addr & 0xfffffffffffff000) + 0x3000; // idk
                    self.cmd(format!("o {} {}", &lib_path, load_addr).as_str())?;
                    full_paths.push(lib_path);

                    sections = self.get_segments().unwrap();
                    high_addr = sections.iter().map(|s| s.vaddr).max().unwrap();

                    for export in &self.get_exports().unwrap() {
                        if let Some(reloc) = relocation_map.get(&export.name) {
                            // write the export address into the reloc
                            self.cmd(format!("wv{} {} @ {}", bits/8, export.vaddr, 
                                reloc.vaddr).as_str())?;
                        }
                    }

                    if let Ok(librs) = self.load_library_helper(lib_paths, &full_paths) {
                        full_paths = librs;
                    }
                    break;
                } else if loaded {
                    // if its already loaded we still have to select it and get the exports
                    self.set_file(&lib_path);
                    for export in &self.get_exports().unwrap() {
                        if let Some(reloc) = relocation_map.get(&export.name) {
                            self.cmd(format!("wv{} {} @ {}", bits/8, export.vaddr, 
                                reloc.vaddr).as_str())?;
                        }
                    }
                    break;
                }
            }
        }

        Ok(full_paths)
    }

    pub fn clear(&mut self) {
        
    }

    pub fn close(&mut self) {
        self.r2p.lock().unwrap().close();
    }
}
