use r2pipe::{R2Pipe, R2PipeSpawnOptions};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::{Arc, Mutex};
use std::u64;
use std::u8;
//use ahash::AHashMap;
//type HashMap<P, Q> = AHashMap<P, Q>;

use std::collections::HashMap;
use std::path::Path;
use std::{thread, time};

pub const STACK_START: u64 = 0xfff00000;
pub const STACK_SIZE: u64 = 0x78000 * 2;

#[derive(Debug, Clone, PartialEq)]
pub enum Endian {
    Little,
    Big,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Default,
    Debugger,
    Frida,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallingConvention {
    pub ret: String,
    pub args: Vec<String>,
}

impl Default for CallingConvention {
    fn default() -> Self {
        CallingConvention {
            ret: String::from("A0"),
            args: vec![
                String::from("A0"),
                String::from("A1"),
                String::from("A2"),
                // String::from("A3"),
            ],
        }
    }
}

impl Endian {
    pub fn from_string(end: &str) -> Endian {
        match end {
            "little" => Endian::Little,
            "big" => Endian::Big,
            "mixed" => Endian::Mixed,
            _ => Endian::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub offset: u64,
    pub size: u64,

    #[serde(default = "invalid")]
    pub opcode: String,

    #[serde(default = "invalid")]
    pub disasm: String,

    #[serde(default)]
    pub esil: String,

    #[serde(default = "blank")]
    pub bytes: String,

    #[serde(default = "invalid")]
    pub r#type: String,

    #[serde(default)]
    pub type_num: i64,

    #[serde(default)]
    pub jump: i64,

    #[serde(default)]
    pub fail: i64,
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
    pub name: String,
    pub size: u64,
    pub vsize: u64,
    pub perm: String,
    pub paddr: u64,
    pub vaddr: u64,
}

#[derive(Debug)]
pub struct Permission {
    pub initialized: bool,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasInfo {
    pub reg: String,
    pub role: u64,
    pub role_str: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInfo {
    pub name: String,
    pub r#type: u64,
    pub type_str: String,
    pub size: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInformation {
    pub alias_info: Vec<AliasInfo>,
    pub reg_info: Vec<RegisterInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreInfo {
    pub file: String,

    #[serde(default)]
    pub size: i64,
    pub mode: String,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinInfo {
    pub arch: String,
    pub bintype: String,
    pub bits: u64,
    pub canary: bool,
    pub endian: String,
    pub os: String,
    pub nx: bool,
}

impl Default for BinInfo {
    fn default() -> Self {
        BinInfo {
            arch: "".to_string(),
            bintype: "".to_string(),
            bits: 64,
            canary: false,
            endian: "little".to_string(),
            os: "".to_string(),
            nx: false,
        }
    }
}

impl Default for CoreInfo {
    fn default() -> Self {
        CoreInfo {
            file: "".to_string(),
            size: 0,
            mode: "".to_string(),
            format: "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Default, Deserialize)]
pub struct Information {
    #[serde(default)]
    pub core: CoreInfo,

    #[serde(default)]
    pub bin: BinInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Syscall {
    pub name: String,
    pub swi: u64,
    pub num: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub r#type: String,
    pub offset: u64,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRef {
    pub addr: u64,
    pub r#type: String,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarRef {
    pub base: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub kind: String,
    pub r#type: String,
    pub r#ref: VarRef,
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
    pub difftype: String,
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

    #[serde(default = "zero")]
    pub jump: i64,

    #[serde(default = "zero")]
    pub fail: i64,
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
    pub is_imported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    #[serde(default)]
    pub ordinal: usize,

    #[serde(default)]
    pub bind: String,

    #[serde(default)]
    pub r#type: String,

    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub plt: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FridaImport {
    pub index: usize,
    pub module: String,
    pub r#type: String,
    pub name: String,

    #[serde(deserialize_with = "from_hex")]
    pub address: u64,
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
    is_imported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjCClassMethod {
    pub name: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjCClassField {
    pub name: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaClassMethod {
    pub name: String,
    pub vaddr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaClassField {
    pub name: String,
    pub vaddr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjCClassInfo {
    pub classname: String,

    #[serde(default)]
    pub methods: Vec<ObjCClassMethod>,

    #[serde(default)]
    pub fields: Vec<ObjCClassField>,

    pub addr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaClassInfo {
    pub classname: String,
    pub vaddr: u64,

    #[serde(default)]
    pub index: i64,
    //pub r#super: String,
    #[serde(default)]
    pub methods: Vec<JavaClassMethod>,

    #[serde(default)]
    pub fields: Vec<JavaClassField>,

    #[serde(rename = "super", default)]
    pub superclass: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relocation {
    #[serde(default = "blank")]
    pub name: String,
    pub vaddr: u64,
    pub paddr: u64,
    pub r#type: String,
    pub demname: String,
    pub is_ifunc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    pub raised: bool,
    pub fd: usize,
    pub uri: String,
    pub from: u64,
    pub writable: bool,
    pub size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FridaInfo {
    pub arch: String,
    pub bits: u64,
    pub os: String,
    pub pid: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entrypoint {
    pub vaddr: u64,
    pub paddr: u64,
    pub baddr: u64,
    pub laddr: u64,
    pub haddr: u64,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub from: u64,
    pub r#type: String,
    pub opcode: String,

    #[serde(default)]
    pub fcn_addr: u64,

    #[serde(default)]
    pub fcn_name: String,

    #[serde(default)]
    pub refname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub vaddr: u64,
    pub paddr: u64,

    #[serde(default)]
    pub ordinal: u64,

    #[serde(default)]
    pub size: usize,
    
    pub length: usize,

    #[serde(default)]
    pub section: String,

    #[serde(default)]
    pub r#type: String,

    #[serde(default)]
    pub string: String,
}

fn from_hex<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    if s.len() > 2 {
        Ok(u64::from_str_radix(&s[2..], 16).unwrap_or(0))
    } else {
        Ok(0)
    }
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
        .map(|d| format!("{:02x}", *d))
        .collect::<Vec<_>>()
        .join("")
}

pub fn hex_decode(data: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    for i in 0..data.len() / 2 {
        result.push(u8::from_str_radix(&data[2 * i..2 * i + 2], 16).unwrap());
    }
    result
}

// #[derive(DerefMut)]
#[derive(Clone)]
pub struct R2Api {
    pub r2p: Arc<Mutex<R2Pipe>>,
    //pub instructions: HashMap<u64, Instruction>,
    //pub permissions: HashMap<u64, Permission>,
    pub info: Information,
    pub mode: Mode,
    do_cache: bool,
    cache: HashMap<String, String>,
}

impl R2Api {
    pub fn new<T: AsRef<str>>(filename: Option<T>, opts: Option<Vec<&'static str>>) -> R2Api {
        let options = &opts.as_ref().map(|o| R2PipeSpawnOptions {
            exepath: "r2".to_owned(),
            args: o.to_owned(),
        });

        let r2pipe = match (&filename, &opts) {
            (None, _) => R2Pipe::open(),
            (Some(name), _) => R2Pipe::spawn(name, options.to_owned()),
            // _ => Err(Error::NoSession),
        };

        let mut r2api = R2Api {
            r2p: Arc::new(Mutex::new(r2pipe.unwrap())),
            info: Information::default(),
            mode: Mode::Default,
            do_cache: false,
            cache: HashMap::new(),
        };

        r2api.info = r2api.get_info().unwrap();
        r2api.mode = if r2api.info.core.file.starts_with("frida:") {
            let _ = r2api.cmd("s `:il~[0]`"); // seek to first module
            Mode::Frida
        } else if r2api.info.core.file.starts_with("dbg:") {
            Mode::Debugger
        } else {
            Mode::Default
        };

        if r2api.mode == Mode::Frida {
            let info = r2api.get_frida_info().unwrap();
            r2api.info.bin.arch = info.arch;
            r2api.info.bin.bits = info.bits;
        }

        // if we are on arm64 default to v35 plugin
        if r2api.info.bin.arch == "arm" && r2api.info.bin.bits == 64 {
            r2api.set_option("asm.arch", "arm.v35").unwrap_or_default();
        }

        r2api
    }

    pub fn cmd(&mut self, cmd: &str) -> R2Result<String> {
        Ok(self.r2p.lock().unwrap().cmd(cmd).unwrap_or_default())
    }

    // cached command
    pub fn ccmd(&mut self, cmd: &str) -> R2Result<String> {
        if self.do_cache {
            if let Some(result) = self.cache.get(cmd) {
                Ok(result.to_owned())
            } else {
                let result = self.cmd(cmd)?;
                self.cache.insert(cmd.to_owned(), result.clone());
                Ok(result)
            }
        } else {
            self.cmd(cmd)
        }
    }

    pub fn get_info(&mut self) -> R2Result<Information> {
        let json = self.cmd("ij")?;
        Ok(serde_json::from_str(json.as_str()).unwrap())
    }

    pub fn get_frida_info(&mut self) -> R2Result<FridaInfo> {
        let json = self.cmd(":ij")?;
        Ok(serde_json::from_str(json.as_str()).unwrap())
    }

    pub fn get_registers(&mut self) -> R2Result<RegisterInformation> {
        let json = self.cmd("aerpj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_cc(&mut self, pc: u64) -> R2Result<CallingConvention> {
        let json = self.cmd(format!("af @ {}; afcrj @ {}", pc, pc).as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_shellcode(&mut self, cmd: &str) -> R2Result<Vec<u8>> {
        let result = self.cmd(&format!("gr;gi exec;gc cmd={};g", cmd))?;
        Ok(hex_decode(&result))
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
        // this sucks, need a central place for arch stuff
        match (self.info.bin.arch.as_str(), self.info.bin.bits) {
            ("x86", 32) => Ok(CallingConvention {
                args: vec![
                    "ebx".to_string(),
                    "ecx".to_string(),
                    "edx".to_string(),
                    "esi".to_string(),
                    "edi".to_string(),
                    "ebp".to_string(),
                ],
                ret: "eax".to_string(),
            }),
            ("x86", 64) => Ok(CallingConvention {
                args: vec![
                    "rdi".to_string(),
                    "rsi".to_string(),
                    "rdx".to_string(),
                    "r10".to_string(),
                    "r8".to_string(),
                    "r9".to_string(),
                ],
                ret: "rax".to_string(),
            }),
            // 16 is thumb mode, need to handle better
            ("arm", 16) | ("arm", 32) => Ok(CallingConvention {
                args: vec![
                    "r0".to_string(),
                    "r1".to_string(),
                    "r2".to_string(),
                    "r3".to_string(),
                    "r4".to_string(),
                    "r5".to_string(),
                    "r6".to_string(),
                ],
                ret: "r0".to_string(),
            }),
            ("arm", 64) => Ok(CallingConvention {
                args: vec![
                    "x0".to_string(),
                    "x1".to_string(),
                    "x2".to_string(),
                    "x3".to_string(),
                    "x4".to_string(),
                    "x5".to_string(),
                    "x6".to_string(),
                    "x7".to_string(),
                    "x8".to_string(), // supposedly xnu/ios can have up 9 args
                ],
                ret: "x0".to_string(),
            }),
            ("riscv", _) | ("mips", _) => Ok(CallingConvention {
                args: vec![
                    "a0".to_string(),
                    "a1".to_string(),
                    "a2".to_string(),
                    "a3".to_string(),
                    "a4".to_string(),
                    "a5".to_string(),
                ],
                ret: "a0".to_string(),
            }),
            ("sparc", _) => Ok(CallingConvention {
                args: vec![
                    "o0".to_string(),
                    "o1".to_string(),
                    "o2".to_string(),
                    "o3".to_string(),
                    "o4".to_string(),
                    "o5".to_string(),
                ],
                ret: "o0".to_string(),
            }),
            ("ppc", _) => Ok(CallingConvention {
                args: vec![
                    "r3".to_string(),
                    "r4".to_string(),
                    "r5".to_string(),
                    "r6".to_string(),
                    "r7".to_string(),
                    "r8".to_string(),
                    "r9".to_string(),
                ],
                ret: "r3".to_string(), // TODO errors are in r0
            }),
            ("xtensa", _) => Ok(CallingConvention {
                args: vec![
                    "a6".to_string(),
                    "a3".to_string(),
                    "a4".to_string(),
                    "a5".to_string(),
                    "a8".to_string(),
                    "a9".to_string(),
                ],
                ret: "a2".to_string(),
            }),
            _ => Err("calling convention not found".to_owned()),
        }
    }

    /*pub fn get_classes(&mut self) -> R2Result<Vec<ClassInfo>> {
        let json = self.cmd("icj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }*/

    pub fn get_objc_class(&mut self, class: &str) -> R2Result<ObjCClassInfo> {
        let json = self.cmd(&format!("icj {}", class))?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_java_class(&mut self, class: &str) -> R2Result<JavaClassInfo> {
        let json = self.cmd(&format!("icj {}", class))?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    /*pub fn get_class_map(&mut self) -> R2Result<HashMap<String, ClassInfo>> {
        let classes = self.get_classes()?;
        let mut class_map = HashMap::new();
        for c in &classes {
            class_map.insert(c.classname.clone(), c.to_owned());
        }
        Ok(class_map)
    }*/

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

    pub fn get_references(&mut self, addr: u64) -> R2Result<Vec<Reference>> {
        let json = self.cmd(&format!("axtj {}", addr))?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_strings(&mut self) -> R2Result<Vec<StringEntry>> {
        let json = self.cmd("izzj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn search(&mut self, string: &str) -> R2Result<Vec<SearchResult>> {
        let json = self.cmd(&format!("/j {}", string))?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn search_bytes(&mut self, data: &[u8]) -> R2Result<Vec<SearchResult>> {
        let json = self.cmd(&format!("/xj {}", hex_encode(data)))?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    /// Gets all strings then filters, slower than search
    pub fn search_strings(&mut self, string: &str) -> R2Result<Vec<u64>> {
        let result = self.cmd(&format!("izz~[2]~{}", string))?;
        Ok(result
            .trim()
            .split('\n')
            .map(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).unwrap_or_default())
            .filter(|x| *x != 0)
            .collect())
    }

    pub fn get_blocks(&mut self, addr: u64) -> R2Result<Vec<BasicBlock>> {
        let cmd = format!("af @ {}; afbj @ {}", addr, addr);
        let json = self.cmd(cmd.as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_ret(&mut self) -> R2Result<String> {
        // simple as that?
        let ret = self.cmd("pae ret")?;
        if ret.is_empty() {
            if self.info.bin.arch == "bpf" {
                Ok("8,sp,+=,sp,[8],pc,=".to_owned())
            } else {
                Err("no ret instruction".to_owned())
            }
        } else {
            Ok(ret[0..ret.len() - 1].to_owned())
        }
    }

    pub fn get_register_value(&mut self, reg: &str) -> R2Result<u64> {
        let val = self.cmd(&format!("aer {}", reg))?;
        Ok(u64::from_str_radix(&val[2..val.len() - 1], 16).unwrap_or_default())
    }

    pub fn set_register_value(&mut self, reg: &str, value: u64) {
        let cmd = format!("aer {}={}", reg, value);
        let _r = self.cmd(cmd.as_str());
    }

    pub fn get_syscall_str(&mut self, sys_num: u64) -> R2Result<String> {
        let cmd = format!("asl {}", sys_num);
        let ret = self.cmd(cmd.as_str())?;
        Ok(ret[0..ret.len() - 1].to_owned())
    }

    pub fn get_syscall_num(&mut self, sys_str: &str) -> R2Result<u64> {
        let cmd = format!("asl {}", sys_str);
        let ret = self.cmd(cmd.as_str())?;
        Ok((&ret[0..ret.len() - 1]).parse::<u64>().unwrap())
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
            _ => Ok("idk".to_string()),
        }
    }

    /// continue concrete execution
    pub fn cont(&mut self) -> R2Result<String> {
        match self.mode {
            Mode::Debugger => self.cmd("dc"),
            Mode::Frida => self.cmd(":dc"),
            _ => self.cmd("aec"),
        }
    }

    pub fn init_debug(&mut self, addr: u64, args: &[String]) {
        (match self.mode {
            Mode::Debugger => self.cmd(&format!("db {};dc", addr)),
            Mode::Frida => panic!("can't enter debug from frida mode, also why would you?"),
            _ => {
                self.mode = Mode::Debugger;
                self.cmd(&format!("doo {};db {};dc", args.join(" "), addr))
            }
        })
        .unwrap_or_default();
    }

    pub fn init_vm(&mut self) {
        let _r = self.cmd(&format!("aei; aeim {} {}", STACK_START, STACK_SIZE));
    }

    pub fn init_entry(&mut self, args: &[String], vars: &[String]) {
        let argc = args.len();
        let argv = args.join(" ");
        let env = vars.join(" ");
        self.init_vm();
        // this is very weird but this is how it works
        let _r = self.cmd(&format!(".aeis {} {} {} @ SP", argc, argv, env));
    }

    pub fn init_frida(&mut self, addr: u64) -> R2Result<HashMap<String, u64>> {
        // we are reaching levels of jankiness previously thought to be impossible
        let _alloc = self.cmd(": global.mem = Memory.alloc(0x2000)")?;
        let func = format!(
            // experimenting with increasingly shitty ways to suspend.
            "{{global.mem.writeUtf8String(JSON.stringify(this.context,{}))}}",
            // need this to convert everything to strings oof
            "function(k,v){return v && typeof v === 'object' && Object.keys(v).length ? v:''+v}",
            // need this to wait for continue, nvmd doesnt work
            // "(function(){while(global.mem.readU8()){Thread.sleep(1)}})()"
        );

        let script_data = format!(
            ": Interceptor.attach(ptr('0x{:x}'),function(){});",
            addr, func
        );

        self.cmd(&script_data).unwrap();
        loop {
            thread::sleep(time::Duration::from_millis(100));
            let out = self.cmd(": global.mem.readUtf8String()")?;
            if out.starts_with("{") {
                let context: Result<HashMap<String, String>, _> = serde_json::from_str(&out);
                break Ok(self.parse_context(context.unwrap_or_default()));
            }
        }
    }

    fn parse_context(&self, context: HashMap<String, String>) -> HashMap<String, u64> {
        let mut newcon = HashMap::new();
        for reg in context.keys() {
            if context[reg].starts_with("0x") {
                newcon.insert(
                    reg.to_owned(),
                    u64::from_str_radix(&context[reg][2..], 16).unwrap_or(0),
                );
            } else if context[reg].contains(".") {
                // cant know if these are f32 or f64 so this will be wrong half the time. this sucks
                newcon.insert(
                    reg.to_owned(),
                    f64::to_bits(context[reg].parse::<f64>().unwrap_or(0.0)),
                );
            } else if !context[reg].starts_with("[") {
                newcon.insert(
                    reg.to_owned(),
                    u64::from_str_radix(&context[reg], 10).unwrap_or(0),
                );
            }
        }
        newcon
    }

    pub fn set_option(&mut self, key: &str, value: &str) -> R2Result<String> {
        self.cmd(format!("e {}={}", key, value).as_str())
    }

    // is.j returns a weird format
    pub fn get_symbol(&mut self, addr: u64) -> R2Result<Symbol> {
        let json = self.cmd(&format!("is.j @ {}", addr))?;
        let result: Option<HashMap<String, Symbol>> = serde_json::from_str(json.as_str()).ok();
        if let Some(mut symmap) = result {
            Ok(symmap.remove("symbols").unwrap())
        } else {
            Err("symbol not found".to_owned())
        }
    }

    pub fn get_symbols(&mut self) -> R2Result<Vec<Symbol>> {
        let json = self.cmd("isj")?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn get_imports(&mut self) -> R2Result<Vec<Import>> {
        if self.mode != Mode::Frida {
            let json = self.cmd("iij")?;
            r2_result(serde_json::from_str(json.as_str()))
        } else {
            // so jank i dont even know
            let json = self.cmd(":iij")?;
            let f_imps: Vec<FridaImport> = serde_json::from_str(json.as_str()).unwrap();

            Ok(f_imps
                .iter()
                .map(|f| Import {
                    name: f.name.to_owned(),
                    r#type: f.r#type.to_owned(),
                    ordinal: f.index,
                    plt: f.address,
                    bind: f.name.to_owned(),
                })
                .collect())
        }
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

    pub fn disassemble_function(&mut self, addr: u64) -> R2Result<Vec<Instruction>> {
        let cmd = format!("af @ {};pdfj @ {}", addr, addr);
        let json = self.cmd(cmd.as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn disassemble_bytes(
        &mut self,
        addr: u64,
        data: &[u8],
        num: usize,
    ) -> R2Result<Vec<Instruction>> {
        // this is unfortunately necessary as there is no padj @, i need to make one
        let cmd = format!("wx {} @ {}; pij {} @ {}", hex_encode(data), addr, num, addr);

        let json = self.cmd(cmd.as_str())?;
        r2_result(serde_json::from_str(json.as_str()))
    }

    pub fn assemble(&mut self, instruction: &str) -> R2Result<Vec<u8>> {
        let cmd = format!("pa {}", instruction);
        let hexpairs = self.cmd(cmd.as_str())?;
        Ok(hex_decode(&hexpairs))
    }

    pub fn read(&mut self, addr: u64, length: usize) -> R2Result<Vec<u8>> {
        let cmd = format!("p8 {} @ {}", length, addr);
        let out = self.cmd(cmd.as_str())?;
        Ok(hex_decode(&out))
    }

    pub fn write(&mut self, addr: u64, data: Vec<u8>) {
        let cmd = format!("wx {} @ {}", hex_encode(&data), addr);
        let _r = self.cmd(cmd.as_str());
    }

    // get_address tries to be a bit smart, maybe a bad idea
    pub fn get_address(&mut self, symbol: &str) -> R2Result<u64> {
        let mut val = "".to_owned();
        if self.mode == Mode::Frida {
            let cmd = format!(":isa {}", symbol);
            val = self.cmd(cmd.as_str()).unwrap_or_default();
        }
        if val == "" || val == "0x0\n" {
            for prefix in &["", "sym.", "sym.imp.", "sym.unk."] {
                let cmd = format!("?v {}{}", prefix, symbol);
                val = self.cmd(cmd.as_str()).unwrap_or_default();
                if val != "" && val != "0x0\n" {
                    break;
                }
            }
        }
        if val.len() > 3 {
            r2_result(u64::from_str_radix(&val[2..val.len() - 1], 16))
        } else {
            Ok(0) // to be consistent with r2?
        }
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

    pub fn get_flag(&mut self, addr: u64) -> R2Result<String> {
        self.cmd(&format!("fd @ 0x{:x}", addr))
    }

    // load libraries, return list of full loaded paths
    pub fn load_libraries(&mut self, lib_paths: &[String]) -> R2Result<Vec<String>> {
        let paths = self.load_library_helper(lib_paths, &[])?;
        self.cmd("op 3").unwrap_or_default(); // usually the main module is 3 idk
        Ok(paths)
    }

    // this got a little nuts
    pub fn load_library_helper(
        &mut self,
        lib_paths: &[String],
        loaded_paths: &[String],
    ) -> R2Result<Vec<String>> {
        let bits = self.info.bin.bits;
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
                let lib_path = Path::new(path)
                    .join(lib)
                    .to_str()
                    .unwrap_or_default()
                    .to_owned();

                let loaded = full_paths.iter().any(|x| x == &lib_path);
                if !loaded && Path::new(&lib_path).exists() {
                    let load_addr = (high_addr & 0xfffffffffffff000) + 0x3000; // idk
                    self.cmd(format!("o {} {}", &lib_path, load_addr).as_str())?;
                    full_paths.push(lib_path);

                    sections = self.get_segments().unwrap();
                    high_addr = sections.iter().map(|s| s.vaddr).max().unwrap();

                    for export in &self.get_exports().unwrap() {
                        if let Some(reloc) = relocation_map.get(&export.name) {
                            // write the export address into the reloc
                            self.cmd(
                                format!("wv{} {} @ {}", bits / 8, export.vaddr, reloc.vaddr)
                                    .as_str(),
                            )?;
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
                            self.cmd(
                                format!("wv{} {} @ {}", bits / 8, export.vaddr, reloc.vaddr)
                                    .as_str(),
                            )?;
                        }
                    }
                    break;
                }
            }
        }

        Ok(full_paths)
    }

    pub fn clear(&mut self) {}

    pub fn close(&mut self) {
        self.r2p.lock().unwrap().close();
    }
}
