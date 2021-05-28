
use r2pipe::R2Pipe;
use serde::{Deserialize, Serialize};
use std::u64;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq)]
pub enum Endian {
    Little,
    Big,
    Mixed,
    Unknown
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
    pub type_num: u64,

    #[serde(default="zero")]
    pub jump: u64,

    #[serde(default="zero")]
    pub fail: u64  
}

fn invalid() -> String {
    "invalid".to_string()
}

fn blank() -> String {
    "".to_string()
}

fn zero() -> u64 {
    0
}

#[derive(Debug)]
pub struct Permission {
    pub  initialized: bool,
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
    pub size: u64,
    pub mode: String,
    pub format: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinInfo {
    pub arch: String,
    pub bits: u64,
    pub canary: bool,
    pub endian: String,
    pub os: String,
    pub nx: bool
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Information {
    pub core: CoreInfo,
    pub bin: BinInfo
}

// #[derive(DerefMut)]
#[derive(Clone)]
pub struct R2Api {
    pub r2p: Arc<Mutex<R2Pipe>>,
    //pub instructions: HashMap<u64, Instruction>,
    //pub permissions: HashMap<u64, Permission>,
    pub info: Option<Information>
}

impl R2Api {
    pub fn new(filename: Option<String>) -> R2Api {
        let mut r2api = R2Api {
            r2p: Arc::new(Mutex::new(open_pipe!(filename).unwrap())),
            //instructions: HashMap::new(),
            //permissions: HashMap::new(),
            info: None
        };
    
        r2api.get_info();
        r2api
    }

    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        self.r2p.lock().unwrap().cmd(cmd)
    }

    fn get_info(&mut self) {
        if self.info.is_none() {
            let json = self.cmd("ij").unwrap();
            self.info = serde_json::from_str(json.as_str()).unwrap();
        }
    }

    pub fn get_registers(&mut self) -> RegisterInformation {
        let json = self.cmd("aerpj").unwrap();
        serde_json::from_str(json.as_str()).unwrap()
    }

    pub fn get_cc(&mut self, pc: u64) -> CallingConvention {
        let json = self.cmd(format!("af @ {}; afcrj @ {}", pc, pc).as_str()).unwrap();
        serde_json::from_str(json.as_str()).unwrap()
    }

    pub fn get_ret(&mut self) -> String {
        // simple as that?
        let ret = self.cmd("pae ret").unwrap();
        ret[0..ret.len()-1].to_owned()
    }

    pub fn get_register_value(&mut self, reg: &str) -> u64 {
        let cmd = format!("aer {}", reg);
        let val = self.cmd(cmd.as_str()).unwrap();
        // println!("val: {}", val);
        u64::from_str_radix(&val[2..val.len()-1], 16).unwrap()
    }

    pub fn seek(&mut self, addr: u64) {
        let _r = self.cmd(format!("s {}", addr).as_str());
    }

    pub fn breakpoint(&mut self, addr: u64) {
        let _r = self.cmd(format!("db {}", addr).as_str());
    }

    pub fn init_vm(&mut self) {
        let _r = self.cmd("aei; aeim");
    }

    pub fn disassemble(&mut self, addr: u64, num: usize) -> Vec<Instruction> {
        let cmd = format!("pdj {} @ {}", num, addr);
        let json = self.cmd(cmd.as_str()).unwrap();
        serde_json::from_str(json.as_str()).unwrap()
    }

    pub fn read(&mut self, addr: u64, length: usize) -> Vec<u8> {
        let cmd = format!("xj {} @ {}", length, addr);
        let json = self.cmd(cmd.as_str()).unwrap();
        serde_json::from_str(json.as_str()).unwrap()
    }

    pub fn write(&mut self, addr: u64, data: Vec<u8>) {
        let cmd = format!("wx {} @ {}", hex::encode(data), addr);
        let _r = self.cmd(cmd.as_str());
    }

    pub fn get_address(&mut self, symbol: &str) -> u64 {
        let cmd = format!("?v {}", symbol);
        let val = self.cmd(cmd.as_str()).unwrap();
        u64::from_str_radix(&val[2..val.len()-1], 16).unwrap()
    }

    pub fn clear(&mut self) {
        
    }

    pub fn close(&mut self) {
        self.r2p.lock().unwrap().close();
    }
}