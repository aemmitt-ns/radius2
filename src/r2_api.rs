
const INSTR_NUM: usize = 16;

use r2pipe::R2Pipe;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::u64;
use hex;

#[derive(Debug, Clone)]
pub enum Endian {
    Little,
    Big,
    Mixed,
    Unknown
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub offset: u64,
    pub size: u64,
    pub opcode: String,
    pub esil: String,
    pub bytes: String,
    pub r#type: String,
    pub type_num: u64  
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
pub struct R2Api {
    pub r2p: R2Pipe,
    pub instructions: HashMap<u64, Instruction>,
    pub permissions: HashMap<u64, Permission>,
    pub info: Option<Information>
}

impl R2Api {
    fn get_info(&mut self) {
        if self.info.is_none() {
            let json = self.r2p.cmd("ij").unwrap();
            self.info = serde_json::from_str(json.as_str()).unwrap();
        }
    }

    pub fn get_registers(&mut self) -> RegisterInformation {
        let json = self.r2p.cmd("aerpj").unwrap();
        let registers: RegisterInformation = 
            serde_json::from_str(json.as_str()).unwrap();

        registers
    }

    pub fn get_register_value(&mut self, reg: &String) -> u64 {
        let cmd = format!("aer {}", reg);
        let val = self.r2p.cmd(cmd.as_str()).unwrap();
        // println!("val: {}", val);
        u64::from_str_radix(&val[2..val.len()-1], 16).unwrap()
    }

    pub fn disassemble(&mut self, addr: u64) -> &Instruction {
        if self.instructions.contains_key(&addr) {
            return self.instructions.get(&addr).unwrap()
        }

        let cmd = format!("pdj {} @ {}", INSTR_NUM, addr);
        let json = self.r2p.cmd(cmd.as_str()).unwrap();
        let instructions: Vec<Instruction> = 
            serde_json::from_str(json.as_str()).unwrap();

        for instr in instructions {
            self.instructions.insert(instr.offset, instr);
        }

        self.instructions.get(&addr).unwrap()
    }

    pub fn read(&mut self, addr: u64, length: usize) -> Vec<u8> {
        let cmd = format!("xj {} @ {}", length, addr);
        let json = self.r2p.cmd(cmd.as_str()).unwrap();
        serde_json::from_str(json.as_str()).unwrap()
    }

    pub fn write(&mut self, addr: u64, data: Vec<u8>) {
        let cmd = format!("wx {} @ {}", hex::encode(data), addr);
        self.r2p.cmd(cmd.as_str());
    }

    fn close(&mut self) {
        self.r2p.close();
    }
}

pub fn create(filename: Option<String>) -> R2Api {
    let mut r2api = R2Api {
        r2p: open_pipe!(filename).unwrap(),
        instructions: HashMap::new(),
        permissions: HashMap::new(),
        info: None
    };

    r2api.get_info();
    r2api
}