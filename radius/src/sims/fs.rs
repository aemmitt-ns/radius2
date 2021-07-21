use crate::value::Value;
use std::fs;

#[derive(Debug, Clone)]
pub enum FileMode {
    Read,
    Write,
    Append
}

/// Stat structure from kernel_stat64
#[derive(Default, Debug, Clone)]
struct Stat {
    st_dev:     u64,
    st_ino:     u64,
    st_mode:    u32,
    st_nlink:   u32,
    st_uid:     u32,
    st_gid:     u32,
    st_rdev:    u64,
    __pad1:     u64,

    st_size:    i64,
    st_blksize: i32,
    __pad2:     i32,

    st_blocks: i64,

    st_atime:     u64,
    st_atimensec: u64,
    st_mtime:     u64,
    st_mtimensec: u64,
    st_ctime:     u64,
    st_ctimensec: u64,
    
    __glibc_reserved: [i32; 2],
}

#[derive(Debug, Clone)]
pub struct SimFile {
    pub path: String,
    pub fd: usize,
    pub position: usize,
    pub mode: FileMode,
    pub content: Vec<Value>,
    pub metadata: Option<fs::Metadata>
}

#[derive(Debug, Clone)]
pub struct SimFilesytem {
    pub files: Vec<SimFile>,
}

impl SimFilesytem {

    pub fn new() -> Self {
        let files = SimFilesytem::get_stdio();
        SimFilesytem {
            files
        }
    }

    pub fn open(&mut self, path: &str, mode: FileMode) -> Option<usize> {

        for file in &self.files {
            if file.path == path {
                return Some(file.fd);
            }
        }

        let fd = self.files.len();
        let data = fs::read(path);

        if data.is_ok() {
            let metadata = fs::metadata(path).unwrap();

            let mut content = vec!();
            for d in data.unwrap() {
                content.push(Value::Concrete(d as u64, 0));
            } 

            let file = SimFile {
                path: path.to_owned(),
                fd,
                position: 0,
                mode,
                content,
                metadata: Some(metadata)
            };

            self.files.push(file);
            Some(fd)
        } else {
            None
        }
    }

    pub fn read(&mut self, fd: usize, length: usize) -> Vec<Value> {
        let mut file = self.files.remove(fd);
        let start = file.position;
        let end = if file.content.len() - start < length {
            file.content.len() - start
        } else {
            length
        };

        file.position = end;
        let data = file.content[start..end].to_vec();
        self.files.insert(fd, file);
        data
    }

    pub fn write(&mut self, fd: usize, data: Vec<Value>) {
        let mut file = self.files.remove(fd);
        file.position = data.len();
        file.content.extend(data);
        self.files.insert(fd, file);
    }

    // for adding data to a file without moving position
    // basically if you want to fake data in a file to be read
    pub fn add(&mut self, fd: usize, data: Vec<Value>) {
        let mut file = self.files.remove(fd);
        file.content.extend(data);
        self.files.insert(fd, file);
    }

    pub fn seek(&mut self, fd: usize, pos: usize) {
        let mut file = self.files.remove(fd);
        file.position = pos;
        self.files.insert(fd, file);
    }

    pub fn access(&mut self, path: &str) -> Value {
        for file in &self.files {
            if file.path == path {
                return Value::Concrete(0, 0);
            }
        }
        let metadata = fs::metadata(path);
        if metadata.is_ok() {
            Value::Concrete(0, 0)
        } else {
            Value::Concrete(-1i64 as u64, 0)
        }
    }

    pub fn touch(&mut self, path: &str, mode: FileMode) {
        let fd = self.files.len();

        let file = SimFile {
            path: path.to_owned(),
            fd,
            position: 0,
            mode,
            content: vec!(),
            metadata: None
        };

        self.files.push(file);
    }

    pub fn close(&mut self, fd: usize) {
        self.seek(fd, 0); // uhh just go to 0 for now
    }

    pub fn get_stdio() -> Vec<SimFile> {
        let mut stdio = vec!();

        stdio.push(SimFile {
            path: "STDIN".to_owned(), // idk
            fd: 0,
            position: 0,
            mode: FileMode::Read,
            content: vec!(),
            metadata: None
        });

        stdio.push(SimFile {
            path: "STDOUT".to_owned(),
            fd: 1,
            position: 0,
            mode: FileMode::Write,
            content: vec!(),
            metadata: None
        });

        stdio.push(SimFile {
            path: "STDERR".to_owned(),
            fd: 2,
            position: 0,
            mode: FileMode::Write,
            content: vec!(),
            metadata: None
        });

        stdio
    }
}