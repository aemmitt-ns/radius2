use crate::value::Value;
use std::fs;
// use std::io;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub enum FileMode {
    Read,
    Write,
    Append,
}

/// Stat structure from kernel_stat64
#[derive(Default, Debug, Clone)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,

    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub st_blocks: i64,

    pub st_atime: u64,
    pub st_atimensec: u64,
    pub st_mtime: u64,
    pub st_mtimensec: u64,
    pub st_ctime: u64,
    pub st_ctimensec: u64,

    pub __glibc_reserved: [i32; 2],
}

#[derive(Debug, Clone)]
pub struct SimFile {
    pub path: String,
    pub fd: usize,
    pub position: usize,
    pub mode: FileMode,
    pub content: Vec<Value>,
    pub metadata: Option<fs::Metadata>,
}

#[derive(Debug, Clone)]
pub struct SimFilesytem {
    pub files: Vec<SimFile>,
}

impl Default for SimFilesytem {
    fn default() -> Self {
        Self::new()
    }
}

impl SimFilesytem {
    pub fn new() -> Self {
        let files = SimFilesytem::get_stdio();
        SimFilesytem { files }
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

            let mut content = Vec::with_capacity(512);
            for d in data.unwrap() {
                content.push(Value::Concrete(d as u64, 0));
            }

            let file = SimFile {
                path: path.to_owned(),
                fd,
                position: 0,
                mode,
                content,
                metadata: Some(metadata),
            };

            self.files.push(file);
            Some(fd)
        } else {
            None
        }
    }

    pub fn read(&mut self, fd: usize, length: usize) -> Vec<Value> {
        if let Some(file) = &mut self.files.get_mut(fd) {
            let start = file.position;
            let end = if file.content.len() - start < length {
                file.content.len()
            } else {
                start + length
            };

            file.position = end;
            file.content[start..end].to_vec()
        } else {
            vec![]
        }
    }

    pub fn fill(&mut self, fd: usize, data: &[Value]) {
        self.files[fd].content.extend(data.to_owned());
    }

    pub fn dump(&mut self, fd: usize) -> Vec<Value> {
        self.files[fd].content.clone()
    }

    pub fn write(&mut self, fd: usize, data: Vec<Value>) -> Option<Value> {
        if let Some(file) = &mut self.files.get_mut(fd) {
            let length = data.len();
            file.position += length;
            file.content.extend(data);
            Some(Value::Concrete(length as u64, 0))
        } else {
            None
        }
    }

    pub fn seek(&mut self, fd: usize, pos: usize, whence: usize) -> Option<Value> {
        if let Some(file) = &mut self.files.get_mut(fd) {
            if whence == 0 {
                file.position = pos;
            } else if whence == 1 {
                file.position += pos;
            } else if whence == 2 {
                file.position = file.content.len() + pos;
            }
            Some(Value::Concrete(file.position as u64, 0))
        } else {
            None
        }
    }

    pub fn getfd(&mut self, path: &str) -> Option<usize> {
        self.files.iter().find(|f| f.path == path).map(|f| f.fd)
    }

    pub fn getpath(&mut self, fd: usize) -> Option<String> {
        self.files
            .iter()
            .find(|f| f.fd == fd)
            .map(|f| f.path.clone())
    }

    pub fn access(&mut self, path: &str) -> Value {
        if self.files.iter().any(|f| f.path == path) {
            return Value::Concrete(0, 0);
        }

        let metadata = fs::metadata(path);
        if metadata.is_ok() {
            Value::Concrete(0, 0)
        } else {
            Value::Concrete(-1i64 as u64, 0)
        }
    }

    pub fn stat(&mut self, path: &str) -> Option<Stat> {
        let metadata = fs::metadata(path);
        if let Ok(meta) = metadata {
            Some(Stat {
                st_dev: 16777234,
                st_ino: 3334575,
                st_mode: 33188,
                st_nlink: 0,
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                __pad0: 0,

                st_size: meta.len() as i64,
                st_blksize: 0x1000,
                st_blocks: 8,

                st_atime: meta
                    .accessed()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                st_atimensec: 0,
                st_mtime: meta
                    .modified()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                st_mtimensec: 0,
                st_ctime: meta
                    .created()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                st_ctimensec: 0,

                __glibc_reserved: [0, 0],
            })
        } else {
            None
        }
    }

    pub fn touch(&mut self, path: &str, mode: FileMode) {
        let fd = self.files.len();

        let file = SimFile {
            path: path.to_owned(),
            fd,
            position: 0,
            mode,
            content: vec![],
            metadata: None,
        };

        self.files.push(file);
    }

    pub fn close(&mut self, fd: usize) {
        self.seek(fd, 0, 0); // uhh just go to 0 for now
    }

    pub fn add_file(&mut self, path: &str, data: &[Value]) {
        self.files.push(SimFile {
            path: path.to_owned(),
            fd: self.files.len(),
            position: 0,
            mode: FileMode::Read,
            content: data.to_owned(),
            metadata: None,
        });
    }

    pub fn remove_file(&mut self, path: &str) {
        let f = self.files.iter().find(|f| f.path == path).map(|f| f.fd);
        if let Some(fd) = f {
            self.files.remove(fd);
        }
    }

    pub fn get_stdio() -> Vec<SimFile> {
        vec![
            SimFile {
                path: "STDIN".to_owned(), // idk
                fd: 0,
                position: 0,
                mode: FileMode::Read,
                content: Vec::with_capacity(256),
                metadata: None,
            },
            SimFile {
                path: "STDOUT".to_owned(),
                fd: 1,
                position: 0,
                mode: FileMode::Write,
                content: Vec::with_capacity(256),
                metadata: None,
            },
            SimFile {
                path: "STDERR".to_owned(),
                fd: 2,
                position: 0,
                mode: FileMode::Write,
                content: Vec::with_capacity(256),
                metadata: None,
            },
        ]
    }
}
