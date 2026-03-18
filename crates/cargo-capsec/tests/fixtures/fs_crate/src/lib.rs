use std::fs;
use std::fs::File;
use std::io::Write;

pub fn read_config() -> String {
    fs::read_to_string("/etc/config.toml").unwrap_or_default()
}

pub fn read_bytes(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

pub fn save_output(path: &str, data: &[u8]) {
    fs::write(path, data).unwrap();
}

pub fn list_dir(path: &str) -> Vec<String> {
    fs::read_dir(path)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect()
}

pub fn open_file(path: &str) {
    let _f = File::open(path).unwrap();
}

pub fn create_file(path: &str) {
    let mut f = File::create(path).unwrap();
    f.write_all(b"hello").unwrap();
}

pub fn cleanup(path: &str) {
    fs::remove_file(path).unwrap();
}

pub fn nuke_dir(path: &str) {
    fs::remove_dir_all(path).unwrap();
}

pub fn copy_file(src: &str, dst: &str) {
    fs::copy(src, dst).unwrap();
}

pub fn check_metadata(path: &str) -> u64 {
    fs::metadata(path).unwrap().len()
}
