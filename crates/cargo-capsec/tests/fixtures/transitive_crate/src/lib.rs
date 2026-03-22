use std::fs;

fn read_helper() -> Vec<u8> {
    fs::read("data.bin").unwrap()
}

pub fn public_api() -> Vec<u8> {
    read_helper()
}
