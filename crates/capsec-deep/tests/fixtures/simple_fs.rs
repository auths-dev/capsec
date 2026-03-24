use std::fs;

fn load_config() -> Vec<u8> {
    fs::read("config.toml").unwrap()
}

fn main() {
    let _ = load_config();
}
