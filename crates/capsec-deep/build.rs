/// Embeds the sysroot library path so the binary can find librustc_driver at runtime.
fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = std::process::Command::new(&rustc)
        .arg("--print=sysroot")
        .output()
        .expect("Failed to run rustc --print=sysroot");
    let sysroot = String::from_utf8(output.stdout)
        .expect("Invalid UTF-8 from rustc --print=sysroot");
    let sysroot = sysroot.trim();

    // Link against the sysroot lib directory so librustc_driver.dylib/.so is found
    println!("cargo:rustc-link-arg=-Wl,-rpath,{sysroot}/lib");
}
