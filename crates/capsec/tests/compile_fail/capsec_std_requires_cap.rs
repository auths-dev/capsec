/// capsec::fs functions require a capability token — calling without one must fail.
fn main() {
    let _ = capsec::fs::read_to_string("/etc/passwd");
}
