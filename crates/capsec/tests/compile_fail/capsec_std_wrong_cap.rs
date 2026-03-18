/// capsec::fs::read_to_string requires Has<FsRead>, not Has<NetConnect>.
/// Passing the wrong capability type must fail.
use capsec::prelude::*;

fn main() {
    let root = capsec::root();
    let net_cap = root.grant::<NetConnect>();
    let _ = capsec::fs::read_to_string("/etc/passwd", &net_cap);
}
