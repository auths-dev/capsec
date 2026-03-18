/// Cap::new() is pub(crate) — external crates cannot construct capability tokens.
/// The only way to obtain a Cap<P> is through CapRoot::grant().
use capsec::prelude::*;

fn main() {
    let _cap = Cap::<FsRead>::new();
}
