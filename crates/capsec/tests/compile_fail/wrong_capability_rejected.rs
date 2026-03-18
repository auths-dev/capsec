/// A Cap<FsRead> must not satisfy Has<NetConnect>.
/// The type system must reject mismatched capabilities.
use capsec::prelude::*;

fn needs_net(_: &impl Has<NetConnect>) {}

fn main() {
    let root = capsec::root();
    let fs_cap = root.grant::<FsRead>();
    needs_net(&fs_cap);
}
