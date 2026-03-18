/// FsAll subsumes FsRead and FsWrite, but NOT NetConnect.
/// Subsumption does not cross permission categories.
use capsec::prelude::*;

fn needs_net(_: &impl Has<NetConnect>) {}

fn main() {
    let root = capsec::root();
    let fs_all = root.grant::<FsAll>();
    needs_net(&fs_all);
}
