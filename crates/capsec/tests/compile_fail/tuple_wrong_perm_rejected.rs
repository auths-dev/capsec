/// A Cap<(FsRead, NetConnect)> must not satisfy Has<FsWrite>.
/// Tuple caps only grant the permissions they contain.
use capsec::prelude::*;

fn needs_write(_: &impl Has<FsWrite>) {}

fn main() {
    let root = capsec::root();
    let cap = root.grant::<(FsRead, NetConnect)>();
    needs_write(&cap);
}
