/// FsRead does NOT subsume FsAll — subsumption only works upward.
/// A narrower permission cannot satisfy a broader requirement.
use capsec::prelude::*;

fn needs_fs_all(_: &impl Has<FsAll>) {}

fn main() {
    let root = capsec::root();
    let fs_read = root.grant::<FsRead>();
    needs_fs_all(&fs_read);
}
