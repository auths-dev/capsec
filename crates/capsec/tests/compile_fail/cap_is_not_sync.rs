/// Cap<P> is !Sync — it cannot be shared across threads by reference.
use capsec::prelude::*;

fn assert_sync<T: Sync>() {}

fn main() {
    assert_sync::<Cap<FsRead>>();
}
