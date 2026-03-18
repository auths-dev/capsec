/// Cap<P> is !Send — it cannot be transferred to another thread.
/// Users must explicitly opt in via make_send() for cross-thread use.
use capsec::prelude::*;

fn assert_send<T: Send>() {}

fn main() {
    assert_send::<Cap<FsRead>>();
}
