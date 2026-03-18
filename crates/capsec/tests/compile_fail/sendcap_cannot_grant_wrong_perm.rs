/// SendCap<FsRead>::as_cap() returns Cap<FsRead>, which cannot satisfy Has<NetConnect>.
/// Cross-thread transfer does not escalate permissions.
use capsec::prelude::*;

fn needs_net(_: &impl Has<NetConnect>) {}

fn main() {
    let root = capsec::root();
    let send_cap = root.grant::<FsRead>().make_send();
    let cap = send_cap.as_cap();
    needs_net(&cap);
}
