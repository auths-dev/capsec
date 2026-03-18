/// The Permission trait is sealed — external crates cannot implement it.
/// This prevents forgery of new permission types outside capsec-core.
use capsec::prelude::*;

struct MyPerm;
impl Permission for MyPerm {}

fn main() {}
