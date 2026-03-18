/// Attempt to implement the private Sealed trait from an external crate.
///
/// The `Permission` trait requires `sealed::Sealed`, which lives in a private
/// module inside capsec-core. External crates cannot name it, so they cannot
/// implement Permission for custom types.
///
/// This test proves that even if you try to reach into the sealed module
/// path, the compiler rejects it.

// Approach 1: try to implement Permission directly (requires Sealed)
use capsec::prelude::*;

struct EvilPerm;
impl Permission for EvilPerm {}

fn main() {}
