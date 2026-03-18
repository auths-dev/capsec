# capsec

Compile-time capability-based security for Rust.

This is the facade crate — it re-exports everything from `capsec-core`, `capsec-macro`, and `capsec-std` under a single dependency. This is the crate you should depend on.

## Install

```bash
cargo add capsec
```

## Quick start

```rust,ignore
use capsec::prelude::*;

fn main() {
    let root = capsec::root();
    let fs_cap = root.grant::<FsRead>();

    let data = load_data("/tmp/data.csv", &fs_cap).unwrap();
    let result = transform(&data);
}

// Requires filesystem read — enforced by the compiler
fn load_data(path: &str, cap: &impl Has<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(path, cap)
}

// No capability token — this function cannot do I/O
fn transform(input: &str) -> String {
    input.to_uppercase()
}
```

## What's re-exported

| From | What you get |
|------|-------------|
| `capsec-core` | `Cap`, `Has`, `Permission`, `CapRoot`, `FsRead`, `NetConnect`, etc. |
| `capsec-macro` | `#[capsec::requires(...)]`, `#[capsec::deny(...)]` |
| `capsec-std` | `capsec::fs`, `capsec::net`, `capsec::env`, `capsec::process` |

## Testing

Use `capsec::test_root()` (requires the `test-support` feature) to bypass the singleton check in tests:

```toml
[dev-dependencies]
capsec = { version = "0.1", features = ["test-support"] }
```

## License

MIT OR Apache-2.0
