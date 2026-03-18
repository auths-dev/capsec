# capsec-core

Zero-cost capability tokens and permission traits for compile-time capability-based security in Rust.

This is the foundation crate of the [capsec](https://github.com/bordumb/capsec) ecosystem. You probably want to depend on the `capsec` facade crate instead of using this directly.

## What's in here

- **`Permission`** — sealed marker trait for capability categories (`FsRead`, `NetConnect`, `Spawn`, etc.)
- **`Cap<P>`** — zero-sized proof token that the holder has permission `P`
- **`Has<P>`** — trait bound for declaring capability requirements in function signatures
- **`CapRoot`** — singleton factory for granting capabilities
- **`Attenuated<P, S>`** — scope-restricted capabilities (`DirScope`, `HostScope`)

All types are zero-sized at runtime. No overhead.

## Example

```rust,ignore
use capsec_core::root::test_root;
use capsec_core::permission::FsRead;
use capsec_core::has::Has;

let root = test_root();
let cap = root.grant::<FsRead>();

fn needs_fs(cap: &impl Has<FsRead>) {
    // can only be called with proof of FsRead permission
}

needs_fs(&cap);
```

## License

MIT OR Apache-2.0
