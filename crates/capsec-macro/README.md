# capsec-macro

Procedural macros for the [capsec](https://github.com/bordumb/capsec) capability-based security system.

You probably want to depend on the `capsec` facade crate instead of using this directly — it re-exports these macros.

## Macros

### `#[capsec::requires(...)]`

Declares a function's capability requirements. Documents intent and enables tooling.

```rust,ignore
#[capsec::requires(fs::read, net::connect)]
fn sync_data(fs: &impl Has<FsRead>, net: &impl Has<NetConnect>) -> Result<()> {
    // ...
}
```

### `#[capsec::deny(...)]`

Marks a function as capability-free. The `cargo capsec check` lint tool will flag any ambient authority call inside it.

```rust,ignore
#[capsec::deny(all)]
fn pure_transform(input: &[u8]) -> Vec<u8> {
    input.iter().map(|b| b.wrapping_add(1)).collect()
}
```

## Supported permissions

`fs::read`, `fs::write`, `fs::all`, `net::connect`, `net::bind`, `net::all`, `env::read`, `env::write`, `spawn`, `all`

## License

MIT OR Apache-2.0
