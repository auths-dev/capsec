# capsec-tests

Adversarial security tests for capsec. This crate tries to break the type system, evade the audit tool, and escape scope restrictions.

## Running

```bash
# All tests
cargo test -p capsec-tests

# By category
cargo test -p capsec-tests --test type_system
cargo test -p capsec-tests --test audit_evasion
cargo test -p capsec-tests --test scope_escapes
cargo test -p capsec-tests --test compile_attacks

# Regenerate compile-fail .stderr snapshots (after toolchain bump)
TRYBUILD=overwrite cargo test -p capsec-tests --test compile_attacks

# Full documented run (saves output + metadata to docs/)
./docs/run-tests.sh
```

## Test organization

```
tests/
  type_system.rs        # Forge capabilities, escalate permissions, bypass CapRoot
  audit_evasion.rs      # Source code that dodges cargo-capsec detection
  scope_escapes.rs      # Break out of DirScope / HostScope restrictions
  compile_attacks.rs    # trybuild harness for attacks that must not compile
  compile_fail/
    sealed_impl_from_outside.rs   # Implement Permission from external crate
    sealed_impl_from_outside.stderr

docs/
  run-tests.sh          # Reproducible test runner (timestamps + metadata)
  run-001/              # First recorded run
    test-output.txt
    findings.md         # Full adversarial review with severity ratings
```

### type_system.rs (20 tests)

- **Has\<P\> forgery** — safe-code capability forgery via `panic!()` divergence (the critical finding)
- **capsec-std end-to-end exploits** — forged caps actually work with `fs::read`, `env::var`
- **unsafe forgery** — `transmute`, `MaybeUninit`, `ptr::read` (expected, documented)
- **SendCap cross-thread** — roundtrip through `make_send()` / `as_cap()`, no escalation
- **Attenuated move semantics** — `.attenuate()` consumes the original cap
- **Negative controls** — clone, subsumption, cross-category all correctly blocked

### audit_evasion.rs (28 tests)

Confirmed evasions: function pointers, `include!()`, inline assembly, module re-exports, dependency re-exports, libc/nix calls.

Fixed evasions: glob imports (`use std::fs::*; read(...)` now detected).

Detection positive controls: `std::fs`, `File::open`, `TcpStream::connect`, `Command::new`, `env::var`, `extern` blocks, tokio, reqwest, aliased imports, closures, cfg-gated code.

### scope_escapes.rs (11 tests)

DirScope: `../` traversal, absolute escape, non-existent paths — all blocked.
HostScope: prefix collision (`api.example.com.evil.com`) — confirmed bug.

### compile_attacks.rs (1 trybuild test)

Proves `impl Permission for EvilPerm {}` fails because `Sealed` is in a private module.
