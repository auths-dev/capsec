# Adversarial Review: capsec v0.1.0

**Date:** 2026-03-18
**Reviewer:** Automated adversarial test suite (`capsec-tests`)
**Toolchain:** Rust 1.94.0 (pinned via `rust-toolchain.toml`)
**Test results:** 53/53 passing (14 type system, 28 audit evasion, 11 scope)

---

## 1. Type System Attacks

### CRITICAL: `Has<P>` is not sealed — safe-code forgery

**Severity: CRITICAL**
**Requires unsafe: NO**

The `Has<P>` trait is public and not sealed. External crates can implement it for arbitrary types using a diverging expression (`panic!()`, `loop {}`, `std::process::exit()`), completely bypassing `CapRoot::grant()`.

**Proof of concept:**

```rust
struct Forgery;

impl Has<FsRead> for Forgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        panic!("never called")
    }
}

// This works — reads /dev/null with a forged capability:
let data = capsec_std::fs::read("/dev/null", &Forgery).unwrap();
```

**Why it works:** `capsec-std` functions accept `_cap: &impl Has<P>` and never call `cap_ref()`. The `panic!()` in `cap_ref()` uses the never type (`!`), which coerces to `Cap<P>`, satisfying the return type. Since `cap_ref()` is never called, the panic never fires.

**Test coverage:**
- `has_forgery_via_panic_divergence` — basic forgery
- `has_forgery_via_loop_divergence` — alternative divergence
- `has_forgery_via_process_exit` — yet another divergence
- `god_forgery_satisfies_all_permissions` — forge ALL permissions at once
- `forgery_works_with_capsec_std_fs_read` — end-to-end exploit
- `forgery_works_with_capsec_std_read_to_string` — variant
- `forgery_works_with_capsec_std_env_var` — env read forgery

**Fix options:**
1. **Seal `Has<P>`** — add `Has<P>: sealed::Sealed` requirement. Prevents external impls entirely.
2. **Call `cap_ref()` in capsec-std** — change `_cap` parameters to call `cap.cap_ref()` and drop the result. Forces the diverging impl to actually execute (and panic). This is a runtime check, not compile-time, but it's defense-in-depth.
3. **Both** — seal the trait AND call `cap_ref()`. Belt and suspenders.

**Recommendation:** Option 3. Sealing `Has` is the correct compile-time fix. Calling `cap_ref()` adds runtime defense against future oversights.

### Expected: unsafe forgery works

Forging `Cap<P>` via `transmute`, `MaybeUninit`, or `ptr::read` all work with `unsafe`. This is expected and NOT a bug — `unsafe` can break any Rust abstraction. Documenting it is sufficient.

**Tests:** `transmute_forgery_works_with_unsafe`, `maybe_uninit_forgery_works_with_unsafe`, `ptr_read_forgery_works_with_unsafe`

### Correctly blocked attacks

| Attack | Result | Evidence |
|--------|--------|----------|
| `Cap::new()` from outside crate | BLOCKED | Existing compile-fail test |
| Implement `Permission` for custom type | BLOCKED | `sealed::Sealed` in private mod |
| `Cap<FsRead>` satisfies `Has<NetConnect>` | BLOCKED | No cross-category impl |
| `Cap<FsRead>` satisfies `Has<FsAll>` | BLOCKED | Subsumption is directional |
| Send `Cap<P>` across threads | BLOCKED | `!Send` via `PhantomData<*const ()>` |
| `SendCap<FsRead>` grants `NetConnect` | BLOCKED | Preserves permission type |
| Clone escalates permissions | BLOCKED | Clone returns same `Cap<P>` |

---

## 2. Audit Tool Evasions

### Confirmed evasions (bugs/limitations)

| Evasion | Risk | Description |
|---------|------|-------------|
| **Glob imports** | HIGH | `use std::fs::*; read("file")` — bare name not expanded |
| **Function pointers** | MEDIUM | `let f = fs::read; f("file")` — assignment not a call |
| **include!()** | HIGH | `include!("malicious.rs")` — not followed by parser |
| **Inline assembly** | LOW | `asm!("syscall", ...)` — opaque to AST analysis |
| **Module re-exports** | MEDIUM | `mod hidden { pub use std::fs::read as load; } hidden::load(...)` |
| **Dependency re-exports** | HIGH | `some_crate::util::load(...)` where it wraps `std::fs::read` |
| **libc function calls** | HIGH | `libc::open(...)` — not in authority registry |
| **nix crate calls** | HIGH | `nix::unistd::read(...)` — not in registry |

### Correctly detected (controls working)

| Pattern | Result |
|---------|--------|
| `std::fs::read(...)` fully qualified | DETECTED |
| `use std::fs; fs::read(...)` | DETECTED |
| `use std::fs::read as load; load(...)` | DETECTED |
| `std::fs::read` inside closure body | DETECTED |
| `File::open(...)` | DETECTED |
| `TcpStream::connect(...)` | DETECTED |
| `Command::new(...)` | DETECTED |
| `env::var(...)` | DETECTED |
| `extern "C" { fn open(...); }` | DETECTED |
| `tokio::fs::read(...)` | DETECTED |
| `reqwest::get(...)` | DETECTED |
| `#[cfg(target_os = "linux")] std::fs::read` | DETECTED |
| `use std::net::*; TcpStream::connect(...)` | DETECTED (path already qualified) |

### Evasion risk assessment

**Supply chain threat:** A malicious crate author would most likely use:
1. **Dependency re-exports** (HIGH) — trivial, natural-looking, no workarounds
2. **Function pointers** (MEDIUM) — harder to review but still plausible
3. **include!()** (HIGH for targeted attacks) — effective but suspicious to reviewers

**For legitimate code auditing**, the biggest gap is:
- **Glob imports** — common in Rust code, especially `use std::io::*`
- **Missing crates in registry** — libc, nix, mio, etc.

---

## 3. Scope Escape Attacks

### HostScope prefix collision (design limitation)

**Severity: MEDIUM**

`HostScope` uses `String::starts_with()` for matching. This means:
- Allowing `"api.example.com"` also matches `"api.example.com.evil.com"`

**Test:** `hostscope_prefix_collision_attack`

**Fix:** Add a separator check — after the prefix match, verify the next character is `:`, `/`, or end-of-string.

### DirScope: solid

All DirScope attacks correctly fail:
- `../` traversal → blocked by canonicalization
- Absolute paths outside scope → blocked by `starts_with`
- Non-existent paths → fail conservatively (can't canonicalize)
- Non-existent root → can't create scope at all

---

## 4. Claim vs Reality Gaps

### `#[requires(...)]` does NOT enforce anything at compile time

The macro adds a `#[doc]` attribute. It does NOT add trait bounds, does NOT modify the function signature, and does NOT inject any compile-time check. A function marked `#[requires(fs::read)]` can freely call `std::fs::read("file")` without any capability token.

**Impact:** Documentation should clearly state that `#[requires]` is for documentation and tooling integration, not enforcement. The enforcement comes from `&impl Has<P>` parameters in function signatures.

### `#[deny(...)]` does NOT enforce anything at compile time

Same as `#[requires]` — purely documentary. The real enforcement is via `cargo capsec audit`.

### `Has<P>` is not sealed (see Critical finding above)

The README says capabilities are "unforgeable." This is true for `Cap<P>` (constructor is `pub(crate)`), but `Has<P>` — the trait actually used in function signatures — can be freely implemented by external crates.

### test-support feature flag leakage

If ANY crate in the dependency tree enables `test-support` on `capsec-core`, `test_root()` becomes available in all crates that depend on it. Cargo feature unification means a dev-dependency enabling it could leak into the main build. Currently mitigated by capsec's own Cargo.toml using `test-support` only in `[dev-dependencies]`, but downstream users could get this wrong.

---

## 5. Honest Threat Model

### What capsec DOES protect against

1. **Accidental ambient authority** — developer forgets they're doing I/O in a function that shouldn't. The `Has<P>` trait bound forces explicit declaration.
2. **Code review clarity** — grep for `CapRoot::grant()` to find every authority entry point.
3. **Dependency auditing** — `cargo capsec audit` catches most standard library I/O in dependencies, making it visible.
4. **Compile-time permission checking** — within cooperative code (code that plays by the rules), permissions are enforced at compile time with zero runtime cost.

### What capsec does NOT protect against

1. **Malicious code** — any code using `unsafe`, `panic!()` in Has impls, or indirect I/O can bypass the system.
2. **Complete dependency coverage** — the audit tool can't see through re-exports, function pointers, proc macros, or `include!()`.
3. **Runtime isolation** — capsec is NOT a sandbox. It doesn't use OS-level mechanisms (seccomp, Capsicum, pledge). A process with capsec still has full ambient authority at the OS level.
4. **Build script authority** — `build.rs` runs with full ambient authority. capsec can flag it but can't prevent it.

### The honest limitation statement

> capsec enforces I/O permissions at compile time within cooperative Rust code. It is a type-level discipline tool, not a security sandbox. Code using `unsafe`, proc macro generation, FFI, or inline assembly can bypass the type system. The audit tool catches common patterns but is not exhaustive — it's an AST-level heuristic, not a formal verifier.

---

## 6. Prior Art Comparison

### vs Capsicum (FreeBSD)

Capsicum operates at the OS level with kernel-enforced capability mode. Once a process enters capability mode, the kernel rejects any ambient authority syscall. capsec operates at the type level — the OS sees no difference. They are complementary, not competing.

### vs "functions take extra parameters"

capsec IS "functions take extra parameters" — but with three additions:
1. **Sealed permission types** prevent forgery of new permission categories
2. **`pub(crate)` constructor** prevents creation of tokens without CapRoot
3. **Subsumption hierarchy** (FsAll > FsRead) reduces boilerplate

The weakness (Has not sealed) means it's currently closer to "just extra parameters" than it should be.

### vs `grep -r 'std::fs'`

The audit tool adds:
1. **Import expansion** — catches `use std::fs::read as load; load()`
2. **Context-aware matching** — `.status()` only flagged when `Command::new` is nearby
3. **Risk levels** — critical vs low findings
4. **Baseline diffing** — only surface new findings in CI
5. **SARIF output** — GitHub Code Scanning integration
6. **Structured configuration** — `.capsec.toml` allow-lists

These are real improvements over grep. But the coverage gaps (glob imports, function pointers, re-exports) mean it's not dramatically better for adversarial scenarios.

---

## 7. What HN Will Say (and draft responses)

### 1. "This is just wrapping std functions with an extra parameter"

**Response:** Yes, at the core, that's exactly what it is — and that's the point. The capability pattern works because the extra parameter is unforgeable (sealed permission types, `pub(crate)` constructor) and zero-cost (ZST, erased at compile time). The value isn't in the mechanism's complexity but in its integration: a sealed type hierarchy, subsumption, proc macro annotations for documentation, and a companion audit tool for dependency scanning. It's the difference between "just add a boolean" and a formal type-level encoding of permissions.

### 2. "Any crate can just use unsafe to bypass this"

**Response:** Correct. capsec is a type-level discipline tool, not an OS sandbox. It works within Rust's type system, and `unsafe` can break any Rust abstraction. The threat model is: (a) catch accidental ambient authority in your own code at compile time, and (b) make intentional authority visible during review. For true isolation against malicious code, you need OS-level mechanisms like seccomp, Capsicum, or WASM sandboxing. capsec complements those — it doesn't replace them.

### 3. "The audit tool is just pattern matching, any obfuscation breaks it"

**Response:** Fair critique. The audit tool is an AST-level heuristic — it catches the 80% case (standard library calls with import expansion). It cannot see through function pointers, proc macros, FFI, or re-exports from dependencies. We should document this more clearly. The audit tool is meant to be run in CI to catch common patterns in dependencies, not to provide a security guarantee. For that, you'd need something like MIRAI or a formal effect system.

### 4. "How is this different from cargo-deny or cargo-vet?"

**Response:** cargo-deny/vet operate at the crate level — "do you trust this dependency?" capsec operates at the call level — "what specific I/O does this dependency do?" They're complementary. You might cargo-vet a crate as trusted but still want to know if it starts reading files in a new version. capsec's audit tool + baseline diffing catches that.

### 5. "The macro doesn't actually enforce anything"

**Response:** You're right — `#[requires(fs::read)]` and `#[deny(fs)]` are currently documentation attributes, not enforcement mechanisms. The compile-time enforcement comes from `&impl Has<P>` trait bounds in function signatures. The macros exist for tooling integration and documentation. We should make this distinction clearer in the README. The audit tool can check that `#[deny]`-annotated functions don't contain flagged calls, but the macro itself doesn't block compilation.

---

## 8. Recommended Fixes (Priority Order)

### P0 — Must fix before any "security" claims

1. **Seal `Has<P>` trait** — add a sealed supertrait to prevent external implementation. This is the only safe-code-only forgery vector.
2. **Call `cap_ref()` in capsec-std** — defense-in-depth: even if sealing is somehow bypassed, diverging impls will panic at runtime.

### P1 — Should fix before v1.0

3. **Fix glob import expansion** — when the parser sees a glob import `use std::fs::*`, it should try to match bare calls against all known names in that module path.
4. **Fix HostScope prefix collision** — add separator check after prefix match.
5. **Add libc/nix/mio to authority registry** — most common alternative I/O crates.
6. **Document #[requires]/#[deny] as non-enforcing** — make it crystal clear these are doc attributes, not enforcement.

### P2 — Nice to have

7. **Add function pointer detection** — flag `let f = std::fs::read;` (ExprPath in non-call context).
8. **Add include!() warning** — at least flag files containing `include!()` directives.
9. **Document the threat model honestly** — add a "Limitations" section to README.
10. **Add feature flag lint** — warn if `test-support` is enabled in a non-test context.
