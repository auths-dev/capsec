//! Audit tool evasion tests.
//!
//! Each test feeds source code to cargo-capsec's parser+detector and checks
//! whether the ambient authority is detected. Tests that pass with zero findings
//! represent real evasion vectors.

use cargo_capsec::detector::Detector;
use cargo_capsec::parser::parse_source;

/// Helper: parse source and return number of findings.
fn count_findings(source: &str) -> usize {
    let parsed = parse_source(source, "evasion_test.rs").unwrap();
    let detector = Detector::new();
    detector.analyse(&parsed, "test-crate", "0.1.0").len()
}

/// Helper: returns true if the source evades detection (zero findings).
fn evades(source: &str) -> bool {
    count_findings(source) == 0
}

// ============================================================================
// EVASION 1: Glob imports — `use std::fs::*; read(...)`
// Risk: HIGH — common Rust pattern, trivial to use
// ============================================================================

#[test]
fn evasion_glob_import() {
    let source = r#"
        use std::fs::*;
        fn sneaky() {
            let _ = read("secret.txt");
        }
    "#;
    // The parser captures glob as ("*", ["std", "fs", "*"]).
    // expand_call sees first segment "read", tries to match against import
    // short names. The glob entry has short_name "*", which doesn't match "read".
    // So the call stays as ["read"], which doesn't suffix-match any pattern.
    let is_evaded = evades(source);
    assert!(
        is_evaded,
        "BUG: glob import `use std::fs::*` should evade detection but was caught. \
         If this test fails, the glob evasion has been FIXED (good!)."
    );
}

#[test]
fn evasion_glob_import_nested_not_evaded() {
    let source = r#"
        use std::net::*;
        fn sneaky() {
            let _ = TcpStream::connect("evil.com:8080");
        }
    "#;
    // Unlike bare function calls, TcpStream::connect is already a two-segment
    // path that suffix-matches the pattern ["TcpStream", "connect"] directly.
    // Glob evasion only works for BARE function names like `read(...)`.
    let findings = count_findings(source);
    assert!(
        findings > 0,
        "Glob import with qualified path IS detected (good — path already matches)"
    );
}

#[test]
fn evasion_glob_import_env_bare_call() {
    let source = r#"
        use std::env::*;
        fn sneaky() {
            let _ = var("SECRET_KEY");
        }
    "#;
    // `var` is a bare call. Glob import gives short_name "*" which doesn't
    // match "var". So the call stays as ["var"], not matching any pattern.
    let is_evaded = evades(source);
    assert!(
        is_evaded,
        "BUG: glob import `use std::env::*; var(...)` evades detection"
    );
}

// ============================================================================
// EVASION 2: Function pointer indirection
// Risk: MEDIUM — requires deliberate obfuscation
// ============================================================================

#[test]
fn evasion_function_pointer() {
    let source = r#"
        use std::fs;
        fn sneaky() {
            let read_fn: fn(&str) -> std::io::Result<Vec<u8>> = fs::read;
            let _ = read_fn("secret.txt");
        }
    "#;
    // The parser captures fs::read as a path expression (assignment RHS),
    // but read_fn("secret.txt") is a call through a local variable,
    // not a path expression — it's ExprCall with ExprPath("read_fn").
    // fs::read on the RHS is NOT inside an ExprCall, so it's not captured.
    let findings = count_findings(source);
    // Note: fs::read IS captured because it appears in an ExprCall-like context?
    // Actually no — `let read_fn = fs::read;` is ExprPath, not ExprCall.
    // The parser only captures ExprCall (function call expressions).
    // So fs::read as an expression (not a call) is NOT captured.
    assert!(
        findings == 0,
        "Expected evasion via function pointer, got {findings} findings"
    );
}

// ============================================================================
// EVASION 3: Closure / higher-order function indirection
// Risk: MEDIUM — the closure body IS parsed, but the call context matters
// ============================================================================

#[test]
fn evasion_closure_hides_import_context() {
    let source = r#"
        fn sneaky() {
            let do_it = || {
                std::fs::read("secret.txt")
            };
            let _ = do_it();
        }
    "#;
    // std::fs::read inside the closure IS within a function body (sneaky),
    // and it's a fully qualified path. So it SHOULD be detected.
    let findings = count_findings(source);
    assert!(
        findings > 0,
        "Fully qualified std::fs::read in closure should be detected"
    );
}

#[test]
fn evasion_closure_with_bare_import() {
    let source = r#"
        use std::fs::read;
        fn sneaky() {
            let do_it = || {
                read("secret.txt")
            };
            let _ = do_it();
        }
    "#;
    // `read` is a bare call inside a closure inside sneaky().
    // Import expansion should resolve it to std::fs::read.
    let findings = count_findings(source);
    assert!(
        findings > 0,
        "Imported read() in closure should be detected via import expansion"
    );
}

// ============================================================================
// EVASION 4: include!() directive
// Risk: HIGH — a real supply-chain attack vector
// ============================================================================

#[test]
fn evasion_include_directive() {
    let source = r#"
        fn sneaky() {
            include!("malicious.rs");
        }
    "#;
    // include!() is a compiler directive that textually includes another file.
    // The audit tool parses each .rs file independently — it does NOT follow
    // include!() directives. The included code is invisible to the scanner.
    let findings = count_findings(source);
    assert!(
        findings == 0,
        "BUG: include!() should evade detection (audit tool doesn't follow includes)"
    );
}

// ============================================================================
// EVASION 5: Inline assembly making raw syscalls
// Risk: LOW (practical) but HIGH (theoretical) — x86-specific, hard to write
// ============================================================================

#[test]
fn evasion_inline_assembly() {
    let source = r#"
        fn sneaky() {
            unsafe {
                // Linux x86_64 read syscall: sys_read(fd=0, buf, count)
                std::arch::asm!(
                    "syscall",
                    in("rax") 0u64,  // SYS_read
                    in("rdi") 0u64,  // fd = stdin
                    in("rsi") 0u64,  // buf (null — would crash, but compiles)
                    in("rdx") 0u64,  // count
                );
            }
        }
    "#;
    // asm!() is opaque to the AST parser. The audit tool can't inspect
    // assembly instructions for syscall patterns.
    let findings = count_findings(source);
    assert!(
        findings == 0,
        "BUG: inline assembly evades detection (expected)"
    );
}

// ============================================================================
// EVASION 6: Type alias / re-export obfuscation
// Risk: MEDIUM — simple renaming trick
// ============================================================================

#[test]
fn evasion_type_alias_renaming() {
    let source = r#"
        use std::fs::read as totally_safe_function;
        fn sneaky() {
            let _ = totally_safe_function("secret.txt");
        }
    "#;
    // This SHOULD be detected: the import alias tracking maps
    // "totally_safe_function" -> ["std", "fs", "read"].
    let findings = count_findings(source);
    assert!(
        findings > 0,
        "Aliased import should be detected via import expansion"
    );
}

// ============================================================================
// EVASION 7: Trait method dispatch (Read/Write traits)
// Risk: HIGH — very natural Rust pattern
// ============================================================================

#[test]
fn evasion_trait_read_on_file() {
    let source = r#"
        use std::io::Read;
        use std::fs::File;
        fn sneaky() {
            let mut f = File::open("secret.txt").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
        }
    "#;
    // File::open IS detected (path pattern ["File", "open"]).
    // But .read_to_end() is a method call on a trait — the parser captures
    // the method name but the detector only flags it if context is present.
    // There's no MethodWithContext entry for "read_to_end" + File::open.
    let findings = count_findings(source);
    // File::open should be found at minimum
    assert!(findings >= 1, "File::open should be detected");
    // But .read_to_end() through trait dispatch may or may not be caught
}

#[test]
fn evasion_trait_write_on_file() {
    let source = r#"
        use std::io::Write;
        use std::fs::File;
        fn sneaky() {
            let mut f = File::create("output.txt").unwrap();
            f.write_all(b"stolen data").unwrap();
        }
    "#;
    let findings = count_findings(source);
    // File::create should be found
    assert!(findings >= 1, "File::create should be detected");
}

// ============================================================================
// EVASION 8: Dependency re-export
// Risk: HIGH — common in real supply-chain attacks
// ============================================================================

#[test]
fn evasion_dependency_reexport() {
    // Simulates: a dependency re-exports std::fs::read as dep::util::load
    let source = r#"
        use some_crate::util::load;
        fn sneaky() {
            let _ = load("secret.txt");
        }
    "#;
    // "load" expands to ["some_crate", "util", "load"] via import expansion.
    // No authority pattern matches this — the registry only knows std paths.
    let findings = count_findings(source);
    assert!(
        findings == 0,
        "Dependency re-exports evade detection (expected — not in registry)"
    );
}

// ============================================================================
// EVASION 9: Conditional compilation
// Risk: MEDIUM — targeted attack on specific platforms
// ============================================================================

#[test]
fn evasion_cfg_conditional() {
    let source = r#"
        #[cfg(target_os = "linux")]
        fn sneaky() {
            let _ = std::fs::read("secret.txt");
        }
        #[cfg(not(target_os = "linux"))]
        fn sneaky() {
            // innocent on non-Linux
        }
    "#;
    // syn parses ALL cfg branches regardless of the current platform.
    // So the fs::read in the linux branch IS visible to the parser.
    let findings = count_findings(source);
    assert!(
        findings > 0,
        "cfg-gated code should still be parsed and detected"
    );
}

// ============================================================================
// EVASION 10: Fully qualified call without import
// Risk: LOW — verbose but works
// ============================================================================

#[test]
fn detection_fully_qualified_no_import() {
    let source = r#"
        fn sneaky() {
            let _ = std::fs::read("secret.txt");
        }
    "#;
    // Fully qualified call: parser captures ["std", "fs", "read"].
    // No import expansion needed. Pattern suffix match works.
    let findings = count_findings(source);
    assert!(
        findings > 0,
        "Fully qualified std::fs::read should be detected"
    );
}

// ============================================================================
// EVASION 11: Module-level re-aliasing
// Risk: MEDIUM — two levels of indirection
// ============================================================================

#[test]
fn evasion_module_reexport() {
    let source = r#"
        mod hidden {
            pub use std::fs::read as load;
        }
        fn sneaky() {
            let _ = hidden::load("secret.txt");
        }
    "#;
    // Parser captures ["hidden", "load"] from the call.
    // There's no import for "hidden" at file level.
    // The inner `pub use` is inside a mod block — does the parser track it?
    // The parser visits use statements at file level AND inside modules.
    // But the import map is flat — "load" maps to ["std", "fs", "read"].
    // The call is ["hidden", "load"], first segment "hidden" doesn't match
    // any import. So it stays as ["hidden", "load"], which doesn't match.
    let findings = count_findings(source);
    assert!(
        findings == 0,
        "Module re-export evades detection (import expansion is single-level)"
    );
}

// ============================================================================
// EVASION 12: FFI via libc (not extern block)
// Risk: HIGH — common way to bypass Rust's std wrappers
// ============================================================================

#[test]
fn evasion_libc_without_extern_block() {
    // If libc is a dependency, these are normal function calls, not extern blocks.
    let source = r#"
        fn sneaky() {
            unsafe {
                libc::open(b"/etc/passwd\0".as_ptr() as *const i8, 0);
            }
        }
    "#;
    // libc::open is a path call ["libc", "open"].
    // No authority pattern for ["libc", "open"] in the registry.
    // Not an extern block (libc declares them internally).
    let findings = count_findings(source);
    assert!(
        findings == 0,
        "libc function calls evade detection (not in registry)"
    );
}

// ============================================================================
// EVASION 13: nix crate (popular Unix abstraction)
// Risk: HIGH — nix is a common dependency
// ============================================================================

#[test]
fn evasion_nix_crate() {
    let source = r#"
        use nix::unistd::read;
        fn sneaky() {
            let mut buf = [0u8; 1024];
            let _ = read(3, &mut buf);  // read from fd 3
        }
    "#;
    // nix::unistd::read is not in the authority registry.
    let findings = count_findings(source);
    assert!(
        findings == 0,
        "nix crate calls evade detection (not in registry)"
    );
}

// ============================================================================
// EVASION 14: tokio::spawn hiding I/O in async task
// Risk: MEDIUM — I/O is inside the closure, not at the spawn site
// ============================================================================

#[test]
fn detection_tokio_fs_in_async_block() {
    let source = r#"
        use tokio::fs;
        async fn sneaky() {
            let _ = fs::read("secret.txt").await;
        }
    "#;
    // tokio::fs::read is in the registry.
    let findings = count_findings(source);
    assert!(findings > 0, "tokio::fs::read should be detected");
}

// ============================================================================
// EVASION 15: Method chaining hiding the source
// Risk: MEDIUM
// ============================================================================

#[test]
fn evasion_method_chain_without_context() {
    let source = r#"
        fn sneaky() {
            let content = get_reader().read_to_string();
        }
    "#;
    // .read_to_string() is a method call. No context path like File::open exists.
    // The detector shouldn't flag this (no context) — but it also means
    // if the reader IS a file handle, we miss it.
    let findings = count_findings(source);
    assert!(
        findings == 0,
        "Method call without matching context should not fire"
    );
}

// ============================================================================
// DETECTION POSITIVE CONTROLS — things that SHOULD be detected
// ============================================================================

#[test]
fn detection_std_fs_read() {
    assert!(!evades("use std::fs; fn f() { let _ = fs::read(\"x\"); }"));
}

#[test]
fn detection_std_fs_write() {
    assert!(!evades(
        "use std::fs; fn f() { let _ = fs::write(\"x\", b\"y\"); }"
    ));
}

#[test]
fn detection_file_open() {
    assert!(!evades(
        "use std::fs::File; fn f() { let _ = File::open(\"x\"); }"
    ));
}

#[test]
fn detection_tcp_connect() {
    assert!(!evades(
        "use std::net::TcpStream; fn f() { let _ = TcpStream::connect(\"x:80\"); }"
    ));
}

#[test]
fn detection_command_new() {
    assert!(!evades(
        "use std::process::Command; fn f() { let _ = Command::new(\"sh\"); }"
    ));
}

#[test]
fn detection_env_var() {
    assert!(!evades(
        "use std::env; fn f() { let _ = env::var(\"SECRET\"); }"
    ));
}

#[test]
fn detection_extern_block() {
    assert!(!evades(
        "extern \"C\" { fn open(p: *const u8, f: i32) -> i32; }"
    ));
}

#[test]
fn detection_remove_dir_all() {
    assert!(!evades(
        "use std::fs; fn f() { let _ = fs::remove_dir_all(\"/tmp/x\"); }"
    ));
}

#[test]
fn detection_reqwest_get() {
    assert!(!evades(
        "use reqwest; fn f() { let _ = reqwest::get(\"https://evil.com\"); }"
    ));
}
