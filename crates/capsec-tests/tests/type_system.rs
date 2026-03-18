//! Type system attacks against capsec.
//!
//! Each test attempts to forge, escalate, or bypass capability tokens.
//! Tests that succeed represent real vulnerabilities.

use capsec_core::cap::Cap;
use capsec_core::has::Has;
use capsec_core::permission::*;
use capsec_core::root::test_root;

// ============================================================================
// A. CRITICAL FINDING: Has<P> is NOT sealed — forgery via divergence
// ============================================================================

/// A type that claims to have FsRead permission without going through CapRoot.
/// This compiles because panic!() diverges, so the return type is satisfied.
struct Forgery;

impl Has<FsRead> for Forgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        panic!("This is never called — capsec-std ignores the cap parameter")
    }
}

/// VULNERABILITY: Forge Has<FsRead> in safe code, no CapRoot needed.
///
/// capsec-std functions accept `_cap: &impl Has<P>` and never call cap_ref().
/// Since Has<P> is not sealed, we can implement it for any type using a
/// diverging expression (panic!, loop{}, unreachable!(), etc).
///
/// The function compiles and the forgery type-checks.
/// capsec-std::fs::read would accept &Forgery as a valid capability.
#[test]
fn has_forgery_via_panic_divergence() {
    let forge = Forgery;

    // This satisfies the Has<FsRead> bound — no CapRoot involved
    fn needs_fs_read(_cap: &impl Has<FsRead>) {
        // In real code, this would be capsec_std::fs::read(path, _cap)
    }
    needs_fs_read(&forge); // Compiles and runs. The forgery was accepted.
}

/// Same attack but with loop {} instead of panic!()
struct LoopForgery;

impl Has<FsRead> for LoopForgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        #[allow(clippy::empty_loop)]
        loop {} // Diverges — satisfies any return type
    }
}

#[test]
fn has_forgery_via_loop_divergence() {
    let forge = LoopForgery;
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forge);
}

/// Forgery that claims EVERY permission at once
struct GodForgery;

impl Has<FsRead> for GodForgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        panic!()
    }
}
impl Has<FsWrite> for GodForgery {
    fn cap_ref(&self) -> Cap<FsWrite> {
        panic!()
    }
}
impl Has<NetConnect> for GodForgery {
    fn cap_ref(&self) -> Cap<NetConnect> {
        panic!()
    }
}
impl Has<NetBind> for GodForgery {
    fn cap_ref(&self) -> Cap<NetBind> {
        panic!()
    }
}
impl Has<Spawn> for GodForgery {
    fn cap_ref(&self) -> Cap<Spawn> {
        panic!()
    }
}
impl Has<EnvRead> for GodForgery {
    fn cap_ref(&self) -> Cap<EnvRead> {
        panic!()
    }
}
impl Has<EnvWrite> for GodForgery {
    fn cap_ref(&self) -> Cap<EnvWrite> {
        panic!()
    }
}

#[test]
fn god_forgery_satisfies_all_permissions() {
    let forge = GodForgery;
    fn needs_everything(
        _cap: &(
             impl Has<FsRead>
             + Has<FsWrite>
             + Has<NetConnect>
             + Has<NetBind>
             + Has<Spawn>
             + Has<EnvRead>
             + Has<EnvWrite>
         ),
    ) {
    }
    needs_everything(&forge);
}

/// Forgery via process::exit — another diverging expression
struct ExitForgery;

impl Has<FsRead> for ExitForgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        std::process::exit(0) // Diverges
    }
}

#[test]
fn has_forgery_via_process_exit() {
    let forge = ExitForgery;
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forge);
}

// ============================================================================
// B. FORGERY VIA CAPSEC-STD DIRECTLY (the real exploit)
// ============================================================================

/// Proves the forgery actually works end-to-end with capsec-std.
/// This reads /dev/null using a forged capability — no CapRoot involved.
#[test]
fn forgery_works_with_capsec_std_fs_read() {
    let forge = Forgery;
    // This is the actual exploit: reading a file with a forged capability
    let result = capsec_std::fs::read("/dev/null", &forge);
    assert!(
        result.is_ok(),
        "Forged capability should work with capsec-std"
    );
}

/// Proves the forgery works for reading file contents as string.
#[test]
fn forgery_works_with_capsec_std_read_to_string() {
    let forge = Forgery;
    let result = capsec_std::fs::read_to_string("/dev/null", &forge);
    assert!(
        result.is_ok(),
        "Forged capability should work with capsec-std"
    );
}

/// Proves env read works with forgery.
struct EnvForgery;

impl Has<EnvRead> for EnvForgery {
    fn cap_ref(&self) -> Cap<EnvRead> {
        panic!()
    }
}

#[test]
fn forgery_works_with_capsec_std_env_var() {
    let forge = EnvForgery;
    // PATH always exists
    let result = capsec_std::env::var("PATH", &forge);
    assert!(
        result.is_ok(),
        "Forged capability should work with capsec-std env::var"
    );
}

// ============================================================================
// C. UNSAFE ATTACKS (expected to work — not real bugs, but documenting)
// ============================================================================

#[test]
fn transmute_forgery_works_with_unsafe() {
    // Cap<FsRead> is a ZST, so transmuting () to it is sound
    let forged: Cap<FsRead> = unsafe { std::mem::transmute(()) };
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forged);
}

#[test]
fn maybe_uninit_forgery_works_with_unsafe() {
    let forged: Cap<FsRead> =
        unsafe { std::mem::MaybeUninit::<Cap<FsRead>>::uninit().assume_init() };
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forged);
}

#[test]
fn ptr_read_forgery_works_with_unsafe() {
    let forged: Cap<FsRead> = unsafe { std::ptr::read(&() as *const () as *const Cap<FsRead>) };
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forged);
}

// ============================================================================
// D. SENDCAP CROSS-THREAD BEHAVIOR
// ============================================================================

/// Proves that make_send() is a genuine opt-in gate, not an accidental
/// escalation path. The flow is:
///   1. Grant Cap<FsRead> on the main thread
///   2. Convert to SendCap via make_send() (explicit opt-in)
///   3. Move SendCap into a spawned thread
///   4. Recover a Cap<FsRead> via as_cap() on the worker thread
///   5. Use that cap to satisfy a Has<FsRead> bound
///
/// The recovered cap is fully usable — it satisfies Has<FsRead> — and it
/// carries only the original permission (FsRead), not anything broader.
#[test]
fn sendcap_cross_thread_roundtrip_is_usable() {
    let root = test_root();
    let cap = root.grant::<FsRead>();

    // Explicit opt-in: Cap -> SendCap
    let send_cap = cap.make_send();

    let handle = std::thread::spawn(move || {
        // Recover a Cap<FsRead> on this thread
        let worker_cap = send_cap.as_cap();

        // The recovered cap satisfies Has<FsRead>
        fn needs_fs_read(cap: &impl Has<FsRead>) -> bool {
            // Prove it's real by calling cap_ref
            let _proof: Cap<FsRead> = cap.cap_ref();
            true
        }
        assert!(needs_fs_read(&worker_cap));

        // Use it with capsec-std for a real I/O operation
        let result = capsec_std::fs::read("/dev/null", &worker_cap);
        assert!(
            result.is_ok(),
            "Cap recovered via as_cap() should work with capsec-std"
        );
    });

    handle.join().expect("worker thread panicked");
}

/// Proves SendCap does NOT escalate: a SendCap<FsRead> yields Cap<FsRead>
/// on the other thread, not Cap<Ambient> or anything else. The cap can only
/// satisfy the original permission bound.
#[test]
fn sendcap_does_not_escalate_across_threads() {
    let root = test_root();
    let send_cap = root.grant::<FsRead>().make_send();

    let handle = std::thread::spawn(move || {
        let worker_cap = send_cap.as_cap();

        // FsRead works
        fn needs_fs_read(_cap: &impl Has<FsRead>) {}
        needs_fs_read(&worker_cap);

        // NetConnect does NOT work — would be a compile error:
        // fn needs_net(_cap: &impl Has<NetConnect>) {}
        // needs_net(&worker_cap);

        // Ambient does NOT work — would be a compile error:
        // fn needs_ambient(_cap: &impl Has<Ambient>) {}
        // needs_ambient(&worker_cap);
    });

    handle.join().expect("worker thread panicked");
}

/// Proves SendCap::clone preserves the permission type too.
#[test]
fn sendcap_clone_across_threads() {
    let root = test_root();
    let send_cap = root.grant::<(FsRead, NetConnect)>().make_send();

    // Clone the SendCap so both threads can use it
    let send_cap2 = send_cap.clone();

    let h1 = std::thread::spawn(move || {
        let cap = send_cap.as_cap();
        fn needs_fs(_: &impl Has<FsRead>) {}
        needs_fs(&cap);
    });

    let h2 = std::thread::spawn(move || {
        let cap = send_cap2.as_cap();
        fn needs_net(_: &impl Has<NetConnect>) {}
        needs_net(&cap);
    });

    h1.join().unwrap();
    h2.join().unwrap();
}

// ============================================================================
// E. ATTENUATED MOVE SEMANTICS
// ============================================================================

/// Proves that .attenuate() consumes the original Cap<P> via move semantics.
/// After attenuating, the original cap is no longer available — the only way
/// to use the permission is through the Attenuated wrapper's scope check.
///
/// This is a key security property: attenuation is irreversible. You can't
/// call .attenuate() to create a scoped cap and then keep using the unscoped
/// original.
#[test]
fn attenuate_consumes_original_cap() {
    use capsec_core::attenuate::{Attenuated, DirScope};

    let root = test_root();
    let cap = root.grant::<FsRead>();

    // Attenuate consumes `cap` (move)
    let _scoped: Attenuated<FsRead, DirScope> = cap.attenuate(DirScope::new("/tmp").unwrap());

    // `cap` is now moved — the lines below would be compile errors:
    // fn needs_fs(_cap: &impl Has<FsRead>) {}
    // needs_fs(&cap);  // ERROR: use of moved value `cap`
    //
    // let _ = cap.clone();  // ERROR: use of moved value `cap`
    //
    // let _ = cap.attenuate(DirScope::new("/tmp").unwrap());  // ERROR: moved
}

/// Same test for HostScope — move semantics don't depend on scope type.
#[test]
fn attenuate_with_hostscope_consumes_cap() {
    use capsec_core::attenuate::{Attenuated, HostScope};

    let root = test_root();
    let cap = root.grant::<NetConnect>();

    let _scoped: Attenuated<NetConnect, HostScope> =
        cap.attenuate(HostScope::new(["api.example.com"]));

    // `cap` is moved — would be a compile error to use it:
    // fn needs_net(_cap: &impl Has<NetConnect>) {}
    // needs_net(&cap);  // ERROR: use of moved value
}

/// Proves you can still use a cloned cap after attenuating the original.
/// This is correct behavior: the clone is independent. If the caller wants
/// to prevent this, they should not clone before attenuating.
#[test]
fn clone_before_attenuate_keeps_unscoped_copy() {
    use capsec_core::attenuate::DirScope;

    let root = test_root();
    let cap = root.grant::<FsRead>();
    let backup = cap.clone(); // Clone BEFORE attenuating

    // Attenuate consumes the original
    let _scoped = cap.attenuate(DirScope::new("/tmp").unwrap());

    // The clone is still usable — this is expected, not a bug.
    // The security model relies on not cloning before attenuating.
    fn needs_fs(_cap: &impl Has<FsRead>) {}
    needs_fs(&backup);
}

// ============================================================================
// F. ATTACKS THAT CORRECTLY FAIL
// ============================================================================

/// Proves that Cap::clone doesn't violate any invariant.
/// Cloning a legitimate cap produces another legitimate cap — this is fine.
#[test]
fn clone_does_not_escalate() {
    let root = test_root();
    let cap = root.grant::<FsRead>();
    let cloned = cap.clone();

    fn needs_fs(_cap: &impl Has<FsRead>) {}
    needs_fs(&cloned); // OK: same permission

    // A cloned FsRead cap STILL can't satisfy Has<NetConnect>
    // (This would be a compile error if uncommented)
    // fn needs_net(_cap: &impl Has<NetConnect>) {}
    // needs_net(&cloned); // ERROR
}

/// Proves make_send doesn't escalate permissions.
#[test]
fn send_cap_preserves_permission_type() {
    let root = test_root();
    let cap = root.grant::<FsRead>();
    let send = cap.make_send();
    let back = send.as_cap();

    fn needs_fs(_cap: &impl Has<FsRead>) {}
    needs_fs(&back);

    // SendCap<FsRead>.as_cap() returns Cap<FsRead>, not Cap<Ambient>
    // (This would be a compile error if uncommented)
    // fn needs_net(_cap: &impl Has<NetConnect>) {}
    // needs_net(&back); // ERROR
}

/// Proves subsumption is directional.
#[test]
fn subsumption_only_goes_one_way() {
    let root = test_root();
    let fs_all = root.grant::<FsAll>();

    fn needs_read(_cap: &impl Has<FsRead>) {}
    fn needs_write(_cap: &impl Has<FsWrite>) {}
    needs_read(&fs_all); // OK: FsAll subsumes FsRead
    needs_write(&fs_all); // OK: FsAll subsumes FsWrite

    // But FsRead does NOT subsume FsAll
    // (This would be a compile error if uncommented)
    // let fs_read = root.grant::<FsRead>();
    // fn needs_all(_cap: &impl Has<FsAll>) {}
    // needs_all(&fs_read); // ERROR
}

/// Proves cross-category subsumption doesn't exist.
#[test]
fn no_cross_category_leak() {
    let root = test_root();
    let fs_all = root.grant::<FsAll>();

    fn needs_fs(_cap: &impl Has<FsRead>) {}
    needs_fs(&fs_all); // OK

    // FsAll does NOT satisfy NetConnect
    // (This would be a compile error if uncommented)
    // fn needs_net(_cap: &impl Has<NetConnect>) {}
    // needs_net(&fs_all); // ERROR
}
