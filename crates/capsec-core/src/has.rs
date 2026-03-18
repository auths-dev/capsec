//! The [`Has<P>`] trait — proof that a capability token includes permission `P`.
//!
//! This is the trait you use in function signatures to declare capability requirements:
//!
//! ```rust,ignore
//! fn read_config(cap: &impl Has<FsRead>) -> String { ... }
//! ```
//!
//! # Multiple capabilities
//!
//! For functions that need multiple permissions, use multiple parameters:
//!
//! ```rust,ignore
//! fn sync_data(fs: &impl Has<FsRead>, net: &impl Has<NetConnect>) { ... }
//! ```
//!
//! Or use a subsumption type like [`FsAll`](crate::permission::FsAll) or
//! [`Ambient`](crate::permission::Ambient) that satisfies multiple bounds.
//!
//! # Subsumption
//!
//! `Cap<FsAll>` satisfies `Has<FsRead>` and `Has<FsWrite>` because `FsAll`
//! subsumes both. `Cap<Ambient>` satisfies `Has<P>` for every permission.

use crate::cap::Cap;
use crate::permission::*;

/// Proof that a capability token includes permission `P`.
///
/// Implement this on your capability types. In practice, you'll use the built-in
/// implementations on [`Cap<P>`](crate::cap::Cap) and its subsumption types.
///
/// # Example
///
/// ```rust,ignore
/// # use capsec_core::root::test_root;
/// # use capsec_core::permission::FsRead;
/// # use capsec_core::has::Has;
/// fn needs_fs(cap: &impl Has<FsRead>) {
///     let _ = cap.cap_ref(); // proof of permission
/// }
///
/// let root = test_root();
/// let cap = root.grant::<FsRead>();
/// needs_fs(&cap);
/// ```
pub trait Has<P: Permission> {
    /// Returns a new `Cap<P>` proving the permission is available.
    fn cap_ref(&self) -> Cap<P>;
}

// ── Direct: Cap<P> implements Has<P> ────────────────────────────

impl<P: Permission> Has<P> for Cap<P> {
    fn cap_ref(&self) -> Cap<P> {
        Cap::new()
    }
}

// ── Subsumption: FsAll, NetAll ──────────────────────────────────

macro_rules! impl_subsumes {
    ($super:ty => $($sub:ty),+) => {
        $(
            impl Has<$sub> for Cap<$super> {
                fn cap_ref(&self) -> Cap<$sub> { Cap::new() }
            }
        )+
    }
}

impl_subsumes!(FsAll => FsRead, FsWrite);
impl_subsumes!(NetAll => NetConnect, NetBind);

// ── Ambient: satisfies everything ───────────────────────────────

macro_rules! impl_ambient {
    ($($perm:ty),+) => {
        $(
            impl Has<$perm> for Cap<Ambient> {
                fn cap_ref(&self) -> Cap<$perm> { Cap::new() }
            }
        )+
    }
}

impl_ambient!(
    FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::test_root;

    #[test]
    fn direct_cap_satisfies_has() {
        let root = test_root();
        let cap = root.grant::<FsRead>();
        fn needs_fs(_: &impl Has<FsRead>) {}
        needs_fs(&cap);
    }

    #[test]
    fn fs_all_subsumes_read_and_write() {
        let root = test_root();
        let cap = root.grant::<FsAll>();
        fn needs_read(_: &impl Has<FsRead>) {}
        fn needs_write(_: &impl Has<FsWrite>) {}
        needs_read(&cap);
        needs_write(&cap);
    }

    #[test]
    fn net_all_subsumes_connect_and_bind() {
        let root = test_root();
        let cap = root.grant::<NetAll>();
        fn needs_connect(_: &impl Has<NetConnect>) {}
        fn needs_bind(_: &impl Has<NetBind>) {}
        needs_connect(&cap);
        needs_bind(&cap);
    }

    #[test]
    fn ambient_satisfies_anything() {
        let root = test_root();
        let cap = root.grant::<Ambient>();
        fn needs_fs(_: &impl Has<FsRead>) {}
        fn needs_net(_: &impl Has<NetConnect>) {}
        fn needs_spawn(_: &impl Has<Spawn>) {}
        needs_fs(&cap);
        needs_net(&cap);
        needs_spawn(&cap);
    }

    #[test]
    fn multiple_cap_params() {
        fn sync_data(_fs: &impl Has<FsRead>, _net: &impl Has<NetConnect>) {}
        let root = test_root();
        let fs = root.grant::<FsRead>();
        let net = root.grant::<NetConnect>();
        sync_data(&fs, &net);
    }
}
