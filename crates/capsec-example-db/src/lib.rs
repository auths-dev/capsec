//! Example: user-defined database permissions with capsec.
//!
//! Demonstrates how library authors can define domain-specific permissions
//! using `#[capsec::permission]`. These permissions mirror the kind of
//! runtime capabilities used by auths (`db:read`, `db:write`).

use capsec::{Cap, Has};

/// Permission to execute database read queries.
#[capsec::permission]
pub struct DbRead;

/// Permission to execute database write statements.
#[capsec::permission]
pub struct DbWrite;

/// Full database access. Subsumes both [`DbRead`] and [`DbWrite`].
#[capsec::permission(subsumes = [DbRead, DbWrite])]
pub struct DbAll;

/// Execute a read query, returning mock results.
pub fn query<C: Has<DbRead>>(sql: &str, cap: &C) -> Vec<String> {
    let _proof: Cap<DbRead> = cap.cap_ref();
    vec![format!("result of: {sql}")]
}

/// Execute a write statement, returning rows affected.
pub fn execute<C: Has<DbWrite>>(sql: &str, cap: &C) -> u64 {
    let _proof: Cap<DbWrite> = cap.cap_ref();
    let _ = sql;
    1
}

/// Run migrations (requires full database access).
pub fn migrate<C: Has<DbAll>>(cap: &C) {
    let _proof: Cap<DbAll> = cap.cap_ref();
    // DbAll subsumes DbRead + DbWrite, so we can extract proofs:
    let _read_proof: Cap<DbRead> = Has::<DbRead>::cap_ref(&_proof);
    let _write_proof: Cap<DbWrite> = Has::<DbWrite>::cap_ref(&_proof);
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_core::root::test_root;

    #[test]
    fn grant_custom_permission() {
        let root = test_root();
        let cap = root.grant::<DbRead>();
        let results = query("SELECT 1", &cap);
        assert_eq!(results, vec!["result of: SELECT 1"]);
    }

    #[test]
    fn grant_custom_write() {
        let root = test_root();
        let cap = root.grant::<DbWrite>();
        let rows = execute("INSERT INTO t VALUES (1)", &cap);
        assert_eq!(rows, 1);
    }

    #[test]
    fn db_all_subsumes_read_and_write() {
        let root = test_root();
        let cap = root.grant::<DbAll>();
        // DbAll satisfies Has<DbRead> and Has<DbWrite>
        let _ = query("SELECT 1", &cap);
        let _ = execute("INSERT INTO t VALUES (1)", &cap);
        migrate(&cap);
    }

    #[test]
    fn custom_permission_is_zst() {
        assert_eq!(std::mem::size_of::<Cap<DbRead>>(), 0);
        assert_eq!(std::mem::size_of::<Cap<DbWrite>>(), 0);
        assert_eq!(std::mem::size_of::<Cap<DbAll>>(), 0);
    }

    #[test]
    fn context_macro_with_custom_permissions() {
        #[capsec::context]
        struct DbCtx {
            read: DbRead,
            write: DbWrite,
        }

        let root = test_root();
        let ctx = DbCtx::new(&root);
        let _ = query("SELECT 1", &ctx);
        let _ = execute("INSERT INTO t VALUES (1)", &ctx);
    }

    #[test]
    fn requires_macro_with_custom_permissions() {
        #[capsec::context]
        struct QueryCtx {
            read: DbRead,
        }

        #[capsec::requires(DbRead, on = ctx)]
        fn checked_query(ctx: &QueryCtx) -> Vec<String> {
            query("SELECT 1", ctx)
        }

        let root = test_root();
        let ctx = QueryCtx::new(&root);
        let results = checked_query(&ctx);
        assert_eq!(results, vec!["result of: SELECT 1"]);
    }

    #[test]
    fn context_with_mixed_builtin_and_custom() {
        use capsec::FsRead;

        #[capsec::context]
        struct MixedCtx {
            fs: FsRead,
            db: DbRead,
        }

        let root = test_root();
        let ctx = MixedCtx::new(&root);
        let _ = query("SELECT 1", &ctx);
        // ctx also satisfies Has<FsRead>
        fn needs_fs(_: &impl Has<FsRead>) {}
        needs_fs(&ctx);
    }
}
