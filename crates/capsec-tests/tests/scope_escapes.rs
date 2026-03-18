//! Scope escape attacks against DirScope and HostScope.

use capsec_core::attenuate::{DirScope, HostScope, Scope};

// ============================================================================
// DirScope attacks
// ============================================================================

#[test]
fn dirscope_blocks_dotdot_traversal() {
    let scope = DirScope::new("/tmp").unwrap();
    // ../etc/passwd should be rejected after canonicalization
    let result = scope.check("/tmp/../etc/passwd");
    assert!(result.is_err(), "Path traversal via ../ should be blocked");
}

#[test]
fn dirscope_blocks_absolute_escape() {
    let scope = DirScope::new("/tmp").unwrap();
    let result = scope.check("/etc/passwd");
    assert!(
        result.is_err(),
        "Absolute path outside scope should be blocked"
    );
}

#[test]
fn dirscope_allows_valid_subpath() {
    let scope = DirScope::new("/tmp").unwrap();
    // /tmp itself should be allowed
    let result = scope.check("/tmp");
    assert!(result.is_ok(), "/tmp should be within scope of /tmp");
}

#[test]
fn dirscope_fails_for_nonexistent_path() {
    let scope = DirScope::new("/tmp").unwrap();
    // A non-existent path can't be canonicalized
    let result = scope.check("/tmp/definitely_nonexistent_file_xyz_123_456");
    assert!(
        result.is_err(),
        "Non-existent path should fail (conservative behavior)"
    );
}

#[test]
fn dirscope_rejects_nonexistent_root() {
    // Can't create a DirScope for a non-existent directory
    let result = DirScope::new("/nonexistent_root_dir_xyz_123");
    assert!(
        result.is_err(),
        "DirScope should fail for non-existent root"
    );
}

// ============================================================================
// HostScope attacks
// ============================================================================

#[test]
fn hostscope_prefix_collision_attack() {
    let scope = HostScope::new(["api.example.com"]);

    // VULNERABILITY: prefix matching allows subdomain spoofing
    // "api.example.com.evil.com" starts with "api.example.com"
    let result = scope.check("api.example.com.evil.com");
    assert!(
        result.is_ok(),
        "BUG: HostScope prefix matching allows domain spoofing. \
         'api.example.com.evil.com' starts with 'api.example.com'. \
         If this test fails, the prefix collision has been FIXED (good!)."
    );
}

#[test]
fn hostscope_rejects_different_host() {
    let scope = HostScope::new(["api.example.com"]);
    let result = scope.check("evil.com");
    assert!(result.is_err());
}

#[test]
fn hostscope_allows_port_suffix() {
    let scope = HostScope::new(["api.example.com"]);
    let result = scope.check("api.example.com:443");
    assert!(result.is_ok(), "Port suffix should be allowed");
}

#[test]
fn hostscope_allows_path_suffix() {
    let scope = HostScope::new(["api.example.com"]);
    let result = scope.check("api.example.com/api/v1");
    assert!(result.is_ok(), "Path suffix should be allowed");
}

#[test]
fn hostscope_empty_target_rejected() {
    let scope = HostScope::new(["api.example.com"]);
    let result = scope.check("");
    assert!(result.is_err(), "Empty target should be rejected");
}

#[test]
fn hostscope_empty_allowlist() {
    let scope = HostScope::new(Vec::<String>::new());
    let result = scope.check("anything.com");
    assert!(result.is_err(), "Empty allowlist should reject everything");
}
