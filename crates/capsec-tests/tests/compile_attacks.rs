//! Compile-fail tests proving that certain attacks are rejected by the compiler.
//!
//! These use trybuild to verify that code which SHOULD NOT compile actually
//! produces the expected errors.

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
