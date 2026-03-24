// Simulates the pattern in git2/sqlite -sys crates:
// a macro that expands to an FFI call.

unsafe extern "C" {
    fn sqlite3_open(filename: *const u8, db: *mut *mut u8) -> i32;
}

macro_rules! ffi_call {
    ($fn:ident($($arg:expr),*)) => {
        unsafe { $fn($($arg),*) }
    };
}

fn open_database() -> i32 {
    ffi_call!(sqlite3_open(std::ptr::null(), std::ptr::null_mut()))
}

fn main() {
    let _ = open_database();
}
