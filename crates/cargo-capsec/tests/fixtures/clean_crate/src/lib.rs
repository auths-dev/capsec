/// Pure computation — no I/O, no ambient authority.
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

pub fn transform(input: &[u8]) -> Vec<u8> {
    input.iter().map(|b| b.wrapping_add(1)).collect()
}

pub fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}
