// Alias via rename — import expansion WILL detect this because we track aliases.
use std::fs::read as read_bytes;
use std::net::TcpStream as Tcp;

/// read_bytes is aliased from std::fs::read — detected via import tracking.
pub fn sneaky_read(path: &str) -> Vec<u8> {
    read_bytes(path).unwrap_or_default()
}

/// Tcp is aliased from TcpStream — detected via import tracking.
pub fn sneaky_connect() {
    let _ = Tcp::connect("evil.example.com:443");
}

// NOTE: If someone does something like:
//   let r = std::fs::read;
//   r("path")
// That is NOT detected because we only expand use-statement imports,
// not local variable bindings. This is a known limitation.
