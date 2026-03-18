//! Capability-gated network operations.
//!
//! Drop-in replacements for `std::net` functions that require a capability token.

use capsec_core::error::CapSecError;
use capsec_core::has::Has;
use capsec_core::permission::{NetBind, NetConnect};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};

/// Opens a TCP connection to the given address.
/// Requires [`NetConnect`] permission.
pub fn tcp_connect(
    addr: impl ToSocketAddrs,
    _cap: &impl Has<NetConnect>,
) -> Result<TcpStream, CapSecError> {
    Ok(TcpStream::connect(addr)?)
}

/// Binds a TCP listener to the given address.
/// Requires [`NetBind`] permission.
pub fn tcp_bind(
    addr: impl ToSocketAddrs,
    _cap: &impl Has<NetBind>,
) -> Result<TcpListener, CapSecError> {
    Ok(TcpListener::bind(addr)?)
}

/// Binds a UDP socket to the given address.
/// Requires [`NetBind`] permission.
pub fn udp_bind(
    addr: impl ToSocketAddrs,
    _cap: &impl Has<NetBind>,
) -> Result<UdpSocket, CapSecError> {
    Ok(UdpSocket::bind(addr)?)
}
