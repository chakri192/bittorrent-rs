//! Loopback helpers shared by the session tests.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;

/// A loopback address nothing listens on: connecting is refused at once.
pub(crate) fn dead_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// An HTTP tracker on loopback that answers every announce with `peer` as
/// the only peer, and records each request line. Returns its announce URL
/// and the record.
pub(crate) fn tracker(peer: SocketAddr) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/announce", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            log.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string());
            let SocketAddr::V4(v4) = peer else { unreachable!("the test peers are v4") };
            let mut peers = v4.ip().octets().to_vec();
            peers.extend_from_slice(&v4.port().to_be_bytes());
            let mut body = format!("d8:intervali1800e5:peers{}:", peers.len()).into_bytes();
            body.extend_from_slice(&peers);
            body.push(b'e');
            let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    (url, seen)
}
