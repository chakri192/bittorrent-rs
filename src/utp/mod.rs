//! uTP (BEP 29): a reliable, ordered byte stream over UDP that backs off
//! when it fills a queue, so that a transfer does not get in the way of
//! whatever else shares the link.

pub mod conn;
pub mod packet;
pub mod socket;

pub use socket::{UtpSocket, UtpStream};
