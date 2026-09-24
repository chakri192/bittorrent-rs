//! BEP 55 Holepunch extension (`ut_holepunch`): lets a peer this client is
//! connected to (the relay, "R") introduce two other peers ("A", the
//! initiator, and "B", the target) that cannot reach each other directly,
//! by telling each the other's endpoint so they can try a fresh connection
//! at the same time. Unlike ut_pex/ut_metadata, the payload is not
//! bencoded: it is a fixed binary layout, given here byte for byte.
//!
//! ```text
//! msg_type (1 byte):  0x00 rendezvous, 0x01 connect, 0x02 error
//! addr_type (1 byte): 0x00 ipv4, 0x01 ipv6
//! addr (4 or 16 bytes, big-endian, as addr_type says)
//! port (2 bytes, big-endian)
//! err_code (4 bytes, big-endian; 0 outside an error message)
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MSG_RENDEZVOUS: u8 = 0x00;
const MSG_CONNECT: u8 = 0x01;
const MSG_ERROR: u8 = 0x02;

const ADDR_V4: u8 = 0x00;
const ADDR_V6: u8 = 0x01;

/// The reasons a relay gives for not acting on a `rendezvous` (BEP 55's table). Never sent for
/// `connect`: a target that will not have the initiator just stays silent, per the BEP's own note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The target endpoint is invalid. The BEP allows [`ErrorCode::NotConnected`] in its place
    /// everywhere this would apply, which this client always does rather than tell the two apart.
    NoSuchPeer,
    /// The relay is not connected to the target peer (or does not know it supports the extension).
    NotConnected,
    /// The relay is connected to the target, but it did not advertise `ut_holepunch`.
    NoSupport,
    /// The named target is the relay's own address.
    NoSelf,
}

impl ErrorCode {
    fn to_u32(self) -> u32 {
        match self {
            ErrorCode::NoSuchPeer => 0x01,
            ErrorCode::NotConnected => 0x02,
            ErrorCode::NoSupport => 0x03,
            ErrorCode::NoSelf => 0x04,
        }
    }

    fn from_u32(n: u32) -> Option<ErrorCode> {
        match n {
            0x01 => Some(ErrorCode::NoSuchPeer),
            0x02 => Some(ErrorCode::NotConnected),
            0x03 => Some(ErrorCode::NoSupport),
            0x04 => Some(ErrorCode::NoSelf),
            _ => None,
        }
    }
}

/// One `ut_holepunch` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolepunchMessage {
    /// Sent by the initiator to the relay: "help me reach this endpoint".
    Rendezvous { target: SocketAddr },
    /// Sent by the relay to both the initiator and the target: "try connecting to this endpoint,
    /// over uTP, now". Also what each is expected to act on by dialing the other.
    Connect { endpoint: SocketAddr },
    /// Sent by the relay back to the initiator alone, naming the same endpoint the `rendezvous`
    /// gave, when the relay could not act on it.
    Error { target: SocketAddr, code: ErrorCode },
}

#[derive(Debug)]
pub enum HolepunchError {
    TooShort,
    UnknownMessageType(u8),
    UnknownAddressType(u8),
    UnknownErrorCode(u32),
}

impl std::fmt::Display for HolepunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HolepunchError::TooShort => write!(f, "ut_holepunch payload is shorter than its fixed layout requires"),
            HolepunchError::UnknownMessageType(n) => write!(f, "unknown ut_holepunch msg_type {}", n),
            HolepunchError::UnknownAddressType(n) => write!(f, "unknown ut_holepunch addr_type {}", n),
            HolepunchError::UnknownErrorCode(n) => write!(f, "unknown ut_holepunch err_code {}", n),
        }
    }
}

impl std::error::Error for HolepunchError {}

impl HolepunchMessage {
    /// The fixed binary payload of the extended message (the extension's own message id is not part of this).
    pub fn encode(&self) -> Vec<u8> {
        let (msg_type, addr, err_code) = match self {
            HolepunchMessage::Rendezvous { target } => (MSG_RENDEZVOUS, *target, 0u32),
            HolepunchMessage::Connect { endpoint } => (MSG_CONNECT, *endpoint, 0u32),
            HolepunchMessage::Error { target, code } => (MSG_ERROR, *target, code.to_u32()),
        };
        let mut out = vec![msg_type];
        match addr.ip() {
            IpAddr::V4(v4) => {
                out.push(ADDR_V4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(ADDR_V6);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&addr.port().to_be_bytes());
        out.extend_from_slice(&err_code.to_be_bytes());
        out
    }

    pub fn decode(payload: &[u8]) -> Result<HolepunchMessage, HolepunchError> {
        if payload.len() < 2 {
            return Err(HolepunchError::TooShort);
        }
        let msg_type = payload[0];
        let addr_type = payload[1];
        let addr_len = match addr_type {
            ADDR_V4 => 4,
            ADDR_V6 => 16,
            other => return Err(HolepunchError::UnknownAddressType(other)),
        };
        // addr_type(1) + addr + port(2) + err_code(4), on top of msg_type(1) already read.
        if payload.len() < 2 + addr_len + 2 + 4 {
            return Err(HolepunchError::TooShort);
        }
        let addr_bytes = &payload[2..2 + addr_len];
        let ip = if addr_type == ADDR_V4 {
            IpAddr::V4(Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]))
        } else {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(addr_bytes);
            IpAddr::V6(Ipv6Addr::from(octets))
        };
        let port_at = 2 + addr_len;
        let port = u16::from_be_bytes([payload[port_at], payload[port_at + 1]]);
        let err_at = port_at + 2;
        let err_code = u32::from_be_bytes([payload[err_at], payload[err_at + 1], payload[err_at + 2], payload[err_at + 3]]);
        let endpoint = SocketAddr::new(ip, port);

        match msg_type {
            MSG_RENDEZVOUS => Ok(HolepunchMessage::Rendezvous { target: endpoint }),
            MSG_CONNECT => Ok(HolepunchMessage::Connect { endpoint }),
            MSG_ERROR => Ok(HolepunchMessage::Error { target: endpoint, code: ErrorCode::from_u32(err_code).ok_or(HolepunchError::UnknownErrorCode(err_code))? }),
            other => Err(HolepunchError::UnknownMessageType(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
    }

    #[test]
    fn rendezvous_round_trips_over_ipv4_and_ipv6() {
        for target in [v4(10, 0, 0, 1, 6881), v6(6881)] {
            let msg = HolepunchMessage::Rendezvous { target };
            assert_eq!(HolepunchMessage::decode(&msg.encode()).unwrap(), msg);
        }
    }

    #[test]
    fn connect_round_trips_over_ipv4_and_ipv6() {
        for endpoint in [v4(192, 168, 1, 2, 51413), v6(51413)] {
            let msg = HolepunchMessage::Connect { endpoint };
            assert_eq!(HolepunchMessage::decode(&msg.encode()).unwrap(), msg);
        }
    }

    #[test]
    fn error_round_trips_every_code() {
        for code in [ErrorCode::NoSuchPeer, ErrorCode::NotConnected, ErrorCode::NoSupport, ErrorCode::NoSelf] {
            let msg = HolepunchMessage::Error { target: v4(1, 2, 3, 4, 999), code };
            assert_eq!(HolepunchMessage::decode(&msg.encode()).unwrap(), msg);
        }
    }

    #[test]
    fn the_wire_layout_matches_the_beps_field_order_exactly() {
        // msg_type=0 (rendezvous), addr_type=0 (v4), 10.0.0.1, port 6881, err_code 0.
        let encoded = HolepunchMessage::Rendezvous { target: v4(10, 0, 0, 1, 6881) }.encode();
        assert_eq!(encoded, vec![0x00, 0x00, 10, 0, 0, 1, 0x1a, 0xe1, 0, 0, 0, 0]);
        assert_eq!(encoded.len(), 12, "1 + 1 + 4 + 2 + 4");
    }

    #[test]
    fn an_ipv6_message_is_twelve_bytes_longer_than_a_v4_one() {
        let v4_len = HolepunchMessage::Connect { endpoint: v4(1, 2, 3, 4, 5) }.encode().len();
        let v6_len = HolepunchMessage::Connect { endpoint: v6(5) }.encode().len();
        assert_eq!(v4_len, 12);
        assert_eq!(v6_len, 24, "1 + 1 + 16 + 2 + 4");
    }

    #[test]
    fn a_hand_written_error_message_decodes_to_its_named_fields() {
        // rendezvous's own target echoed back, NotConnected (0x02).
        let raw = [0x02u8, 0x00, 203, 0, 113, 42, 0x1a, 0xe1, 0x00, 0x00, 0x00, 0x02];
        assert_eq!(HolepunchMessage::decode(&raw).unwrap(), HolepunchMessage::Error { target: v4(203, 0, 113, 42, 6881), code: ErrorCode::NotConnected });
    }

    #[test]
    fn truncated_payloads_are_rejected_not_panicked_on() {
        assert!(matches!(HolepunchMessage::decode(&[]), Err(HolepunchError::TooShort)));
        assert!(matches!(HolepunchMessage::decode(&[0x00]), Err(HolepunchError::TooShort)));
        // A full v4 layout minus its last byte.
        let short = &HolepunchMessage::Connect { endpoint: v4(1, 2, 3, 4, 5) }.encode()[..11];
        assert!(matches!(HolepunchMessage::decode(short), Err(HolepunchError::TooShort)));
        // Claims v6 (needs 24 bytes) but is only as long as a v4 message.
        let mut lying = HolepunchMessage::Connect { endpoint: v4(1, 2, 3, 4, 5) }.encode();
        lying[1] = 0x01;
        assert!(matches!(HolepunchMessage::decode(&lying), Err(HolepunchError::TooShort)));
    }

    #[test]
    fn unknown_message_and_address_types_are_named_errors() {
        let mut raw = HolepunchMessage::Connect { endpoint: v4(1, 2, 3, 4, 5) }.encode();
        raw[0] = 0x7f;
        assert!(matches!(HolepunchMessage::decode(&raw), Err(HolepunchError::UnknownMessageType(0x7f))));

        let mut raw = HolepunchMessage::Connect { endpoint: v4(1, 2, 3, 4, 5) }.encode();
        raw[1] = 0x7f;
        assert!(matches!(HolepunchMessage::decode(&raw), Err(HolepunchError::UnknownAddressType(0x7f))));
    }

    #[test]
    fn an_unrecognized_error_code_is_named_rather_than_silently_accepted() {
        let mut raw = HolepunchMessage::Error { target: v4(1, 2, 3, 4, 5), code: ErrorCode::NoSelf }.encode();
        *raw.last_mut().unwrap() = 0xff; // no such code
        assert!(matches!(HolepunchMessage::decode(&raw), Err(HolepunchError::UnknownErrorCode(0xff))));
    }

    #[test]
    fn error_codes_are_the_beps_own_numbers() {
        assert_eq!(ErrorCode::NoSuchPeer.to_u32(), 0x01);
        assert_eq!(ErrorCode::NotConnected.to_u32(), 0x02);
        assert_eq!(ErrorCode::NoSupport.to_u32(), 0x03);
        assert_eq!(ErrorCode::NoSelf.to_u32(), 0x04);
    }
}
