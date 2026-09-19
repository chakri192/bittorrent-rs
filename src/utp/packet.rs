//! The uTP packet format (BEP 29): a 20-byte header, then optional
//! extensions, then the payload.
//!
//! ```text
//!  0       4       8               16              24              32
//! +-------+-------+---------------+---------------+---------------+
//! | type  | ver   | extension     | connection_id                 |
//! +-------+-------+---------------+---------------+---------------+
//! | timestamp_microseconds                                        |
//! +---------------+---------------+---------------+---------------+
//! | timestamp_difference_microseconds                             |
//! +---------------+---------------+---------------+---------------+
//! | wnd_size                                                      |
//! +---------------+---------------+---------------+---------------+
//! | seq_nr                        | ack_nr                        |
//! +---------------+---------------+---------------+---------------+
//! ```
//!
//! Extensions form a chain: the header's `extension` byte names the first,
//! and each one is `next-extension, length, payload`. Only selective ACK
//! (type 1) means anything here; others are skipped over by their length.

/// Bytes in the fixed header.
pub const HEADER_LEN: usize = 20;
const VERSION: u8 = 1;
const EXT_SELECTIVE_ACK: u8 = 1;
/// Most selective-ack bytes read or written: 64 packets past the hole.
pub const MAX_SACK_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Payload.
    Data,
    /// The sender is done sending; `seq_nr` is the last packet.
    Fin,
    /// An acknowledgement, with no payload and no sequence number of its own.
    State,
    /// Abort.
    Reset,
    /// Open a connection.
    Syn,
}

impl PacketType {
    fn code(self) -> u8 {
        match self {
            PacketType::Data => 0,
            PacketType::Fin => 1,
            PacketType::State => 2,
            PacketType::Reset => 3,
            PacketType::Syn => 4,
        }
    }

    fn from_code(code: u8) -> Option<PacketType> {
        Some(match code {
            0 => PacketType::Data,
            1 => PacketType::Fin,
            2 => PacketType::State,
            3 => PacketType::Reset,
            4 => PacketType::Syn,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub kind: PacketType,
    pub connection_id: u16,
    /// The sender's clock, in microseconds, modulo 2^32.
    pub timestamp: u32,
    /// The sender's measure of how long the last packet it received from us
    /// took: its clock minus the `timestamp` on that packet.
    pub timestamp_diff: u32,
    /// Bytes of receive buffer the sender has free.
    pub wnd_size: u32,
    pub seq_nr: u16,
    pub ack_nr: u16,
    /// Selective ACK bitmask: bit `i` (least significant first, byte by
    /// byte) says whether `ack_nr + 2 + i` has arrived.
    pub sack: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    TooShort,
    /// Not version 1, or a type that does not exist. Also what a DHT
    /// message looks like to this parser.
    NotUtp,
    /// An extension whose length runs past the end of the datagram.
    BadExtension,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::TooShort => write!(f, "shorter than a uTP header"),
            PacketError::NotUtp => write!(f, "not a uTP packet"),
            PacketError::BadExtension => write!(f, "an extension runs past the end of the packet"),
        }
    }
}

impl std::error::Error for PacketError {}

impl Packet {
    /// The packet as it goes on the wire.
    pub fn encode(&self) -> Vec<u8> {
        let sack = &self.sack[..self.sack.len().min(MAX_SACK_BYTES)];
        let mut out = Vec::with_capacity(HEADER_LEN + 2 + sack.len() + self.payload.len());
        out.push(self.kind.code() << 4 | VERSION);
        out.push(if sack.is_empty() { 0 } else { EXT_SELECTIVE_ACK });
        out.extend_from_slice(&self.connection_id.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.timestamp_diff.to_be_bytes());
        out.extend_from_slice(&self.wnd_size.to_be_bytes());
        out.extend_from_slice(&self.seq_nr.to_be_bytes());
        out.extend_from_slice(&self.ack_nr.to_be_bytes());
        if !sack.is_empty() {
            out.push(0); // no extension after this one
            out.push(sack.len() as u8);
            out.extend_from_slice(sack);
        }
        out.extend_from_slice(&self.payload);
        out
    }

    /// Reads a packet from a datagram.
    pub fn decode(datagram: &[u8]) -> Result<Packet, PacketError> {
        if datagram.len() < HEADER_LEN {
            return Err(PacketError::TooShort);
        }
        if datagram[0] & 0x0F != VERSION {
            return Err(PacketError::NotUtp);
        }
        let kind = PacketType::from_code(datagram[0] >> 4).ok_or(PacketError::NotUtp)?;
        let be16 = |at: usize| u16::from_be_bytes([datagram[at], datagram[at + 1]]);
        let be32 = |at: usize| u32::from_be_bytes([datagram[at], datagram[at + 1], datagram[at + 2], datagram[at + 3]]);

        // The extension chain, which ends at a next-extension byte of 0.
        let mut next = datagram[1];
        let mut at = HEADER_LEN;
        let mut sack = Vec::new();
        while next != 0 {
            let (Some(&following), Some(&len)) = (datagram.get(at), datagram.get(at + 1)) else { return Err(PacketError::BadExtension) };
            let body = datagram.get(at + 2..at + 2 + len as usize).ok_or(PacketError::BadExtension)?;
            if next == EXT_SELECTIVE_ACK && sack.is_empty() {
                sack = body[..body.len().min(MAX_SACK_BYTES)].to_vec();
            }
            next = following;
            at += 2 + len as usize;
        }

        Ok(Packet { kind, connection_id: be16(2), timestamp: be32(4), timestamp_diff: be32(8), wnd_size: be32(12), seq_nr: be16(16), ack_nr: be16(18), sack, payload: datagram[at..].to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Packet {
        Packet { kind: PacketType::Data, connection_id: 0x1234, timestamp: 0xAABBCCDD, timestamp_diff: 0x01020304, wnd_size: 0x0005_0000, seq_nr: 0x8001, ack_nr: 0x7FFF, sack: Vec::new(), payload: b"hello".to_vec() }
    }

    #[test]
    fn the_header_is_laid_out_as_the_bep_draws_it() {
        let bytes = sample().encode();
        assert_eq!(bytes.len(), HEADER_LEN + 5);
        assert_eq!(bytes[0], 0x01, "type 0 (data) in the high nibble, version 1 in the low");
        assert_eq!(bytes[1], 0, "no extension");
        assert_eq!(&bytes[2..4], &[0x12, 0x34], "connection id");
        assert_eq!(&bytes[4..8], &[0xAA, 0xBB, 0xCC, 0xDD], "timestamp");
        assert_eq!(&bytes[8..12], &[1, 2, 3, 4], "timestamp difference");
        assert_eq!(&bytes[12..16], &[0, 5, 0, 0], "window size");
        assert_eq!(&bytes[16..18], &[0x80, 0x01], "seq_nr");
        assert_eq!(&bytes[18..20], &[0x7F, 0xFF], "ack_nr");
        assert_eq!(&bytes[20..], b"hello");
    }

    #[test]
    fn every_type_has_its_number_in_the_high_nibble() {
        for (kind, byte) in [(PacketType::Data, 0x01), (PacketType::Fin, 0x11), (PacketType::State, 0x21), (PacketType::Reset, 0x31), (PacketType::Syn, 0x41)] {
            let bytes = Packet { kind, payload: Vec::new(), ..sample() }.encode();
            assert_eq!(bytes[0], byte, "{:?}", kind);
            assert_eq!(Packet::decode(&bytes).unwrap().kind, kind);
        }
    }

    #[test]
    fn a_packet_reads_back_as_written() {
        let packet = sample();
        assert_eq!(Packet::decode(&packet.encode()).unwrap(), packet);
    }

    #[test]
    fn selective_ack_is_an_extension_between_the_header_and_the_payload() {
        let packet = Packet { kind: PacketType::State, sack: vec![0b0000_0101, 0, 0, 0x80], payload: Vec::new(), ..sample() };
        let bytes = packet.encode();
        assert_eq!(bytes[1], 1, "the header says a selective ack follows");
        assert_eq!(&bytes[20..], &[0, 4, 0b0000_0101, 0, 0, 0x80], "no further extension, four bytes of mask");
        assert_eq!(Packet::decode(&bytes).unwrap(), packet);
    }

    #[test]
    fn a_payload_after_an_extension_is_found() {
        let packet = Packet { sack: vec![1, 2, 3, 4], ..sample() };
        let decoded = Packet::decode(&packet.encode()).unwrap();
        assert_eq!((decoded.sack, decoded.payload), (vec![1, 2, 3, 4], b"hello".to_vec()));
    }

    #[test]
    fn extensions_of_other_kinds_are_stepped_over() {
        // An unknown extension (type 7, 3 bytes), then the selective ack, then the payload.
        let mut bytes = sample().encode();
        bytes.truncate(HEADER_LEN);
        bytes[1] = 7;
        bytes.extend_from_slice(&[EXT_SELECTIVE_ACK, 3, 9, 9, 9]);
        bytes.extend_from_slice(&[0, 4, 0xF0, 0, 0, 0]);
        bytes.extend_from_slice(b"tail");
        let decoded = Packet::decode(&bytes).unwrap();
        assert_eq!((decoded.sack, decoded.payload), (vec![0xF0, 0, 0, 0], b"tail".to_vec()));
    }

    #[test]
    fn what_is_not_a_utp_packet_is_refused() {
        assert_eq!(Packet::decode(&[]), Err(PacketError::TooShort));
        assert_eq!(Packet::decode(&[0x01; HEADER_LEN - 1]), Err(PacketError::TooShort));
        let mut wrong_version = sample().encode();
        wrong_version[0] = 0x02;
        assert_eq!(Packet::decode(&wrong_version), Err(PacketError::NotUtp));
        let mut wrong_type = sample().encode();
        wrong_type[0] = 0x51;
        assert_eq!(Packet::decode(&wrong_type), Err(PacketError::NotUtp));
        // A DHT query begins with 'd'.
        assert_eq!(Packet::decode(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"), Err(PacketError::NotUtp));
    }

    #[test]
    fn an_extension_that_runs_off_the_end_is_refused() {
        let mut bytes = Packet { payload: Vec::new(), sack: vec![1, 2, 3, 4], ..sample() }.encode();
        bytes.truncate(bytes.len() - 1);
        assert_eq!(Packet::decode(&bytes), Err(PacketError::BadExtension));
        let mut no_length = sample().encode();
        no_length.truncate(HEADER_LEN);
        no_length[1] = 1;
        assert_eq!(Packet::decode(&no_length), Err(PacketError::BadExtension));
    }

    #[test]
    fn a_long_selective_ack_is_cut_to_what_is_used_on_both_ends() {
        let long = Packet { sack: vec![0xFF; 32], ..sample() };
        assert_eq!(long.encode()[21], MAX_SACK_BYTES as u8, "writing sends no more");
        let mut wire = sample().encode();
        wire.truncate(HEADER_LEN);
        wire[1] = 1;
        wire.extend_from_slice(&[0, 32]);
        wire.extend_from_slice(&[0xFF; 32]);
        assert_eq!(Packet::decode(&wire).unwrap().sack.len(), MAX_SACK_BYTES, "and reading keeps no more");
    }
}
