//! BitTorrent peer wire handshake (BEP 3), 68 bytes fixed:
//! `pstrlen(1) + pstr(19) + reserved(8) + info_hash(20) + peer_id(20)`.

const PSTR: &[u8; 19] = b"BitTorrent protocol";
pub const HANDSHAKE_LEN: usize = 1 + 19 + 8 + 20 + 20;

/// Reserved-byte bit for BEP 10 (Extension Protocol): the last of the 8
/// reserved bytes, bit `0x10` (bit index 20 counting from the most
/// significant bit of the whole 64-bit reserved field, per BEP 10's own
/// wording -- concretely: `reserved[5] |= 0x10`).
const EXTENSION_PROTOCOL_BIT_BYTE: usize = 5;
const EXTENSION_PROTOCOL_BIT_MASK: u8 = 0x10;

/// Reserved-byte bit for BEP 6 (Fast Extension): `reserved[7] |= 0x04`.
/// Used between two peers only if both set it.
const FAST_EXTENSION_BIT_BYTE: usize = 7;
const FAST_EXTENSION_BIT_MASK: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    TooShort,
    BadPstrLen(u8),
    BadPstr,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::TooShort => write!(f, "handshake buffer shorter than {} bytes", HANDSHAKE_LEN),
            HandshakeError::BadPstrLen(n) => write!(f, "expected pstrlen 19, got {}", n),
            HandshakeError::BadPstr => write!(f, "pstr was not b\"BitTorrent protocol\""),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl Handshake {
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20], support_extensions: bool) -> Self {
        let mut reserved = [0u8; 8];
        if support_extensions {
            reserved[EXTENSION_PROTOCOL_BIT_BYTE] |= EXTENSION_PROTOCOL_BIT_MASK;
        }
        Handshake { reserved, info_hash, peer_id }
    }

    /// This handshake, with the Fast Extension bit (BEP 6) set or cleared.
    pub fn with_fast(mut self, fast: bool) -> Self {
        if fast {
            self.reserved[FAST_EXTENSION_BIT_BYTE] |= FAST_EXTENSION_BIT_MASK;
        } else {
            self.reserved[FAST_EXTENSION_BIT_BYTE] &= !FAST_EXTENSION_BIT_MASK;
        }
        self
    }

    /// Whether the sender speaks the Fast Extension (BEP 6).
    pub fn supports_fast(&self) -> bool {
        self.reserved[FAST_EXTENSION_BIT_BYTE] & FAST_EXTENSION_BIT_MASK != 0
    }

    pub fn supports_extensions(&self) -> bool {
        self.reserved[EXTENSION_PROTOCOL_BIT_BYTE] & EXTENSION_PROTOCOL_BIT_MASK != 0
    }

    pub fn to_bytes(&self) -> [u8; HANDSHAKE_LEN] {
        let mut buf = [0u8; HANDSHAKE_LEN];
        buf[0] = 19;
        buf[1..20].copy_from_slice(PSTR);
        buf[20..28].copy_from_slice(&self.reserved);
        buf[28..48].copy_from_slice(&self.info_hash);
        buf[48..68].copy_from_slice(&self.peer_id);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, HandshakeError> {
        if buf.len() < HANDSHAKE_LEN {
            return Err(HandshakeError::TooShort);
        }
        if buf[0] != 19 {
            return Err(HandshakeError::BadPstrLen(buf[0]));
        }
        if &buf[1..20] != PSTR.as_slice() {
            return Err(HandshakeError::BadPstr);
        }
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[20..28]);
        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&buf[28..48]);
        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&buf[48..68]);
        Ok(Handshake { reserved, info_hash, peer_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_without_extensions() {
        let hs = Handshake::new([0xAA; 20], [0xBB; 20], false);
        let bytes = hs.to_bytes();
        assert_eq!(bytes.len(), HANDSHAKE_LEN);
        let parsed = Handshake::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, hs);
        assert!(!parsed.supports_extensions());
    }

    #[test]
    fn round_trips_with_extensions() {
        let hs = Handshake::new([0x11; 20], [0x22; 20], true);
        let bytes = hs.to_bytes();
        let parsed = Handshake::from_bytes(&bytes).unwrap();
        assert!(parsed.supports_extensions());
        assert_eq!(parsed.reserved[5], 0x10);
    }

    #[test]
    fn extension_bit_does_not_disturb_other_reserved_bits() {
        let hs = Handshake::new([0; 20], [0; 20], true);
        assert_eq!(hs.reserved, [0, 0, 0, 0, 0, 0x10, 0, 0]);
    }

    #[test]
    fn wire_layout_matches_spec_byte_offsets() {
        let hs = Handshake::new([0xAB; 20], [0xCD; 20], true);
        let bytes = hs.to_bytes();
        assert_eq!(bytes[0], 19);
        assert_eq!(&bytes[1..20], PSTR.as_slice());
        assert_eq!(bytes[20..28], [0, 0, 0, 0, 0, 0x10, 0, 0]);
        assert_eq!(&bytes[28..48], &[0xAB; 20]);
        assert_eq!(&bytes[48..68], &[0xCD; 20]);
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(Handshake::from_bytes(&[0u8; 10]), Err(HandshakeError::TooShort));
    }

    #[test]
    fn rejects_wrong_pstrlen() {
        let mut buf = [0u8; HANDSHAKE_LEN];
        buf[0] = 20;
        assert_eq!(Handshake::from_bytes(&buf), Err(HandshakeError::BadPstrLen(20)));
    }

    #[test]
    fn rejects_wrong_pstr() {
        let mut buf = Handshake::new([0; 20], [0; 20], false).to_bytes();
        buf[1] = b'X';
        assert_eq!(Handshake::from_bytes(&buf), Err(HandshakeError::BadPstr));
    }

    #[test]
    fn accepts_trailing_garbage_after_68_bytes() {
        // Some peers pipeline the first wire message right after the
        // handshake in the same TCP segment; from_bytes only needs the
        // prefix to be valid.
        let mut buf = Handshake::new([1; 20], [2; 20], false).to_bytes().to_vec();
        buf.extend_from_slice(&[0, 0, 0, 1, 2]); // e.g. start of an Unchoke message
        assert!(Handshake::from_bytes(&buf).is_ok());
    }

    #[test]
    fn the_fast_extension_bit_is_reserved_7_0x04_and_leaves_the_others_alone() {
        let plain = Handshake::new([1; 20], [2; 20], true);
        assert!(!plain.supports_fast());
        let fast = plain.clone().with_fast(true);
        assert!(fast.supports_fast());
        assert_eq!(fast.reserved[7], 0x04);
        assert!(fast.supports_extensions(), "the extension protocol bit is still set");
        assert_eq!(fast.to_bytes()[27], 0x04, "byte 27 of the handshake: 20 + 7");
        assert!(Handshake::from_bytes(&fast.to_bytes()).unwrap().supports_fast(), "and it survives the wire");
        assert!(!fast.with_fast(false).supports_fast(), "and can be cleared");
    }
}
