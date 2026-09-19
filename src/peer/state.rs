//! Per-peer connection state: the four choke/interest flags plus the
//! peer's known piece availability (bitfield), updated as `Message`s
//! arrive. This is pure state-transition logic -- no I/O -- so it's fully
//! unit-testable without a socket.

use super::message::Message;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerState {
    /// We are choking this peer (refusing to upload to them).
    pub am_choking: bool,
    /// We are interested in this peer (they have pieces we want).
    pub am_interested: bool,
    /// This peer is choking us (won't upload to us).
    pub peer_choking: bool,
    /// This peer is interested in us.
    pub peer_interested: bool,
    /// Bitfield of pieces this peer claims to have, one bit per piece,
    /// MSB-first within each byte (BEP 3 `bitfield`/`have` semantics).
    pub peer_has_pieces: Vec<bool>,
    /// Whether the post-handshake extended handshake (BEP 10) has been
    /// exchanged and this peer supports it. Set by the connection layer,
    /// not by `apply_message` (the extended handshake payload itself is
    /// parsed in Phase 4).
    pub supports_extensions: bool,
    /// The most outstanding requests the peer said it will queue (`reqq` in
    /// its extended handshake), if it said.
    pub peer_request_limit: Option<usize>,
    /// How many pieces `peer_has_pieces` may ever describe: the torrent's
    /// piece count. Piece indices come off the wire, so without a bound a
    /// single `have` for piece 4294967295 makes the client allocate 4 GiB.
    piece_limit: usize,
}

/// The ceiling on pieces tracked when the torrent's real piece count is
/// not known (16 Mi pieces, 16 MiB of state). Real torrents have far fewer.
pub const MAX_TRACKED_PIECES: usize = 1 << 24;

impl Default for PeerState {
    /// Per BEP 3: both sides start choked and not-interested.
    fn default() -> Self {
        PeerState {
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            peer_has_pieces: Vec::new(),
            supports_extensions: false,
            peer_request_limit: None,
            piece_limit: MAX_TRACKED_PIECES,
        }
    }
}

impl PeerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// State for a peer of a torrent with `piece_count` pieces: anything a
    /// peer says about a piece beyond that is ignored.
    pub fn for_torrent(piece_count: usize) -> Self {
        PeerState { piece_limit: piece_count.min(MAX_TRACKED_PIECES), ..Self::default() }
    }

    /// Ensures `peer_has_pieces` can index up to `piece_index` inclusive,
    /// growing (never shrinking) with `false` for any newly-added slots.
    fn ensure_capacity(&mut self, piece_index: usize) {
        if self.peer_has_pieces.len() <= piece_index {
            self.peer_has_pieces.resize(piece_index + 1, false);
        }
    }

    /// Applies an incoming `Message`'s effect on this peer's state.
    /// Returns `true` if the message was one this state machine handles
    /// (choke/unchoke/interested/not-interested/have/bitfield); `Request`,
    /// `Piece`, `Cancel`, `Port`, `Extended`, and `KeepAlive` don't affect
    /// these flags and are left for the downloader/extension layers
    /// (Phases 4-5) to act on, so this returns `false` for those without
    /// treating them as an error.
    pub fn apply_message(&mut self, msg: &Message) -> bool {
        match msg {
            Message::Choke => {
                self.peer_choking = true;
                true
            }
            Message::Unchoke => {
                self.peer_choking = false;
                true
            }
            Message::Interested => {
                self.peer_interested = true;
                true
            }
            Message::NotInterested => {
                self.peer_interested = false;
                true
            }
            Message::Have { piece_index } => {
                let index = *piece_index as usize;
                if index >= self.piece_limit {
                    return false; // a piece this torrent does not have: ignore it
                }
                self.ensure_capacity(index);
                self.peer_has_pieces[index] = true;
                true
            }
            Message::Bitfield(bits) => {
                self.peer_has_pieces = bytes_to_bitfield(bits);
                // A bitfield is padded to whole bytes, and a peer may send
                // more than that; only the torrent's pieces count.
                self.peer_has_pieces.truncate(self.piece_limit);
                true
            }
            _ => false,
        }
    }

    /// Serializes our current availability into a BEP 3 `bitfield` payload
    /// (used when we send our own bitfield right after the handshake).
    pub fn encode_bitfield(have: &[bool]) -> Vec<u8> {
        bitfield_to_bytes(have)
    }
}

/// Unpacks a `bitfield` message payload into one `bool` per piece,
/// MSB-first: bit 7 of byte 0 is piece 0, bit 6 of byte 0 is piece 1, etc.
fn bytes_to_bitfield(bytes: &[u8]) -> Vec<bool> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for bit in (0..8).rev() {
            out.push((byte >> bit) & 1 == 1);
        }
    }
    out
}

/// Inverse of `bytes_to_bitfield`; pads the final byte with zero bits.
fn bitfield_to_bytes(have: &[bool]) -> Vec<u8> {
    let num_bytes = have.len().div_ceil(8);
    let mut out = vec![0u8; num_bytes];
    for (i, &has_it) in have.iter().enumerate() {
        if has_it {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_matches_bep3_initial_values() {
        let s = PeerState::default();
        assert!(s.am_choking);
        assert!(!s.am_interested);
        assert!(s.peer_choking);
        assert!(!s.peer_interested);
        assert!(s.peer_has_pieces.is_empty());
    }

    #[test]
    fn choke_unchoke_toggle_peer_choking() {
        let mut s = PeerState::new();
        s.apply_message(&Message::Unchoke);
        assert!(!s.peer_choking);
        s.apply_message(&Message::Choke);
        assert!(s.peer_choking);
    }

    #[test]
    fn interested_not_interested_toggle_peer_interested() {
        let mut s = PeerState::new();
        s.apply_message(&Message::Interested);
        assert!(s.peer_interested);
        s.apply_message(&Message::NotInterested);
        assert!(!s.peer_interested);
    }

    #[test]
    fn have_sets_single_piece_and_grows_vector() {
        let mut s = PeerState::new();
        s.apply_message(&Message::Have { piece_index: 5 });
        assert_eq!(s.peer_has_pieces.len(), 6);
        assert!(s.peer_has_pieces[5]);
        assert!(!s.peer_has_pieces[0]);
    }

    #[test]
    fn multiple_haves_accumulate() {
        let mut s = PeerState::new();
        s.apply_message(&Message::Have { piece_index: 0 });
        s.apply_message(&Message::Have { piece_index: 2 });
        assert_eq!(s.peer_has_pieces, vec![true, false, true]);
    }

    #[test]
    fn bitfield_unpacks_msb_first() {
        let mut s = PeerState::new();
        // 0b1010_0000 -> piece 0 = true, piece 1 = false, piece 2 = true, rest false
        s.apply_message(&Message::Bitfield(vec![0b1010_0000]));
        assert_eq!(s.peer_has_pieces, vec![true, false, true, false, false, false, false, false]);
    }

    #[test]
    fn bitfield_replaces_prior_have_state() {
        let mut s = PeerState::new();
        s.apply_message(&Message::Have { piece_index: 0 });
        s.apply_message(&Message::Bitfield(vec![0b0000_0000]));
        assert_eq!(s.peer_has_pieces, vec![false; 8]);
    }

    #[test]
    fn requests_and_pieces_do_not_affect_flags_and_return_false() {
        let mut s = PeerState::new();
        let handled = s.apply_message(&Message::Request { index: 0, begin: 0, length: 16384 });
        assert!(!handled);
        assert_eq!(s, PeerState::default());
    }

    #[test]
    fn encode_bitfield_round_trips_through_bytes_to_bitfield() {
        let have = vec![true, false, true, true, false, false, false, false, true];
        let encoded = PeerState::encode_bitfield(&have);
        assert_eq!(encoded.len(), 2); // 9 bits -> 2 bytes, padded
        let decoded = bytes_to_bitfield(&encoded);
        assert_eq!(&decoded[..9], have.as_slice());
        assert_eq!(&decoded[9..], &[false; 7]); // padding bits are zero
    }

    #[test]
    fn encode_bitfield_empty_is_empty_bytes() {
        assert_eq!(PeerState::encode_bitfield(&[]), Vec::<u8>::new());
    }

    #[test]
    fn a_have_beyond_the_torrent_is_ignored_and_allocates_nothing() {
        // One nine-byte message used to make the client allocate 4 GiB.
        let mut s = PeerState::for_torrent(100);
        assert!(!s.apply_message(&Message::Have { piece_index: u32::MAX }));
        assert!(!s.apply_message(&Message::Have { piece_index: 100 }));
        assert!(s.peer_has_pieces.is_empty(), "nothing grew: {}", s.peer_has_pieces.len());
    }

    #[test]
    fn the_last_piece_is_tracked_and_the_one_after_it_is_not() {
        let mut s = PeerState::for_torrent(100);
        assert!(s.apply_message(&Message::Have { piece_index: 99 }));
        assert!(s.peer_has_pieces[99]);
        assert_eq!(s.peer_has_pieces.len(), 100);
        assert!(!s.apply_message(&Message::Have { piece_index: 100 }));
        assert_eq!(s.peer_has_pieces.len(), 100);
    }

    #[test]
    fn without_a_known_piece_count_there_is_still_a_ceiling() {
        let mut s = PeerState::new();
        assert!(!s.apply_message(&Message::Have { piece_index: u32::MAX }));
        assert!(!s.apply_message(&Message::Have { piece_index: MAX_TRACKED_PIECES as u32 }));
        assert!(s.peer_has_pieces.is_empty());
        assert!(PeerState::for_torrent(usize::MAX).piece_limit == MAX_TRACKED_PIECES, "a huge claimed count is capped too");
    }

    #[test]
    fn a_bitfield_longer_than_the_torrent_is_cut_to_it() {
        let mut s = PeerState::for_torrent(10);
        assert!(s.apply_message(&Message::Bitfield(vec![0xff; 1000])));
        assert_eq!(s.peer_has_pieces.len(), 10, "not 8000");
        assert!(s.peer_has_pieces.iter().all(|&b| b));
    }

    #[test]
    fn a_bitfield_within_the_torrent_is_kept_whole() {
        let mut s = PeerState::for_torrent(100);
        s.apply_message(&Message::Bitfield(vec![0b1010_0000]));
        assert_eq!(&s.peer_has_pieces, &[true, false, true, false, false, false, false, false]);
    }
}
