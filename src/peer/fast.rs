//! The Fast Extension's allowed fast set (BEP 6).
//!
//! A peer that has us choked would ordinarily send us nothing, so a new
//! connection has to wait for its first unchoke before it can start. The
//! Fast Extension gives every peer a few pieces it may request at once, and
//! chooses them by a deterministic recipe from the peer's address and the
//! torrent, so the two sides need not agree on them beforehand and a peer
//! cannot ask for a set of its choosing.

use sha1::{Digest, Sha1};
use std::net::Ipv4Addr;

/// The `count` pieces (of `piece_count`) that the peer at `ip` may request
/// while choked, for the torrent `info_hash`, in the order BEP 6 generates
/// them. Only IPv4 addresses are covered by the BEP.
pub fn allowed_fast_set(ip: Ipv4Addr, info_hash: &[u8; 20], piece_count: u32, count: usize) -> Vec<u32> {
    if piece_count == 0 {
        return Vec::new();
    }
    // Never ask for more than there are to give.
    let count = count.min(piece_count as usize);
    // The peer's address with its last byte masked off, so that peers on one
    // /24 share a set, followed by the info hash.
    let mut seed = Vec::with_capacity(24);
    seed.extend_from_slice(&(u32::from(ip) & 0xFFFF_FF00).to_be_bytes());
    seed.extend_from_slice(info_hash);

    let mut set: Vec<u32> = Vec::with_capacity(count);
    let mut x = seed;
    while set.len() < count {
        x = Sha1::digest(&x).to_vec();
        for chunk in x.as_chunks::<4>().0 {
            if set.len() == count {
                break;
            }
            let index = u32::from_be_bytes(*chunk) % piece_count;
            if !set.contains(&index) {
                set.push(index);
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    const AA: [u8; 20] = [0xaa; 20];

    #[test]
    fn the_seven_piece_set_from_the_specification_is_reproduced() {
        // BEP 6's own worked example: a peer at 80.4.4.200, a torrent whose
        // info hash is twenty 0xaa bytes and which has 1313 pieces.
        assert_eq!(allowed_fast_set(Ipv4Addr::new(80, 4, 4, 200), &AA, 1313, 7), vec![1059, 431, 808, 1217, 287, 376, 1188]);
    }

    #[test]
    fn the_nine_piece_set_extends_the_seven_piece_one() {
        let nine = allowed_fast_set(Ipv4Addr::new(80, 4, 4, 200), &AA, 1313, 9);
        assert_eq!(nine, vec![1059, 431, 808, 1217, 287, 376, 1188, 353, 508], "the specification's second example");
    }

    #[test]
    fn peers_in_one_slash_24_share_a_set_and_others_do_not() {
        let a = allowed_fast_set(Ipv4Addr::new(80, 4, 4, 1), &AA, 1313, 7);
        let b = allowed_fast_set(Ipv4Addr::new(80, 4, 4, 250), &AA, 1313, 7);
        let c = allowed_fast_set(Ipv4Addr::new(80, 4, 5, 200), &AA, 1313, 7);
        assert_eq!(a, b, "the last byte does not matter");
        assert_ne!(a, c, "the third does");
    }

    #[test]
    fn a_different_torrent_gives_a_different_set() {
        let ip = Ipv4Addr::new(80, 4, 4, 200);
        assert_ne!(allowed_fast_set(ip, &AA, 1313, 7), allowed_fast_set(ip, &[0xbb; 20], 1313, 7));
    }

    #[test]
    fn the_set_has_no_repeats_and_stays_within_the_torrent() {
        for pieces in [1u32, 2, 5, 10, 100, 1313] {
            let set = allowed_fast_set(Ipv4Addr::new(1, 2, 3, 4), &AA, pieces, 10);
            assert_eq!(set.len(), (pieces as usize).min(10), "as many as asked for, or every piece if fewer");
            let mut sorted = set.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), set.len(), "no repeats: {:?}", set);
            assert!(set.iter().all(|&p| p < pieces));
        }
    }

    #[test]
    fn a_torrent_with_no_pieces_or_a_zero_count_gives_an_empty_set() {
        assert!(allowed_fast_set(Ipv4Addr::LOCALHOST, &AA, 0, 5).is_empty());
        assert!(allowed_fast_set(Ipv4Addr::LOCALHOST, &AA, 100, 0).is_empty());
    }
}
