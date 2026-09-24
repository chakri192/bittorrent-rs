//! Node ids that say where they are from (BEP 42): the first 21 bits of an id are made from a CRC-32C of the node's
//! IP address, so that one machine cannot pick the ids it has, and placing many of them where it wants (next to a
//! victim's info hash, say) takes as many addresses as ids. A node makes its own id this way once it knows its
//! external address, and can check anyone else's.

use super::krpc::NodeId;
use std::net::IpAddr;

/// CRC-32C (Castagnoli), the checksum BEP 42 takes: reflected, polynomial `0x1EDC6F41` (`0x82F63B78` reversed), initial value
/// and final xor `0xFFFFFFFF`.
pub fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    !crc
}

/// What BEP 42 keeps of an IPv4 address (its mask `0x030f3fff`) and of the first 64 bits of an IPv6 one (`0x0103070f1f3f7fff`).
const MASK_V4: [u8; 4] = [0x03, 0x0f, 0x3f, 0xff];
const MASK_V6: [u8; 8] = [0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];

/// The CRC-32C an id for `ip` starts with, with the three low bits of `rand` mixed into the address as BEP 42 has it.
fn checksum(ip: IpAddr, rand: u8) -> u32 {
    let r = (rand & 0x07) << 5;
    match ip {
        IpAddr::V4(v4) => {
            let mut bytes = v4.octets();
            for (byte, mask) in bytes.iter_mut().zip(MASK_V4) {
                *byte &= mask;
            }
            bytes[0] |= r;
            crc32c(&bytes)
        }
        IpAddr::V6(v6) => {
            let mut bytes: [u8; 8] = v6.octets()[..8].try_into().unwrap_or_default();
            for (byte, mask) in bytes.iter_mut().zip(MASK_V6) {
                *byte &= mask;
            }
            bytes[0] |= r;
            crc32c(&bytes)
        }
    }
}

/// An id for a node at `ip`: `random` with its first 21 bits taken from the checksum, and `rand` (whose low three bits went into
/// the checksum) as its last byte, so that anyone can work the check out again.
pub fn node_id_for(ip: IpAddr, rand: u8, mut random: NodeId) -> NodeId {
    let crc = checksum(ip, rand);
    random[0] = (crc >> 24) as u8;
    random[1] = (crc >> 16) as u8;
    random[2] = ((crc >> 8) as u8 & 0xf8) | (random[2] & 0x07);
    random[19] = rand;
    random
}

/// Whether `id` is one a node at `ip` could have made. Addresses that are not the open internet's (a private network, loopback,
/// link-local) are exempt, as BEP 42 says: nothing there could be told from anything else.
pub fn is_valid(id: &NodeId, ip: IpAddr) -> bool {
    if is_local(ip) {
        return true;
    }
    let crc = checksum(ip, id[19]);
    id[0] == (crc >> 24) as u8 && id[1] == (crc >> 16) as u8 && id[2] & 0xf8 == (crc >> 8) as u8 & 0xf8
}

/// Addresses BEP 42 leaves out: private (10/8, 172.16/12, 192.168/16), loopback, link-local (169.254/16, fe80::/10) and unique-local
/// IPv6 (fc00::/7), and unspecified.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> NodeId {
        let mut id = [0u8; 20];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        id
    }

    #[test]
    fn crc32c_is_the_castagnoli_checksum() {
        // The standard check value of the algorithm, and two more that pin the initial value and the final xor.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    /// The example ids of BEP 42 itself: an address, the `rand` byte, and an id that goes with them.
    const BEP42: [(&str, u8, &str); 5] = [
        ("124.31.75.21", 1, "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"),
        ("21.75.31.124", 86, "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256"),
        ("65.23.51.170", 22, "a5d43220bc8f112a3d426c84764f8c2a1150e616"),
        ("84.124.73.14", 65, "1b0321dd1bb1fe518101ceef99462b947a01ff41"),
        ("43.213.53.83", 90, "e56f6cbf5b7c4be0237986d5243b87aa6d51305a"),
    ];

    #[test]
    fn the_examples_of_the_bep_are_valid_and_the_ids_we_make_for_them_start_the_same_way() {
        for (ip, rand, id) in BEP42 {
            let (ip, id): (IpAddr, NodeId) = (ip.parse().unwrap(), hex(id));
            assert!(is_valid(&id, ip), "{} with {:02x?}", ip, id);
            let mine = node_id_for(ip, rand, [0xAA; 20]);
            assert_eq!(&mine[..2], &id[..2], "the first two bytes come from the checksum alone");
            assert_eq!(mine[2] & 0xf8, id[2] & 0xf8, "and so do five bits of the third");
            assert_eq!(mine[19], rand);
            assert!(is_valid(&mine, ip));
        }
    }

    #[test]
    fn an_id_is_valid_for_the_address_it_was_made_for_and_almost_never_for_another() {
        let (ip, other): (IpAddr, IpAddr) = ("124.31.75.21".parse().unwrap(), "124.31.75.22".parse().unwrap());
        let id = node_id_for(ip, 1, [0x55; 20]);
        assert!(is_valid(&id, ip));
        // (Which of the addresses next to it the same ids also suit is by chance, 1 in 2^21: this one is not.)
        assert!(!is_valid(&id, other) || is_valid(&node_id_for(other, 1, [0x55; 20]), other));
        let mut wrong = id;
        wrong[0] ^= 0x01;
        assert!(!is_valid(&wrong, ip), "a flipped bit of the first byte");
        wrong = id;
        wrong[1] ^= 0x80;
        assert!(!is_valid(&wrong, ip), "and of the second");
        wrong = id;
        wrong[2] ^= 0x08;
        assert!(!is_valid(&wrong, ip), "and of the 21st bit");
        wrong = id;
        wrong[2] ^= 0x07;
        assert!(is_valid(&wrong, ip), "the three bits after the 21st are free");
        wrong = id;
        wrong[5] ^= 0xFF;
        assert!(is_valid(&wrong, ip), "as is everything after them, but the last byte");
    }

    #[test]
    fn the_last_byte_carries_the_random_number_the_checksum_used() {
        let ip: IpAddr = "65.23.51.170".parse().unwrap();
        let id = node_id_for(ip, 22, [0; 20]);
        assert!(is_valid(&id, ip));
        let mut changed = id;
        changed[19] = 23; // another low three bits: another checksum
        assert!(!is_valid(&changed, ip));
        changed[19] = 22 + 8; // the same low three bits: the same one
        assert!(is_valid(&changed, ip), "only the low three bits count");
    }

    #[test]
    fn ipv6_ids_are_made_and_checked_from_the_first_sixty_four_bits() {
        let ip: IpAddr = "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap();
        let id = node_id_for(ip, 5, [0x33; 20]);
        assert!(is_valid(&id, ip));
        // The same network prefix is the same address for this: its interface bits are not in the checksum.
        let neighbour: IpAddr = "2001:db8:85a3:8d3:ffff:ffff:ffff:ffff".parse().unwrap();
        assert!(is_valid(&id, neighbour));
        let elsewhere: IpAddr = "2001:db8:85a3:8d4:1319:8a2e:370:7348".parse().unwrap();
        assert_ne!(checksum(ip, 5), checksum(elsewhere, 5), "another /64 has another checksum");
        // Worked out here without the masks' arrays: the same bytes as the BEP's mask, 0x0103070f1f3f7fff.
        let mut bytes = [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3];
        for (byte, mask) in bytes.iter_mut().zip(0x0103_070f_1f3f_7fffu64.to_be_bytes()) {
            *byte &= mask;
        }
        bytes[0] |= 5 << 5;
        assert_eq!(checksum(ip, 5), crc32c(&bytes));
    }

    #[test]
    fn addresses_that_are_not_the_open_internets_are_exempt() {
        let anything = [0x99u8; 20];
        for ip in ["10.1.2.3", "172.16.0.9", "192.168.1.1", "127.0.0.1", "169.254.7.7", "::1", "fe80::1", "fd00::1"] {
            assert!(is_valid(&anything, ip.parse().unwrap()), "{}", ip);
        }
        for ip in ["8.8.8.8", "124.31.75.21", "2001:db8::1"] {
            assert!(!is_valid(&anything, ip.parse().unwrap()), "{} is not exempt, and that id is nobody's", ip);
        }
    }
}
