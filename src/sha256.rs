//! SHA-256 (FIPS 180-4), for BitTorrent v2 (BEP 52): its info hash, the
//! block hashes and the merkle trees over them.
//!
//! Written here rather than pulled in, like the rest of the primitives, and
//! checked against the standard's own test vectors and against Python's
//! `hashlib` in the tests.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/// An incremental SHA-256.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256 { state: INITIAL, buffer: [0; 64], buffered: 0, length: 0 }
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, word) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, add) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(add);
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                return;
            }
            let block = self.buffer;
            compress(&mut self.state, &block);
            self.buffered = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            compress(&mut self.state, &fixed);
        }
        let rest = blocks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bits = self.length.wrapping_mul(8);
        let mut tail = vec![0x80u8];
        tail.resize(1 + ((119 - self.buffered) % 64), 0);
        tail.extend_from_slice(&bits.to_be_bytes());
        let length = self.length;
        self.update(&tail);
        self.length = length;
        debug_assert_eq!(self.buffered, 0);
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// The SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn the_standards_test_vectors() {
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        assert_eq!(hex(&sha256(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    }

    #[test]
    fn a_million_as() {
        let mut hasher = Sha256::new();
        for _ in 0..10_000 {
            hasher.update(&[b'a'; 100]);
        }
        assert_eq!(hex(&hasher.finalize()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    #[test]
    fn lengths_around_the_padding_boundaries_agree_with_hashlib() {
        // Python: hashlib.sha256(bytes((i * 31 + 7) & 0xff for i in range(n))).hexdigest()
        let expected = [
            (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (1, "ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879"),
            (54, "c802146d5788fb540fbf29d8ff485730ad10f4f13b78961c032e78691b582647"),
            (55, "8aa994584139d128848eeebc4e815639ba5ab6e6e39574195a63ac4f14f7c43b"),
            (56, "ad574708f75c044c9b85de64cb568ee7711ff4f36448c6242f053ba8f6cc2b63"),
            (57, "5b46e502092be01b1100193e089fdda95638c12e19a1d24f308eb2c3d3ae849d"),
            (63, "280ed3e8ff1df845b2e7dfe6ac6cee817bef20e783cc65abc41b818b4d2fe076"),
            (64, "c6ab9724ade5b6a7a1edfffb12f3aa9181351355af8fd08c919952ad211339dd"),
            (65, "788367c73c7ddf4c53f65e68cc0d943e6227ab55b0e78ba63ace822b1c6301c0"),
            (119, "3d610547d68216dedf7435a4fb6260353911f6b3fd3f18805ddb8be285d726fe"),
            (120, "1f80156a804cb7862ad113e8200e9d74499723e7c7854d5f48776d3148e09656"),
            (127, "192409cd280e14b743642ad1343fbd3e82d9305de72c078117745a679210cc3d"),
            (128, "cc548ca2dec1f6fe4f58b2e27aa9c7521607df1130d140b55a4dad0665302356"),
            (129, "81e89a7b2911aaa7795f9e3d4910cb47d6cd2b00d83b8399481527261a1a7519"),
            (1000, "5097e7d587352f5097062ae679f37bda5802d9f875aba14c8cb4d1a188ada179"),
        ];
        for (len, digest) in expected {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            assert_eq!(hex(&sha256(&data)), digest, "length {}", len);
            // And fed in pieces of every awkward size, the same.
            for step in [1usize, 3, 7, 63, 64, 65] {
                let mut hasher = Sha256::new();
                for chunk in data.chunks(step) {
                    hasher.update(chunk);
                }
                assert_eq!(hex(&hasher.finalize()), digest, "length {} fed {} at a time", len, step);
            }
        }
    }
}
