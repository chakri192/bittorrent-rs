//! Message Stream Encryption (MSE, also called protocol encryption): an
//! obfuscation layer some peers and many ISPs' traffic shapers care about.
//! A connection starts with a Diffie-Hellman exchange, proves both sides
//! know the torrent's info hash without sending it, and then carries the
//! ordinary BitTorrent stream through RC4, or in plaintext if both agree.
//!
//! It is obfuscation, not security: the info hash is the only secret, and
//! RC4 is weak. What it buys is that the traffic does not begin with the
//! recognisable `\x13BitTorrent protocol`.
//!
//! The exchange, `A` connecting to `B`, with `S` the shared secret and
//! `SKEY` the info hash (all hashes SHA-1):
//!
//! ```text
//! A -> B  Ya, PadA                      Ya = 2^a mod P, 96 bytes; 0-512 pad
//! B -> A  Yb, PadB
//! A -> B  HASH("req1", S)
//!         HASH("req2", SKEY) xor HASH("req3", S)
//!         RC4(VC, crypto_provide, len(PadC), PadC, len(IA)), RC4(IA)
//! B -> A  RC4(VC, crypto_select, len(PadD), PadD)
//!         then the payload, RC4 or plaintext as selected
//! ```
//!
//! `VC` is eight zero bytes; `crypto_provide` and `crypto_select` are bit
//! fields (1 = plaintext, 2 = RC4); `IA` is initial payload that saves a
//! round trip. A's cipher is keyed `HASH("keyA", S, SKEY)` and B's
//! `HASH("keyB", S, SKEY)`, and each drops the first 1024 bytes it makes.
//! Neither side knows how long the other's pad is, so each finds what it is
//! waiting for by scanning for it: B for `HASH("req1", S)`, A for the
//! encrypted `VC`.
//!
//! This was written from the specification and checked against reference
//! values (the big-integer arithmetic against Python's, RC4 against its
//! published test vectors) and against itself; it has not been exercised
//! against another client's implementation.

use super::stream::{Closer, PeerStream};
use sha1::{Digest, Sha1};
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Whether to use MSE, and how firmly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encryption {
    /// Plaintext only; encrypted connections are not understood.
    #[default]
    Off,
    /// Encrypted where the peer will, plaintext otherwise. An outgoing
    /// connection tries MSE first and falls back to a plain connection;
    /// an incoming one may be either.
    Prefer,
    /// Encrypted only: outgoing connections that cannot be encrypted fail,
    /// and plaintext incoming ones are refused.
    Require,
}

impl Encryption {
    pub fn parse(text: &str) -> Result<Encryption, String> {
        match text.to_ascii_lowercase().as_str() {
            "off" | "no" | "false" => Ok(Encryption::Off),
            "prefer" | "on" | "true" => Ok(Encryption::Prefer),
            "require" | "force" => Ok(Encryption::Require),
            other => Err(format!("not an encryption mode: {:?} (use off, prefer or require)", other)),
        }
    }
}

// ---- 768-bit arithmetic --------------------------------------------------

/// Limbs in a 768-bit number.
const LIMBS: usize = 24;
/// Bytes in a Diffie-Hellman public key.
pub const KEY_BYTES: usize = 96;

/// The prime `P`, big-endian hex, from the specification.
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563";

type Big = [u32; LIMBS];

fn from_be_bytes(bytes: &[u8]) -> Big {
    let mut out = [0u32; LIMBS];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        if i / 4 < LIMBS {
            out[i / 4] |= (byte as u32) << (8 * (i % 4));
        }
    }
    out
}

fn to_be_bytes(n: &Big) -> [u8; KEY_BYTES] {
    let mut out = [0u8; KEY_BYTES];
    for i in 0..KEY_BYTES {
        out[KEY_BYTES - 1 - i] = (n[i / 4] >> (8 * (i % 4))) as u8;
    }
    out
}

fn cmp(a: &Big, b: &Big) -> std::cmp::Ordering {
    for i in (0..LIMBS).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// `a - b`, wrapping; the caller knows `a >= b` (or wants the wrap).
fn sub(a: &Big, b: &Big) -> Big {
    let mut out = [0u32; LIMBS];
    let mut borrow = 0i64;
    for i in 0..LIMBS {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        out[i] = d as u32;
        borrow = i64::from(d < 0);
    }
    out
}

struct Montgomery {
    modulus: Big,
    /// `-modulus^-1 mod 2^32`.
    n0: u32,
    /// `R^2 mod modulus`, with `R = 2^768`.
    r2: Big,
}

impl Montgomery {
    fn new(modulus: Big) -> Montgomery {
        // Newton's iteration for the inverse of the low limb mod 2^32.
        let m0 = modulus[0];
        let mut inv = 1u32;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(m0.wrapping_mul(inv)));
        }
        // R^2 mod m by doubling 1 a total of 2 * 768 times, reducing as we go.
        let mut r2 = [0u32; LIMBS];
        r2[0] = 1;
        for _ in 0..(2 * 32 * LIMBS) {
            let mut carry = 0u32;
            for limb in r2.iter_mut() {
                let next = *limb >> 31;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            if carry == 1 || cmp(&r2, &modulus) != std::cmp::Ordering::Less {
                r2 = sub(&r2, &modulus);
            }
        }
        Montgomery { modulus, n0: inv.wrapping_neg(), r2 }
    }

    /// `a * b * R^-1 mod m` for `a, b < m` (coarsely integrated operand
    /// scanning).
    fn mul(&self, a: &Big, b: &Big) -> Big {
        let mut t = [0u32; LIMBS + 2];
        for &bi in b.iter() {
            let mut carry = 0u64;
            for j in 0..LIMBS {
                let v = t[j] as u64 + a[j] as u64 * bi as u64 + carry;
                t[j] = v as u32;
                carry = v >> 32;
            }
            let v = t[LIMBS] as u64 + carry;
            t[LIMBS] = v as u32;
            t[LIMBS + 1] = (v >> 32) as u32;

            let q = t[0].wrapping_mul(self.n0);
            let v = t[0] as u64 + q as u64 * self.modulus[0] as u64;
            let mut carry = v >> 32;
            for j in 1..LIMBS {
                let v = t[j] as u64 + q as u64 * self.modulus[j] as u64 + carry;
                t[j - 1] = v as u32;
                carry = v >> 32;
            }
            let v = t[LIMBS] as u64 + carry;
            t[LIMBS - 1] = v as u32;
            t[LIMBS] = t[LIMBS + 1] + (v >> 32) as u32;
        }
        let mut out = [0u32; LIMBS];
        out.copy_from_slice(&t[..LIMBS]);
        if t[LIMBS] != 0 || cmp(&out, &self.modulus) != std::cmp::Ordering::Less {
            out = sub(&out, &self.modulus);
        }
        out
    }

    /// `base ^ exponent mod m`, the exponent big-endian bytes.
    fn pow(&self, base: &Big, exponent: &[u8]) -> Big {
        let one = {
            let mut one = [0u32; LIMBS];
            one[0] = 1;
            one
        };
        let base_m = self.mul(base, &self.r2);
        let mut result = self.mul(&one, &self.r2);
        for &byte in exponent {
            for bit in (0..8).rev() {
                result = self.mul(&result, &result);
                if (byte >> bit) & 1 == 1 {
                    result = self.mul(&result, &base_m);
                }
            }
        }
        self.mul(&result, &one)
    }
}

fn group() -> &'static Montgomery {
    static GROUP: OnceLock<Montgomery> = OnceLock::new();
    GROUP.get_or_init(|| {
        let bytes: Vec<u8> = (0..PRIME_HEX.len() / 2).map(|i| u8::from_str_radix(&PRIME_HEX[2 * i..2 * i + 2], 16).unwrap_or(0)).collect();
        Montgomery::new(from_be_bytes(&bytes))
    })
}

/// `2^private mod P`: the public key for `private` (big-endian bytes).
fn public_key(private: &[u8]) -> [u8; KEY_BYTES] {
    let mut two = [0u32; LIMBS];
    two[0] = 2;
    to_be_bytes(&group().pow(&two, private))
}

/// The shared secret from the peer's public key and our private one, or
/// `None` if the peer's key is not one it is safe to use (0, 1, `P - 1` or
/// anything not below `P`).
fn shared_secret(peer_public: &[u8; KEY_BYTES], private: &[u8]) -> Option<[u8; KEY_BYTES]> {
    let g = group();
    let y = from_be_bytes(peer_public);
    let mut one = [0u32; LIMBS];
    one[0] = 1;
    let mut prime_minus_one = g.modulus;
    prime_minus_one[0] -= 1; // P is odd, so this does not borrow
    if cmp(&y, &one) != std::cmp::Ordering::Greater || cmp(&y, &prime_minus_one) != std::cmp::Ordering::Less {
        return None;
    }
    Some(to_be_bytes(&g.pow(&y, private)))
}

// ---- RC4 -----------------------------------------------------------------

/// The RC4 stream cipher.
#[derive(Clone)]
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Rc4 {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// MSE's ciphers throw away the first 1024 bytes of keystream.
    fn keyed_for_mse(key: &[u8]) -> Rc4 {
        let mut rc4 = Rc4::new(key);
        rc4.apply(&mut [0u8; 1024]);
        rc4
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[self.s[self.i as usize].wrapping_add(self.s[self.j as usize]) as usize];
            *byte ^= k;
        }
    }
}

// ---- the stream ----------------------------------------------------------

/// A connection after the MSE exchange: RC4 in each direction, or plain
/// (with a few bytes to hand out first, if some were read ahead).
pub struct MseStream {
    inner: Box<dyn PeerStream>,
    encrypt: Option<Rc4>,
    decrypt: Option<Rc4>,
    /// Bytes to return from `read` before reading `inner`: already in the
    /// clear (initial payload, or what was read to tell plaintext from MSE).
    replay: VecDeque<u8>,
}

impl fmt::Debug for MseStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MseStream").field("encrypted", &self.encrypt.is_some()).field("replay", &self.replay.len()).finish()
    }
}

impl MseStream {
    /// Whether the stream is encrypted (RC4) rather than plain.
    pub fn is_encrypted(&self) -> bool {
        self.encrypt.is_some()
    }
}

impl Read for MseStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.replay.is_empty() {
            let n = buf.len().min(self.replay.len());
            for (slot, byte) in buf.iter_mut().zip(self.replay.drain(..n)) {
                *slot = byte;
            }
            return Ok(n);
        }
        let n = self.inner.read(buf)?;
        if let Some(cipher) = &mut self.decrypt {
            cipher.apply(&mut buf[..n]);
        }
        Ok(n)
    }
}

impl Write for MseStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.encrypt {
            None => self.inner.write(buf),
            Some(cipher) => {
                // Everything is encrypted and written whole: the cipher has
                // moved on by `buf.len()` bytes, so a partial write could
                // not be reported honestly.
                let mut sealed = buf.to_vec();
                cipher.apply(&mut sealed);
                self.inner.write_all(&sealed)?;
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl PeerStream for MseStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    fn closer(&self) -> io::Result<Arc<dyn Closer>> {
        self.inner.closer()
    }
}

// ---- the exchange --------------------------------------------------------

#[derive(Debug)]
pub enum MseError {
    Io(io::Error),
    /// The peer did not follow the protocol.
    Protocol(&'static str),
    /// The peer asked for a torrent we do not have.
    UnknownTorrent,
    /// No method both sides will use (plaintext refused, or RC4 refused).
    NoCommonMethod,
}

impl fmt::Display for MseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MseError::Io(e) => write!(f, "io error during encryption handshake: {}", e),
            MseError::Protocol(what) => write!(f, "encryption handshake: {}", what),
            MseError::UnknownTorrent => write!(f, "encryption handshake: the peer asked for a torrent we do not have"),
            MseError::NoCommonMethod => write!(f, "encryption handshake: no method both sides accept"),
        }
    }
}

impl std::error::Error for MseError {}

impl From<io::Error> for MseError {
    fn from(e: io::Error) -> Self {
        MseError::Io(e)
    }
}

const CRYPTO_PLAINTEXT: u32 = 1;
const CRYPTO_RC4: u32 = 2;
/// The longest pad the specification allows.
const MAX_PAD: usize = 512;

fn hash(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn random(buf: &mut [u8]) {
    // Failing to get randomness is not something to carry on through.
    if getrandom::getrandom(buf).is_err() {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos()) as u8).wrapping_add(i as u8).wrapping_mul(167);
        }
    }
}

fn random_pad_len() -> usize {
    let mut n = [0u8; 2];
    random(&mut n);
    u16::from_be_bytes(n) as usize % (MAX_PAD + 1)
}

fn random_private() -> [u8; 20] {
    let mut key = [0u8; 20];
    loop {
        random(&mut key);
        if key.iter().any(|&b| b != 0) {
            return key;
        }
    }
}

fn read_exact(stream: &mut dyn PeerStream, buf: &mut [u8]) -> Result<(), MseError> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(MseError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "the peer closed the connection during the encryption handshake"))),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(MseError::Io(e)),
        }
    }
    Ok(())
}

/// Reads bytes one at a time until the last `pattern.len()` of them equal
/// `pattern`, giving up after `limit` bytes. Neither side knows how long the
/// other's pad is, so this is how the next part of the exchange is found.
fn scan_for(stream: &mut dyn PeerStream, pattern: &[u8], limit: usize) -> Result<(), MseError> {
    let mut window: VecDeque<u8> = VecDeque::with_capacity(pattern.len());
    let mut byte = [0u8; 1];
    for _ in 0..limit {
        read_exact(stream, &mut byte)?;
        if window.len() == pattern.len() {
            window.pop_front();
        }
        window.push_back(byte[0]);
        if window.len() == pattern.len() && window.iter().eq(pattern.iter()) {
            return Ok(());
        }
    }
    Err(MseError::Protocol("did not find where the pad ends"))
}

struct Ciphers {
    /// Applied to what we write.
    encrypt: Rc4,
    /// Applied to what we read.
    decrypt: Rc4,
}

fn ciphers(secret: &[u8; KEY_BYTES], skey: &[u8; 20], initiator: bool) -> Ciphers {
    let key_a = Rc4::keyed_for_mse(&hash(&[b"keyA", secret, skey]));
    let key_b = Rc4::keyed_for_mse(&hash(&[b"keyB", secret, skey]));
    if initiator {
        Ciphers { encrypt: key_a, decrypt: key_b }
    } else {
        Ciphers { encrypt: key_b, decrypt: key_a }
    }
}

/// Connects, as `A`, to a peer over `stream`: the whole exchange, ending in
/// a stream that carries the BitTorrent protocol. `allow_plaintext` lets the
/// peer choose to drop encryption once the exchange is done. `payload` is
/// sent as the initial payload (IA), which saves a round trip when it is the
/// BitTorrent handshake.
pub fn initiate(stream: Box<dyn PeerStream>, info_hash: &[u8; 20], allow_plaintext: bool, payload: &[u8]) -> Result<MseStream, MseError> {
    initiate_with_pads(stream, info_hash, allow_plaintext, payload, random_pad_len(), random_pad_len())
}

fn initiate_with_pads(mut stream: Box<dyn PeerStream>, info_hash: &[u8; 20], allow_plaintext: bool, payload: &[u8], pad_a: usize, pad_c: usize) -> Result<MseStream, MseError> {
    let private = random_private();
    let public = public_key(&private);

    let mut hello = public.to_vec();
    let mut pad = vec![0u8; pad_a];
    random(&mut pad);
    hello.extend_from_slice(&pad);
    stream.write_all(&hello)?;

    let mut theirs = [0u8; KEY_BYTES];
    read_exact(&mut *stream, &mut theirs)?;
    let secret = shared_secret(&theirs, &private).ok_or(MseError::Protocol("the peer's public key is not usable"))?;

    let mut c = ciphers(&secret, info_hash, true);
    let mut request = Vec::new();
    request.extend_from_slice(&hash(&[b"req1", &secret]));
    let mask = hash(&[b"req3", &secret]);
    let wanted = hash(&[b"req2", info_hash]);
    request.extend(wanted.iter().zip(mask.iter()).map(|(a, b)| a ^ b));

    let mut sealed = vec![0u8; 8]; // VC
    let provide = CRYPTO_RC4 | if allow_plaintext { CRYPTO_PLAINTEXT } else { 0 };
    sealed.extend_from_slice(&provide.to_be_bytes());
    sealed.extend_from_slice(&(pad_c as u16).to_be_bytes());
    let mut pad = vec![0u8; pad_c];
    random(&mut pad);
    sealed.extend_from_slice(&pad);
    sealed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    sealed.extend_from_slice(payload);
    c.encrypt.apply(&mut sealed);
    request.extend_from_slice(&sealed);
    stream.write_all(&request)?;

    // What their answer starts with: eight zero bytes through their cipher.
    let mut pattern = [0u8; 8];
    c.decrypt.clone().apply(&mut pattern);
    scan_for(&mut *stream, &pattern, MAX_PAD + 8)?;
    c.decrypt.apply(&mut [0u8; 8]); // past the VC just matched

    let mut head = [0u8; 6];
    read_exact(&mut *stream, &mut head)?;
    c.decrypt.apply(&mut head);
    let select = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let pad_d = u16::from_be_bytes([head[4], head[5]]) as usize;
    if pad_d > MAX_PAD {
        return Err(MseError::Protocol("the peer's pad is longer than allowed"));
    }
    let mut skip = vec![0u8; pad_d];
    read_exact(&mut *stream, &mut skip)?;
    c.decrypt.apply(&mut skip);

    match select {
        CRYPTO_RC4 => Ok(MseStream { inner: stream, encrypt: Some(c.encrypt), decrypt: Some(c.decrypt), replay: VecDeque::new() }),
        CRYPTO_PLAINTEXT if allow_plaintext => Ok(MseStream { inner: stream, encrypt: None, decrypt: None, replay: VecDeque::new() }),
        _ => Err(MseError::NoCommonMethod),
    }
}

/// What `respond` was prepared to do.
#[derive(Debug, Clone, Copy)]
pub struct Accept {
    pub allow_rc4: bool,
    pub allow_plaintext: bool,
}

/// Answers, as `B`, a peer that has begun the exchange. `already_read` is
/// the start of its public key, if some of it was read to tell MSE from a
/// plaintext handshake. `known` are the info hashes we will talk about; the
/// peer's proof picks one. Returns the stream, the info hash chosen, and any
/// initial payload the peer sent ahead (already in the clear, and first to
/// be read from the stream).
pub fn respond(stream: Box<dyn PeerStream>, already_read: &[u8], known: &[[u8; 20]], accept: Accept) -> Result<(MseStream, [u8; 20]), MseError> {
    respond_with_pad(stream, already_read, known, accept, random_pad_len())
}

fn respond_with_pad(mut stream: Box<dyn PeerStream>, already_read: &[u8], known: &[[u8; 20]], accept: Accept, pad_b: usize) -> Result<(MseStream, [u8; 20]), MseError> {
    let mut theirs = [0u8; KEY_BYTES];
    let have = already_read.len().min(KEY_BYTES);
    theirs[..have].copy_from_slice(&already_read[..have]);
    read_exact(&mut *stream, &mut theirs[have..])?;

    let private = random_private();
    let mut reply = public_key(&private).to_vec();
    let mut pad = vec![0u8; pad_b];
    random(&mut pad);
    reply.extend_from_slice(&pad);
    stream.write_all(&reply)?;

    let secret = shared_secret(&theirs, &private).ok_or(MseError::Protocol("the peer's public key is not usable"))?;

    // Past their pad, to the hash that says where the request begins.
    scan_for(&mut *stream, &hash(&[b"req1", &secret]), MAX_PAD + 20)?;
    let mut proof = [0u8; 20];
    read_exact(&mut *stream, &mut proof)?;
    let mask = hash(&[b"req3", &secret]);
    let skey = known
        .iter()
        .find(|candidate| {
            let expected = hash(&[b"req2", &candidate[..]]);
            expected.iter().zip(mask.iter()).map(|(a, b)| a ^ b).eq(proof.iter().copied())
        })
        .copied()
        .ok_or(MseError::UnknownTorrent)?;

    let mut c = ciphers(&secret, &skey, false);
    let mut head = [0u8; 8 + 4 + 2];
    read_exact(&mut *stream, &mut head)?;
    c.decrypt.apply(&mut head);
    if head[..8] != [0u8; 8] {
        return Err(MseError::Protocol("the verification constant is wrong"));
    }
    let provide = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    let pad_c = u16::from_be_bytes([head[12], head[13]]) as usize;
    if pad_c > MAX_PAD {
        return Err(MseError::Protocol("the peer's pad is longer than allowed"));
    }
    let mut skip = vec![0u8; pad_c + 2];
    read_exact(&mut *stream, &mut skip)?;
    c.decrypt.apply(&mut skip);
    let payload_len = u16::from_be_bytes([skip[pad_c], skip[pad_c + 1]]) as usize;
    let mut payload = vec![0u8; payload_len];
    read_exact(&mut *stream, &mut payload)?;
    c.decrypt.apply(&mut payload);

    let select = if provide & CRYPTO_RC4 != 0 && accept.allow_rc4 {
        CRYPTO_RC4
    } else if provide & CRYPTO_PLAINTEXT != 0 && accept.allow_plaintext {
        CRYPTO_PLAINTEXT
    } else {
        return Err(MseError::NoCommonMethod);
    };

    let pad_d = random_pad_len();
    let mut answer = vec![0u8; 8];
    answer.extend_from_slice(&select.to_be_bytes());
    answer.extend_from_slice(&(pad_d as u16).to_be_bytes());
    let mut pad = vec![0u8; pad_d];
    random(&mut pad);
    answer.extend_from_slice(&pad);
    c.encrypt.apply(&mut answer);
    stream.write_all(&answer)?;

    let replay: VecDeque<u8> = payload.into();
    let stream = if select == CRYPTO_RC4 { MseStream { inner: stream, encrypt: Some(c.encrypt), decrypt: Some(c.decrypt), replay } } else { MseStream { inner: stream, encrypt: None, decrypt: None, replay } };
    Ok((stream, skey))
}

/// The bytes every plaintext BitTorrent connection begins with.
const PLAINTEXT_PREFIX: &[u8; 20] = b"\x13BitTorrent protocol";

/// Takes an incoming connection, whichever it is. The first twenty bytes
/// tell: a plaintext handshake begins with the protocol string, and the
/// start of a public key is random. Returns the stream ready for the
/// BitTorrent handshake, and whether it is encrypted.
pub fn accept(mut stream: Box<dyn PeerStream>, known: &[[u8; 20]], mode: Encryption) -> Result<(MseStream, bool), MseError> {
    let mut first = [0u8; 20];
    read_exact(&mut *stream, &mut first)?;
    if &first == PLAINTEXT_PREFIX {
        if mode == Encryption::Require {
            return Err(MseError::NoCommonMethod);
        }
        return Ok((MseStream { inner: stream, encrypt: None, decrypt: None, replay: first.iter().copied().collect() }, false));
    }
    if mode == Encryption::Off {
        return Err(MseError::Protocol("not a BitTorrent handshake, and encryption is off"));
    }
    let (stream, _) = respond(stream, &first, known, Accept { allow_rc4: true, allow_plaintext: mode != Encryption::Require })?;
    let encrypted = stream.is_encrypted();
    Ok((stream, encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::thread;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    // ---- against Python's own arithmetic ----

    /// (private exponent, 2^x mod P, an arbitrary base, base^x mod P), from Python's pow().
    const VECTORS: [(&str, &str, &str, &str); 4] = [
        ("a6a3a4506513270e269e0d37f2a74de452e6b438", "26d7e0f20848d52738cfaeadccbde735d8b359594f96c6950987674843e91e6bd8ccee184edae41d5f34bf4655f2e3b336ebefcaebb4ab4dc6444ad0b50ea5238cb5285593d3eb9eeb12a4725e4df94f9a1ef413ca8bba9628a0c58a4c885896", "001fb17c90c192cfd3ac94af0f21ddb66cad4a268d116ece1738f7d93d9c172411e20b8f6b0d549b6f03675a1600a35a099950d836f675cc81e74ef5e8e25d940ed904759531985d5d9dc9f81818e811892f902bd23f0824128b2f330c5c7fd1", "6a6c622cadca63139de481b4306374b3209521b59eb5031f4e24a7fa9967eeccf8d1a65818c29b5dec519465e715569f1467c93addf7c966b7f38dcb689ea6eb86ee6b7927c2ad5b1d72931639c4e8f80afef14bcd3bc1717e80e8ec9bd531d9"),
        ("953f48f1a09f76b5a170b33839263059f28c105d", "8fcd96b8f05f5bfabfcaec31fc87b475c664ba6a7bd02d4dfc1460b213c4b062506d2b723e5650288fefa546e68f8088fbb8594b1416aaf7435b8d99a1657cfa204c24b0b983950d9dfd0993149be7c73c44b3c323d9ee4eeccfb724f42e792d", "001a61db2e44158bae97ba94d0eda82f8f6d05584ef8aa38922766581e27a1c08a6a63ec24ede6a46b4cb2424a23d5962217beaddbc496cb8e81973e0becd7b03898d190f9ebdacc0cb1e29c658cda1495e60af593bd04cf0fd630f1f29d0da9", "bc9fc2e3259108ab46bdc6e1ef61e1c84a69cffec4856287edca944c044c0d9536819bd0287091a6b9ce525e2f26ca0e636323cb8ecb03b37d87fa833001a4cba2313b2185c29a6998cdfc079fbe29e6eef0b6831107c715f18b767f0f222401"),
        ("5f557203301850c5a38fd547923a736994e3bf91", "c8e99496b6b626e2be234a87a105c3173fd789b33f98dfad315f2934028e0888d256a1ee086189a98dfd91e14ff85bdc0adbacaab561a20e525d44ebde24a9271ba1fff60a37d5468a195d8e1557946214df54cb9d0050af9f596218c24e69bd", "00b2f14c2e05319acb5c74273f98e2774cbd87ad5c90a9587403e430ec66a78795e761d17731af10506bf2efc6f877186d76b07e881ed162ae2eb1547f15052434b9b5df9e7769b10f4205b4907a70c31012f037b64ce4228c38fb2918f135d3", "76f4466bdabae5a9eef93f6a3ffd5c729e12f5aa6c6ee76cd0267a2883f716423d2fd617a87f5364893ab9860f71fbe5fb57828e7f0122b79ae860004d8264075589f21cfaca548eaa591708a121479f1150b7b27963a7fe1287b6bbeb425b65"),
        ("4cdd2055930d6eaf14f4733f3e7d1bfbc7a2ea20", "84f8c23aca954586e70720c7fc9ff8206b9e42495ceb594c332659c95e20dc9d1d8e7619f58106b9309f8ed39b45d9359527c1c9f3bc00938a77b83e3a342113925746cdb236475fed05feca5024b4c7a186351876a6bcd3fd1a06c24c750813", "0013deefab1031d0f646e1f40a097c976bf46c697d2caf82eeeacbe226e875555790f82ec1d3fcff2a3af4d46b0a18e8830e07bc1e398f1012bd4acefaecbd389be4bcfc49b64a0872e6cc3ababced2057ee05cde00902c77ebff20686734721", "fb73f1fd1ef8bb2c26771189998b3e70aa8bc7ba412eab3010083838e6bcd7f62dfbd62a5ad7444adea5f774772f2b1d015532617f40323088259af9f77225da645ced121558705440966a19ed738aa4dfcc23883773ec3a5391e9b7b18ba650"),
    ];

    #[test]
    fn public_keys_match_pythons_modular_exponentiation() {
        for (private, public, _, _) in VECTORS {
            assert_eq!(public_key(&hex(private)).to_vec(), hex(public), "2^{} mod P", private);
        }
    }

    #[test]
    fn shared_secrets_match_pythons_for_arbitrary_bases() {
        for (private, _, base, secret) in VECTORS {
            let base: [u8; KEY_BYTES] = hex(base).try_into().unwrap();
            assert_eq!(shared_secret(&base, &hex(private)).unwrap().to_vec(), hex(secret));
        }
    }

    #[test]
    fn the_exchange_agrees_on_a_secret_from_either_end() {
        let (a, b) = ([0x37u8; 20], [0x5au8; 20]);
        let (ya, yb) = (public_key(&a), public_key(&b));
        assert_eq!(shared_secret(&yb, &a).unwrap(), shared_secret(&ya, &b).unwrap());
    }

    #[test]
    fn exponent_edge_cases() {
        let g = group();
        let mut two = [0u32; LIMBS];
        two[0] = 2;
        assert_eq!(to_be_bytes(&g.pow(&two, &[])).to_vec(), {
            let mut one = vec![0u8; KEY_BYTES];
            one[KEY_BYTES - 1] = 1;
            one
        }, "anything to the zero is one");
        assert_eq!(to_be_bytes(&g.pow(&two, &[1])).to_vec()[KEY_BYTES - 1], 2, "to the first power is itself");
        // (P - 1)^2 = 1 mod P.
        let mut minus_one = g.modulus;
        minus_one[0] -= 1;
        let squared = g.pow(&minus_one, &[2]);
        assert_eq!(squared[0], 1);
        assert!(squared[1..].iter().all(|&l| l == 0));
    }

    #[test]
    fn unusable_public_keys_are_refused() {
        let private = [7u8; 20];
        let zero = [0u8; KEY_BYTES];
        let mut one = zero;
        one[KEY_BYTES - 1] = 1;
        let mut p_minus_one = to_be_bytes(&group().modulus);
        p_minus_one[KEY_BYTES - 1] -= 1;
        let p = to_be_bytes(&group().modulus);
        let all_ones = [0xFFu8; KEY_BYTES];
        for bad in [zero, one, p_minus_one, p, all_ones] {
            assert!(shared_secret(&bad, &private).is_none());
        }
    }

    // ---- RC4 ----

    #[test]
    fn rc4_matches_its_published_test_vectors() {
        let mut data = b"Plaintext".to_vec();
        Rc4::new(b"Key").apply(&mut data);
        assert_eq!(data, hex("bbf316e8d940af0ad3"));
        let mut data = b"pedia".to_vec();
        Rc4::new(b"Wiki").apply(&mut data);
        assert_eq!(data, hex("1021bf0420"));
    }

    #[test]
    fn mse_keys_drop_the_first_1024_bytes_of_keystream() {
        let key = hash(&[b"keyA", &[1u8; 96], &[2u8; 20]]);
        assert_eq!(key.to_vec(), hex("08811958cf46c97141d68601adca743d0a79034e"), "the key itself, as Python hashes it");
        let mut data = [0u8; 16];
        Rc4::keyed_for_mse(&key).apply(&mut data);
        assert_eq!(data.to_vec(), hex("395545b6830945ef1b910991d05b49bd"), "the keystream after the drop, as Python makes it");
    }

    #[test]
    fn rc4_applied_twice_from_the_same_key_gives_back_the_data() {
        let mut data: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        let original = data.clone();
        Rc4::new(b"secret").apply(&mut data);
        assert_ne!(data, original);
        Rc4::new(b"secret").apply(&mut data);
        assert_eq!(data, original);
    }

    // ---- the exchange over real sockets ----

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for s in [&client, &server] {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        }
        (client, server)
    }

    const HASH: [u8; 20] = [0x42; 20];
    const RC4_ONLY: Accept = Accept { allow_rc4: true, allow_plaintext: false };

    type Answered = Result<(MseStream, [u8; 20]), MseError>;

    /// Runs both ends on their own threads and returns the two streams.
    fn negotiate(initiator: impl FnOnce(Box<dyn PeerStream>) -> Result<MseStream, MseError> + Send + 'static, responder: impl FnOnce(Box<dyn PeerStream>) -> Answered + Send + 'static) -> (Result<MseStream, MseError>, Answered) {
        let (client, server) = pair();
        let b = thread::spawn(move || responder(Box::new(server)));
        let a = initiator(Box::new(client));
        (a, b.join().unwrap())
    }

    #[test]
    fn both_ends_come_out_talking_rc4_and_the_responder_learns_the_torrent() {
        let (a, b) = negotiate(|s| initiate(s, &HASH, false, b""), |s| respond(s, &[], &[[1; 20], HASH, [3; 20]], RC4_ONLY));
        let (mut a, (mut b, skey)) = (a.unwrap(), b.unwrap());
        assert_eq!(skey, HASH, "picked out of the ones it knows by the proof");
        assert!(a.is_encrypted() && b.is_encrypted());

        a.write_all(b"from a to b").unwrap();
        let mut got = [0u8; 11];
        b.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"from a to b");
        b.write_all(b"and back again").unwrap();
        let mut got = [0u8; 14];
        a.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"and back again");
    }

    #[test]
    fn a_great_deal_of_data_goes_through_both_ways_and_in_awkward_chunks() {
        let (a, b) = negotiate(|s| initiate(s, &HASH, false, b""), |s| respond(s, &[], &[HASH], RC4_ONLY));
        let (mut a, (mut b, _)) = (a.unwrap(), b.unwrap());
        let data: Vec<u8> = (0..300_000).map(|i| (i * 7 % 251) as u8).collect();
        let expected = data.clone();
        let writer = thread::spawn(move || {
            for chunk in data.chunks(1237) {
                a.write_all(chunk).unwrap();
            }
            a
        });
        let mut got = vec![0u8; expected.len()];
        let mut filled = 0;
        while filled < got.len() {
            let end = filled + 700.min(got.len() - filled);
            let n = b.read(&mut got[filled..end]).unwrap();
            assert!(n > 0);
            filled += n;
        }
        assert_eq!(got, expected);
        drop(writer.join().unwrap());
    }

    #[test]
    fn the_pads_may_be_empty_or_as_long_as_the_specification_allows() {
        for (pad_a, pad_c, pad_b) in [(0, 0, 0), (512, 512, 512), (1, 511, 257)] {
            let (a, b) = negotiate(move |s| initiate_with_pads(s, &HASH, false, b"", pad_a, pad_c), move |s| respond_with_pad(s, &[], &[HASH], RC4_ONLY, pad_b));
            let (mut a, (mut b, _)) = (a.unwrap_or_else(|e| panic!("pads {:?}: {}", (pad_a, pad_c, pad_b), e)), b.unwrap());
            a.write_all(b"ok").unwrap();
            let mut got = [0u8; 2];
            b.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"ok");
        }
    }

    #[test]
    fn initial_payload_arrives_first_and_in_the_clear_to_the_reader() {
        let (a, b) = negotiate(|s| initiate(s, &HASH, false, b"the handshake, sent ahead"), |s| respond(s, &[], &[HASH], RC4_ONLY));
        let (mut a, (mut b, _)) = (a.unwrap(), b.unwrap());
        a.write_all(b" and then more").unwrap();
        let mut got = vec![0u8; "the handshake, sent ahead and then more".len()];
        b.read_exact(&mut got).unwrap();
        assert_eq!(got, b"the handshake, sent ahead and then more");
    }

    #[test]
    fn a_peer_that_offers_plaintext_may_be_answered_in_plaintext_and_then_the_stream_is_plain() {
        let (a, b) = negotiate(|s| initiate(s, &HASH, true, b""), |s| respond(s, &[], &[HASH], Accept { allow_rc4: false, allow_plaintext: true }));
        let (a, (b, _)) = (a.unwrap(), b.unwrap());
        assert!(!a.is_encrypted() && !b.is_encrypted(), "the responder chose plaintext");
    }

    #[test]
    fn rc4_is_preferred_when_both_are_on_offer() {
        let (a, b) = negotiate(|s| initiate(s, &HASH, true, b""), |s| respond(s, &[], &[HASH], Accept { allow_rc4: true, allow_plaintext: true }));
        assert!(a.unwrap().is_encrypted() && b.unwrap().0.is_encrypted());
    }

    #[test]
    fn with_no_method_in_common_both_ends_fail() {
        // The initiator offers only RC4; the responder will only do plaintext.
        let (a, b) = negotiate(|s| initiate(s, &HASH, false, b""), |s| respond(s, &[], &[HASH], Accept { allow_rc4: false, allow_plaintext: true }));
        assert!(matches!(b, Err(MseError::NoCommonMethod)), "{:?}", b.err());
        assert!(a.is_err());
    }

    #[test]
    fn a_torrent_the_responder_does_not_have_is_refused() {
        let (a, b) = negotiate(|s| initiate(s, &[0x99; 20], false, b""), |s| respond(s, &[], &[HASH], RC4_ONLY));
        assert!(matches!(b, Err(MseError::UnknownTorrent)), "{:?}", b.err());
        assert!(a.is_err(), "and the initiator sees the connection close");
    }

    /// A peer stream that returns at most one byte per read, like a slow link.
    #[derive(Debug)]
    struct Dribble(TcpStream);

    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(1);
            self.0.read(&mut buf[..n])
        }
    }

    impl Write for Dribble {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl PeerStream for Dribble {
        fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
            self.0.set_read_timeout(t)
        }

        fn set_write_timeout(&self, t: Option<Duration>) -> io::Result<()> {
            self.0.set_write_timeout(t)
        }

        fn closer(&self) -> io::Result<Arc<dyn Closer>> {
            self.0.closer()
        }
    }

    #[test]
    fn the_exchange_survives_a_link_that_delivers_one_byte_at_a_time() {
        let (client, server) = pair();
        let b = thread::spawn(move || respond(Box::new(Dribble(server)), &[], &[HASH], RC4_ONLY));
        let mut a = initiate(Box::new(Dribble(client)), &HASH, false, b"payload").unwrap();
        let (mut b, _) = b.join().unwrap().unwrap();
        a.write_all(b"!").unwrap();
        let mut got = [0u8; 8];
        b.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"payload!");
    }

    /// Records what passes between two sockets, both ways.
    fn tap(server_side: TcpStream) -> (TcpStream, Arc<Mutex<Vec<u8>>>) {
        let (client, front) = pair();
        let seen = Arc::new(Mutex::new(Vec::new()));
        for (mut from, mut to) in [(front.try_clone().unwrap(), server_side.try_clone().unwrap()), (server_side, front)] {
            let seen = Arc::clone(&seen);
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = from.read(&mut buf) {
                    if n == 0 || to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    seen.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
        }
        (client, seen)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn what_crosses_the_wire_is_not_the_bittorrent_handshake_when_encrypted() {
        let (via, server) = pair();
        let (client, seen) = tap(via);
        let b = thread::spawn(move || respond(Box::new(server), &[], &[HASH], RC4_ONLY));
        let mut a = initiate(Box::new(client), &HASH, false, b"").unwrap();
        let (mut b, _) = b.join().unwrap().unwrap();
        let recognisable = [b"\x13BitTorrent protocol".as_slice(), &[0xABu8; 64]].concat();
        a.write_all(&recognisable).unwrap();
        let mut got = vec![0u8; recognisable.len()];
        b.read_exact(&mut got).unwrap();
        assert_eq!(got, recognisable);

        thread::sleep(Duration::from_millis(100));
        let wire = seen.lock().unwrap().clone();
        assert!(!contains(&wire, b"BitTorrent protocol"), "the protocol string never appears");
        assert!(!contains(&wire, &[0xABu8; 16]), "nor does the payload");
        assert!(wire.len() >= recognisable.len() + 2 * KEY_BYTES, "but it did carry it");
    }

    #[test]
    fn and_when_plaintext_is_selected_the_payload_is_plain_after_the_exchange() {
        let (via, server) = pair();
        let (client, seen) = tap(via);
        let b = thread::spawn(move || respond(Box::new(server), &[], &[HASH], Accept { allow_rc4: false, allow_plaintext: true }));
        let mut a = initiate(Box::new(client), &HASH, true, b"").unwrap();
        let (mut b, _) = b.join().unwrap().unwrap();
        a.write_all(&[0xCDu8; 64]).unwrap();
        let mut got = [0u8; 64];
        b.read_exact(&mut got).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert!(contains(&seen.lock().unwrap(), &[0xCDu8; 32]), "plaintext was agreed, and plaintext is what went across");
    }

    // ---- telling plaintext from encrypted on an incoming connection ----

    #[test]
    fn an_incoming_plaintext_handshake_is_recognised_and_nothing_is_lost() {
        let (client, server) = pair();
        let mut client = client;
        let server = thread::spawn(move || accept(Box::new(server), &[HASH], Encryption::Prefer));
        let mut handshake = b"\x13BitTorrent protocol".to_vec();
        handshake.extend_from_slice(&[0u8; 8]);
        handshake.extend_from_slice(&HASH);
        handshake.extend_from_slice(&[7u8; 20]);
        client.write_all(&handshake).unwrap();

        let (mut stream, encrypted) = server.join().unwrap().unwrap();

        assert!(!encrypted);
        let mut got = vec![0u8; handshake.len()];
        stream.read_exact(&mut got).unwrap();
        assert_eq!(got, handshake, "the twenty bytes read to decide are read again");
    }

    #[test]
    fn an_incoming_encrypted_connection_is_recognised_and_completed() {
        let (client, server) = pair();
        let server = thread::spawn(move || accept(Box::new(server), &[HASH], Encryption::Prefer));
        let mut a = initiate(Box::new(client), &HASH, false, b"hello").unwrap();
        let (mut b, encrypted) = server.join().unwrap().unwrap();
        assert!(encrypted);
        a.write_all(b" there").unwrap();
        let mut got = [0u8; 11];
        b.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello there");
    }

    #[test]
    fn the_modes_decide_what_an_incoming_connection_may_be() {
        // Require refuses plaintext.
        let (mut client, server) = pair();
        let server = thread::spawn(move || accept(Box::new(server), &[HASH], Encryption::Require));
        client.write_all(b"\x13BitTorrent protocol").unwrap();
        assert!(matches!(server.join().unwrap(), Err(MseError::NoCommonMethod)));

        // Off refuses encryption (treats it as the garbage it cannot read).
        let (client, server) = pair();
        let server = thread::spawn(move || accept(Box::new(server), &[HASH], Encryption::Off));
        let _ = initiate(Box::new(client), &HASH, false, b"");
        assert!(matches!(server.join().unwrap(), Err(MseError::Protocol(_))));

        // Require insists on RC4 even from a peer that would take plaintext.
        let (client, server) = pair();
        let server = thread::spawn(move || accept(Box::new(server), &[HASH], Encryption::Require));
        let a = initiate(Box::new(client), &HASH, true, b"").unwrap();
        assert!(a.is_encrypted());
        assert!(server.join().unwrap().unwrap().1);
    }

    #[test]
    fn the_modes_parse() {
        assert_eq!(Encryption::parse("off"), Ok(Encryption::Off));
        assert_eq!(Encryption::parse("Prefer"), Ok(Encryption::Prefer));
        assert_eq!(Encryption::parse("REQUIRE"), Ok(Encryption::Require));
        assert!(Encryption::parse("sometimes").is_err());
        assert_eq!(Encryption::default(), Encryption::Off);
    }

    #[test]
    fn garbage_in_place_of_a_public_key_is_an_error_not_a_hang_or_a_panic() {
        let (mut client, server) = pair();
        let responder = thread::spawn(move || respond(Box::new(server), &[], &[HASH], RC4_ONLY));
        client.write_all(&[0u8; KEY_BYTES]).unwrap(); // a public key of zero
        assert!(matches!(responder.join().unwrap(), Err(MseError::Protocol(_))));
    }

    #[test]
    fn a_pad_that_never_ends_is_given_up_on() {
        let (mut client, server) = pair();
        let responder = thread::spawn(move || respond(Box::new(server), &[], &[HASH], RC4_ONLY));
        client.write_all(&public_key(&[9u8; 20])).unwrap();
        client.write_all(&vec![0x55u8; 1200]).unwrap(); // never the proof
        assert!(matches!(responder.join().unwrap(), Err(MseError::Protocol(_))));
    }

    #[test]
    fn a_request_whose_verification_constant_is_not_zero_is_refused() {
        // A hand-made initiator, correct in every respect but the VC.
        let (mut client, server) = pair();
        let responder = thread::spawn(move || respond(Box::new(server), &[], &[HASH], RC4_ONLY));
        let private = [11u8; 20];
        client.write_all(&public_key(&private)).unwrap();
        let mut theirs = [0u8; KEY_BYTES];
        client.read_exact(&mut theirs).unwrap();
        let secret = shared_secret(&theirs, &private).unwrap();
        let mut c = ciphers(&secret, &HASH, true);
        let mut request = hash(&[b"req1", &secret]).to_vec();
        let mask = hash(&[b"req3", &secret]);
        request.extend(hash(&[b"req2", &HASH]).iter().zip(mask.iter()).map(|(a, b)| a ^ b));
        let mut sealed = vec![1u8; 8]; // not the zeros it must be
        sealed.extend_from_slice(&CRYPTO_RC4.to_be_bytes());
        sealed.extend_from_slice(&[0, 0, 0, 0]); // no pad, no initial payload
        c.encrypt.apply(&mut sealed);
        request.extend_from_slice(&sealed);
        client.write_all(&request).unwrap();

        assert!(matches!(responder.join().unwrap(), Err(MseError::Protocol(m)) if m.contains("verification constant")));
    }
}
