//! BEP 44: storing arbitrary data in the DHT. An immutable item is content-addressed by the
//! SHA-1 hash of its bencoded value; a mutable item is addressed by an ed25519 public key (plus
//! an optional salt, for one key to hold several unrelated items), signed by whoever holds the
//! matching private key, and updatable in place via a monotonically increasing sequence number.
//! BEP 46 is a thin convention on top of the mutable kind: a torrent's "live pointer" is a
//! mutable item whose value is `{"ih": <20-byte infohash>}`, letting a torrent's current version
//! be found from nothing but a public key -- see [`super::krpc`] for the wire format and
//! [`super::responder`]/[`super::lookup`] for how a node serves and looks these up.
//!
//! The signing/verification math is delegated to `ed25519-dalek` rather than hand-rolled, unlike
//! every other primitive in this project (SHA-1, SHA-256, RC4): getting elliptic-curve signature
//! verification wrong is a security hazard, not just a correctness bug. What *is* this module's
//! own responsibility, and so is tested byte-for-byte against BEP 44's own published test
//! vectors below, is building the exact buffer the signature covers -- getting that construction
//! wrong (an off-by-one in a length prefix, the salt in the wrong place) would make every
//! signature this client checks meaningless without ever entering the crypto library at all.

use crate::bencode::{self, Bencode};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Storing nodes MAY reject a `put` whose bencoded `v` is longer than this (BEP 44); it is not
/// safe to assume storing more will succeed.
pub const MAX_VALUE_LEN: usize = 1000;
/// The salt string MUST NOT be longer than this (BEP 44).
pub const MAX_SALT_LEN: usize = 64;

/// The SHA-1 target an immutable item with this exact bencoded value is stored and looked up
/// under.
pub fn immutable_target(bencoded_value: &[u8]) -> [u8; 20] {
    Sha1::digest(bencoded_value).into()
}

/// The SHA-1 target a mutable item under public key `k` (and optional `salt`) is stored and
/// looked up under. `None` and `Some(&[])` give the same target, matching the BEP's own "if the
/// salt entry is not present, it can be assumed to be an empty string" -- concatenating nothing
/// changes nothing either way.
pub fn mutable_target(k: &[u8; 32], salt: Option<&[u8]>) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(k);
    if let Some(salt) = salt {
        hasher.update(salt);
    }
    hasher.finalize().into()
}

/// The exact byte sequence a mutable item's signature covers, per BEP 44's "Signature
/// Verification" section: `4:salt<len>:<salt>` (only when `salt` is given and non-empty --
/// omitted entirely otherwise, not sent as an empty string, matching the BEP's own note that an
/// empty salt "is as if it was not specified"), then `3:seqi<seq>e1:v` and the bencoded value
/// itself -- `bencoded_v` is passed in already in its own self-length-prefixed bencoded form
/// (e.g. `12:Hello World!` for the 12-byte string `Hello World!`), the same as every other
/// dict *value* in this scheme; only the two dict *keys* (`salt`, `seq`, `v`) get an explicit
/// `<len>:` written out here, since a bencoded byte string carries its own length already.
/// Signing exactly this construction, rather than the bencoded dict as a whole, is what the BEP
/// says makes it "not possible to convince a node that part of the length is actually part of
/// the sequence number even if the parser contains certain bugs."
pub fn signing_buffer(salt: Option<&[u8]>, seq: i64, bencoded_v: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(salt) = salt {
        if !salt.is_empty() {
            buf.extend_from_slice(format!("4:salt{}:", salt.len()).as_bytes());
            buf.extend_from_slice(salt);
        }
    }
    buf.extend_from_slice(format!("3:seqi{}e1:v", seq).as_bytes());
    buf.extend_from_slice(bencoded_v);
    buf
}

/// Signs a mutable item with `signing_key` (an ordinary 32-byte-seed ed25519 key, however it was
/// generated), for publishing or republishing under it.
pub fn sign_mutable(signing_key: &SigningKey, salt: Option<&[u8]>, seq: i64, bencoded_v: &[u8]) -> [u8; 64] {
    signing_key.sign(&signing_buffer(salt, seq, bencoded_v)).to_bytes()
}

/// Verifies a mutable item's signature against its claimed public key. `false` for a public key
/// that is not a valid point on the curve as well as for a signature that does not check out --
/// callers do not need to tell the two apart, both mean "do not trust this item."
pub fn verify_mutable(k: &[u8; 32], salt: Option<&[u8]>, seq: i64, bencoded_v: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(k) else { return false };
    let signature = Signature::from_bytes(sig);
    verifying_key.verify(&signing_buffer(salt, seq, bencoded_v), &signature).is_ok()
}

/// Without re-announcement an item MAY expire in two hours (BEP 44); this node holds to exactly
/// that, filtering an item out once it has gone this long since it was last stored or refreshed
/// rather than running a separate sweep for it.
pub const ITEM_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);

/// Items held at once. This client is a downloader first, a BEP 44 storage node second, the
/// same stance [`super::responder`] takes for announced peers -- bounded so that storing
/// arbitrary data for the network cannot itself be turned into an unbounded memory sink.
pub const MAX_STORED_ITEMS: usize = 1000;

/// Why a `put` was refused, named for the BEP 44 error code that goes with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutError {
    /// 205: the bencoded `v` is longer than [`MAX_VALUE_LEN`].
    ValueTooLarge,
    /// 207: `salt` is longer than [`MAX_SALT_LEN`].
    SaltTooLarge,
    /// 206: the signature does not check out against `k`/`salt`/`seq`/`v`.
    BadSignature,
    /// 301: `cas` did not match the sequence number currently stored.
    CasMismatch,
    /// 302: `seq` is not greater than the sequence number currently stored.
    SequenceTooLow,
    /// The store is at [`MAX_STORED_ITEMS`] and this would add a new key rather than update one
    /// already held. Not one of BEP 44's own codes (running out of room is this node's problem,
    /// not the publisher's); callers surface it as a generic server error.
    StoreFull,
}

struct Item {
    v: Bencode,
    /// `Some` for a mutable item (its public key, salt, sequence number and signature); `None`
    /// for an immutable one, which is never updated once stored.
    mutable: Option<MutableMeta>,
    stored_at: Instant,
}

struct MutableMeta {
    k: [u8; 32],
    // `salt` is not kept: the target this item is stored under already binds `k` to whatever
    // salt produced it (BEP 44 never returns salt in a `get` response either, for the same
    // reason -- a requester who did not already know it could not have looked this target up).
    seq: i64,
    sig: [u8; 64],
}

/// What a successful `get` returns: the value, and, for a mutable item, enough to let the
/// requester verify it independently rather than trust this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredItem {
    pub v: Bencode,
    pub mutable: Option<([u8; 32], i64, [u8; 64])>,
}

/// The items this node holds for other nodes (BEP 44): a downloading client's own use of the
/// DHT never needs this table for itself, only to be a good citizen storing data on behalf of
/// whoever published it. See [`super::lookup`] for the client side (`Dht::get_item`) that reads
/// items other nodes hold, using the same verification this store applies to what it accepts.
#[derive(Default)]
pub struct Store {
    items: HashMap<[u8; 20], Item>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// The item under `target`, if this node holds one and it has not expired.
    pub fn get(&self, target: &[u8; 20], now: Instant) -> Option<StoredItem> {
        let item = self.items.get(target)?;
        if now.saturating_duration_since(item.stored_at) >= ITEM_LIFETIME {
            return None;
        }
        Some(StoredItem { v: item.v.clone(), mutable: item.mutable.as_ref().map(|m| (m.k, m.seq, m.sig)) })
    }

    /// Stores an immutable item, content-addressed by its own hash. Immutable items are never
    /// rejected for their content (there is nothing to authenticate), only for size or a full
    /// store.
    pub fn put_immutable(&mut self, v: Bencode, now: Instant) -> Result<[u8; 20], PutError> {
        let bencoded = bencode::encode(&v);
        if bencoded.len() > MAX_VALUE_LEN {
            return Err(PutError::ValueTooLarge);
        }
        let target = immutable_target(&bencoded);
        if !self.items.contains_key(&target) && self.items.len() >= MAX_STORED_ITEMS {
            return Err(PutError::StoreFull);
        }
        self.items.insert(target, Item { v, mutable: None, stored_at: now });
        Ok(target)
    }

    /// Stores or updates a mutable item, after checking its signature, `cas` (if given) and
    /// that `seq` is not stale, in that order, per BEP 44. `now` both times out a stale existing
    /// entry (treated as no entry at all, so a lower `seq` than an expired one is accepted) and
    /// timestamps the new one.
    #[allow(clippy::too_many_arguments)]
    pub fn put_mutable(&mut self, k: [u8; 32], salt: Option<Vec<u8>>, seq: i64, sig: [u8; 64], v: Bencode, cas: Option<i64>, now: Instant) -> Result<[u8; 20], PutError> {
        if let Some(salt) = &salt {
            if salt.len() > MAX_SALT_LEN {
                return Err(PutError::SaltTooLarge);
            }
        }
        let bencoded = bencode::encode(&v);
        if bencoded.len() > MAX_VALUE_LEN {
            return Err(PutError::ValueTooLarge);
        }
        if !verify_mutable(&k, salt.as_deref(), seq, &bencoded, &sig) {
            return Err(PutError::BadSignature);
        }
        let target = mutable_target(&k, salt.as_deref());
        let current = self.items.get(&target).filter(|item| now.saturating_duration_since(item.stored_at) < ITEM_LIFETIME);
        if let Some(current) = current {
            let current_seq = current.mutable.as_ref().map(|m| m.seq).unwrap_or(i64::MIN);
            if let Some(cas) = cas {
                if cas != current_seq {
                    return Err(PutError::CasMismatch);
                }
            }
            if seq < current_seq {
                return Err(PutError::SequenceTooLow);
            }
            // seq == current_seq with the same value: BEP 44 says reset the timeout, not
            // reject -- storing again below does exactly that.
        } else if self.items.len() >= MAX_STORED_ITEMS {
            return Err(PutError::StoreFull);
        }
        self.items.insert(target, Item { v, mutable: Some(MutableMeta { k, seq, sig }), stored_at: now });
        Ok(target)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // ---- BEP 44's own published test vectors (bittorrent.org/beps/bep_0044.html), fetched and
    // transcribed directly from the spec, not from memory. The buffer-construction checks below
    // need no cryptography at all -- they are the BEP's own given strings, byte for byte. The
    // signature checks use ed25519-dalek's `hazmat` module (test-only, see Cargo.toml) because
    // the BEP's "private key" test values turn out to be the pre-expanded (scalar || nonce
    // prefix) form some ed25519 implementations accept directly, not an ordinary 32-byte seed:
    // confirmed by writing the RFC 8032 signing algorithm from scratch against these exact
    // vectors before touching this file, and finding the *first* 32 bytes, used as the scalar
    // with no further hashing, reproduce the given public key and both given signatures exactly.
    // Production signing (`sign_mutable`) uses the ordinary `SigningKey` seed-based API instead,
    // since that is the key format any real user's keypair is actually in; it is tested for
    // self-consistency below, not against these vectors.

    const TEST_PUBKEY_HEX: &str = "77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548";
    const TEST_EXPANDED_PRIVKEY_HEX: &str = "e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74db7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d";

    #[test]
    fn immutable_target_matches_beps_test_3() {
        let value = b"12:Hello World!";
        assert_eq!(hex::encode(immutable_target(value)), "e5f96f6f38320f0f33959cb4d3d656452117aadb");
    }

    #[test]
    fn mutable_target_without_salt_matches_beps_test_1() {
        let k: [u8; 32] = from_hex(TEST_PUBKEY_HEX).try_into().unwrap();
        assert_eq!(hex::encode(mutable_target(&k, None)), "4a533d47ec9c7d95b1ad75f576cffc641853b750");
    }

    #[test]
    fn mutable_target_with_salt_matches_beps_test_2() {
        let k: [u8; 32] = from_hex(TEST_PUBKEY_HEX).try_into().unwrap();
        assert_eq!(hex::encode(mutable_target(&k, Some(b"foobar"))), "411eba73b6f087ca51a3795d9c8c938d365e32c1");
    }

    #[test]
    fn signing_buffer_without_salt_matches_the_beps_own_example_bytes() {
        assert_eq!(signing_buffer(None, 1, b"12:Hello World!"), b"3:seqi1e1:v12:Hello World!".to_vec());
    }

    #[test]
    fn signing_buffer_with_salt_matches_the_beps_own_example_bytes() {
        assert_eq!(signing_buffer(Some(b"foobar"), 1, b"12:Hello World!"), b"4:salt6:foobar3:seqi1e1:v12:Hello World!".to_vec());
    }

    #[test]
    fn an_empty_salt_is_the_same_as_no_salt_at_all() {
        assert_eq!(signing_buffer(Some(b""), 1, b"12:Hello World!"), signing_buffer(None, 1, b"12:Hello World!"));
        let k: [u8; 32] = from_hex(TEST_PUBKEY_HEX).try_into().unwrap();
        assert_eq!(mutable_target(&k, Some(b"")), mutable_target(&k, None));
    }

    #[test]
    fn hazmat_raw_sign_reproduces_beps_test_1_signature_byte_for_byte() {
        // The strongest check in this file: not just that a signature verifies, but that
        // signing with the BEP's own key (in its actual pre-expanded encoding) reproduces its
        // own published signature exactly, proving `signing_buffer` builds precisely the bytes
        // the BEP's reference tool signed over.
        use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
        use sha2::Sha512;
        let pub_bytes: [u8; 32] = from_hex(TEST_PUBKEY_HEX).try_into().unwrap();
        let expanded: [u8; 64] = from_hex(TEST_EXPANDED_PRIVKEY_HEX).try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pub_bytes).unwrap();
        let esk = ExpandedSecretKey::from_bytes(&expanded);

        let buf = signing_buffer(None, 1, b"12:Hello World!");
        let sig = raw_sign::<Sha512>(&esk, &buf, &vk);
        assert_eq!(hex::encode_sig(sig.to_bytes()), "305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01");

        let buf2 = signing_buffer(Some(b"foobar"), 1, b"12:Hello World!");
        let sig2 = raw_sign::<Sha512>(&esk, &buf2, &vk);
        assert_eq!(hex::encode_sig(sig2.to_bytes()), "6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17ddf9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08");
    }

    #[test]
    fn verify_mutable_accepts_beps_own_signature_test_1_no_salt() {
        let k: [u8; 32] = from_hex(TEST_PUBKEY_HEX).try_into().unwrap();
        let sig: [u8; 64] = from_hex("305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01").try_into().unwrap();
        assert!(verify_mutable(&k, None, 1, b"12:Hello World!", &sig));
    }

    #[test]
    fn verify_mutable_accepts_beps_own_signature_test_2_with_salt() {
        let k: [u8; 32] = from_hex(TEST_PUBKEY_HEX).try_into().unwrap();
        let sig: [u8; 64] = from_hex("6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17ddf9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08").try_into().unwrap();
        assert!(verify_mutable(&k, Some(b"foobar"), 1, b"12:Hello World!", &sig));
    }

    #[test]
    fn verify_mutable_rejects_a_tampered_value_signature_or_key() {
        let k: [u8; 32] = from_hex(TEST_PUBKEY_HEX).try_into().unwrap();
        let sig: [u8; 64] = from_hex("305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01").try_into().unwrap();
        assert!(!verify_mutable(&k, None, 1, b"12:Hello World?", &sig), "a changed value");
        assert!(!verify_mutable(&k, None, 2, b"12:Hello World!", &sig), "a changed sequence number");
        assert!(!verify_mutable(&k, Some(b"salt"), 1, b"12:Hello World!", &sig), "a salt that was never signed over");
        let mut wrong_sig = sig;
        wrong_sig[0] ^= 0xff;
        assert!(!verify_mutable(&k, None, 1, b"12:Hello World!", &wrong_sig), "a flipped signature bit");
        let mut wrong_key = k;
        wrong_key[0] ^= 0xff;
        assert!(!verify_mutable(&wrong_key, None, 1, b"12:Hello World!", &sig), "the wrong public key");
    }

    #[test]
    fn a_key_that_is_not_a_valid_curve_point_is_rejected_not_panicked_on() {
        let garbage = [0xffu8; 32];
        let sig = [0u8; 64];
        assert!(!verify_mutable(&garbage, None, 1, b"x", &sig));
    }

    // ---- sign_mutable / verify_mutable round trip, with an ordinary seed-based key (the
    // format a real user's keypair is actually in, as opposed to BEP 44's own pre-expanded
    // test-vector encoding above) ----

    fn keypair(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    #[test]
    fn a_signature_made_with_sign_mutable_is_accepted_by_verify_mutable() {
        let key = keypair(0x42);
        let pubkey = key.verifying_key().to_bytes();
        for salt in [None, Some(b"salt" as &[u8])] {
            let sig = sign_mutable(&key, salt, 7, b"3:abc");
            assert!(verify_mutable(&pubkey, salt, 7, b"3:abc", &sig));
        }
    }

    #[test]
    fn a_signature_from_a_different_key_does_not_verify() {
        let a = keypair(0x11);
        let b = keypair(0x22);
        let sig = sign_mutable(&a, None, 1, b"3:abc");
        assert!(!verify_mutable(&b.verifying_key().to_bytes(), None, 1, b"3:abc", &sig));
    }

    #[test]
    fn max_lengths_are_what_the_bep_says() {
        assert_eq!(MAX_VALUE_LEN, 1000);
        assert_eq!(MAX_SALT_LEN, 64);
    }

    // ---- Store ----

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn an_immutable_item_is_stored_under_and_found_by_its_content_hash() {
        let mut store = Store::new();
        let v = Bencode::Bytes(b"Hello World!".to_vec());
        let target = store.put_immutable(v.clone(), now()).unwrap();
        assert_eq!(target, immutable_target(&bencode::encode(&v)));
        let got = store.get(&target, now()).unwrap();
        assert_eq!(got.v, v);
        assert!(got.mutable.is_none());
    }

    #[test]
    fn an_immutable_put_too_large_is_rejected_and_nothing_is_stored() {
        let mut store = Store::new();
        let big = Bencode::Bytes(vec![b'x'; MAX_VALUE_LEN + 1]);
        assert_eq!(store.put_immutable(big, now()), Err(PutError::ValueTooLarge));
        assert!(store.is_empty());
    }

    #[test]
    fn a_get_for_something_never_stored_is_none() {
        let store = Store::new();
        assert!(store.get(&[0u8; 20], now()).is_none());
    }

    #[test]
    fn an_expired_immutable_item_is_treated_as_absent() {
        let mut store = Store::new();
        let v = Bencode::Bytes(b"x".to_vec());
        let start = now();
        let target = store.put_immutable(v, start).unwrap();
        assert!(store.get(&target, start + Duration::from_secs(1)).is_some(), "still fresh");
        assert!(store.get(&target, start + ITEM_LIFETIME).is_none(), "aged out at exactly the lifetime");
    }

    fn mutable_put(store: &mut Store, key: &SigningKey, salt: Option<&[u8]>, seq: i64, v: &[u8], cas: Option<i64>, at: Instant) -> Result<[u8; 20], PutError> {
        let value = Bencode::Bytes(v.to_vec());
        let bencoded = bencode::encode(&value);
        let sig = sign_mutable(key, salt, seq, &bencoded);
        store.put_mutable(key.verifying_key().to_bytes(), salt.map(<[u8]>::to_vec), seq, sig, value, cas, at)
    }

    #[test]
    fn a_mutable_item_is_stored_under_its_key_and_found_with_its_seq_and_sig() {
        let mut store = Store::new();
        let key = keypair(0x33);
        let target = mutable_put(&mut store, &key, None, 1, b"first", None, now()).unwrap();
        assert_eq!(target, mutable_target(&key.verifying_key().to_bytes(), None));
        let got = store.get(&target, now()).unwrap();
        assert_eq!(got.v, Bencode::Bytes(b"first".to_vec()));
        let (k, seq, _sig) = got.mutable.expect("a mutable item carries its key/seq/sig");
        assert_eq!(k, key.verifying_key().to_bytes());
        assert_eq!(seq, 1);
    }

    #[test]
    fn a_mutable_put_with_a_bad_signature_is_rejected() {
        let mut store = Store::new();
        let key = keypair(0x33);
        let value = Bencode::Bytes(b"first".to_vec());
        let mut sig = sign_mutable(&key, None, 1, &bencode::encode(&value));
        sig[0] ^= 0xff;
        assert_eq!(store.put_mutable(key.verifying_key().to_bytes(), None, 1, sig, value, None, now()), Err(PutError::BadSignature));
        assert!(store.is_empty());
    }

    #[test]
    fn a_mutable_put_with_a_salt_too_long_is_rejected_before_checking_the_signature() {
        let mut store = Store::new();
        let key = keypair(0x33);
        let salt = vec![b's'; MAX_SALT_LEN + 1];
        let result = mutable_put(&mut store, &key, Some(&salt), 1, b"x", None, now());
        assert_eq!(result, Err(PutError::SaltTooLarge));
    }

    #[test]
    fn a_higher_sequence_number_updates_the_stored_item_a_lower_one_is_refused() {
        let mut store = Store::new();
        let key = keypair(0x33);
        mutable_put(&mut store, &key, None, 5, b"v5", None, now()).unwrap();

        assert_eq!(mutable_put(&mut store, &key, None, 4, b"v4", None, now()), Err(PutError::SequenceTooLow));
        let target = mutable_target(&key.verifying_key().to_bytes(), None);
        assert_eq!(store.get(&target, now()).unwrap().v, Bencode::Bytes(b"v5".to_vec()), "the lower seq did not overwrite it");

        mutable_put(&mut store, &key, None, 6, b"v6", None, now()).unwrap();
        assert_eq!(store.get(&target, now()).unwrap().v, Bencode::Bytes(b"v6".to_vec()), "a higher seq does");
    }

    #[test]
    fn cas_only_succeeds_when_it_matches_the_currently_stored_sequence_number() {
        let mut store = Store::new();
        let key = keypair(0x33);
        mutable_put(&mut store, &key, None, 1, b"v1", None, now()).unwrap();

        assert_eq!(mutable_put(&mut store, &key, None, 2, b"v2", Some(99), now()), Err(PutError::CasMismatch));
        assert!(mutable_put(&mut store, &key, None, 2, b"v2", Some(1), now()).is_ok(), "matches the seq actually stored (1)");
    }

    #[test]
    fn a_different_salt_under_the_same_key_is_a_different_item() {
        let mut store = Store::new();
        let key = keypair(0x33);
        let a = mutable_put(&mut store, &key, Some(b"a"), 1, b"va", None, now()).unwrap();
        let b = mutable_put(&mut store, &key, Some(b"b"), 1, b"vb", None, now()).unwrap();
        assert_ne!(a, b);
        assert_eq!(store.get(&a, now()).unwrap().v, Bencode::Bytes(b"va".to_vec()));
        assert_eq!(store.get(&b, now()).unwrap().v, Bencode::Bytes(b"vb".to_vec()));
    }

    #[test]
    fn an_expired_mutable_item_accepts_a_seq_lower_than_its_own_as_if_it_were_gone() {
        let mut store = Store::new();
        let key = keypair(0x33);
        let start = now();
        mutable_put(&mut store, &key, None, 9, b"stale", None, start).unwrap();

        // Long after it expired, a lower seq must not be refused: nothing current to conflict with.
        let later = start + ITEM_LIFETIME + Duration::from_secs(1);
        assert!(mutable_put(&mut store, &key, None, 1, b"fresh", None, later).is_ok());
    }

    #[test]
    fn the_store_is_bounded_and_a_full_store_still_accepts_updates_to_keys_it_already_holds() {
        let mut store = Store::new();
        for n in 0..MAX_STORED_ITEMS {
            let mut v = vec![0u8; 20];
            v[..8].copy_from_slice(&(n as u64).to_be_bytes());
            store.put_immutable(Bencode::Bytes(v), now()).unwrap();
        }
        assert_eq!(store.len(), MAX_STORED_ITEMS);
        assert_eq!(store.put_immutable(Bencode::Bytes(b"one more".to_vec()), now()), Err(PutError::StoreFull));

        let key = keypair(0x44);
        assert_eq!(mutable_put(&mut store, &key, None, 1, b"v1", None, now()), Err(PutError::StoreFull), "a new key is refused the same way an immutable put is");
        assert_eq!(store.len(), MAX_STORED_ITEMS);
    }

    #[test]
    fn a_full_store_still_lets_an_existing_mutable_key_update() {
        let mut store = Store::new();
        let key = keypair(0x44);
        mutable_put(&mut store, &key, None, 1, b"v1", None, now()).unwrap();
        for n in 0..(MAX_STORED_ITEMS - 1) {
            let mut v = vec![0u8; 20];
            v[..8].copy_from_slice(&(n as u64).to_be_bytes());
            store.put_immutable(Bencode::Bytes(v), now()).unwrap();
        }
        assert_eq!(store.len(), MAX_STORED_ITEMS);

        // The same key, a higher seq: updates the entry it already has, not a new one.
        assert!(mutable_put(&mut store, &key, None, 2, b"v2", None, now()).is_ok());
        assert_eq!(store.len(), MAX_STORED_ITEMS, "no new entry was needed");
        let target = mutable_target(&key.verifying_key().to_bytes(), None);
        assert_eq!(store.get(&target, now()).unwrap().v, Bencode::Bytes(b"v2".to_vec()));
    }

    mod hex {
        pub fn encode(bytes: [u8; 20]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
        pub fn encode_sig(bytes: [u8; 64]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
    }
}
