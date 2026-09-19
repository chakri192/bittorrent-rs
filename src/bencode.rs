//! Bencode decoder (BEP 3).
//!
//! Grammar:
//!   int     ::= 'i' ['-'] digit+ 'e'
//!   bytes   ::= len ':' byte*          (len = ascii digit+, no leading zero except "0")
//!   list    ::= 'l' value* 'e'
//!   dict    ::= 'd' (bytes value)* 'e' (keys must appear in sorted order)
//!
//! `Bencode::Dict` uses `BTreeMap<Vec<u8>, Bencode>` so key ordering is
//! canonical regardless of what order keys appeared on the wire -- but for
//! InfoHash purposes we never re-serialize; we slice the *original* bytes
//! (see `parse_with_spans`), because bencode dicts in the wild are not
//! guaranteed byte-identical to a round-tripped re-encoding (e.g. integer
//! representations, though rare, or non-canonical but still-valid encodes).

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bencode {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Bencode>),
    Dict(BTreeMap<Vec<u8>, Bencode>),
}

impl Bencode {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Bencode::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Bencode::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Bencode]> {
        match self {
            Bencode::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Bencode>> {
        match self {
            Bencode::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// Convenience: dict.get(key: &str)
    pub fn get(&self, key: &str) -> Option<&Bencode> {
        self.as_dict()?.get(key.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Lists and dicts nested deeper than [`MAX_DEPTH`].
    TooDeep,
    UnexpectedEof,
    InvalidDigit(u8),
    InvalidTag(u8),
    LeadingZero,
    LengthMismatch { expected: usize, remaining: usize },
    TrailingGarbage(usize),
    NonUtf8Int,
    UnsortedOrDuplicateKey,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooDeep => write!(f, "lists/dicts nested deeper than {} levels", MAX_DEPTH),
            DecodeError::UnexpectedEof => write!(f, "unexpected end of input"),
            DecodeError::InvalidDigit(b) => write!(f, "invalid digit byte: {:#04x}", b),
            DecodeError::InvalidTag(b) => write!(f, "invalid bencode tag byte: {:#04x} ({:?})", b, *b as char),
            DecodeError::LeadingZero => write!(f, "invalid leading zero in length/integer"),
            DecodeError::LengthMismatch { expected, remaining } => {
                write!(f, "string length {} exceeds remaining {} bytes", expected, remaining)
            }
            DecodeError::TrailingGarbage(pos) => write!(f, "trailing data after top-level value at offset {}", pos),
            DecodeError::NonUtf8Int => write!(f, "integer digits were not valid utf8"),
            DecodeError::UnsortedOrDuplicateKey => write!(f, "dict keys not strictly sorted / duplicate key"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A single-pass decoder over a byte slice. Tracks `pos` so callers can
/// recover the raw byte span `[start, end)` of any decoded value -- this is
/// what makes an exact (non-reserialized) InfoHash possible.
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    /// Strict mode enforces BEP 3's canonical form (sorted, unique dict
    /// keys). Lenient mode accepts unsorted/duplicate keys (first
    /// occurrence wins) -- needed for *wire* data: real clients (and DHT
    /// nodes) routinely send non-canonical extension handshakes, and
    /// rejecting them costs us an otherwise-usable peer. Strict stays the
    /// default for anything we might hash or re-serialize.
    strict: bool,
    /// How many lists/dicts enclose the value being decoded.
    depth: usize,
}

/// The deepest nesting of lists and dicts the decoder will follow.
///
/// Decoding is recursive, so without a limit a few hundred kilobytes of
/// `llll...` from a peer, a tracker or a DHT node overflows the stack and
/// aborts the whole process. Real data is shallow (a `.torrent`'s deepest
/// value is about six levels in); libtorrent's default limit is also 100.
pub const MAX_DEPTH: usize = 100;

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Decoder { data, pos: 0, strict: true, depth: 0 }
    }

    pub fn new_lenient(data: &'a [u8]) -> Self {
        Decoder { data, pos: 0, strict: false, depth: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn peek(&self) -> Result<u8, DecodeError> {
        self.data.get(self.pos).copied().ok_or(DecodeError::UnexpectedEof)
    }

    fn advance(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(DecodeError::LengthMismatch {
                expected: n,
                remaining: self.data.len() - self.pos,
            });
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Parses ASCII digits (optionally signed) up to and including a
    /// terminator byte, returning the parsed i64. Used both for `i<n>e`
    /// and for the length prefix of byte strings.
    fn parse_signed_until(&mut self, terminator: u8) -> Result<i64, DecodeError> {
        let start = self.pos;
        let negative = self.peek()? == b'-';
        if negative {
            self.pos += 1;
        }
        let digits_start = self.pos;
        loop {
            let b = self.peek()?;
            if b == terminator {
                break;
            }
            if !b.is_ascii_digit() {
                return Err(DecodeError::InvalidDigit(b));
            }
            self.pos += 1;
        }
        let digits = &self.data[digits_start..self.pos];
        if digits.is_empty() {
            return Err(DecodeError::InvalidDigit(terminator));
        }
        // Reject leading zero, except the literal single digit "0".
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(DecodeError::LeadingZero);
        }
        if digits == b"0" && negative {
            // "-0" is not canonical bencode.
            return Err(DecodeError::LeadingZero);
        }
        let s = std::str::from_utf8(&self.data[start..self.pos]).map_err(|_| DecodeError::NonUtf8Int)?;
        self.pos += 1; // consume terminator
        s.parse::<i64>().map_err(|_| DecodeError::InvalidDigit(terminator))
    }

    fn decode_int(&mut self) -> Result<i64, DecodeError> {
        debug_assert_eq!(self.peek()?, b'i');
        self.pos += 1; // consume 'i'
        self.parse_signed_until(b'e')
    }

    fn decode_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.parse_signed_until(b':')?;
        if len < 0 {
            return Err(DecodeError::InvalidDigit(b':'));
        }
        Ok(self.advance(len as usize)?.to_vec())
    }

    fn decode_list(&mut self) -> Result<Vec<Bencode>, DecodeError> {
        debug_assert_eq!(self.peek()?, b'l');
        self.pos += 1; // consume 'l'
        let mut items = Vec::new();
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                return Ok(items);
            }
            items.push(self.decode_value()?);
        }
    }

    fn decode_dict(&mut self) -> Result<BTreeMap<Vec<u8>, Bencode>, DecodeError> {
        debug_assert_eq!(self.peek()?, b'd');
        self.pos += 1; // consume 'd'
        let mut map = BTreeMap::new();
        let mut last_key: Option<Vec<u8>> = None;
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                return Ok(map);
            }
            let key = self.decode_bytes()?;
            if self.strict {
                if let Some(prev) = &last_key {
                    // BEP 3: keys must appear in sorted (raw byte) order, no dupes.
                    if key <= *prev {
                        return Err(DecodeError::UnsortedOrDuplicateKey);
                    }
                }
                last_key = Some(key.clone());
            }
            let value = self.decode_value()?;
            // Lenient mode: first occurrence of a duplicate key wins (the
            // value is still fully parsed either way so the stream stays
            // in sync). In strict mode duplicates were already rejected.
            map.entry(key).or_insert(value);
        }
    }

    pub fn decode_value(&mut self) -> Result<Bencode, DecodeError> {
        let tag = self.peek()?;
        if tag == b'l' || tag == b'd' {
            if self.depth >= MAX_DEPTH {
                return Err(DecodeError::TooDeep);
            }
            self.depth += 1;
            let value = if tag == b'l' { self.decode_list().map(Bencode::List) } else { self.decode_dict().map(Bencode::Dict) };
            self.depth -= 1;
            return value;
        }
        match tag {
            b'i' => Ok(Bencode::Int(self.decode_int()?)),
            b'0'..=b'9' => Ok(Bencode::Bytes(self.decode_bytes()?)),
            other => Err(DecodeError::InvalidTag(other)),
        }
    }

    /// Decode exactly one top-level value, erroring on trailing bytes.
    pub fn decode_top_level(mut self) -> Result<Bencode, DecodeError> {
        let value = self.decode_value()?;
        if self.pos != self.data.len() {
            return Err(DecodeError::TrailingGarbage(self.pos));
        }
        Ok(value)
    }

    /// Decode a value starting at `pos`, returning (value, byte span [start,end)).
    /// Used to locate the raw `info` dict for hashing without re-encoding.
    pub fn decode_value_with_span(&mut self) -> Result<(Bencode, (usize, usize)), DecodeError> {
        let start = self.pos;
        let value = self.decode_value()?;
        Ok((value, (start, self.pos)))
    }
}

/// Top-level convenience: decode a full bencoded buffer (strict, BEP 3
/// canonical form).
pub fn decode(data: &[u8]) -> Result<Bencode, DecodeError> {
    Decoder::new(data).decode_top_level()
}

/// Lenient top-level decode for data received from remote peers/nodes on
/// the wire (extension handshakes, tracker responses, DHT/KRPC messages):
/// accepts unsorted and duplicate dict keys (first wins). Be strict in
/// what you send, lenient in what you accept.
pub fn decode_lenient(data: &[u8]) -> Result<Bencode, DecodeError> {
    Decoder::new_lenient(data).decode_top_level()
}

/// Encodes a `Bencode` value to its canonical byte form (dict keys sorted
/// -- `BTreeMap` guarantees iteration order). Everything this client
/// *sends* (extension handshakes, KRPC messages) goes through here.
pub fn encode(value: &Bencode) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Bencode, out: &mut Vec<u8>) {
    match value {
        Bencode::Int(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        Bencode::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        Bencode::List(items) => {
            out.push(b'l');
            for item in items {
                encode_into(item, out);
            }
            out.push(b'e');
        }
        Bencode::Dict(map) => {
            out.push(b'd');
            // BTreeMap already iterates in sorted key order, matching BEP 3.
            for (k, v) in map {
                encode_into(&Bencode::Bytes(k.clone()), out);
                encode_into(v, out);
            }
            out.push(b'e');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_positive_int() {
        assert_eq!(decode(b"i42e").unwrap(), Bencode::Int(42));
    }

    #[test]
    fn decodes_negative_int() {
        assert_eq!(decode(b"i-42e").unwrap(), Bencode::Int(-42));
    }

    #[test]
    fn decodes_zero() {
        assert_eq!(decode(b"i0e").unwrap(), Bencode::Int(0));
    }

    #[test]
    fn rejects_leading_zero_int() {
        assert_eq!(decode(b"i042e"), Err(DecodeError::LeadingZero));
    }

    #[test]
    fn rejects_negative_zero() {
        assert_eq!(decode(b"i-0e"), Err(DecodeError::LeadingZero));
    }

    #[test]
    fn decodes_bytes() {
        assert_eq!(decode(b"4:spam").unwrap(), Bencode::Bytes(b"spam".to_vec()));
    }

    #[test]
    fn decodes_empty_bytes() {
        assert_eq!(decode(b"0:").unwrap(), Bencode::Bytes(vec![]));
    }

    #[test]
    fn rejects_string_longer_than_buffer() {
        assert!(matches!(decode(b"10:short"), Err(DecodeError::LengthMismatch { .. })));
    }

    #[test]
    fn decodes_list() {
        assert_eq!(
            decode(b"l4:spam4:eggse").unwrap(),
            Bencode::List(vec![Bencode::Bytes(b"spam".to_vec()), Bencode::Bytes(b"eggs".to_vec())])
        );
    }

    #[test]
    fn decodes_nested_list() {
        assert_eq!(
            decode(b"li1eli2ei3eee").unwrap(),
            Bencode::List(vec![Bencode::Int(1), Bencode::List(vec![Bencode::Int(2), Bencode::Int(3)])])
        );
    }

    #[test]
    fn decodes_empty_list() {
        assert_eq!(decode(b"le").unwrap(), Bencode::List(vec![]));
    }

    #[test]
    fn decodes_dict() {
        let d = decode(b"d3:cow3:moo4:spam4:eggse").unwrap();
        let map = d.as_dict().unwrap();
        assert_eq!(map.get(b"cow".as_slice()).unwrap().as_bytes().unwrap(), b"moo");
        assert_eq!(map.get(b"spam".as_slice()).unwrap().as_bytes().unwrap(), b"eggs");
    }

    #[test]
    fn decodes_empty_dict() {
        assert_eq!(decode(b"de").unwrap(), Bencode::Dict(Default::default()));
    }

    #[test]
    fn rejects_unsorted_dict_keys() {
        // "spam" before "cow" -- violates BEP 3 sort order.
        assert_eq!(decode(b"d4:spam4:eggs3:cow3:mooe"), Err(DecodeError::UnsortedOrDuplicateKey));
    }

    #[test]
    fn rejects_duplicate_dict_keys() {
        assert_eq!(decode(b"d3:cow3:moo3:cow3:mooe"), Err(DecodeError::UnsortedOrDuplicateKey));
    }

    #[test]
    fn decodes_dict_with_nested_structures() {
        // d 3:key l i1e i2e e e  ->  {"key": [1, 2]}
        let d = decode(b"d3:keyli1ei2eee").unwrap();
        let map = d.as_dict().unwrap();
        let list = map.get(b"key".as_slice()).unwrap().as_list().unwrap();
        assert_eq!(list, &[Bencode::Int(1), Bencode::Int(2)]);
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(matches!(decode(b"i1eXX"), Err(DecodeError::TrailingGarbage(_))));
    }

    #[test]
    fn rejects_unterminated_int() {
        assert_eq!(decode(b"i42"), Err(DecodeError::UnexpectedEof));
    }

    #[test]
    fn rejects_bad_tag() {
        assert_eq!(decode(b"x"), Err(DecodeError::InvalidTag(b'x')));
    }

    #[test]
    fn lenient_accepts_unsorted_dict_keys() {
        // Same input the strict test rejects.
        let d = decode_lenient(b"d4:spam4:eggs3:cow3:mooe").unwrap();
        let map = d.as_dict().unwrap();
        assert_eq!(map.get(b"cow".as_slice()).unwrap().as_bytes().unwrap(), b"moo");
        assert_eq!(map.get(b"spam".as_slice()).unwrap().as_bytes().unwrap(), b"eggs");
    }

    #[test]
    fn lenient_duplicate_keys_first_occurrence_wins() {
        let d = decode_lenient(b"d3:cow3:moo3:cow3:bahe").unwrap();
        assert_eq!(d.get("cow").unwrap().as_bytes().unwrap(), b"moo");
    }

    #[test]
    fn lenient_still_rejects_structural_garbage() {
        assert!(decode_lenient(b"d3:cow").is_err());
        assert!(decode_lenient(b"x").is_err());
    }

    #[test]
    fn encode_round_trips_through_decode() {
        let src = b"d3:cow3:moo4:spamli1ei-2eee";
        let val = decode(src).unwrap();
        assert_eq!(encode(&val), src.to_vec());
    }

    #[test]
    fn encode_canonicalizes_key_order() {
        // Decoded leniently from unsorted input, re-encoded sorted.
        let val = decode_lenient(b"d4:spam4:eggs3:cow3:mooe").unwrap();
        assert_eq!(encode(&val), b"d3:cow3:moo4:spam4:eggse".to_vec());
    }

    #[test]
    fn span_tracking_roundtrips_to_source_bytes() {
        let src = b"d4:infod6:lengthi12345eee";
        let mut dec = Decoder::new(src);
        let (_val, (start, end)) = dec.decode_value_with_span().unwrap();
        assert_eq!(&src[start..end], &src[..]);
    }

    /// `n` lists nested in each other around an integer: `lll...i0e...eee`.
    fn nested_lists(n: usize) -> Vec<u8> {
        let mut v = b"l".repeat(n);
        v.extend_from_slice(b"i0e");
        v.extend_from_slice(&b"e".repeat(n));
        v
    }

    /// The same with dicts: `d1:ad1:ad...i0e...ee`.
    fn nested_dicts(n: usize) -> Vec<u8> {
        let mut v = b"d1:a".repeat(n);
        v.extend_from_slice(b"i0e");
        v.extend_from_slice(&b"e".repeat(n));
        v
    }

    #[test]
    fn nesting_up_to_the_limit_is_accepted() {
        assert!(decode(&nested_lists(MAX_DEPTH)).is_ok());
        assert!(decode(&nested_dicts(MAX_DEPTH)).is_ok());
        assert!(decode_lenient(&nested_lists(MAX_DEPTH)).is_ok());
    }

    #[test]
    fn nesting_beyond_the_limit_is_an_error() {
        assert_eq!(decode(&nested_lists(MAX_DEPTH + 1)), Err(DecodeError::TooDeep));
        assert_eq!(decode(&nested_dicts(MAX_DEPTH + 1)), Err(DecodeError::TooDeep));
        assert_eq!(decode_lenient(&nested_lists(MAX_DEPTH + 1)), Err(DecodeError::TooDeep));
        assert_eq!(decode_lenient(&nested_dicts(MAX_DEPTH + 1)), Err(DecodeError::TooDeep));
    }

    #[test]
    fn a_hostile_payload_is_an_error_not_a_stack_overflow() {
        // 200 KB of `l`, the size of a modest extended handshake, decoded on
        // a stack no larger than a worker thread's. It used to abort the
        // whole process; peers, trackers and DHT nodes could all send it.
        let result = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| (decode(&b"l".repeat(200_000)), decode_lenient(&b"d1:a".repeat(200_000))))
            .unwrap()
            .join()
            .expect("the decoder must not overflow the stack");
        assert_eq!(result, (Err(DecodeError::TooDeep), Err(DecodeError::TooDeep)));
    }

    #[test]
    fn the_depth_count_comes_back_down_after_each_container() {
        // Two siblings, each MAX_DEPTH - 1 deep. If leaving a container did
        // not decrement the count, the second would look too deep.
        let branch = nested_lists(MAX_DEPTH - 1);
        let mut v = b"l".to_vec();
        v.extend_from_slice(&branch);
        v.extend_from_slice(&branch);
        v.push(b'e');
        assert!(decode(&v).is_ok());
    }

    #[test]
    fn the_span_decoder_used_for_the_info_hash_has_the_same_limit() {
        let deep = nested_lists(MAX_DEPTH + 1);
        assert_eq!(Decoder::new(&deep).decode_value_with_span().unwrap_err(), DecodeError::TooDeep);
    }
}
