# bittorrent-rs

From-scratch BitTorrent client in Rust. No `torrent`/`libtorrent`-style crates —
bencode parsing, wire protocol, tracker comms, and piece assembly are all
hand-rolled.

## Roadmap

- [x] **Phase 1** — Bencode parser + exact-byte SHA-1 InfoHash (`src/bencode.rs`, `src/torrent.rs`)
- [x] **Phase 2** — Tracker communication (`src/tracker/`) — HTTP GET announce over raw `TcpStream`, UDP announce (BEP 15) over raw `UdpSocket`, compact peer decoding (BEP 23)
- [x] **Phase 3** — Wire protocol handshake + peer message state machine (`src/peer/`)
- [x] **Phase 4** — BEP 10 extension handshake + BEP 9 metadata exchange (`src/peer/extension.rs`, `src/metadata.rs`, `src/magnet.rs`)
- [ ] **Phase 5** — Concurrent piece downloader / work queue

## Phase 1

`src/bencode.rs` — single-pass decoder for `i<n>e`, `<len>:<bytes>`, `l...e`, `d...e`.
Enforces BEP 3 canonical form (sorted, unique dict keys; no leading zeros).
`Decoder::decode_value_with_span` exposes the `[start, end)` byte range of
any decoded value.

`src/torrent.rs` — parses a `.torrent` file into `TorrentFile`. The InfoHash
is computed by locating the raw byte span of the `info` value in the
*original* buffer (`find_key_span`) and hashing those bytes directly —
not a re-serialization of the parsed tree. This avoids a class of bugs
where a re-encoded dict doesn't byte-match the source.

```sh
cargo test                              # 25 unit tests
cargo run --bin infohash -- file.torrent
```

## Phase 2

`src/tracker/mod.rs` — shared `AnnounceRequest`/`AnnounceResponse`, RFC 3986
percent-encoding for raw `info_hash`/`peer_id` bytes (not UTF-8 safe, so this
operates on `&[u8]`), and `parse_compact_peers` (BEP 23: 6 bytes/peer, 4-byte
big-endian IPv4 + 2-byte big-endian port) shared by both transports.

`src/tracker/http.rs` — HTTP GET announce hand-rolled over `TcpStream`: no
`reqwest`/`hyper`. Builds the request line + headers manually, parses the
response's status line, handles both `Content-Length` and
`Transfer-Encoding: chunked`, then bencode-decodes the body. HTTPS trackers
return `TrackerError::UnsupportedScheme` (no TLS implementation here).

`src/tracker/udp.rs` — BEP 15 UDP tracker: 16-byte connect request/response
to obtain a `connection_id`, then a 98-byte IPv4 announce packet. Retries
use BEP 15's exponential backoff (`15 * 2^n` seconds). All fields are packed
with explicit `to_be_bytes()`/`from_be_bytes()` — no serde, no `byteorder`.

```sh
cargo test                              # 47 unit tests
```

## Phase 3

`src/peer/handshake.rs` — the 68-byte handshake (`pstrlen + pstr + reserved(8) + info_hash(20) + peer_id(20)`). BEP 10 support is signaled by `reserved[5] |= 0x10`.

`src/peer/message.rs` — length-prefixed message framing (`Read`/`Write` generic, so it's tested against in-memory `Cursor`s, no live peer needed). Zero-length prefix = keep-alive. Payload length is capped at 1 MiB to bound memory use against a hostile length prefix. `Extended { id, payload }` carries BEP 10 messages as opaque bytes for Phase 4 to parse.

`src/peer/state.rs` — `PeerState` (am_choking/am_interested/peer_choking/peer_interested + the peer's piece bitfield), starting choked/not-interested per spec. `apply_message` is pure state transition, no I/O — returns `false` (not an error) for message types it doesn't own (Request/Piece/Cancel/Port/Extended), leaving those to Phases 4-5.

`src/peer/connection.rs` — thin `TcpStream` wrapper: `connect_and_handshake` sends ours first, validates the peer's `info_hash` matches, and hands back the stream + parsed peer handshake.

```sh
cargo test                              # 82 unit tests
```

## Phase 4

`src/magnet.rs` — magnet URI parsing. `xt=urn:btih:` accepts both 40-char hex and 32-char base32 (RFC 4648, hand-rolled decoder — 32 chars × 5 bits = 160 bits = 20 bytes exactly, no padding). `dn`/`tr` go through a percent-decoder that, unlike form-encoding, leaves `+` literal (tracker URLs can contain one).

`src/peer/extension.rs` — BEP 10 extended handshake (`Message::Extended { id: 0, .. }`). Parses the peer's `m` dict to learn *their* chosen id for `ut_metadata` (`peer_ut_metadata_id()`), plus `metadata_size` if they have it. Added a minimal bencode *encoder* here (the Phase 1 decoder had no inverse) since handshakes and metadata messages both need to produce bencode, not just consume it.

`src/metadata.rs` — the actual BEP 9 exchange: `MetadataMessage::{Request, Data, Reject}`, where `Data` is a bencoded header immediately followed by raw (non-bencoded) piece bytes — decoded by tracking how many bytes `Decoder::decode_value_with_span` consumed and treating the rest as the raw chunk. `MetadataAssembler` collects 16 KiB pieces (validating each piece's exact expected length, including the shorter final piece), and `assemble_and_verify` is the trust boundary: it SHA-1s the reassembled info dict and refuses to return it unless the hash matches the magnet link's InfoHash.

```sh
cargo test                              # 112 unit tests
```

## License

MIT
