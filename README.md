# bittorrent-rs

A working BitTorrent client in Rust, built from scratch. No `libtorrent`-style
crate anywhere — bencode parsing, wire protocol, tracker comms, BEP 10/9
magnet support, and piece assembly are all hand-rolled. Dependencies:
`sha1`, and `rustls`+`webpki-roots` for HTTPS tracker support (TLS itself
is deliberately not hand-rolled — see below).

```sh
cargo run --bin download -- file.torrent --out ./downloads
cargo run --bin download -- "magnet:?xt=urn:btih:...&tr=..." --out ./downloads
```

## Does it actually work?

```sh
cargo run --bin e2e_harness
```

This spins up a fake tracker and a fake peer on `127.0.0.1` (no real
internet needed), then runs the *actual* `download` binary against them
as a subprocess and diffs the result byte-for-byte against the source
data. It's the strongest proof available in an environment with no
reachable BitTorrent trackers/peers: the full pipeline — HTTP tracker
announce, handshake, bitfield, pipelined block requests, per-piece SHA-1
verification, multi-piece disk writes — runs for real, just against a
peer/tracker this repo also controls instead of the live internet.

## Roadmap

- [x] **Phase 1** — Bencode parser + exact-byte SHA-1 InfoHash (`src/bencode.rs`, `src/torrent.rs`)
- [x] **Phase 2** — Tracker communication (`src/tracker/`) — HTTP GET announce over raw `TcpStream`, UDP announce (BEP 15) over raw `UdpSocket`, compact peer decoding (BEP 23)
- [x] **Phase 3** — Wire protocol handshake + peer message state machine (`src/peer/`)
- [x] **Phase 4** — BEP 10 extension handshake + BEP 9 metadata exchange (`src/peer/extension.rs`, `src/metadata.rs`, `src/magnet.rs`)
- [x] **Phase 5** — Concurrent piece downloader / work queue (`src/downloader/`)
- [x] **Integration** — magnet metadata bootstrap (`src/magnet_fetch.rs`), multi-tracker announce dispatch (`src/tracker_discovery.rs`), end-to-end CLI (`src/bin/download.rs`)

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

## Phase 5

`src/downloader/piece_assembler.rs` — `PieceAssembler` tracks one piece's 16 KiB blocks: `next_requests(n)` hands out fresh `(index, begin, length)` tuples without repeats (pipelining), `record_block` accepts blocks out of order, `finish()` is the trust boundary — SHA-1-checks against the torrent's piece hash before returning bytes.

`src/downloader/queue.rs` — `WorkQueue`, a `Mutex<VecDeque<PieceWork>>` shared via `Arc` across worker threads. Tested with 8 real threads draining 200 pieces to confirm no piece is dropped or duplicated.

`src/downloader/file_writer.rs` — maps global torrent byte offsets to on-disk files (`FileSpan`), writes pieces that straddle a file boundary in multi-file torrents, creates nested directories on demand.

`src/downloader/worker.rs` — the real per-peer loop: handshake, send `Interested`, wait for unchoke, pipeline requests up to `pipeline_depth` (default 5, the long-standing mainline/libtorrent convention), assemble + verify + write each piece, requeue on hash mismatch or failure. **Tested end-to-end** against a mock peer on loopback (`127.0.0.1`, no outbound network needed) that performs a real handshake, bitfield, unchoke, and serves `Request`s with matching `Piece` responses — confirms the full pipeline including the on-disk bytes, not just the isolated units.

`src/downloader/mod.rs::build_work_queue` — the `TorrentFile` ↔ `PieceWork` adapter: works unmodified whether `TorrentFile` came from a `.torrent` file (Phase 1) or from a magnet-derived info dict (Phase 4's `MetadataAssembler::assemble_and_verify` output, once run through `parse_torrent_file`-equivalent construction). No separate magnet-specific downloader needed.

```sh
cargo test                              # 147 unit tests, incl. loopback integration tests
```

## Integration: making it a real client

`src/torrent.rs::from_info_dict_bytes` — the magnet ↔ `.torrent` adapter promised at the end of Phase 5. A magnet-derived info dict and a `.torrent` file's info dict build the identical `TorrentFile` through the same shared `build_torrent_from_info`, so `build_work_queue` and everything downstream never needs to know which one it's holding. Re-checks the SHA-1 against the expected InfoHash on its own, independent of whatever check the caller already did.

`src/magnet_fetch.rs` — the piece that was scaffolded in Phase 4 but not wired up: connects to a peer, does the BEP 3 + BEP 10 handshakes, requests every `ut_metadata` piece in sequence, and returns the verified info dict. **Tested end-to-end** against a mock peer that deliberately uses a *different* extension id than ours, to prove the BEP 10 id-remapping (you send peer X, they respond with your id) is actually implemented correctly and not just assumed.

`src/tracker_discovery.rs` — announces to every tracker URL a torrent lists (mixing `http://`, `https://`, and `udp://`), merges and dedupes the peer lists, and treats a single bad tracker as a warning, not a fatal error (only *all* trackers failing is fatal — that's the actual "no peers findable" case).

`src/tracker/https.rs` — most public trackers today (Ubuntu's included) only offer `https://` announce URLs, so `http`-only support wasn't actually "complete." TLS is provided by `rustls` (pure Rust, `ring` crypto backend, no OpenSSL/system-TLS dependency) — this is deliberately *not* hand-rolled like everything else, because implementing TLS yourself is a well-known way to introduce catastrophic security bugs, and "from scratch" doesn't mean "don't use a cryptography library reviewed by people who specialize in exactly that." Certificate validation is never overridable — rustls's API doesn't expose a way to disable it. Everything *around* the TLS session (the HTTP request line, response parsing, bencode decoding) is the same code `tracker::http` uses; only the transport differs.

`src/bin/download.rs` — the real CLI: `.torrent` file or magnet link in, verified file(s) on disk out. Bounds concurrent peer connections (`--peers`, default 30), never panics on bad input (bad file paths, malformed torrents, magnet links with no trackers, unrecognized flags all exit cleanly with a message), and requeues any piece a peer fails to deliver correctly for another peer to try.

`src/bin/e2e_harness.rs` — described above; the thing that actually proves all of this fits together.

### Known limitations

Stated plainly rather than glossed over:

- **No DHT or PEX.** Peer discovery is tracker-only. A magnet link with no `tr=` trackers has no way to find a single peer in this client.
- **No seeding/uploading.** This is a downloader. `PeerState::am_choking`/`am_interested` exist but nothing drives them the other direction.
- **Single upfront tracker announce.** Real clients re-announce periodically (per the tracker's returned `interval`) and report `completed`/`stopped` events. This client announces once and never again.
- **No resume support.** Every run starts from piece 0; there's no on-disk state tracking what was already verified from a prior run.
- **Peer failure handling is coarse.** A peer that fails a piece gets that piece taken away and is not retried further this run, but there's no reputation tracking across peers/pieces beyond that.

None of these were required by the original five-phase spec, so they weren't built, but a "complete" client built further from this base would need them.

## License

MIT
