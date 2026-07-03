# bittorrent-rs

From-scratch BitTorrent client in Rust. No `torrent`/`libtorrent`-style crates —
bencode parsing, wire protocol, tracker comms, and piece assembly are all
hand-rolled.

## Roadmap

- [x] **Phase 1** — Bencode parser + exact-byte SHA-1 InfoHash (`src/bencode.rs`, `src/torrent.rs`)
- [ ] **Phase 2** — Tracker communication (HTTP/UDP announce, compact peer list parsing)
- [ ] **Phase 3** — Wire protocol handshake + peer message state machine
- [ ] **Phase 4** — BEP 10 extension handshake + BEP 9 metadata exchange (magnet links)
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

## License

MIT
