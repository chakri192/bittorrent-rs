# Fuzz targets

Eight targets covering every place this client parses untrusted
byte-level input. (The same parsers also run through a deterministic
mutation fuzzer inside `cargo test`, which needs no nightly toolchain;
these are for open-ended runs.)

- `bencode_decode` — the core bencode parser (`.torrent` files, tracker
  responses, BEP 9 metadata all flow through this)
- `magnet_parse` — magnet URI parsing (base32/hex InfoHash decode,
  percent-decoding)
- `torrent_parse` — end-to-end `.torrent` file parsing
- `krpc_decode` — DHT messages and compact node lists (any UDP sender)
- `peer_message` — framed peer wire messages (any connected peer)
- `extension_handshake` — BEP 10 extended handshakes
- `metadata_message` — BEP 9 `ut_metadata` messages
- `pex_parse` — BEP 11 peer exchange and compact peer lists

## Running

Requires nightly Rust and `cargo-fuzz` (neither is set up by default —
this scaffolding was written and structurally reviewed but **not run**,
since the environment it was built in only had a stable, older
toolchain with no `cargo-fuzz` available):

```sh
cargo install cargo-fuzz
rustup install nightly
cargo +nightly fuzz run bencode_decode
cargo +nightly fuzz run magnet_parse
cargo +nightly fuzz run torrent_parse
cargo +nightly fuzz run krpc_decode
cargo +nightly fuzz run peer_message
cargo +nightly fuzz run extension_handshake
cargo +nightly fuzz run metadata_message
cargo +nightly fuzz run pex_parse
```

Let each run for a while (minutes to hours depending on how thorough you
want to be) — `cargo-fuzz` prints a crash report and saves the failing
input to `fuzz/artifacts/<target>/` if it finds one. A crash here means
a real panic on attacker-controlled input, which is a legitimate bug in
a client that talks to arbitrary trackers, peers, and files.
