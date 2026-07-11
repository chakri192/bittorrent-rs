# Fuzz targets

Three targets covering every place this client parses untrusted
byte-level input:

- `bencode_decode` — the core bencode parser (`.torrent` files, tracker
  responses, BEP 9 metadata all flow through this)
- `magnet_parse` — magnet URI parsing (base32/hex InfoHash decode,
  percent-decoding)
- `torrent_parse` — end-to-end `.torrent` file parsing

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
```

Let each run for a while (minutes to hours depending on how thorough you
want to be) — `cargo-fuzz` prints a crash report and saves the failing
input to `fuzz/artifacts/<target>/` if it finds one. A crash here means
a real panic on attacker-controlled input, which is a legitimate bug in
a client that talks to arbitrary trackers, peers, and files.
