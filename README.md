# bittorrent-rs

A BitTorrent client built from scratch in Rust. Bencode, the peer wire protocol, tracker communication, magnet links, and piece assembly are all hand-rolled — no `libtorrent`-style crate. Only third-party deps: `sha1`, and `rustls` for HTTPS trackers (TLS itself deliberately not reimplemented).

## Verified behavior

| Scenario | Behavior |
|---|---|
| `.torrent` file download | Byte-identical to publisher's checksum (tested against Debian netinst, SHA-512 confirmed) |
| Magnet link download | Metadata fetched and SHA-1-verified from a live peer (BEP 9) before any piece download starts |
| Tracker unreachable | Skipped with a warning; download proceeds if any other tracker responds |
| Tracker slow/unresponsive | Bounded to a 20s overall timeout — doesn't stall on one dead tracker |
| Peer disconnects mid-download | Piece requeued for another peer; tracker re-announced periodically to find replacements |
| Corrupted/malicious piece data | Rejected via SHA-1 mismatch before it ever reaches disk |

---

## Requirements

- Rust toolchain (`rustup` recommended: `rustup.rs`)

---

## Installation

### 1. Build

```zsh
git clone https://github.com/chakri192/bittorrent-rs.git
cd bittorrent-rs
cargo build --release
```

Binary is at `target/release/download`.

### 2. Optional: shell function

Magnet links need quoting, so a plain `alias` doesn't work well — use a function instead. Add to `~/.zshrc`:

```zsh
btdl() { /path/to/bittorrent-rs/target/release/download "$@"; }
```

---

## Usage

```zsh
./target/release/download <file.torrent | magnet-link> [--out DIR] [--peers N] [--reannounce SECONDS]
```

```zsh
./target/release/download debian-13.5.0-amd64-netinst.iso.torrent
./target/release/download "magnet:?xt=urn:btih:HASH&tr=http://tracker.example.com/announce"
```

### options

| Flag | Default | Description |
|---|---|---|
| `--out DIR` | `~/Downloads` | Where to write downloaded file(s) |
| `--peers N` | `30` | Max concurrent peer connections |
| `--reannounce SECONDS` | tracker's requested interval | Re-query interval for new peers; real trackers often request 20–30+ min — override for faster testing |

---

## How it works

1. Parses the `.torrent` file, or — for a magnet link — connects to a peer and requests the torrent's metadata over BEP 9/10, verifying it against the magnet's InfoHash before trusting it
2. Announces to every tracker in the torrent concurrently (HTTP, HTTPS, UDP), merging peer lists and skipping any that fail or time out
3. Connects to each peer directly, performs the BitTorrent handshake, and pipelines block requests to keep the connection saturated
4. Every downloaded piece is SHA-1-hashed and checked against the torrent's recorded hash before being written to disk
5. Re-announces to trackers periodically so a dropped peer doesn't permanently strand the download

---

## Testing without a real torrent

```zsh
cargo run --bin e2e_harness
```

Spins up a fake tracker and fake peer on `127.0.0.1`, runs the real `download` binary against them, and diffs the result byte-for-byte. Confirms a working build without internet access or a real torrent.

```zsh
cargo test
```

Unit and integration tests, loopback only.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Stuck at "found 1 peer(s)" with no piece progress | Thin/unhealthy swarm on the tracker's end, not this client — try another torrent or compare against `aria2c`/`transmission-cli` on the same file |
| `tracker ... failed: ...` warnings | Normal — public trackers go down constantly. Only fatal if *every* tracker fails |
| A peer fails to provide metadata or a piece | Normal peer churn — client automatically tries the next peer |
| Magnet link resolves no peers at all | Magnet link has no `tr=` tracker params and this client has no DHT/PEX support |

---

## What it doesn't do

- **No seeding** — download only, never uploads to other peers
- **No DHT or PEX** — peer discovery is tracker-only
- **No resume** — every run starts from piece 0

---

## License

MIT

## Contributors

| Contributor | Role |
|---|---|
| [chakri192](https://github.com/chakri192) | Author |
| Claude (Anthropic) | AI pair programmer |
