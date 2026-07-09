# bittorrent-rs

A BitTorrent client written in Rust from scratch. No `libtorrent`-style
crate — bencode parsing, the peer wire protocol, tracker communication,
magnet link support, and piece assembly are all implemented directly.
The only third-party dependencies are `sha1` and `rustls` (for HTTPS
tracker support — TLS itself is deliberately not hand-rolled).

Verified against a real swarm: downloads from `.torrent` files come out
byte-identical to the publisher's official checksum (tested against
Debian's netinst ISO, SHA-512 match confirmed).

## What it does

- Parses `.torrent` files and magnet links (`magnet:?xt=urn:btih:...`)
- Announces to trackers over HTTP, HTTPS, and UDP to find peers
- Connects to peers directly, verifies each downloaded piece's SHA-1
  hash before writing it to disk, and downloads from multiple peers at
  once
- For magnet links: fetches the torrent's metadata from a peer first
  (there's no `.torrent` file to read it from), then proceeds exactly
  like a normal download
- Re-announces to trackers periodically so a dropped peer doesn't
  permanently strand a download

## What it doesn't do

- **No seeding.** This is a downloader only — it never uploads to other
  peers.
- **No DHT or PEX.** Peer discovery is tracker-only. A magnet link with
  no `tr=` tracker parameters has no way to find any peer.
- **No resume.** Every run starts from piece 0; there's no on-disk
  record of what a previous run already verified.

## Building

Requires a Rust toolchain (`rustup` recommended: `rustup.rs`).

```sh
cargo build --release
```

The binary is at `target/release/download`.

## Usage

```sh
download <file.torrent | magnet-link> [--out DIR] [--peers N] [--reannounce SECONDS]
```

**From a `.torrent` file:**

```sh
./target/release/download ubuntu-24.04.iso.torrent --out ./downloads
```

**From a magnet link** (quote it — shells will otherwise mangle the `&`):

```sh
./target/release/download "magnet:?xt=urn:btih:HASH&tr=http://tracker.example.com/announce" --out ./downloads
```

**Options:**

| Flag | Default | Meaning |
|---|---|---|
| `--out DIR` | `downloads` | Where to write the downloaded file(s) |
| `--peers N` | `30` | Max number of peer connections to use |
| `--reannounce SECONDS` | tracker's requested interval | How often to re-query trackers for new peers. Trackers often request long intervals (20-30+ minutes); override this for faster peer discovery while testing |

Progress prints as each piece is individually verified:

```
torrent: debian-13.5.0-amd64-netinst.iso (700000000 bytes, 3020 pieces)
found 4 peer(s), connecting up to 30
piece 0 verified (1/3020)
piece 1 verified (2/3020)
...
download complete: debian-13.5.0-amd64-netinst.iso -> ./downloads
```

If a run gets stuck at "found 1 peer(s)" with no progress, that's
almost always a thin/unhealthy swarm on the tracker's end, not this
client — try a different torrent, or compare against another client
(`transmission-cli`, `aria2c`) against the same `.torrent` file to
confirm.

### Testing without a real torrent

```sh
cargo run --bin e2e_harness
```

Spins up a fake tracker and a fake peer on `127.0.0.1` and runs the
real `download` binary against them, then diffs the result
byte-for-byte. Useful for confirming a working build without needing
internet access or a real torrent.

## Development

```sh
cargo test          # unit + integration tests (loopback only, no network needed)
cargo build --release
```

---
## AI Tooling
| Model | Used for |
|-------|----------|
| `qwen2.5-coder:7b` | Code suggestions, refactoring |
| `llama3.1:8b` | Prose, documentation, commit messages |
---

## License

MIT
