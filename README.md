# bittorrent-rs

A BitTorrent client written in Rust from scratch — bencode parsing, the
peer wire protocol, tracker communication, magnet link support, and
piece assembly are all implemented directly, no `libtorrent`-style
crate. Only third-party dependencies: `sha1`, and `rustls` for HTTPS
tracker support (TLS itself is deliberately not hand-rolled).

**Verified against real swarms**, not just local tests:
- `.torrent` downloads come out byte-identical to the publisher's
  official checksum (tested against Debian's netinst ISO, SHA-512 match)
- Magnet links fetch and SHA-1-verify metadata from a live peer (BEP 9),
  then download normally against a real tracker/swarm

## What it does

- Parses `.torrent` files and magnet links (`magnet:?xt=urn:btih:...`)
- Announces to trackers over HTTP, HTTPS, and UDP — all queried
  concurrently with a bounded overall timeout, so one dead/slow tracker
  can't stall the others
- Downloads from multiple peers at once, verifying each piece's SHA-1
  hash before it's written to disk
- For magnet links: fetches the torrent's metadata from a peer first
  (BEP 9/10), then proceeds like a normal download
- Re-announces to trackers periodically so a dropped peer doesn't
  permanently strand a download

## What it doesn't do

- **No seeding** — download only, never uploads to other peers
- **No DHT or PEX** — peer discovery is tracker-only; a magnet link with
  no `tr=` params has no way to find any peer
- **No resume** — every run starts from piece 0

## Build

```sh
cargo build --release
```

Binary is at `target/release/download`.

## Usage

```sh
./target/release/download <file.torrent | magnet-link> [--out DIR] [--peers N] [--reannounce SECONDS]
```

Quote magnet links — shells will otherwise mangle the `&`:

```sh
./target/release/download "magnet:?xt=urn:btih:HASH&tr=http://tracker.example.com/announce"
```

| Flag | Default | Meaning |
|---|---|---|
| `--out DIR` | `~/Downloads` | Where to write downloaded file(s) |
| `--peers N` | `30` | Max concurrent peer connections |
| `--reannounce SECONDS` | tracker's requested interval | How often to re-query trackers. Real intervals are often 20-30+ min; override for faster testing |

Convenience shell function (a plain `alias` doesn't handle magnet-link
quoting well):

```sh
# add to ~/.zshrc or similar
btdl() { /path/to/bittorrent-rs/target/release/download "$@"; }
```

## Reading the output

```
torrent: debian-13.5.0-amd64-netinst.iso (700000000 bytes, 3020 pieces)
found 4 peer(s), connecting up to 30
piece 0 verified (1/3020)
...
download complete: debian-13.5.0-amd64-netinst.iso -> /Users/you/Downloads
```

Magnet links show an extra metadata-fetch phase first (trying peers
until one provides the torrent's metadata, verifying it, then the same
piece-by-piece flow above).

**Normal, not bugs:** tracker warnings, and a peer or two failing before
a working one is found — that's real swarm churn. **Actually stuck:**
zero peer progress for several minutes at "found 1 peer(s)" — that's
almost always a thin/unhealthy swarm on the tracker's end, not this
client. Compare against `aria2c`/`transmission-cli` on the same file to
confirm, or try a different torrent.

## Testing without a real torrent

```sh
cargo run --bin e2e_harness
```

Spins up a fake tracker + fake peer on `127.0.0.1`, runs the real
`download` binary against them, and diffs the result byte-for-byte —
confirms a working build with no internet or real torrent needed.

```sh
cargo test          # unit + integration tests, loopback only
```

## License

MIT
