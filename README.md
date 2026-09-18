<div align="center">

# bittorrent-rs

**A complete BitTorrent client implemented from the specifications in Rust.**

Every layer is written here — the bencode parser, the peer wire protocol, tracker communication, the mainline DHT, and piece selection. No `libtorrent`-style crate performs any part of the work.

<p>
  <img alt="Rust" src="https://img.shields.io/badge/Rust-stable-1c1c1e?style=flat-square&logo=rust&logoColor=DEA584" />
  <img alt="Size" src="https://img.shields.io/badge/~10k-lines-1c1c1e?style=flat-square" />
  <img alt="Tests" src="https://img.shields.io/badge/tests-291%20passing-1c1c1e?style=flat-square" />
  <img alt="BEPs" src="https://img.shields.io/badge/BEP-3%20·%205%20·%209%2F10%20·%2011%20·%2015%20·%2019%20·%2027-1c1c1e?style=flat-square" />
  <img alt="Fuzzed" src="https://img.shields.io/badge/parsers-fuzzed-1c1c1e?style=flat-square" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-1c1c1e?style=flat-square" />
</p>

<br />

<img src="docs/dashboard.svg" alt="The live dashboard: piece-map heatmap, throughput sparklines, and a colour-coded activity log" width="840">

</div>

---

## Overview

bittorrent-rs downloads and seeds torrents using the standard BitTorrent protocol suite. It accepts both `.torrent` files and magnet links, discovers peers through four independent mechanisms, verifies every piece against the torrent's SHA-1 hashes before writing, and serves completed pieces back to the swarm.

It has been validated against real public torrents, including a 21 GB distribution image verified byte for byte on completion.

## Specifications implemented

| BEP | Title | Scope |
|---|---|---|
| 3 | The BitTorrent Protocol | Bencode, `.torrent` parsing, peer wire protocol, HTTP trackers |
| 5 | DHT Protocol | Kademlia routing table, iterative `get_peers`, `announce_peer`, inbound query handling |
| 9 / 10 | Metadata Exchange · Extension Protocol | Retrieving the info dictionary from peers for magnet links |
| 11 | Peer Exchange | Peer discovery through connected peers |
| 27 | Private Torrents | Honours the `private` flag: tracker-only peer discovery, no DHT or PEX |
| 15 | UDP Tracker Protocol | Connectionless tracker announces |
| 19 | WebSeed — HTTP/FTP Seeding | Ranged HTTP retrieval from web servers |

## Requirements

Rust 1.88 or newer (the floor set by the locked dependency graph, and checked in CI). No system libraries beyond those the listed crates require.

## Installation

```sh
git clone https://github.com/chakri192/bittorrent-rs.git
cd bittorrent-rs
cargo build --release
```

The resulting binary is `target/release/download`.

## Usage

```sh
# A .torrent file
./target/release/download debian-12.8.0-amd64-DVD-1.iso.torrent

# A magnet link
./target/release/download "magnet:?xt=urn:btih:HASH&tr=udp://tracker.example:1337"

# Inspect contents, retrieve a subset, and continue seeding
./target/release/download foo.torrent --list
./target/release/download foo.torrent --only .mkv
./target/release/download foo.torrent --seed
```

A well-seeded, legally distributed torrent such as a current Debian image is the appropriate test case. It exercises all four discovery mechanisms and distinguishes a client defect from a sparsely populated swarm.

### Options

Defaults may be placed in `~/.config/bittorrent-rs.toml`. Every key is optional, and a command-line flag always takes precedence.

| Flag | Description |
|---|---|
| `--out DIR` | Output directory. Defaults to `~/Downloads` |
| `--peers N` | Maximum concurrent peer connections. Defaults to 30 |
| `--port PORT` | TCP listen and UDP DHT port. Defaults to 6881 |
| `--only SUB` · `--files 1,3` · `--list` | File selection within a multi-file torrent |
| `--seed` | Continue seeding after completion until interrupted |
| `--no-dht` · `--no-portmap` · `--no-webseed` | Disable individual discovery mechanisms |
| `--quiet` · `--no-tui` | Suppress output · force the plain text interface |

## Architecture

```
  .torrent ─┐
  magnet ───┴─ metadata (BEP 9/10) ─▶ TorrentFile
                                          │
   trackers ─┐                            ▼
   DHT       ├─▶ dial queue ─────▶    WorkQueue    ─▶ peer workers
   PEX       │                     (rarest-first,     web-seed workers (HTTP)
   webseeds ─┘                      endgame)                 │
                                                             ▼
                                          assemble ─▶ verify SHA-1 ─▶ write to disk
                                                             │
                                    seeder ◀─────────────────┘
```

### Concurrency model

One operating-system thread per peer connection and per web seed, drawing from a shared work queue. There is no async runtime; the implementation uses blocking sockets and channels. The DHT node and the inbound seeder each occupy a dedicated background thread.

This is a deliberate simplification appropriate to the default connection limit of 30. It is not a design intended to scale to thousands of concurrent peers.

### Peer discovery

Four mechanisms feed a single deduplicated dial queue. IPv6 addresses are excluded when the host has no IPv6 route, rather than consuming connection slots on unreachable peers. UDP tracker transactions use cryptographically random identifiers, the anti-spoofing measure the connectionless protocol depends on.

### Piece selection

The scarcest piece in the swarm is requested first, so rare pieces do not become unavailable while common ones circulate. For the final pieces, requests go to every capable peer at once; the first verified copy is accepted and the rest cancelled, avoiding the extended tail near completion.

### Verification

Pieces are assembled and verified against the torrent's SHA-1 hashes in memory before any data reaches the filesystem. Peer and web-seed workers share that path, so hashing, resume, and endgame behave identically regardless of transport.

An interrupted transfer re-hashes what is on disk and retains what remains valid; a stored progress file is never trusted without verification.

## Interface

A `ratatui` dashboard with a piece-map heatmap, throughput sparklines, and an activity log, backed by a full logfile. Piped output falls back to plain status lines automatically; `--no-tui` forces it.

## Testing

```sh
cargo test
cargo run --bin e2e_harness      # loopback scenarios: public, private, resume, --only, dropped peer, --timeout
```

291 tests, all passing, all confined to loopback.

Coverage spans parsing, the KRPC codec verified against BEP 5's published byte strings, DHT lookup and announce over a scripted transport, workers driven against mock peers, the seeder against a mock leecher, and web-seed range arithmetic. An end-to-end harness runs the real binary against a synthetic tracker and peer on `127.0.0.1` and compares output byte for byte. Its scenarios cover a public torrent, a private one (no DHT, no PEX), a client killed mid-download that must resume and fetch only the pieces it lacks, `--only` on one file of three (only the pieces that file touches may be requested), a peer that hangs up halfway through a piece while another supplies the rest, and `--timeout` against a peer that goes silent (the client must stop, exit non-zero, report the download incomplete and keep its resume file). Three `cargo-fuzz` targets exercise the parsers handling untrusted input.

## Limitations

- **One thread per peer with blocking I/O.** Appropriate at the default connection limit; not a scaling strategy.
- **Seeding unchokes every interested peer** up to the connection cap. There is no tit-for-tat rate measurement.
- **The DHT is IPv4-only** (BEP 32 is not implemented), and uses a fixed-bucket routing table.
- **Under `--only`, a piece spanning a selected and an unselected file is retrieved in full**, which may leave an adjacent file partially written. This matches standard client behaviour.
- **Magnet links to private torrents use the DHT briefly.** The `private` flag lives in the info dict, which a magnet link does not carry, so the DHT runs while the metadata is fetched and is shut down as soon as the flag is seen. A `.torrent` file never touches the DHT.
- **No partial-piece resume across peers.** A peer disconnecting mid-piece forfeits that connection's progress on it. Complete verified pieces from earlier sessions resume normally.

## Network configuration

Port mapping is attempted on a best-effort basis through UPnP and NAT-PMP. The NAT-PMP implementation is written here, as no suitable crate provided it. Mapping failure is not fatal; the client continues with outbound connections only.

## Project structure

```
src/
├── bencode.rs        BEP 3 decoder with lenient wire mode, and encoder
├── torrent.rs        .torrent parsing, exact-byte infohash computation
├── magnet*.rs        Magnet URIs and BEP 9/10 metadata retrieval
├── tracker/          HTTP, HTTPS (rustls), and UDP announce
├── dht/              Mainline DHT — KRPC codec, routing table, lookups
├── peer/             Handshake, wire messages, PEX, extension protocol
├── downloader/       Work queue, piece assembler, file writer, resume
├── seeder.rs         Inbound listener serving verified pieces
├── webseed.rs        BEP 19 HTTP workers
├── portmap.rs        UPnP and NAT-PMP port mapping
├── selection.rs      File selection logic
├── session/          Peer pool, download plan, rate sampler, background services
├── config.rs         Optional TOML configuration
├── tui.rs · ui.rs    Terminal dashboard
└── bin/download.rs   Command-line entry point

fuzz/                 Bencode, magnet, and torrent parser fuzz targets
```

## License

MIT

## Contributors

| | |
|---|---|
| [chakri192](https://github.com/chakri192) | Author |
| [aider](https://github.com/Aider-AI/aider) | AI pair programmer |
