<div align="center">

# bittorrent-rs

**A complete BitTorrent client implemented from the specifications in Rust.**

Every layer is written here — the bencode parser, the peer wire protocol, tracker communication, the mainline DHT, and piece selection. No `libtorrent`-style crate performs any part of the work.

<p>
  <img alt="Rust" src="https://img.shields.io/badge/Rust-stable-1c1c1e?style=flat-square&logo=rust&logoColor=DEA584" />
  <img alt="Size" src="https://img.shields.io/badge/~10k-lines-1c1c1e?style=flat-square" />
  <img alt="Tests" src="https://img.shields.io/badge/tests-1204%20passing-1c1c1e?style=flat-square" />
  <img alt="BEPs" src="https://img.shields.io/badge/BEP-3%20·%205%20·%206%20·%209%2F10%20·%2011%20·%2014%20·%2015%20·%2019%20·%2027%20·%2029%20·%2052-1c1c1e?style=flat-square" />
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
| 5 | DHT Protocol | Kademlia routing table, iterative `get_peers`, `announce_peer`, inbound query handling. Found and found by aria2's DHT on loopback |
| 32 | IPv6 extension for DHT | A second node on an IPv6 socket, with its own routing table, `nodes6` and 18-byte peer values; its peers arrive on the same channel, and the listener takes IPv6 too. On whenever IPv6 peers are (`--ipv6` / `--no-ipv6` / a route probe). Checked against aria2's IPv6 DHT in both directions on `::1`; the `want` parameter is not read (a node answers for the family the query came in on). Not tried across a real IPv6 network |
| 6 | Fast Extension | `have all` / `have none`, allowed-fast pieces (requested while choked, and granted to peers by BEP 6's own recipe), `reject request`; both sides. Checked against the BEP's published test vectors, and exercised against aria2 1.37 (which offers it) in both directions; other clients untested |
| 12 | Multitracker Metadata Extension | The `announce-list` as tiers: a tier's trackers are shuffled once and tried in order until one answers, which then goes to the front of its tier; a later tier is asked only if every tracker before it failed; `completed` and `stopped` go to the tracker that has been answering. `--tracker-mode concurrent` asks every tracker at once instead, for more peers sooner. A magnet link's trackers (which carry no tiers) are asked at once while its metadata is found |
| 9 / 10 | Metadata Exchange · Extension Protocol | Retrieving the info dictionary from peers for magnet links, and serving it to peers that ask |
| 11 | Peer Exchange | Peer discovery through connected peers |
| 21 | Extension for Partial Seeds | Says `upload_only` when it has every piece |
| — | Message Stream Encryption | RC4 obfuscation of the peer connection, with a Diffie-Hellman exchange and the info hash as the shared secret; both sides |
| 27 | Private Torrents | Honours the `private` flag: tracker-only peer discovery, no DHT or PEX |
| 14 | Local Service Discovery | Announces the torrent to the multicast group `239.192.152.143:6771` every five minutes and dials whoever announces the same one there; IPv4 only, and not for private torrents. Checked over loopback, against the BEP's message format, and between two sockets on the real group on one machine (which took several seconds to deliver the first datagram), and against aria2's local peer discovery in both directions over the real group (a client that starts later is answered at once, not five minutes later); **not between machines** or with any other client |
| 29 | uTP | A reliable stream over UDP with LEDBAT congestion control (a 100 ms queuing-delay target), selective acks and retransmission; dialed and accepted, sharing the DHT's UDP port. **Opt-in** (`--transport`), and, on loopback, **against Transmission 4.1.3's uTP (libutp) and libtorrent 2.1.1's, in both directions** (`scripts/interop-transmission.sh`, `scripts/interop-libtorrent.sh`); not yet across a real network |
| 47 | Padding Files and Extended File Attributes | A file whose `attr` holds `p` is a padding file: its bytes are in the pieces (as zeros, so the hashes cover them) and on no disk. Never written, never created, read back as zeros to answer a peer or check a piece, never asked of a web seed, and left out of `--list`, of the numbers `--files` counts and of what `--only` matches. This is how libtorrent and qBittorrent lay out a hybrid torrent, so without it those would litter the download with `.pad/N` files. Checked against **libtorrent 2.1.1** in both directions (`scripts/interop-libtorrent.sh`). The other attributes (`x`, `h`, `l`) are read and ignored; a symlink is downloaded as an ordinary file. `create_torrent` makes no padding |
| 52 | BitTorrent v2 | The file tree, SHA-256 merkle trees over 16 KiB blocks and the piece layers: a v2-only torrent is **downloaded, seeded, resumed and verified** with each piece checked against its layer (a file's last piece is short, and no piece spans two files), and a hybrid one is downloaded through its v1 hashes. **Hash requests** (`hash request`, `hashes`, `hash reject`) both ways: a torrent that does not carry its piece layers, as a magnet link's never does, gets them from a peer, every hash checked with its uncle hashes against the file's root, and a seed answers the requests of a peer that lacks them. **Magnet links with only a v2 hash** (`urn:btmh:`) work: the metadata is fetched (BEP 9) and checked against all 256 bits. Made by `create_torrent --v2`. The trees and SHA-256 are checked against Python's `hashlib`; the whole of it -- TCP, uTP, encryption, magnet links, hash requests, in both directions -- against **libtorrent 2.1.1** (`scripts/interop-libtorrent.sh`). A seed answers requests for the 16 KiB leaf hashes too, worked out from the data (for the pieces it has; checked against the whole tree for every range of every kind of file, though no client has asked for them here, since one does only to find which block of a failed piece was bad). **Web seeds** serve a v2 torrent (each piece is one ranged request of one file, checked by its merkle root). Nothing is left out of the BEP that this client needs |
| 53 | Select Specific Files to Download | A magnet link's `so=` (`0,2,4-6`: numbers and ranges, counted from 0) says which files it is for: the download fetches just the pieces those files touch, as `--files` would, and `--only` or `--files` on the command line overrides it. In the daemon it becomes the torrent's `files` option when the link is added, so it outlives the link (which becomes a `.torrent` once its metadata is in). The files are those `--list` shows, padding files not among them. A malformed `so`, or one naming more than 65,536 files, is ignored, so the whole torrent is fetched rather than some other part of it; an index past the last file is refused when the metadata arrives. Tested against this client only |
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

# Magnet links may also carry peers to try (x.pe), web seeds (ws), a
# v2 hash beside the v1 one (a hybrid torrent; the v1 hash is what is used), and
# the files they are for (so=0,2,4-6, BEP 53: counted from 0, as --list counts from 1)

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
| `--seed-ratio R` · `--seed-time T` | Stop seeding by itself once `R` times the torrent's size has been uploaded (`1`, `2.5`), or after `T` (`90`, `30m`, `12h`, `1d`, `1h30m`), whichever comes first. Either one turns `--seed` on. Also settable as `seed_ratio` and `seed_time` in the config file |
| `--save-torrent FILE` | Write the torrent to `FILE` as a `.torrent`: for a magnet link, what its metadata resolved to (with the link's trackers), so the metadata exchange is not needed next time. An existing file is replaced; it is written whole or not at all |
| `--json` | Write status as JSON lines on stdout instead of a dashboard, for scripts (see below). Not with `--quiet` |
| `--prefer SUBSTR` | Fetch the pieces of files whose path contains `SUBSTR` (case-insensitive, repeatable) before all others, rarest first within each group; still downloads everything else. A pattern that matches no file is an error. Unlike `--only`, which leaves the other files out |
| `--sequential` | Fetch pieces in order instead of rarest first, so a file can be played while it downloads. It gives up the swarm-health benefit of rarest-first, so leave it off for anything you are not previewing |
| `--verify` | Check the files already on disk against the torrent and exit, with no network: which files are whole, damaged or missing, and status 0 only if everything wanted is whole. Needs a `.torrent` file; `--only` limits it |
| `--transport MODE` | How peers are dialed: `tcp` (the default), `utp` (BEP 29 only) or `both` (TCP, and uTP for a peer TCP cannot reach). Anything but `tcp` opens a UDP socket on `--port`, shared with the DHT, and takes uTP connections as a seeder too. Written from the specification and checked against a separate Python endpoint and a simulated lossy network, and against Transmission 4.1.3's and libtorrent 2.1.1's own uTP, in both directions, on loopback; not yet across a real network, which is why it is not on by default. Also `transport` in the config file |
| `--tracker-mode MODE` | How the trackers are asked: `tiered` (the default: BEP 12's tiers, one tracker at a time, the next tier only if the whole tier failed) or `concurrent` (every tracker at once, the union of their peers). Also `tracker_mode` in the config file |
| `--encryption MODE` | Message stream encryption (MSE): `off`, `prefer` (encrypted where the peer will, plain otherwise) or `require`. Left unset, outgoing connections are plain and incoming ones may be either. Written from the specification, checked against reference values and an independent implementation, and against aria2 1.37 in both directions with encryption required of both; other clients untested, which is why it is not on by default. Also `encryption` in the config file |
| `--recheck` | Verify every piece against the files on disk instead of trusting the resume file. This also happens by itself when files exist but no resume file does, so a finished download can be re-verified and seeded, and files from elsewhere adopted |
| `--peer ADDRESS:PORT` | A peer to try before any tracker or the DHT has named one (repeatable; an address and port, not a name). For a magnet link it is added to the link's own `x.pe` peers |
| `--no-dht` · `--no-lsd` · `--no-portmap` · `--no-webseed` | Disable individual discovery mechanisms (`--no-lsd`: announcing on, and listening to, the local network, BEP 14; also `lsd = false` in the config file. It is on by default and tells everyone on the local network which torrent you are sharing, so turn it off on a network you do not trust; private torrents never use it) |
| `--max-down RATE` · `--max-up RATE` | Limit download / upload speed across all connections, e.g. `500K`, `1.5M` (binary units, bytes per second). Applies to peers and web seeds |
| `--retry-delay SECS` | First wait before redialing a peer that failed; later retries wait 3× and 9× as long. Defaults to 15 |
| `--quiet` · `--no-tui` | Suppress output · force the plain text interface |

Ctrl-C and `SIGTERM` stop the client cleanly whether or not there is a terminal: the listener and DHT stop, the router's port mapping is removed, the trackers are told the client is leaving (BEP 3 `stopped`), and the resume file is kept. Every connection is shut down at once, and waits on a silent web seed or a slow `--max-down` are cut short, so nothing that has gone quiet delays the stop, and a tracker that does not answer `stopped` is waited for at most three seconds. A second signal exits immediately (status 130).

### Machine-readable output

With `--json` stdout is nothing but JSON objects, one per line, each with an `"event"` field; the human log still goes to the log file and errors to stderr.

```sh
./target/release/download foo.torrent --json | while read -r line; do ... done
```

| Event | When | Fields |
|---|---|---|
| `torrent` | once, when the torrent is known | `name`, `info_hash`, `total_bytes`, `pieces` |
| `progress` | every second, and once more at the end | `status`, `percent`, `done_bytes`, `total_bytes`, `verified_pieces`, `total_pieces`, `down_bytes_per_sec`, `up_bytes_per_sec`, `uploaded_bytes`, `peers`, `peers_dialed`, `peers_known`, `trackers_ok`, `trackers_total`, `dht_nodes`, `web_seeds`, `eta_seconds` (`null` when unknown), `elapsed_seconds`, `endgame` |
| `file` | with `--list`, one per file | `index` (from 1, as `--files` counts), `path`, `bytes`, `selected` |
| `done` · `error` · `stopped` | last, exactly one | `summary` · `message` · none |

`status` is one of `connecting`, `waiting`, `downloading`, `endgame`, `complete` and `seeding`. An interrupted run ends with `stopped` and exits 0, as it does without `--json`; a failure ends with `error` and exits 1.

### Making a torrent

`create_torrent` is the other direction: it hashes a file or a directory and writes the `.torrent`.

```sh
./target/release/create_torrent ~/Videos/holiday --announce http://tracker.example/announce
./target/release/create_torrent ./album --announce "udp://a:1337,udp://b:6969" --announce http://c/announce \
    --web-seed https://mirror.example/album/ --piece-length 1M --private --comment "for the group"
```

| Flag | Description |
|---|---|
| `--out FILE` | Where to write. Defaults to `<name>.torrent`; an existing file is not replaced without `--force` |
| `--announce URLS` | One tier of trackers (BEP 12), comma-separated; give the flag again for another tier |
| `--web-seed URL` | A BEP 19 web seed; repeatable |
| `--piece-length SIZE` | A power of two from `1K` to `128M`. By default chosen to give about 1500 pieces, between 16 KiB and 16 MiB |
| `--v2` | Makes a BitTorrent v2 torrent (BEP 52): a file tree with a SHA-256 merkle root per file and the piece layers, no v1 piece hashes. The piece length must then be at least 16K. The client can list, `--verify`, download and seed such a torrent, provided it carries its piece layers (which `create_torrent` writes) |
| `--private` | Sets the BEP 27 flag: no DHT, no peer exchange. It is part of the info dictionary, so it changes the info hash |
| `--comment TEXT` · `--name NAME` | A comment; a name other than the file's or directory's |
| `--no-date` | Leave out the creation date, so the same input always gives the same file |

Files are listed in path order, so the result is reproducible. Symbolic links are skipped instead of followed, and file names that are not valid UTF-8 are refused.

### Many torrents at once: the daemon

`download` runs one torrent and exits. `daemon` keeps running and takes any number of them, on **one** port: one listener that tells the torrents apart by the info hash in each peer's handshake, one DHT node per address family, one uTP socket, one port mapping and one pair of rate limits, shared by all of them. Each torrent is the same session `download` runs (resume, verification, trackers, DHT, peer exchange, web seeds), on a thread of its own, and is seeded after it finishes until it is removed.

```sh
./target/release/daemon run --max-up 2M &                    # start it; it stays up
./target/release/daemon add debian.torrent --out ~/Downloads   # or a magnet link
./target/release/daemon add "magnet:?xt=urn:btih:HASH&tr=udp://tracker.example:1337"
./target/release/daemon list                                    # ID, state, progress, rates, name
./target/release/daemon status 3f2a                             # one torrent, with its latest log lines
./target/release/daemon pause 3f2a                              # set it aside (off the port and the DHT) until `resume`
./target/release/daemon resume 3f2a                             # start it again; also a finished or a failed one
./target/release/daemon remove 3f2a                             # stop it and forget it; its files stay
./target/release/daemon stop                                    # end the daemon (also SIGINT / SIGTERM)
```

An ID is a torrent's info hash or the start of it (four digits at least, if they are enough to tell). `--json` prints what the daemon answered, one JSON object to a line.

`add` takes what `download` does for one torrent: `--only SUBSTR` (repeatable) to fetch just the files whose path contains it, `--files 1,3` to fetch those by the numbers `--list` gives (a magnet link's `so=` is taken for it unless one of these is given, and is kept with the torrent across a restart), `--prefer SUBSTR`, `--sequential`, and `--max-up` / `--max-down` for that torrent's own rate, which holds as well as the daemon's (the torrent is a part of the daemon-wide limit, so several torrents together still stay under it). A pattern that matches none of a `.torrent`'s files is refused at once; for a magnet link it is found out when the metadata arrives, and the torrent fails saying so. Pausing, finishing (a `--seed-ratio` / `--seed-time` limit) and these options are remembered across a restart: a paused or finished torrent comes back paused or finished, not running.

| Flag (`daemon run`) | Description |
|---|---|
| `--state-dir DIR` | Where it remembers what it was given (a list of torrents, and its copy of each `.torrent`; a magnet link is kept as the file it resolved to). Defaults to `$BITTORRENT_RS_STATE_DIR`, else `$XDG_STATE_HOME/bittorrent-rs`, else `~/.local/state/bittorrent-rs`. Started again on the same directory, it starts the same torrents again |
| `--socket PATH` | The control socket. Defaults to `daemon.sock` in the state directory. Unix sockets have a short path limit (about 100 bytes) |
| `--port PORT` · `--peers N` | The one TCP and UDP port, and the peers each torrent dials at once |
| `--max-up RATE` · `--max-down RATE` | Limits over **all** torrents together |
| `--no-dht` · `--no-lsd` · `--no-portmap` · `--ipv6` · `--no-ipv6` · `--transport` · `--encryption` | As for `download`, for the whole daemon |
| `--seed-ratio R` · `--seed-time T` | Stop seeding each torrent at that point; the torrent is then listed as `finished`. With neither, a torrent is seeded until it is removed |

The control socket is made readable and writable by its owner alone; the commands travel over it as one flat JSON object to a line (`{"cmd":"add","source":"...","out":"/absolute/dir"}`, `list`, `status`, `remove`, `shutdown`), each answered with a line per torrent and a last line that says `"ok":true`, or `"ok":false` with an `"error"`. Nothing listens on the network for commands.

Removing a torrent never deletes what was downloaded. A torrent whose `.torrent` file has gone, or that cannot be read, is listed as `failed`, with the reason, and can be removed, or resumed once the file is back.

## Architecture

This section is the short version; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) covers the threads, the life of a download, the rules that hold everywhere and how the tests are layered.

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

One operating-system thread per peer connection and per web seed, drawing from a shared work queue. There is no async runtime; the implementation uses blocking sockets and channels. The DHT node and the seeder's listener each occupy a dedicated background thread; a seeding client also connects out, on threads of their own, to the peers it knows of (from trackers, the DHT and the local network), so a leecher that cannot be reached from outside is served too, and lets go of any that turns out to be a seed.

This is a deliberate simplification appropriate to the default connection limit of 30. It is not a design intended to scale to thousands of concurrent peers.

### Peer discovery

Four mechanisms feed a single deduplicated dial queue. IPv6 addresses are excluded when the host has no IPv6 route, rather than consuming connection slots on unreachable peers. UDP tracker transactions use cryptographically random identifiers, the anti-spoofing measure the connectionless protocol depends on.

### Piece selection

The scarcest piece in the swarm is requested first, so rare pieces do not become unavailable while common ones circulate. "Scarcest" is judged among the pieces the peer being asked actually has: a peer holding only common pieces is given those rather than left waiting on a rare one it could never supply. For the final pieces, requests go to every capable peer at once; the first verified copy is accepted and the rest cancelled, avoiding the extended tail near completion.

### Request pipelining

A request pays off one round trip after it is sent, so a queue of a fixed length caps a peer's throughput at `queue * 16 KiB / round-trip time`: five requests over a 100 ms link is 800 KB/s however fast the peer is. Each connection therefore sizes its queue from what the peer is delivering: enough requests to cover two seconds of data at the measured rate, never fewer than five, and never more than the peer said it will queue (`reqq` in its extended handshake, or 64 when it says nothing). Against a peer with a 20 ms round trip this fetches 4 MiB in about a quarter of the time a queue of two would need.

The queue does not end with a piece: once every block of the piece in hand has been asked for and there is room in it, the next piece is taken from the queue and asked for too, and the one after that, up to eight ahead, always the rarest one that peer has and never a duplicate of a piece being fetched. With 64 KiB pieces from a peer 30 ms away that is about four round trips for sixteen pieces where a piece at a time is sixteen. Pieces taken ahead go back to the queue, with the blocks that arrived, if the connection fails or the piece before them does not verify.

A peer that chokes the client mid-piece discards every request it has not answered yet, and does not send them after unchoking. The worker forgets them too, stops asking while choked, waits for the unchoke (as long as it waits for one when connecting, about a minute at the default timeout, sending keep-alives), and then asks again for just the blocks that had not arrived, keeping the ones that had.

### Verification

Pieces are assembled and verified against the torrent's SHA-1 hashes in memory before any data reaches the filesystem. Peer and web-seed workers share that path, so hashing, resume, and endgame behave identically regardless of transport.

An interrupted transfer re-hashes what is on disk and retains what remains valid; a stored progress file is never trusted without verification.

## Interface

A `ratatui` dashboard with a piece-map heatmap, throughput sparklines, and an activity log, backed by a full logfile. On a terminal at least 104 columns wide a peer table sits beside the log: each connected peer's address, what it is doing (`connecting`, `downloading`, `choked`, `idle`), its current rate and the bytes received from it, fastest first, with a count of any that do not fit. Piped output falls back to plain status lines automatically; `--no-tui` forces it.

## Testing

```sh
cargo test
cargo run --bin e2e_harness      # loopback scenarios: public, private, magnet, hostile torrent, resume, --only, dropped peer, retry, ban, --timeout, --seed
./scripts/soak-daemon.sh          # two daemons, many torrents, removals and additions for a while: threads, files, memory
./scripts/interop-lan.sh          # for two machines: local discovery between them, and a download over a real IPv6 address
./scripts/interop-libtorrent.sh   # against libtorrent, if its Python bindings are installed: v1 and v2, TCP/uTP/encryption, magnet links, hash requests, padding files
./scripts/interop-transmission.sh # against Transmission, if installed: TCP, uTP alone and required encryption, both directions
./scripts/interop-aria2.sh        # against a real client, aria2, if installed: plain and encrypted, both directions, magnet metadata, the DHT over IPv4 and IPv6, the daemon's two torrents on one port both ways (INTEROP_LSD=1 adds local discovery)
```

1204 tests (1202 unit, 1 integration, 1 doctest), all passing. They stay on loopback, with one exception: a test of local discovery uses the real multicast group if the machine has one, and says so if it has not.

Coverage spans parsing, the KRPC codec verified against BEP 5's published byte strings, DHT lookup and announce over a scripted transport, workers driven against mock peers, the seeder against a mock leecher, and web-seed range arithmetic. An end-to-end harness runs the real binary against a synthetic tracker and peer on `127.0.0.1` and compares output byte for byte. Its scenarios cover a public torrent, a hostile one whose paths would write outside the download directory (it must be refused with nothing written), a private one (no DHT, no PEX), a client killed mid-download that must resume and fetch only the pieces it lacks, `--only` on one file of three (only the pieces that file touches may be requested), local service discovery (a torrent with no tracker and no DHT finds its only peer from a datagram on the "local network", announces itself with the BEP's message, hash and port, and does not dial a neighbour that announced a different torrent), BitTorrent v2 (a directory made into a v2 torrent by `create_torrent --v2` has the info hash an independent builder in the harness computes, `--list` names its files, `--verify` passes intact ones and catches a wrong byte down to the piece, and a copy without its piece layers is refused for a download, saying why), BitTorrent v2 downloads (a v2-only torrent of five files, one empty, with two-block pieces and short last pieces, is downloaded byte for byte from a peer serving the v2 layout, and the seeding client serves every piece back and ignores a request longer than a short piece holds), uTP (a peer whose TCP port refuses is downloaded from with `--transport both` and `utp` and is out of reach for `tcp`, and the client as a seeder serves all the pieces to a leecher on its UDP port), the Fast Extension (a download from a peer that keeps the client choked until the one piece it allowed has been served, which only finishes if that piece is asked for while choked; and as a seeder, `have all`, the allowed pieces, one served with no unchoke and another refused rather than ignored), message stream encryption (a download over it, a fallback to plain, refusal under `require`, and an encrypted leecher served), a finished client serving its info dictionary to a peer that has only the info hash (byte for byte, and told it is a seed), a hybrid magnet link (a v2 hash beside the v1 one) with no tracker, only an `x.pe` peer hint, a tracker that redirects every announce (followed), a torrent's empty files (created though no piece contains them, and only the selected ones under `--only`), a disk that cannot be written to (the run ends at once and blames the disk, not the swarm), a peer that hangs up halfway through a piece while another supplies the rest (asked only for the block that had not arrived), and `--timeout` against a peer that goes silent (the client must stop, exit non-zero, report the download incomplete and keep its resume file), `--seed` (the client announces started and completed, stays up, and serves every piece back to a leecher on the port it announced), two peers that each have only part of the torrent (the client must combine them and ask each only for what it has), a leecher connected to the client's listener before the download began (it must be told of each piece as the client verifies it, once each), `--prefer` (the preferred file's pieces requested before the rest, a typo refused before any request), `--seed-ratio` (still seeding at half the ratio, gone once the whole torrent has been uploaded) and `--seed-time`, a magnet link (a peer found through the tracker serves the metadata, which the client verifies before downloading, and `--save-torrent` keeps a torrent with the same info hash), `--verify` (intact files pass; a wrong byte, a truncated and a missing file each fail and are named; no network), `--json` (nothing but JSON on stdout for a download, a failure, a `--list` and an interruption), the only peer dropping the first connection (the client must dial it again and finish), a peer that sends corrupt data beside an honest one (the download must be correct and the liar dialed exactly once), a finished download run again (verified in place, nothing fetched), one with a single damaged piece (exactly that piece fetched), `--max-down` / `--max-up` (a download and a leecher's pull must each take as long as the limit says, with every byte still correct), `create_torrent` on a directory (it must make the same info hash as an independent builder in the harness, refuse to overwrite, and produce a torrent the client downloads byte for byte), the daemon (two torrents told to it over its socket are downloaded together and seeded on one port that both announce and both are served on; one removed, told to its tracker, refused on the port with its files kept and the other carrying on; and after `stop` and a restart only the other is there, seeding again), and real SIGINT and SIGTERM sent to the running binary (a clean stop with status 0, the resume file kept and the tracker told what was left, within a few hundred milliseconds even while the only peer is silent; a tracker that ignores the `stopped` announce delays the exit by about three seconds and no more, and a second signal during that wait exits at once with status 130). Every parser that reads untrusted bytes also runs through a deterministic mutation fuzzer inside `cargo test` (a uTP connection is fed damaged packets and the passage of time too) (bit flips, every truncation, extreme lengths, splices), which must never panic and must round-trip whatever it accepts; ten `cargo-fuzz` targets (adding local-discovery announcements and uTP packets, the latter also fed to a connection) do the same open-ended on a nightly toolchain.

## Security

The client treats everything from the network, and every `.torrent` or magnet link, as hostile. What it defends against, each with a test that fails when the defence is removed:

| Attack | Defence |
|---|---|
| A torrent naming `../../.ssh/authorized_keys`, or an absolute path, to write outside the download directory | The name and every path component must be exactly one ordinary path component; the torrent is refused before any network use |
| Deeply nested bencode (`llll…`) overflowing the stack in a peer's handshake, a tracker reply or a DHT datagram | Nesting is limited to 100 levels |
| A peer advertising a huge `metadata_size` to make magnet resolution allocate without bound | Accepted only between 1 byte and 16 MiB |
| A `have` for piece 4294967295 (or an oversized bitfield) growing per-peer state to 4 GiB | Tracked only up to the torrent's real piece count |
| A tracker streaming an endless HTTP response, or sending a chunk size that overflows | Responses capped at 4 MiB; chunk arithmetic checked |
| A `.torrent` whose piece count, lengths or piece length do not add up | Cross-checked when parsed; piece length capped at 128 MiB |
| One announcing many info-hashes to grow the DHT node's memory | At most 1000 remembered |
| A panic in one thread poisoning shared state for all of them | Locks recover the data rather than propagate the panic |
| A peer sending pieces that fail verification, again and again | Banned for the session after the first bad piece (never redialed, even if announced again) |

`unwrap()` and `expect()` are linted against in non-test code, so a new way to panic on network input has to be argued for.

## Limitations

- **Encryption has met three other clients.** MSE is implemented from the specification, verified against Python's big-integer arithmetic, RC4's published vectors and a second implementation written for the purpose, and works with aria2 1.37, Transmission 4.1.3 and libtorrent 2.1.1 both ways with encryption required; it stays opt-in until it has been used on a real network.
- **One thread per peer with blocking I/O.** Appropriate at the default connection limit; not a scaling strategy.
- **Choking is the seeding half of tit-for-tat only.** The seeder serves four peers at a time: three chosen by how much they took in the last ten seconds and one optimistic slot that moves every thirty; the rest are choked. Inbound peers are never downloaded from, so there is no reciprocation to reward.
- **BitTorrent v2 has met one other implementation.** Hash requests, v2 magnet links and everything else in the table above work against libtorrent 2.1.1 on loopback, in both directions; not against another v2 client (there are few), nor across a real network. Answers for the 16 KiB leaf layer and v2 web seeds are checked against this project's own trees and mirror only. A peer that gives the piece layers wrongly is refused and another tried; a torrent none can supply them for is given up on after 90 seconds. Hybrid torrents work, through their v1 hashes.
- **uTP has met two other implementations, on one machine.** Its connection logic is tested against a simulated network with loss, reordering, duplication and a slow link, over loopback UDP, against a separately written Python endpoint, and against Transmission 4.1.3's libutp in both directions (3 MiB each way, Transmission's TCP switched off). and libtorrent 2.1.1's (v1 and v2 torrents, both directions). Nothing has tested it over a real, lossy network, so it stays opt-in; and inbound uTP needs the UDP port to equal the TCP port, which it does unless the preferred port was taken.
- **Local discovery is IPv4-only and has met one other client, on one machine.** It finds and is found by aria2 over the real multicast group, in both directions, though the first datagram between fresh sockets has taken several seconds; it has not been tried between machines. `cargo test --lib lsd -- --nocapture` says whether the group works on yours. A client that starts after another hears it only when that one next announces (every five minutes), unless it answers newcomers, as this one does.
- **The DHT keeps a fixed-bucket routing table**, one for each family (BEP 32), and does not answer for the family a query did not come in on, so a node that asks for both (`want`) gets one. It has been tried against aria2's DHT on loopback in both families, not across a real IPv6 network.
- **The daemon has only met loopback.** Two daemons exchange torrents on one port, the real binary does the same against fake peers and trackers in the harness, and aria2 downloads two torrents from its one port and is downloaded from by it, two at a time; it has been run against the live public swarm only briefly (2.5 minutes, two current Debian netinst torrents at once at a 1 MiB/s cap: about 87 MiB of one of them arrived and every piece checked out under `--verify`), and `scripts/soak-daemon.sh` has run two daemons against each other on loopback with 150 torrents each (about 300 threads, 160 open files and 18 MiB apiece, steady while torrents were removed and added for 90 seconds, every file intact). It is Unix-only (its control socket is a Unix socket). Every torrent's lookups share one DHT thread per family and take turns, each given a share of a ten-second budget (at least a fifth of it, so a lookup that keeps getting answers is cut off at two seconds when there are five torrents or more); a lookup that gets no answer ends after a moment either way.
- **Under `--only`, a piece spanning a selected and an unselected file is retrieved in full**, which may leave an adjacent file partially written. This matches standard client behaviour.
- **Magnet links to private torrents use the DHT briefly.** The `private` flag lives in the info dict, which a magnet link does not carry, so the DHT runs while the metadata is fetched and is shut down as soon as the flag is seen. A `.torrent` file never touches the DHT.
- **Partial pieces are kept across a clean stop, not a crash.** When a peer fails part-way through a piece, the blocks it delivered are kept in memory (up to 64 MiB) and the next peer asked only for the rest; and when a run ends (Ctrl-C, `SIGTERM`, `--timeout`, a dead swarm) with pieces unfinished, those blocks are written to a `.<info hash>.partial` file beside the resume file and given back to the queue by the next run, which then asks only for what is missing. A run that is killed outright (`SIGKILL`, power loss) keeps only its complete verified pieces, as before. Nothing in the file is trusted: a piece resumed from it is checked against its hash like any other, and one that fails is fetched again from scratch.

## Network configuration

Port mapping is attempted on a best-effort basis through UPnP and NAT-PMP. The NAT-PMP implementation is written here, as no suitable crate provided it. Mapping failure is not fatal; the client continues with outbound connections only.

## Project structure

```
src/
├── bencode.rs        BEP 3 decoder with lenient wire mode, and encoder
├── create.rs         Making a .torrent from files on disk
├── json.rs           JSON lines for --json, and a strict reader to check them
├── torrent.rs        .torrent parsing, exact-byte infohash computation
├── magnet*.rs        Magnet URIs and BEP 9/10 metadata retrieval
├── tracker/          HTTP, HTTPS (rustls), and UDP announce
├── dht/              Mainline DHT — KRPC codec, routing table, responder, lookups, service
├── peer/             Handshake, wire messages, PEX, extension protocol
├── downloader/       Work queue, piece assembler, file writer, resume
├── seeder.rs         The listener serving verified pieces, and the connections a seed makes out to leechers
├── lsd.rs            BEP 14 local service discovery
├── v2.rs · sha256.rs BEP 52: merkle trees, the file tree, piece layers; and the SHA-256 they use
├── utp/              BEP 29 uTP: packet codec, the connection state machine (LEDBAT), and the UDP socket
├── webseed.rs        BEP 19 HTTP workers
├── portmap.rs        UPnP and NAT-PMP port mapping
├── selection.rs      File selection logic
├── session/          Setup and the download loop: magnet resolution, prepare, workers, announcer; and `network`, the ports and limits torrents share
├── daemon/           The multi-torrent daemon: a job per torrent, the manager, the state directory, the control socket
├── config.rs         Optional TOML configuration
├── tui.rs · ui.rs    Terminal dashboard
└── bin/              download (the client), daemon, create_torrent, and two helpers

fuzz/                 Bencode, magnet, and torrent parser fuzz targets
```

## License

MIT

## Contributors

| | |
|---|---|
| [chakri192](https://github.com/chakri192) | Author |
| [aider](https://github.com/Aider-AI/aider) | AI pair programmer |
