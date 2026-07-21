# bittorrent-rs

A complete BitTorrent client built from scratch in Rust. Bencode, the peer wire protocol, tracker communication (HTTP/HTTPS/UDP), magnet links (BEP 9/10), the mainline DHT (BEP 5), peer exchange (BEP 11), web seeds (BEP 19), endgame mode, and seeding are all hand-rolled — no `libtorrent`-style crate. Protocol dependencies stay minimal: `sha1`, and `rustls` for HTTPS trackers (TLS itself deliberately not reimplemented). The `download` binary additionally uses `ratatui` for its live terminal dashboard.

<p align="center"><em>Live dashboard: progress gauge, throughput sparklines, peer/swarm stats, and a tailing activity log — with the full per-peer detail streamed to a logfile.</em></p>

## Verified behavior

| Scenario | Behavior |
|---|---|
| `.torrent` file download | Byte-identical to publisher's checksum (tested against Debian netinst, SHA-512 confirmed) |
| Magnet link download | Metadata fetched and SHA-1-verified from a live peer (BEP 9) before any piece download starts |
| Trackerless magnet (no `tr=`) | Peers found via the DHT alone; metadata then fetched over BEP 9 |
| Web seed present (BEP 19) | Pieces pulled over HTTP(S) in parallel with peers via ranged GETs; completes even with zero peers, and stops a mirror after repeated failures |
| Tracker unreachable | Skipped with a warning; download proceeds if any other tracker or the DHT responds |
| Tracker slow/unresponsive | Bounded to a 20s overall timeout — doesn't stall on one dead tracker |
| Peer unchokes slowly (>10s) | Tolerated with a bounded wait (~60s) instead of dropping the connection on the first read timeout |
| Peer sends non-canonical bencode | Accepted (lenient wire decode) instead of discarding an otherwise-usable peer |
| Peer disconnects mid-download | Piece requeued for another peer; every discovery source keeps refilling the dial queue |
| Peer has nothing we need | Connection released after a bounded wait instead of holding the slot forever |
| Corrupted/malicious piece data | Rejected via SHA-1 mismatch before it ever reaches disk |
| Final pieces crawl (endgame) | Remaining pieces are requested from *every* capable peer in parallel; first verified copy wins, stragglers get `Cancel` |
| Rerunning after an interrupted download | Already-downloaded pieces are re-verified against actual disk bytes and skipped — a resume file surviving corrupted/deleted data doesn't get blindly trusted |
| Inbound peers while downloading | Verified pieces are served back to the swarm the whole time (and after completion with `--seed`) |
| Fuzz harness build | `bencode`, magnet URI, and `.torrent` parsers all compile and run clean against seed inputs (`fuzz/`) |

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
./target/release/download <file.torrent | magnet-link> [options]
```

```zsh
./target/release/download debian-13.5.0-amd64-netinst.iso.torrent
./target/release/download "magnet:?xt=urn:btih:HASH" --seed
```

### options

| Flag | Default | Description |
|---|---|---|
| `--out DIR` | `~/Downloads` | Where to write downloaded file(s) |
| `--peers N` | `30` | Max **concurrent** peer connections; the dial queue draws replacements from every discovery source as connections die |
| `--port PORT` | `6881` | Preferred listen port (TCP for serving pieces, UDP for the DHT node); falls back to an ephemeral port if taken |
| `--seed` | off | Keep seeding after the download completes, until Ctrl-C |
| `--no-dht` | off | Disable the DHT node (tracker/PEX discovery only) |
| `--ipv6` / `--no-ipv6` | auto | Force IPv6 peers on/off. Auto-detects a local IPv6 route and skips v6 peers when there isn't one, so a v4-only host doesn't burn dial slots on unroutable addresses |
| `--only SUBSTR` | all files | Download only files whose path contains SUBSTR (case-insensitive; repeatable) |
| `--files 1,3,5` | all files | Download only these 1-based file indices (see `--list`) |
| `--list` | off | Print the torrent's file table (index, size, selection) and exit — resolves magnet metadata first if needed |
| `--reannounce SECONDS` | tracker's requested interval | Re-query interval for new peers; real trackers often request 20–30+ min — override for faster testing |
| `--timeout SECONDS` | none | Overall wall-clock budget for the whole run; stops and reports what's left instead of running indefinitely |
| `--config FILE` / `--no-config` | `~/.config/bittorrent-rs.toml` | Use a specific config file, or ignore config entirely |
| `--log FILE` | `<out>/bittorrent-rs.log` | Where to stream the full per-peer/DHT/PEX detail |
| `--no-log` | off | Disable the logfile entirely |
| `--tui` / `--no-tui` | auto | Force the dashboard on, or the plain status-line interface even on a TTY |
| `--dht` / `--no-dht` | on | Force the DHT node on/off |
| `--portmap` / `--no-portmap` | on | Auto-forward the listen port via UPnP/NAT-PMP (best-effort; silently skipped if the router doesn't support it) |
| `--webseed` / `--no-webseed` | on | Use the torrent's BEP 19 web seeds (HTTP) alongside peers |
| `--seed` / `--no-seed` | off | Force seeding after completion on/off |
| `--quiet` / `-q` | off | Suppress all status output (warnings/errors still print) |
| `--verbose` / `-v` | off | (reserved) |

Interrupted or killed mid-download? Just rerun the same command — already-verified pieces are detected and skipped, not re-downloaded.

### Interface

On an interactive terminal, `download` shows a live dashboard: a progress gauge, download/upload throughput sparklines, transfer stats (rate, ETA, pieces), a swarm panel (active/dialed/known peers, tracker health, DHT node count, PEX, endgame state), and a tailing activity log. Press `q` (or `Esc` / `Ctrl-C`) to stop. The high-volume detail — every peer connect/disconnect, each DHT/PEX discovery, per-piece verification — is streamed to the logfile rather than the screen, so `tail -f <out>/bittorrent-rs.log` gives the firehose while the dashboard stays readable.

When stdout isn't a TTY (piped, redirected, CI) the interface automatically degrades to a periodic one-line status print, so scripted use and logs stay clean.

### Config file

Defaults can be set in `~/.config/bittorrent-rs.toml` (or `$XDG_CONFIG_HOME/bittorrent-rs.toml`) so you don't retype flags. Every key is optional; a CLI flag always overrides its config value. A missing file is fine; a malformed one is a hard error.

```toml
out = "/data/torrents"
peers = 60
port = 51413
seed = true
dht = true
portmap = true
webseed = true
ipv6 = "auto"      # "auto" | "always" | "never"
reannounce = 900
tui = true
```

---

## How it works

1. Parses the `.torrent` file, or — for a magnet link — fetches the torrent's metadata from a peer over BEP 9/10, verifying it against the magnet's InfoHash before trusting it. A magnet with no trackers gets its first peers from the DHT.
2. Discovers peers from three sources feeding one dial queue, each address dialed at most once:
   - **Trackers** (BEP 3/15/23): every tracker in the torrent announced to concurrently — HTTP, HTTPS, UDP; IPv4 and IPv6 peers from HTTP(S) trackers — merging peer lists and skipping any that fail or time out, re-announcing on the tracker's interval (early once the dial queue runs dry).
   - **DHT** (BEP 5): a real mainline DHT node — bootstraps from well-known routers, runs iterative `get_peers` lookups, `announce_peer`s our listen port, and answers inbound `ping`/`find_node`/`get_peers`/`announce_peer` from other nodes.
   - **PEX** (BEP 11): peer addresses pushed by connected peers over the extension protocol.
   - **Web seeds** (BEP 19): if the torrent's `url-list` names HTTP(S) mirrors, one worker per mirror fetches pieces via ranged GETs into the same verify-write pipeline as peers — so a torrent with a healthy web seed finishes even with no peers at all.
3. Checks for a resume file from a previous run — any piece it claims is done gets re-read off disk and re-hashed before being trusted; anything that doesn't check out goes back on the download list.
4. Runs up to `--peers` concurrent connections, each pipelining block requests to keep the pipe full; dead connections are replaced from the dial queue immediately.
5. Picks pieces **rarest-first**, and switches to **endgame mode** for the tail: the last in-flight pieces are requested from every capable peer in parallel, the first verified copy wins, and stragglers get `Cancel` — no more "99% then crawls" hostage situation.
6. Every downloaded piece is SHA-1-hashed against the torrent's recorded hash before being written to disk and recorded to the resume file.
7. Serves verified pieces to inbound peers the entire time — during the download and, with `--seed`, indefinitely after it — reporting real `uploaded/downloaded/left` numbers to trackers.

---

## Design notes & honest simplifications

- **Threading model**: one OS thread per peer connection with blocking sockets — no async runtime. At `--peers 30` this is deliberate simplicity, not a scaling strategy.
- **Choking policy (upload)**: every interested inbound peer is unchoked, bounded by a global inbound-connection cap, with no tit-for-tat rate measurement. Tit-for-tat allocates *scarce* upload slots; a connection cap bounds the same resource with far less machinery.
- **DHT**: fixed 160-bucket routing table (no dynamic bucket splitting), evicts least-recently-seen without a ping-first grace round, single non-rotating announce-token secret per run, IPv4 only (no BEP 32). Only nodes that actually respond to us are inserted.
- **Bencode**: strict canonical parsing for anything hashed or re-serialized; lenient (unsorted/duplicate keys tolerated) for anything received over the wire — be strict in what you send, lenient in what you accept.
- **Boundary files under `--only`/`--files`** — a piece straddling a selected and an unselected file is downloaded in full (it carries the selected file's bytes), so an unselected *neighbour* file may end up partially written. Files entirely outside the selection are never created. This keeps piece hashing and resume simple, and matches mainline client behaviour.
- **No partial-piece resume across peers** — if a peer disconnects mid-piece, that piece's progress on this connection is lost (whole pieces already on disk from *previous runs* still resume fine).

---

## Testing without a real torrent

```zsh
cargo run --bin e2e_harness
```

Spins up a fake tracker and fake peer on `127.0.0.1`, runs the real `download` binary against them, and diffs the result byte-for-byte. Confirms a working build without internet access or a real torrent.

```zsh
cargo test
```

Unit and integration tests, loopback only. Highlights: workers exercised end-to-end against protocol-correct mock peers (including a slow-unchoker and a never-unchoker), the seeder served by a mock leecher, KRPC round-trips pinned against the exact byte strings printed in BEP 5, and DHT lookup/announce/token flows driven through a scripted in-memory transport.

CI (GitHub Actions) runs `cargo fmt --check`, `clippy -D warnings`, the test suite, the loopback harness, and builds+smoke-runs all three fuzz targets on nightly.

---

## Fuzz testing

```zsh
cd fuzz
cargo install cargo-fuzz   # one-time
rustup install nightly     # one-time -- fuzzing needs nightly's sanitizer coverage
cargo +nightly fuzz run bencode_decode
```

Three targets under `fuzz/fuzz_targets/`: the bencode decoder, magnet URI
parser, and full `.torrent` file parser — all three consume untrusted
input directly (peer/tracker data, user-supplied files/links), so a
panic on malformed input there is a real bug. See `fuzz/README.md`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Stuck with no piece progress | Thin/unhealthy swarm — leave it running: the DHT re-looks-up every 3 minutes and trackers get re-announced (early when the dial queue empties). Compare against `aria2c`/`transmission-cli` on the same torrent to separate client issues from swarm issues |
| `tracker ... failed: ...` warnings | Normal — public trackers go down constantly. Only fatal if *every* tracker fails **and** the DHT finds nothing |
| `DHT disabled (couldn't bind UDP socket)` | Another client owns the port — pass `--port` to pick a different one |
| Lots of `HostUnreachable`/`NetworkUnreachable` on v6 peers | Your host has no IPv6 route; auto-detect normally skips these, but `--no-ipv6` forces it. These are logged, not shown, and never fatal |
| A peer fails to provide metadata or a piece | Normal peer churn — client automatically tries the next peer |
| Rerun re-downloads pieces I thought were already done | The resume check re-verifies against actual disk bytes — if the file was moved, edited, or `--out` changed between runs, those pieces legitimately no longer check out |
| Port-forwarding / NAT | Inbound connections and DHT reachability improve with `--port` forwarded on your router; everything still works outbound-only, just less sociably |

---

## License

MIT

## Contributors

| Contributor | Role |
|-------------|------|
| [chakri192](https://github.com/chakri192) | Author |
| [aider](https://github.com/Aider-AI/aider) | AI pair programmer |
| [Claude](https://claude.ai) | DHT/PEX/seeding/endgame implementation pass |

### AI tooling

README and code contributions assisted by [aider](https://github.com/Aider-AI/aider) using local LLMs via [Ollama](https://ollama.com), and by Anthropic's Claude:

| Model | Used for |
|-------|----------|
| `qwen2.5-coder:7b` | Code suggestions, refactoring |
| `llama3.1:8b` | Prose, documentation, commit messages |
| Claude | BEP 5 (DHT), BEP 11 (PEX), seeding, endgame mode, peer-lifecycle fixes |
