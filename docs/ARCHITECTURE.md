# Architecture

How the client is put together, and why. The README says what it does; this
says where things live and which rules hold everywhere. It is written for
someone about to change the code.

## The shape of it

```
                 bin/download.rs                         bin/create_torrent.rs
        flags, config file, signals, dashboard                  create.rs
                        │
                        ▼
   ┌──────────────── session/ ─────────────────────────────────────────┐
   │  metadata   magnet link → info dict (BEP 9), or the .torrent      │
   │  prepare    resume state, file selection, workers, first announce│
   │  run        the loop: results, peers, discovery, announces        │
   │  seed       stay up afterwards, until a limit or a signal         │
   └───┬───────────────┬───────────────────┬────────────────┬──────────┘
       │               │                   │                │
       ▼               ▼                   ▼                ▼
  downloader/       tracker/ +          dht/             seeder.rs
  one worker        tracker_discovery   Kademlia node    inbound peers
  thread per peer   HTTP·HTTPS·UDP      (BEP 5)          + Have broadcast
       │
       ▼
  peer/  handshake · wire messages · extensions (BEP 10) · PEX (BEP 11)
  bencode.rs · torrent.rs   the formats everything above reads
```

`bin/download.rs` used to hold the whole download in one long function. What
had no reason to live in a binary moved into `session/`, one piece at a time,
each with tests, which is why the binary is now argument parsing and the
choice of what to print.

## Threads

There is no async runtime. Each source of data has a thread and blocking
sockets, and threads talk over channels or share a few small structures
behind locks.

| Thread | Does | Ends when |
|---|---|---|
| main | reads the terminal, refreshes the dashboard | the run ends or the user quits |
| orchestration | `session::run`, then seeding | it returns |
| one per peer | `downloader::worker::run_worker` | queue empty, connection fails, or interrupted |
| one per web seed | `webseed::run_web_worker` | queue empty or told to stop |
| seeder accept + one per inbound peer | `seeder` | `SeederHandle::stop` |
| DHT | `dht::service` | `Services::shutdown` |

**Shared state**, all small: the `WorkQueue` (pieces still to fetch, and how
common each is), the `HaveMap` (pieces verified on disk, read by the seeder),
and the `RateLimiter`s. Disk needs no lock of its own: each verified piece is
written at its own offset in the files, and no two workers hold the same
piece except in endgame, where the copies are identical. Locks come from
`sync::lock`, which carries on if another thread panicked while holding it:
one crashed worker must not freeze the download.

**Stopping** is the part threads make hard. A worker blocked in `read` cannot
be woken from outside, so each registers its socket with an `Interrupt`
(`worker/mod.rs`); `Workers::shutdown` shuts every socket down and the reads
return at once. A second signal skips all of this and exits with status 130.

## One download, start to finish

1. **Resolve.** A `.torrent` is parsed (`torrent.rs`); a magnet link asks the
   trackers and the DHT for peers, and fetches the info dict from one of them
   (`session::metadata`), checking it against the link's hash.
2. **Prepare** (`session::prepare`). Work out which pieces are wanted
   (`selection`). Trust the resume file, or check the files on disk against
   the piece hashes (`downloader::resume`) when asked to or when there is data
   but no resume file. Build the `WorkQueue` of what is missing. Start the
   seeder, the DHT and the port mapping (`Services`). Make the first announce.
3. **Run** (`Session::run`), on a 250 ms tick: collect verified pieces from
   the workers, retire ended workers into the `PeerPool` (which decides on
   retries and bans), gather new addresses from PEX and the DHT, dial more
   peers, re-announce when due, publish a snapshot to the dashboard.
4. **In a worker** (`downloader::worker`): connect, handshake, exchange
   extended handshakes, express interest, wait to be unchoked. Then loop:
   take the rarest piece this peer has (`WorkQueue::take_for`), request its
   blocks with a pipeline sized to the peer's speed (`pipeline`), assemble
   them (`PieceAssembler`), **check the SHA-1**, write to disk, report.
5. **Finish.** Announce `completed`, seed if asked (until `--seed-ratio`,
   `--seed-time` or a signal), announce `stopped`, shut the services down.

Piece data reaches disk only after its hash has matched. Everything before
that is untrusted bytes in a buffer.

## Rules that hold everywhere

- **Untrusted input never panics.** `unwrap()` and `expect()` are linted
  against outside tests. Sizes read off the wire are bounded before they are
  used to allocate: bencode nesting, piece counts, `metadata_size`, a `have`
  index, HTTP response bodies, DHT stored hashes. The README's Security table
  lists each, and each has a test that failed before the fix.
- **Paths from a torrent are checked** (`torrent::is_safe_component`), so a
  hostile torrent cannot write outside the download directory. The e2e
  harness has a scenario that would notice a file landing anywhere else.
- **Time is injected** where logic depends on it (`Instant` parameters in
  `PeerPool`, `RateLimiter`, `Throughput`, `SeedLimits`), so tests need not
  sleep.
- **Network sits behind traits** where a real network cannot be used in
  tests: `dht::Transport`, `session::TrackerClient`, `ProgressSink`.

## Tests

Four layers, each catching what the one below cannot.

1. **Unit tests**, next to the code. A test is not trusted until it has been
   seen to fail: the change it covers is broken on purpose and the test must
   go red. That caught weak tests several times.
2. **Mutation fuzzing** in `cargo test` (`fuzz.rs`, `robustness.rs`): every
   parser that reads untrusted bytes is fed bit flips, truncations, extreme
   lengths and splices, and must neither panic nor accept something it cannot
   round-trip. `fuzz/` holds the same targets for open-ended `cargo-fuzz`.
3. **Loopback e2e** (`bin/e2e_harness.rs`): the real `download` and
   `create_torrent` binaries against a fake tracker and fake peers written
   independently of the client (`Fixture` builds torrents by hand rather than
   calling the library), so a bug in a shared assumption shows up as a
   disagreement. Scenarios cover resuming, dropped and corrupt peers, limits,
   signals, magnet links, hostile torrents and more; run one with
   `cargo run --bin e2e_harness <name>`.
4. **CI** runs clippy with warnings as errors, the tests, the harness, and a
   build on the minimum supported Rust version.

## Where the simplifications are

Deliberate, and the README's Limitations lists them: one thread per
connection (fine for tens of peers, not thousands); the seeder unchokes every
interested peer up to a connection cap rather than running tit-for-tat;
trackers are asked concurrently rather than by BEP 12 tier; a piece
interrupted part-way starts again; no encryption or uTP.
