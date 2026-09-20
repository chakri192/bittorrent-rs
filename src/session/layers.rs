//! Getting a BitTorrent v2 torrent's piece layers from peers (BEP 52 hash requests).
//!
//! A `.torrent` file carries them, but the info dictionary a magnet link fetches does not: it has only each file's
//! `pieces root`. The layers are the hashes that pieces are checked against, so a v2 torrent cannot be downloaded
//! without them, and peers are the only place they can come from. Every hash a peer sends is checked, with the
//! uncle hashes that come with it, against the file's root -- which the info dictionary does have, and which the
//! info hash vouches for -- so nothing a peer sends is taken on trust.

use crate::peer::connection::connect_and_handshake_with;
use crate::peer::message::{HashRequest, Message};
use crate::peer::{Encryption, Transport};
use crate::dht::DhtService;
use crate::torrent::TorrentFile;
use crate::tracker_discovery::{announce_to_all, build_request, TransferTotals};
use crate::v2::{file_height, piece_layer, verify_range, Hash, MAX_HASHES_PER_REQUEST};
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// The most pieces a file may have for its layer to be fetched: 4M of them is 128 MiB of hashes.
const MAX_PIECES_PER_FILE: u64 = 1 << 22;

/// How the peers are talked to.
#[derive(Clone)]
pub struct LayerConfig {
    pub our_peer_id: [u8; 20],
    pub timeout: Duration,
    pub encryption: Encryption,
    pub transport: Transport,
}

/// Asks one peer for the piece layers of `missing` (the `pieces root` and length of each file), a request at a time.
/// What it gave that checks out is returned even if it then failed to give the rest: the `Err` says why it stopped.
pub fn fetch_from_peer(addr: SocketAddr, torrent: &TorrentFile, missing: &[(Hash, u64)], config: &LayerConfig, stop: &AtomicBool) -> (BTreeMap<Hash, Vec<Hash>>, Option<String>) {
    let mut got = BTreeMap::new();
    let connected = connect_and_handshake_with(addr, torrent.info_hash, config.our_peer_id, false, false, config.timeout, config.encryption, &config.transport);
    let mut stream = match connected {
        Ok((stream, _)) => stream,
        Err(e) => return (got, Some(format!("connecting: {}", e))),
    };
    let piece_length = torrent.piece_length as u64;
    let at_layer = piece_layer(piece_length);
    for &(root, length) in missing {
        let (pieces, height) = (length.div_ceil(piece_length), file_height(length, piece_length));
        if pieces > MAX_PIECES_PER_FILE {
            return (got, Some(format!("a file of {} pieces is too large to fetch the layer of", pieces)));
        }
        let padded = 1u32 << (height - at_layer);
        let per_request = padded.min(MAX_HASHES_PER_REQUEST);
        // Enough layers of proof to reach the root, of which the hashes themselves account for some.
        let proof_layers = height - at_layer - 1;
        let mut layer = Vec::with_capacity(pieces as usize);
        for index in (0..padded).step_by(per_request as usize) {
            if stop.load(Ordering::SeqCst) {
                return (got, Some("stopped".to_string()));
            }
            let request = HashRequest { root, base_layer: at_layer, index, length: per_request, proof_layers };
            if let Err(e) = Message::HashRequest(request).write_to(&mut stream) {
                return (got, Some(format!("sending a hash request: {}", e)));
            }
            let hashes = loop {
                match Message::read_from(&mut stream) {
                    Ok(Message::Hashes { request: answered, hashes }) if answered == request => break hashes,
                    Ok(Message::HashReject(rejected)) if rejected == request => return (got, Some("the peer would not send hashes".to_string())),
                    Ok(_) => continue, // what a peer says as it connects: bitfield, unchoke, extension handshake
                    Err(e) => return (got, Some(format!("waiting for hashes: {}", e))),
                }
            };
            if hashes.len() < per_request as usize || !verify_range(&root, at_layer, height, index, &hashes[..per_request as usize], &hashes[per_request as usize..], proof_layers) {
                return (got, Some("the hashes the peer sent do not lead to the file's root".to_string()));
            }
            layer.extend_from_slice(&hashes[..per_request as usize]);
        }
        layer.truncate(pieces as usize);
        got.insert(root, layer);
    }
    (got, None)
}

/// Fetches the layers `torrent` lacks from whichever peers `peers` names (asked again as it goes, so that peers found
/// while this waits are used), trying each once, until it has them all, `stop` is set or `budget` is spent.
pub fn fetch_layers(torrent: &TorrentFile, mut peers: impl FnMut() -> Vec<SocketAddr>, config: &LayerConfig, budget: Duration, stop: &AtomicBool, log: &dyn Fn(String)) -> Result<BTreeMap<Hash, Vec<Hash>>, String> {
    let mut missing = torrent.missing_layers();
    let mut got = BTreeMap::new();
    let mut tried = HashSet::new();
    let deadline = Instant::now() + budget;
    while !missing.is_empty() {
        for addr in peers() {
            if !tried.insert(addr) || stop.load(Ordering::SeqCst) {
                continue;
            }
            let (layers, failure) = fetch_from_peer(addr, torrent, &missing, config, stop);
            if !layers.is_empty() {
                log(format!("piece layers of {} file(s) from {}", layers.len(), addr));
            }
            if let Some(why) = failure {
                log(format!("{}: {}", addr, why));
            }
            got.extend(layers);
            missing.retain(|(root, _)| !got.contains_key(root));
            if missing.is_empty() {
                break;
            }
        }
        if missing.is_empty() {
            break;
        }
        if stop.load(Ordering::SeqCst) {
            return Err("stopped".to_string());
        }
        if Instant::now() >= deadline {
            return Err(format!("no peer sent the piece layers of {} file(s) within {}s: without them the pieces cannot be checked, so this torrent cannot be downloaded", missing.len(), budget.as_secs()));
        }
        thread::sleep(Duration::from_millis(250));
    }
    Ok(got)
}

/// Where to find the peers to ask.
pub struct Discovery<'a> {
    /// Peers already known: from a magnet link, or named on the command line.
    pub bootstrap: Vec<SocketAddr>,
    pub dht: Option<&'a DhtService>,
    /// The trackers, in tiers (they are all asked here: the layers are wanted from whoever answers first).
    pub trackers: Vec<Vec<String>>,
    /// The port announced to trackers.
    pub announce_port: u16,
}

/// How long the layers are looked for before the torrent is given up on.
pub const LAYER_BUDGET: Duration = Duration::from_secs(90);

/// Gives a v2 torrent that lacks piece layers (as one from a magnet link does) the layers, from peers found through
/// `discovery`. Does nothing if it has them all.
pub fn complete_torrent(torrent: &mut TorrentFile, discovery: Discovery, config: &LayerConfig, budget: Duration, stop: &AtomicBool, log: &dyn Fn(String)) -> Result<(), String> {
    if torrent.missing_layers().is_empty() {
        return Ok(());
    }
    log(format!("the torrent does not carry its piece layers; asking peers for them (BEP 52), for {} file(s)", torrent.missing_layers().len()));
    let mut known = discovery.bootstrap.clone();
    let urls: Vec<String> = discovery.trackers.iter().flatten().cloned().collect();
    let mut last_announce: Option<Instant> = None;
    let (info_hash, peer_id) = (torrent.info_hash, config.our_peer_id);
    let peers = || {
        if !urls.is_empty() && last_announce.is_none_or(|at| at.elapsed() >= Duration::from_secs(30)) {
            let request = build_request(info_hash, peer_id, discovery.announce_port, TransferTotals { uploaded: 0, downloaded: 0, left: 1 }, None);
            known.extend(announce_to_all(&urls, &request).0);
            last_announce = Some(Instant::now());
        }
        if let Some(dht) = discovery.dht {
            for batch in dht.peers_rx.try_iter() {
                known.extend(batch);
            }
        }
        known.clone()
    };
    let layers = fetch_layers(torrent, peers, config, budget, stop, log)?;
    torrent.install_layers(layers).map_err(|e| format!("the piece layers a peer sent do not fit the torrent: {}", e))?;
    log("the piece layers are in place".to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{create, CreateOptions};
    use crate::peer::handshake::{Handshake, HANDSHAKE_LEN};
    use crate::torrent::parse_torrent_file;
    use crate::v2::HashSource;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// A v2 torrent of two files of `pieces` and `pieces / 2` pieces of 16 KiB (and a small one), with its piece layers, and
    /// the same torrent without them, as a magnet link would give it.
    fn torrents(name: &str, pieces: usize) -> (TorrentFile, TorrentFile) {
        let dir: PathBuf = std::env::temp_dir().join(format!("bt-layers-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("t")).unwrap();
        let mut state = 5u64;
        let mut bytes = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    (state >> 56) as u8
                })
                .collect()
        };
        std::fs::write(dir.join("t/big"), bytes(pieces * 16384 - 100)).unwrap();
        std::fs::write(dir.join("t/half"), bytes(pieces / 2 * 16384 + 5)).unwrap();
        std::fs::write(dir.join("t/small"), bytes(1000)).unwrap();
        let created = create(&dir.join("t"), &CreateOptions { v2: true, piece_length: Some(16384), ..Default::default() }, |_, _| {}).unwrap();
        let full = parse_torrent_file(&created.bytes).unwrap();
        // The same torrent without the `piece layers` key.
        let mut top = crate::bencode::decode(&created.bytes).unwrap();
        if let crate::bencode::Bencode::Dict(map) = &mut top {
            map.remove(b"piece layers".as_slice());
        }
        let bare = parse_torrent_file(&crate::bencode::encode(&top)).unwrap();
        assert!(full.v2_ready() && !bare.v2_ready() && bare.missing_layers().len() == 2, "two files longer than a piece lack their layers");
        (full, bare)
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Peer {
        Honest,
        /// Flips a bit in the first hash it sends.
        Tampers,
        /// Refuses every request.
        Rejects,
        /// Answers this many requests, then hangs up.
        HangsUpAfter(usize),
        /// Says nothing at all after the handshake.
        Silent,
    }

    /// A peer on loopback that answers hash requests from `full`'s layers as `behaviour` says; the address, and how many requests it got.
    fn peer(full: &TorrentFile, behaviour: Peer) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let meta = full.v2.as_ref().unwrap();
        let source = HashSource::new(&meta.files, &meta.layers, full.piece_length as u64).unwrap();
        let info_hash = full.info_hash;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut hs = [0u8; HANDSHAKE_LEN];
            if stream.read_exact(&mut hs).is_err() || stream.write_all(&Handshake::new(info_hash, [9; 20], false).to_bytes()).is_err() {
                return;
            }
            // What a peer says as it connects.
            let _ = Message::Bitfield(vec![0xFF]).write_to(&mut stream);
            let _ = Message::Unchoke.write_to(&mut stream);
            while let Ok(message) = Message::read_from(&mut stream) {
                let Message::HashRequest(request) = message else { continue };
                let seen = counted.fetch_add(1, Ordering::SeqCst) + 1;
                let reply = match (behaviour, source.answer(&request.root, request.base_layer, request.index, request.length, request.proof_layers)) {
                    (Peer::Silent, _) => continue,
                    (Peer::Rejects, _) | (_, None) => Message::HashReject(request),
                    (Peer::HangsUpAfter(n), _) if seen > n => return,
                    (behaviour, Some(range)) => {
                        let mut hashes: Vec<Hash> = range.hashes.into_iter().chain(range.uncles).collect();
                        if behaviour == Peer::Tampers {
                            hashes[0][0] ^= 1;
                        }
                        Message::Hashes { request, hashes }
                    }
                };
                if reply.write_to(&mut stream).is_err() {
                    return;
                }
            }
        });
        (addr, requests)
    }

    fn config() -> LayerConfig {
        LayerConfig { our_peer_id: [7; 20], timeout: Duration::from_secs(2), encryption: Encryption::Off, transport: Transport::default() }
    }

    #[test]
    fn a_peer_gives_the_layers_of_every_file_that_lacks_one_however_many_requests_they_take() {
        let (full, bare) = torrents("honest", 1200);
        let (addr, requests) = peer(&full, Peer::Honest);
        let stop = AtomicBool::new(false);

        let (got, failure) = fetch_from_peer(addr, &bare, &bare.missing_layers(), &config(), &stop);

        assert_eq!(failure, None);
        let meta = full.v2.as_ref().unwrap();
        assert_eq!(got, meta.layers, "exactly the layers the full torrent carries");
        // 1200 pieces are 2048 wide: four requests of 512; 600 are 1024 wide: two.
        assert_eq!(requests.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn hashes_that_do_not_lead_to_the_files_root_are_refused_and_nothing_is_kept() {
        let (full, bare) = torrents("tamper", 100);
        let (addr, _) = peer(&full, Peer::Tampers);
        let (got, failure) = fetch_from_peer(addr, &bare, &bare.missing_layers(), &config(), &AtomicBool::new(false));
        assert!(got.is_empty(), "not one layer taken from a peer whose proofs fail");
        assert!(failure.is_some_and(|f| f.contains("do not lead to the file's root")), "the reason is given");
    }

    #[test]
    fn a_peer_that_refuses_or_leaves_or_says_nothing_gives_nothing_and_says_why() {
        let (full, bare) = torrents("bad-peers", 100);
        for (behaviour, wants) in [(Peer::Rejects, "would not send"), (Peer::HangsUpAfter(0), "waiting for hashes"), (Peer::Silent, "waiting for hashes")] {
            let (addr, _) = peer(&full, behaviour);
            let (got, failure) = fetch_from_peer(addr, &bare, &bare.missing_layers(), &config(), &AtomicBool::new(false));
            assert!(got.is_empty());
            assert!(failure.is_some_and(|f| f.contains(wants)), "{}", wants);
        }
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(fetch_from_peer(dead, &bare, &bare.missing_layers(), &config(), &AtomicBool::new(false)).1.unwrap().contains("connecting"));
    }

    #[test]
    fn what_a_peer_gave_before_it_failed_is_kept() {
        let (full, bare) = torrents("partial", 100);
        // Answers the first file's request, hangs up on the second's.
        let (addr, _) = peer(&full, Peer::HangsUpAfter(1));
        let missing = bare.missing_layers();
        let (got, failure) = fetch_from_peer(addr, &bare, &missing, &config(), &AtomicBool::new(false));
        assert_eq!(got.len(), 1, "the file it finished");
        assert!(got.contains_key(&missing[0].0));
        assert!(failure.is_some());
    }

    #[test]
    fn half_a_layer_is_never_kept() {
        let (full, bare) = torrents("half-layer", 1200);
        // Answers two requests, of the four the big file takes (asked first), and leaves.
        let (addr, _) = peer(&full, Peer::HangsUpAfter(2));
        let mut missing = bare.missing_layers();
        missing.sort_by_key(|(_, length)| std::cmp::Reverse(*length));
        let (got, failure) = fetch_from_peer(addr, &bare, &missing, &config(), &AtomicBool::new(false));
        assert!(failure.is_some());
        assert!(got.is_empty(), "the big file's layer was half there, and nothing else was reached");
        for (root, layer) in &got {
            assert_eq!(layer, &full.v2.as_ref().unwrap().layers[root], "a layer that is kept is a whole one");
        }
    }

    #[test]
    fn a_peer_is_asked_again_for_only_what_is_still_missing() {
        let (full, bare) = torrents("rest", 100);
        let (first, first_requests) = peer(&full, Peer::HangsUpAfter(1));
        let (second, second_requests) = peer(&full, Peer::Honest);
        let log = std::cell::RefCell::new(Vec::new());
        let got = fetch_layers(&bare, || vec![first, second], &config(), Duration::from_secs(20), &AtomicBool::new(false), &|m| log.borrow_mut().push(m)).unwrap();
        assert_eq!(got, full.v2.as_ref().unwrap().layers);
        assert_eq!(first_requests.load(Ordering::SeqCst), 2, "the first served one file's request and left on the next");
        assert_eq!(second_requests.load(Ordering::SeqCst), 1, "so the second was asked for the one file still missing, not for both");
        assert!(log.borrow().iter().any(|m| m.contains("piece layers of 1 file")));
    }

    #[test]
    fn a_torrent_that_has_its_layers_asks_nobody() {
        let (full, _) = torrents("has-all", 10);
        let got = fetch_layers(&full, || panic!("no peer is wanted"), &config(), Duration::from_secs(1), &AtomicBool::new(false), &|_| {}).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn with_no_peer_that_can_help_it_gives_up_when_the_budget_is_spent_and_says_what_it_means() {
        let (full, bare) = torrents("giveup", 10);
        let (rejecting, _) = peer(&full, Peer::Rejects);
        let started = Instant::now();
        let error = fetch_layers(&bare, || vec![rejecting], &config(), Duration::from_millis(600), &AtomicBool::new(false), &|_| {}).unwrap_err();
        assert!(error.contains("2 file(s) within 0s") && error.contains("cannot be downloaded"), "{}", error);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_stop_ends_the_wait() {
        let (_, bare) = torrents("stop", 10);
        let stop = AtomicBool::new(true);
        assert_eq!(fetch_layers(&bare, Vec::new, &config(), Duration::from_secs(60), &stop, &|_| {}).unwrap_err(), "stopped");
    }

    #[test]
    fn a_torrent_completed_this_way_can_be_downloaded_and_one_that_cannot_be_completed_says_so() {
        let (full, mut bare) = torrents("complete", 100);
        let (addr, _) = peer(&full, Peer::Honest);
        let discovery = Discovery { bootstrap: vec![addr], dht: None, trackers: Vec::new(), announce_port: 6881 };
        complete_torrent(&mut bare, discovery, &config(), Duration::from_secs(10), &AtomicBool::new(false), &|_| {}).unwrap();
        assert!(bare.v2_ready());
        assert_eq!(bare.v2_pieces, full.v2_pieces, "every piece has what it is checked against, as if the file had carried them");
        assert_eq!(bare.pieces, full.pieces);

        let (_, mut lacking) = torrents("cannot", 10);
        let none = Discovery { bootstrap: Vec::new(), dht: None, trackers: Vec::new(), announce_port: 6881 };
        assert!(complete_torrent(&mut lacking, none, &config(), Duration::from_millis(300), &AtomicBool::new(false), &|_| {}).is_err());
        assert!(!lacking.v2_ready());
        // Nothing to do for a torrent that has them.
        let mut whole = full;
        complete_torrent(&mut whole, Discovery { bootstrap: Vec::new(), dht: None, trackers: Vec::new(), announce_port: 1 }, &config(), Duration::from_secs(1), &AtomicBool::new(false), &|_| panic!("nothing to say")).unwrap();
    }

    #[test]
    fn layers_that_do_not_belong_to_the_torrent_are_not_installed() {
        let (full, mut bare) = torrents("install", 100);
        let mut layers = full.v2.as_ref().unwrap().layers.clone();
        let (root, layer) = layers.iter_mut().next().map(|(r, l)| (*r, l)).unwrap();
        layer[3][0] ^= 1;
        let error = bare.install_layers(layers.clone());
        assert!(error.is_err(), "a layer that does not come to the file's root");
        assert!(!bare.v2_ready() && bare.v2.as_ref().unwrap().layers.is_empty(), "and the torrent is as it was");
        layers.get_mut(&root).unwrap().pop();
        assert!(bare.install_layers(layers).is_err(), "nor one of the wrong length");
    }
}
