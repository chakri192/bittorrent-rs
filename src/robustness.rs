//! Hostile-input tests for every parser that reads untrusted bytes.
//!
//! Each starts from valid examples and runs them through
//! [`crate::fuzz::hammer`], which damages them in thousands of ways. Two
//! properties hold for all of it: the parser never panics (or overflows the
//! stack, or allocates without bound), and whatever it *accepts* means the
//! same thing after being written out and read back.

use crate::bencode::{self, Bencode};
use crate::dht::krpc::{parse_compact_nodes, CompactNode, KrpcMessage, Query, Response};
use crate::downloader::{build_work_queue, PieceAssembler, PieceWork};
use crate::fuzz::{hammer, Rng};
use crate::magnet::parse_magnet_uri;
use crate::metadata::MetadataMessage;
use crate::peer::extension::ExtendedHandshake;
use crate::peer::handshake::Handshake;
use crate::peer::message::Message;
use crate::peer::pex::parse_ut_pex;
use crate::peer::state::PeerState;
use crate::torrent::parse_torrent_file;
use crate::tracker::{parse_compact_peers, parse_compact_peers_v6};
use std::path::{Component, Path};

/// Mutations tried per seed. Every prefix of each seed is tried as well.
const ITERATIONS: usize = 4000;

fn v4(s: &str) -> std::net::SocketAddr {
    s.parse().unwrap()
}

// ---- seeds -----------------------------------------------------------

fn torrent_seeds() -> Vec<Vec<u8>> {
    let unhex = |text: &str| -> Vec<u8> { (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap()).collect() };
    // BitTorrent v2 (BEP 52): v2 only, and hybrid, built by a separate script.
    let v2_only = unhex("64383a616e6e6f756e636531383a687474703a2f2f742e6578616d706c652f61343a696e666f64393a66696c65207472656564353a662e62696e64303a64363a6c656e6774686934303030306531313a70696563657320726f6f7433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68265656531323a6d6574612076657273696f6e693265343a6e616d65353a662e62696e31323a7069656365206c656e677468693136333834656531323a7069656365206c61796572736433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68239363acfa57d60545ac82e09b63df067e2396f9377bac5311c3b159e50a61a2275876be25b78513a631bd38a5cc26875de9b787f1250a16ec6ad92f880fb37bfe5fa62eebf7c92de9855ef3886236a4378a7054258749ace85d10875991b9f13a6abab6565");
    let hybrid = unhex("64343a696e666f64393a66696c65207472656564353a662e62696e64303a64363a6c656e6774686934303030306531313a70696563657320726f6f7433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa682656565363a6c656e6774686934303030306531323a6d6574612076657273696f6e693265343a6e616d65353a662e62696e31323a7069656365206c656e67746869313633383465363a70696563657336303a6ab462cc165379d368dc9206fc25f8546e894131fd1d4adde2a16bf56c84129d6902e8d056d38311218898aa5c30e0ed9d2e1f9451b673dda2498a366531323a7069656365206c61796572736433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68239363acfa57d60545ac82e09b63df067e2396f9377bac5311c3b159e50a61a2275876be25b78513a631bd38a5cc26875de9b787f1250a16ec6ad92f880fb37bfe5fa62eebf7c92de9855ef3886236a4378a7054258749ace85d10875991b9f13a6abab6565");
    let hashes = |n: usize| vec![0xAB; n * 20];
    let single = {
        let mut v = b"d8:announce20:http://tracker.test/13:announce-listll20:http://tracker.test/ee4:infod6:lengthi40000e4:name8:file.bin12:piece lengthi16384e6:pieces60:".to_vec();
        v.extend_from_slice(&hashes(3));
        v.extend_from_slice(b"ee");
        v
    };
    let multi = {
        let mut v = b"d4:infod5:filesld6:lengthi300e4:pathl1:a3:x.yeed6:lengthi300e4:pathl1:beee4:name3:dir12:piece lengthi256e6:pieces60:".to_vec();
        v.extend_from_slice(&hashes(3));
        v.extend_from_slice(b"7:privatei1ee8:url-list19:http://mirror.test/e");
        v
    };
    // Torrents that are valid bencode but hostile: the parser must refuse
    // them, and if it ever stopped, the property below would fail.
    let hostile = |name: &str, path: &str| {
        let mut v = format!("d4:infod5:filesld6:lengthi100e4:pathl{}:{}ee", path.len(), path).into_bytes();
        v.extend_from_slice(format!("e4:name{}:{}12:piece lengthi256e6:pieces20:", name.len(), name).as_bytes());
        v.extend_from_slice(&hashes(1));
        v.extend_from_slice(b"ee");
        v
    };
    vec![single, multi, v2_only, hybrid, hostile("dir", ".."), hostile("dir", "/etc/passwd"), hostile("..", "ok"), hostile("a/b", "ok"), hostile("dir", "a\\b")]
}

fn bencode_seeds() -> Vec<Vec<u8>> {
    let mut seeds = torrent_seeds();
    seeds.extend([b"i-42e".to_vec(), b"4:spam".to_vec(), b"l4:spami42eld3:keyi1eeee".to_vec(), b"d1:ad1:bl1:ceeee".to_vec(), b"de".to_vec(), b"le".to_vec()]);
    seeds
}

fn krpc_seeds() -> Vec<Vec<u8>> {
    let id = [0x11; 20];
    let node = CompactNode { id: [0x22; 20], addr: v4("10.0.0.2:6881") };
    vec![
        KrpcMessage::Query { t: b"aa".to_vec(), query: Query::Ping { id } }.encode(),
        KrpcMessage::Query { t: b"ab".to_vec(), query: Query::FindNode { id, target: [0x33; 20] } }.encode(),
        KrpcMessage::Query { t: b"ac".to_vec(), query: Query::GetPeers { id, info_hash: [0x44; 20] } }.encode(),
        KrpcMessage::Query { t: b"ad".to_vec(), query: Query::AnnouncePeer { id, info_hash: [0x44; 20], port: 6881, token: b"tok".to_vec(), implied_port: true } }.encode(),
        KrpcMessage::Response { t: b"ae".to_vec(), response: Response { id, nodes: vec![node.clone(), node], values: vec![v4("1.2.3.4:5678")], token: Some(b"tok".to_vec()), ip: Some(v4("5.6.7.8:9012")) } }.encode(),
        KrpcMessage::Error { t: b"af".to_vec(), code: 203, message: "bad token".to_string() }.encode(),
        // BEP 32: nodes6, and values of both sizes.
        KrpcMessage::Response {
            t: b"ag".to_vec(),
            response: Response {
                id,
                nodes: vec![CompactNode { id: [0x33; 20], addr: "[2001:db8::3]:6881".parse().unwrap() }, CompactNode { id: [0x22; 20], addr: v4("10.0.0.2:6881") }],
                values: vec!["[2001:db8::4]:5678".parse().unwrap(), v4("1.2.3.4:5678")],
                token: Some(b"tok".to_vec()),
                ip: Some("[2001:db8::9]:6881".parse().unwrap()),
            },
        }
        .encode(),
    ]
}

fn message_seeds() -> Vec<Vec<u8>> {
    [
        Message::KeepAlive,
        Message::Choke,
        Message::Unchoke,
        Message::Interested,
        Message::NotInterested,
        Message::Have { piece_index: 7 },
        Message::Bitfield(vec![0b1010_0000, 0xff]),
        Message::Request { index: 1, begin: 16384, length: 16384 },
        Message::Piece { index: 1, begin: 0, block: vec![9; 40] },
        Message::Cancel { index: 1, begin: 0, length: 16384 },
        Message::Port(6881),
        Message::Extended { id: 1, payload: b"d1:md6:ut_pexi2eee".to_vec() },
        Message::HashRequest(crate::peer::message::HashRequest { root: [3; 32], base_layer: 2, index: 0, length: 512, proof_layers: 9 }),
        Message::HashReject(crate::peer::message::HashRequest { root: [4; 32], base_layer: 0, index: 2, length: 2, proof_layers: 0 }),
        Message::Hashes { request: crate::peer::message::HashRequest { root: [5; 32], base_layer: 2, index: 4, length: 2, proof_layers: 2 }, hashes: vec![[1; 32], [2; 32], [3; 32], [4; 32]] },
    ]
    .iter()
    .map(Message::to_bytes)
    .collect()
}

fn extension_seeds() -> Vec<Vec<u8>> {
    vec![ExtendedHandshake::build(3, None), ExtendedHandshake::build(3, Some(48213)), ExtendedHandshake::build_with_pex(1, Some(1), false), b"d1:md11:ut_metadatai2e6:ut_pexi1eee13:metadata_sizei34521e1:pi6881e4:reqqi500ee".to_vec()]
}

fn metadata_message_seeds() -> Vec<Vec<u8>> {
    vec![
        MetadataMessage::Request { piece: 3 }.encode(),
        MetadataMessage::Reject { piece: 3 }.encode(),
        MetadataMessage::Data { piece: 0, total_size: 20, data: vec![7; 20] }.encode(),
    ]
}

fn pex_seeds() -> Vec<Vec<u8>> {
    vec![b"d5:added12:\x0a\x01\x02\x03\x1a\x0b\x0a\x01\x02\x04\x1a\x0c7:added.f2:\x10\x107:dropped6:\x0a\x01\x02\x03\x1a\x0be".to_vec(), b"d6:added618:\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1a\x0be".to_vec()]
}

fn magnet_seeds() -> Vec<Vec<u8>> {
    [
        "magnet:?xt=urn:btih:dae9da07cb6632b66bb62673c03cff48652f4a4f",
        "magnet:?xt=urn:btih:dae9da07cb6632b66bb62673c03cff48652f4a4f&dn=Some%20Name&tr=udp%3A%2F%2Ftracker.example%3A6969&tr=http%3A%2F%2Fb.test%2Fannounce",
        "magnet:?xt=urn:btih:3JVNFNFEN6M2SA2RPNMOOR7EXBNMEP4T&dn=base32+hash&xl=1234",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect()
}

// ---- properties ------------------------------------------------------

/// Whether `part` is one ordinary path component (what the download
/// directory's safety rests on).
fn is_plain_component(part: &str) -> bool {
    let mut c = Path::new(part).components();
    matches!((c.next(), c.next()), (Some(Component::Normal(_)), None)) && !part.contains(['/', '\\', '\0'])
}

#[test]
fn bencode_survives_hostile_input_and_round_trips_what_it_accepts() {
    hammer(&bencode_seeds(), ITERATIONS, |input| {
        if let Ok(value) = bencode::decode(input) {
            assert_eq!(bencode::encode(&value), input, "strict decoding is canonical: it re-encodes to the same bytes");
        }
        if let Ok(value) = bencode::decode_lenient(input) {
            let canonical = bencode::encode(&value);
            assert_eq!(bencode::decode(&canonical).as_ref(), Ok(&value), "what lenient accepts is stable once made canonical");
        }
    });
}

#[test]
fn bencode_nesting_does_not_grow_the_stack_with_the_input() {
    // Deep structures on a worker-sized stack, both shapes, at many sizes.
    let outcome = std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(|| {
            for depth in [1usize, 10, 99, 100, 101, 1000, 100_000] {
                let lists = b"l".repeat(depth);
                let dicts = b"d1:a".repeat(depth);
                let _ = bencode::decode(&lists);
                let _ = bencode::decode_lenient(&dicts);
            }
        })
        .unwrap()
        .join();
    assert!(outcome.is_ok());
}

#[test]
fn torrent_parsing_survives_hostile_input_and_only_yields_safe_torrents() {
    hammer(&torrent_seeds(), ITERATIONS, |input| {
        let Ok(t) = parse_torrent_file(input) else { return };

        // Nothing that gets past the parser can escape the download directory.
        assert!(is_plain_component(&t.name), "name {:?}", t.name);
        assert_eq!(t.padding.len(), t.files.len(), "the padding flags are one per file");
        for (path, _) in &t.files {
            assert!(!path.is_empty(), "a file with no path");
            for part in path {
                assert!(is_plain_component(part), "component {:?}", part);
            }
        }

        // The piece arithmetic downstream is consistent for anything accepted.
        assert!(t.piece_length > 0 && t.piece_length <= crate::torrent::MAX_PIECE_LENGTH);
        if t.is_v2_only() {
            // BitTorrent v2: no v1 hashes; the layers add up, and the files are the tree's.
            let meta = t.v2.as_ref().unwrap();
            assert!(t.pieces.len() == t.v2_pieces.len() && crate::v2::valid_piece_length(t.piece_length));
            assert_eq!(build_work_queue(&t).len(), t.v2_pieces.len());
            if t.v2_ready() {
                assert_eq!(t.v2_pieces.iter().map(|p| p.length as u64).sum::<u64>(), t.total_length(), "the pieces cover the files exactly");
            }
            assert!(crate::v2::validate_layers(&meta.files, &meta.layers, t.piece_length).is_ok());
            assert_eq!(meta.files.len(), t.files.len());
            assert_eq!(meta.short_hash(), t.info_hash);
            let _ = t.tracker_urls();
            return;
        }
        let total = t.total_length();
        assert_eq!(t.pieces.len() as u64, total.div_ceil(t.piece_length as u64), "piece count matches the length");
        if t.pieces.len() <= 100_000 {
            let sum: u64 = (0..t.pieces.len()).map(|i| t.piece_len(i)).sum();
            assert_eq!(sum, total, "the pieces exactly cover the data");
        }
        assert_eq!(build_work_queue(&t).len(), t.pieces.len());
        let _ = t.tracker_urls();
    });
}

#[test]
fn magnet_parsing_survives_hostile_input() {
    hammer(&magnet_seeds(), ITERATIONS, |input| {
        let _ = parse_magnet_uri(&String::from_utf8_lossy(input));
    });
}

#[test]
fn krpc_survives_hostile_input_and_round_trips_what_it_accepts() {
    hammer(&krpc_seeds(), ITERATIONS, |input| {
        if let Ok(message) = KrpcMessage::decode(input) {
            assert_eq!(KrpcMessage::decode(&message.encode()).ok(), Some(message.clone()), "re-reading what we would send back gives the same message");
        }
        let _ = parse_compact_nodes(input);
        let _ = crate::dht::krpc::parse_compact_nodes6(input);
    });
}

#[test]
fn peer_wire_messages_survive_hostile_input_and_round_trip() {
    hammer(&message_seeds(), ITERATIONS, |input| {
        let mut reader = input;
        // A stream can hold several messages: read until it stops making sense.
        for _ in 0..8 {
            match Message::read_from(&mut reader) {
                Ok(message) => {
                    assert_eq!(Message::read_from(&mut message.to_bytes().as_slice()).ok(), Some(message.clone()), "round trip of {:?}", message);
                    // Whatever the peer said, its state stays bounded by the torrent.
                    let mut state = PeerState::for_torrent(50);
                    state.apply_message(&message);
                    assert!(state.peer_has_pieces.len() <= 50, "state grew to {}", state.peer_has_pieces.len());
                }
                Err(_) => break,
            }
        }
    });
}

#[test]
fn handshakes_survive_hostile_input_and_round_trip() {
    let seed = Handshake::new([0x42; 20], [0x99; 20], true).to_bytes();
    hammer(&[seed.to_vec()], ITERATIONS, |input| {
        if let Ok(handshake) = Handshake::from_bytes(input) {
            assert_eq!(Handshake::from_bytes(&handshake.to_bytes()), Ok(handshake));
        }
    });
}

#[test]
fn extension_handshakes_survive_hostile_input() {
    hammer(&extension_seeds(), ITERATIONS, |input| {
        let _ = ExtendedHandshake::parse(input);
    });
}

#[test]
fn metadata_messages_survive_hostile_input_and_round_trip() {
    hammer(&metadata_message_seeds(), ITERATIONS, |input| {
        if let Ok(message) = MetadataMessage::decode(input) {
            assert_eq!(MetadataMessage::decode(&message.encode()).ok(), Some(message));
        }
    });
}

#[test]
fn peer_exchange_and_compact_peer_lists_survive_hostile_input() {
    hammer(&pex_seeds(), ITERATIONS, |input| {
        let _ = parse_ut_pex(input);
        let _ = parse_compact_peers(input);
        let _ = parse_compact_peers_v6(input);
    });
    // A compact list is exactly as long as its peers say.
    let mut rng = Rng::new(9);
    for _ in 0..2000 {
        let data: Vec<u8> = (0..rng.below(60)).map(|_| rng.next_u64() as u8).collect();
        match parse_compact_peers(&data) {
            Ok(peers) => assert_eq!(peers.len() * 6, data.len()),
            Err(_) => assert!(!data.len().is_multiple_of(6)),
        }
    }
}

#[test]
fn piece_assembly_survives_blocks_at_hostile_offsets_and_sizes() {
    let mut rng = Rng::new(21);
    for _ in 0..500 {
        let length = 1 + rng.below(70_000) as u32;
        let mut assembler = PieceAssembler::new(PieceWork { index: 0, hash: [0; 20], length, merkle: None });
        for _ in 0..40 {
            // Offsets and lengths a lying peer might use, including ones
            // that overflow when added.
            let begin = [0u32, 1, 16383, 16384, 32768, length, length.wrapping_sub(1), u32::MAX, u32::MAX - 5, rng.next_u64() as u32][rng.below(10)];
            let data = vec![0u8; [0usize, 1, 100, 16384, 16385][rng.below(5)]];
            let _ = assembler.record_block(begin, &data);
            let _ = assembler.next_requests(1 + rng.below(8));
        }
        let _ = assembler.finish();
    }
}

#[test]
fn the_bitfield_helpers_agree_with_each_other() {
    let mut rng = Rng::new(33);
    for _ in 0..1000 {
        let have: Vec<bool> = (0..rng.below(200)).map(|_| rng.below(2) == 1).collect();
        let bytes = PeerState::encode_bitfield(&have);
        let mut state = PeerState::for_torrent(have.len());
        state.apply_message(&Message::Bitfield(bytes));
        assert_eq!(state.peer_has_pieces, have, "a bitfield we encode is read back exactly");
    }
}

/// `Bencode` values built by hand encode and decode to themselves, so the
/// canonical-form checks above are checking something real.
#[test]
fn a_known_value_survives_encoding() {
    let value = Bencode::List(vec![Bencode::Int(-3), Bencode::Bytes(b"x".to_vec())]);
    assert_eq!(bencode::decode(&bencode::encode(&value)), Ok(value));
}

#[test]
fn a_claimed_metadata_size_is_only_ever_accepted_within_its_bounds() {
    use crate::metadata::{MetadataAssembler, MAX_METADATA_SIZE};
    let mut rng = Rng::new(77);
    for _ in 0..20_000 {
        let claimed = match rng.below(4) {
            0 => rng.next_u64() as i64,
            1 => (rng.next_u64() % 40_000_000) as i64,
            2 => -((rng.next_u64() % 1000) as i64),
            _ => i64::MAX - (rng.next_u64() % 4) as i64,
        };
        match MetadataAssembler::for_claimed_size(claimed) {
            Ok(a) => assert!((1..=MAX_METADATA_SIZE).contains(&claimed) && a.num_pieces() <= 1024, "{} was accepted", claimed),
            Err(_) => assert!(!(1..=MAX_METADATA_SIZE).contains(&claimed), "{} was refused", claimed),
        }
    }
}

#[test]
fn local_discovery_announcements_survive_hostile_input_and_round_trip() {
    use crate::lsd::{announcement, parse};
    let host = std::net::SocketAddr::from(([239, 192, 152, 143], 6771));
    let seeds = vec![announcement(host, 6881, &[0xAB; 20], "cookie"), announcement(host, 1, &[0x00; 20], ""), b"BT-SEARCH * HTTP/1.1\nport: 5\ninfohash: ABABABABABABABABABABABABABABABABABABABAB\n\n".to_vec()];
    hammer(&seeds, ITERATIONS, |input| {
        if let Ok(parsed) = parse(input) {
            assert!(parsed.port != 0 && !parsed.info_hashes.is_empty() && parsed.info_hashes.len() <= 16);
            assert!(parsed.cookie.as_deref().is_none_or(|c| c.len() <= 64));
        }
    });
}

#[test]
fn utp_packets_survive_hostile_input_and_round_trip_what_they_accept() {
    use crate::utp::packet::{Packet, PacketType};
    let base = Packet { kind: PacketType::Data, connection_id: 0x1234, timestamp: 99, timestamp_diff: 7, wnd_size: 1 << 20, seq_nr: 65535, ack_nr: 3, sack: Vec::new(), payload: b"payload".to_vec() };
    let seeds = vec![base.encode(), Packet { kind: PacketType::State, sack: vec![0b101, 0, 0, 0x80], payload: Vec::new(), ..base.clone() }.encode(), Packet { kind: PacketType::Syn, payload: Vec::new(), ..base.clone() }.encode(), Packet { kind: PacketType::Fin, ..base.clone() }.encode()];
    hammer(&seeds, ITERATIONS, |input| {
        if let Ok(packet) = Packet::decode(input) {
            assert_eq!(Packet::decode(&packet.encode()).as_ref(), Ok(&packet), "what is accepted means the same written out and read back");
        }
    });
}

/// A connection is fed packets that are damaged versions of real ones, in
/// both of its states, with time passing. It must not panic (an arithmetic
/// slip on a hostile acknowledgement would) nor let its bookkeeping go wrong.
#[test]
fn a_utp_connection_survives_hostile_packets_and_time() {
    use crate::utp::conn::Connection;
    use crate::utp::packet::{Packet, PacketType};
    use std::time::{Duration, Instant};

    let start = Instant::now();
    // Real traffic of both kinds, from a real pair of connections.
    let mut a = Connection::connect(start, 100);
    let syn = Packet::decode(&a.take_outgoing()[0]).unwrap();
    let mut b = Connection::accept(start, &syn, 5000);
    let mut seeds = Vec::new();
    let mut now = start;
    a.write(&vec![7u8; 60_000]);
    for _ in 0..200 {
        now += Duration::from_millis(30);
        for bytes in b.take_outgoing() {
            seeds.push(bytes.clone());
            a.on_packet(now, &Packet::decode(&bytes).unwrap());
        }
        a.on_tick(now);
        for bytes in a.take_outgoing() {
            seeds.push(bytes.clone());
            b.on_packet(now, &Packet::decode(&bytes).unwrap());
        }
        b.on_tick(now);
    }
    seeds.push(Packet { kind: PacketType::Reset, connection_id: 100, timestamp: 0, timestamp_diff: 0, wnd_size: 0, seq_nr: 0, ack_nr: 0, sack: vec![0xFF; 8], payload: Vec::new() }.encode());
    assert!(seeds.len() > 20, "the pair produced traffic to damage: {} packets, a {:?} b {:?}", seeds.len(), a.state(), b.state());

    hammer(&seeds, 200, |input| {
        let Ok(packet) = Packet::decode(input) else { return };
        for mut conn in [Connection::connect(start, 1), Connection::accept(start, &syn, 9)] {
            conn.write(&[1u8; 3000]);
            let mut at = start;
            for step in 0..6 {
                at += Duration::from_millis(400 * (step + 1));
                conn.on_packet(at, &packet);
                conn.on_tick(at);
                conn.flush(at);
                let _ = conn.take_outgoing();
                let mut buf = [0u8; 256];
                let _ = conn.read(&mut buf);
                let _ = conn.next_timeout();
            }
            conn.close();
            conn.on_tick(at + Duration::from_secs(120));
        }
    });
}

// ---- the daemon ------------------------------------------------------

#[test]
fn control_requests_survive_hostile_input_and_round_trip_what_they_accept() {
    use crate::daemon::control::{parse_request, Request};
    let seeds: Vec<Vec<u8>> = [
        Request::Add { source: "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=a%20b".into(), out: "/downloads/a b".into(), options: Default::default() },
        Request::Add { source: "/tmp/x \"quoted\".torrent".into(), out: "/o".into(), options: crate::daemon::JobOptions { files: vec![1, 3], only: vec!["a".into(), "b c".into()], prefer: vec!["x".into()], sequential: true, max_up: Some(5), max_down: Some(6) } },
        Request::Pause { id: "ab12".into() },
        Request::Resume { id: "ab12".into() },
        Request::List,
        Request::Status { id: "ab12".into() },
        Request::Remove { id: "0123456789abcdef".into() },
        Request::Shutdown,
    ]
    .iter()
    .map(|r| r.to_line().into_bytes())
    .collect();
    hammer(&seeds, ITERATIONS, |input| {
        let Ok(text) = std::str::from_utf8(input) else { return };
        if let Ok(request) = parse_request(text) {
            assert_eq!(parse_request(&request.to_line()), Ok(request.clone()), "{:?} did not survive being written and read", request);
        }
    });
}

#[test]
fn the_daemons_state_file_survives_hostile_input_and_round_trips_what_it_accepts() {
    use crate::daemon::state::{parse_entries, Entry};
    use crate::daemon::Source;
    use crate::daemon::state::Dormant;
    use crate::daemon::JobOptions;
    let mut with_options = Entry::new([2; 20], Source::File("/state/torrents/y.torrent".into()), "/o".into());
    with_options.options = JobOptions { files: vec![2, 4], only: vec!["a b".into(), ".mkv".into()], prefer: vec!["\"q\"".into()], sequential: true, max_up: Some(1000), max_down: Some(2_000_000) };
    with_options.dormant = Some(Dormant::Finished("seed ratio 1.00 reached".into()));
    let mut paused = Entry::new([3; 20], Source::Magnet("magnet:?xt=urn:btih:0303".into()), "/o".into());
    paused.dormant = Some(Dormant::Paused);
    let entries = [Entry::new([0xAB; 20], Source::Magnet("magnet:?xt=urn:btih:abab&dn=\"q\"".into()), "/down loads".into()), Entry::new([1; 20], Source::File("/state/torrents/x.torrent".into()), "/o".into()), with_options, paused];
    let mut file = String::new();
    for entry in &entries {
        file.push_str(&entry.to_line());
        file.push('\n');
    }
    let seeds = vec![file.into_bytes(), entries[0].to_line().into_bytes()];
    hammer(&seeds, ITERATIONS, |input| {
        let Ok(text) = std::str::from_utf8(input) else { return };
        let (read, _) = parse_entries(text);
        for entry in read {
            assert_eq!(Entry::from_line(&entry.to_line()), Ok(entry.clone()), "{:?}", entry);
        }
    });
}

#[test]
fn flat_json_survives_hostile_input() {
    let seeds: Vec<Vec<u8>> = [
        r#"{"cmd":"add","source":"a\"b\\c\n","out":"/o"}"#,
        r#"{"ok":true,"n":-12.5e3,"x":null,"u":"\u00e9\ud83d\ude00"}"#,
        r#"{"a":1,"b":[1]}"#,
        r#"{ "spaced" : "out" }"#,
        "{}",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    hammer(&seeds, ITERATIONS, |input| {
        if let Ok(text) = std::str::from_utf8(input) {
            let _ = crate::json::parse_object(text);
        }
    });
}
