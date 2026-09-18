//! A mock peer on loopback (127.0.0.1) is just a `TcpListener`, no
//! outbound network access needed, so these end-to-end-exercise
//! `run_worker` against fake-but-protocol-correct peers.
use super::*;
use crate::downloader::file_writer::build_file_spans;
use crate::downloader::piece_assembler::PieceWork;
use crate::peer::handshake::Handshake;
use crate::peer::message::Message as WireMessage;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bittorrent-rs-worker-test-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha1_of(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

/// A protocol-correct-enough fake peer: performs the handshake,
/// announces it has every piece via `Bitfield`, unchokes after
/// `unchoke_delay`, then serves `Request`s with matching `Piece`
/// responses until the worker disconnects.
fn spawn_mock_peer(listener: TcpListener, info_hash: [u8; 20], pieces: Vec<Vec<u8>>, unchoke_delay: Duration) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();

        let mut hs_buf = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
        let their_hs = Handshake::from_bytes(&hs_buf).unwrap();
        assert_eq!(their_hs.info_hash, info_hash);

        let our_hs = Handshake::new(info_hash, [0x99; 20], false);
        std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();

        // Bitfield: one bit per piece, MSB-first, all set.
        let num_pieces = pieces.len();
        let mut bits = vec![0u8; num_pieces.div_ceil(8)];
        for i in 0..num_pieces {
            bits[i / 8] |= 1 << (7 - (i % 8));
        }
        WireMessage::Bitfield(bits).write_to(&mut stream).unwrap();
        if !unchoke_delay.is_zero() {
            thread::sleep(unchoke_delay);
        }
        WireMessage::Unchoke.write_to(&mut stream).unwrap();

        loop {
            let msg = match WireMessage::read_from(&mut stream) {
                Ok(m) => m,
                Err(_) => return, // worker closed the connection; done
            };
            if let WireMessage::Request { index, begin, length } = msg {
                let piece = &pieces[index as usize];
                let block = piece[begin as usize..(begin + length) as usize].to_vec();
                WireMessage::Piece { index, begin, block }.write_to(&mut stream).unwrap();
            }
        }
    })
}

#[test]
fn run_worker_downloads_all_pieces_from_mock_peer_and_writes_to_disk() {
    let piece0 = vec![0xAAu8; 16384];
    let piece1 = vec![0xBBu8; 16384];
    let info_hash = [0x42; 20];

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone(), piece1.clone()], Duration::ZERO);

    let work = vec![
        PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384 },
        PieceWork { index: 1, hash: sha1_of(&piece1), length: 16384 },
    ];
    let queue = Arc::new(WorkQueue::new(work, 2));

    let dir = tmp_dir("e2e");
    let files = vec![(vec!["out.bin".to_string()], 32768i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));

    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5) };

    run_worker(addr, &config, &queue, &spans, 16384, &tx, None).unwrap();
    mock.join().unwrap();

    let mut results: Vec<_> = rx.try_iter().collect();
    results.sort_by_key(|r| r.index);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].data, piece0);
    assert_eq!(results[1].data, piece1);
    assert!(queue.is_empty());

    let mut on_disk = Vec::new();
    fs::File::open(dir.join("out.bin")).unwrap().read_to_end(&mut on_disk).unwrap();
    assert_eq!(&on_disk[..16384], &piece0[..]);
    assert_eq!(&on_disk[16384..], &piece1[..]);
}

#[test]
fn run_worker_survives_a_peer_that_unchokes_slower_than_the_read_timeout() {
    // Regression test for the field failure that dropped the only
    // handshake-complete peer in a swarm: read timeout was 10s, the
    // peer's unchoke came later than that, and the resulting
    // WouldBlock was treated as fatal at stage "wait_for_unchoke".
    // Here: read timeout 100ms, unchoke after 350ms -- several
    // timeouts *must* be tolerated for this download to succeed.
    let piece0 = vec![0xCDu8; 16384];
    let info_hash = [0x43; 20];

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone()], Duration::from_millis(350));

    let work = vec![PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384 }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("slow-unchoke");
    let files = vec![(vec!["out.bin".to_string()], 16384i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100) };

    run_worker(addr, &config, &queue, &spans, 16384, &tx, None).unwrap();
    mock.join().unwrap();

    let results: Vec<_> = rx.try_iter().collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].data, piece0);
}

#[test]
fn run_worker_gives_up_on_a_peer_that_never_unchokes() {
    // The other side of the coin: tolerance must stay bounded, or a
    // permanently-choking peer holds its slot forever.
    let info_hash = [0x44; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let mock = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hs_buf = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
        let our_hs = Handshake::new(info_hash, [0x99; 20], false);
        std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();
        // Never unchoke; just linger longer than the worker's budget.
        thread::sleep(Duration::from_secs(3));
    });

    let work = vec![PieceWork { index: 0, hash: [0; 20], length: 100 }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("never-unchokes");
    let files = vec![(vec!["out.bin".to_string()], 100i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));
    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100) };

    let result = run_worker(addr, &config, &queue, &spans, 100, &tx, None);
    assert!(matches!(result, Err(WorkerError::Connection { stage: "peer_never_unchoked", .. })), "expected bounded give-up, got: {:?}", result);
    assert_eq!(queue.len(), 1, "piece must remain available for another peer");
    let _ = mock.join();
}

#[test]
fn run_worker_gives_up_on_peer_with_no_needed_pieces_instead_of_hanging() {
    let info_hash = [0x88; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Mock peer: real handshake, but its bitfield claims it has ZERO
    // pieces -- there is nothing this worker can ever get from it.
    let mock = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hs_buf = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
        let our_hs = Handshake::new(info_hash, [0x99; 20], false);
        std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();
        WireMessage::Bitfield(vec![0x00]).write_to(&mut stream).unwrap(); // claims: has piece 0..7, all false
        WireMessage::Unchoke.write_to(&mut stream).unwrap();
        // Then just... never send anything else relevant. Read
        // whatever the worker sends (Interested) and go quiet.
        let _ = WireMessage::read_from(&mut stream);
        thread::sleep(Duration::from_secs(8));
    });

    let work = vec![PieceWork { index: 0, hash: [0; 20], length: 100 }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("no-needed-pieces");
    let files = vec![(vec!["out.bin".to_string()], 100i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));
    let (tx, _rx) = mpsc::channel();
    // Short connect_timeout also governs the per-read timeout on the
    // stream, so this test doesn't take anywhere near 8 real seconds
    // despite the mock peer sleeping that long.
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100) };

    let result = run_worker(addr, &config, &queue, &spans, 100, &tx, None);
    assert!(matches!(result, Err(WorkerError::Connection { stage: "peer_has_no_needed_pieces", .. })), "expected bounded give-up, got: {:?}", result);
    assert_eq!(queue.len(), 1); // piece went back for another peer

    let _ = mock.join();
}

#[test]
fn run_worker_requeues_piece_on_hash_mismatch_and_stops() {
    let piece0 = vec![0xCCu8; 16384];
    let info_hash = [0x77; 20];

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone()], Duration::ZERO);

    // Deliberately wrong hash -- the mock peer serves real data, but
    // the assembler should refuse to hand it back as verified.
    let work = vec![PieceWork { index: 0, hash: [0u8; 20], length: 16384 }];
    let queue = Arc::new(WorkQueue::new(work, 1));

    let dir = tmp_dir("hash-mismatch");
    let files = vec![(vec!["out.bin".to_string()], 16384i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));

    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x22; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5) };

    let result = run_worker(addr, &config, &queue, &spans, 16384, &tx, None);
    assert!(matches!(result, Err(WorkerError::PieceHashMismatch)));
    let _ = mock.join();

    // The piece went back on the queue for another peer to try.
    assert_eq!(queue.len(), 1);
}

#[test]
fn worker_reports_pex_peers_from_a_pex_sending_peer() {
    // Mock peer with the extension bit set: exchanges extended
    // handshakes, pushes a ut_pex message with one added peer, then
    // unchokes and serves the piece normally.
    let piece0 = vec![0xEEu8; 16384];
    let info_hash = [0x55; 20];
    let piece0_for_mock = piece0.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let mock = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hs_buf = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
        let their_hs = Handshake::from_bytes(&hs_buf).unwrap();
        assert!(their_hs.supports_extensions());
        let our_hs = Handshake::new(info_hash, [0x99; 20], true);
        std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();

        // Their extended handshake arrives first; read until we see it
        // and learn the ut_pex id they chose for inbound PEX.
        let their_ut_pex = loop {
            match WireMessage::read_from(&mut stream).unwrap() {
                WireMessage::Extended { id: 0, payload } => {
                    break crate::peer::ExtendedHandshake::parse(&payload).unwrap().peer_ut_pex_id().unwrap();
                }
                _ => continue,
            }
        };

        // Our own extended handshake back, then a PEX push:
        // added = 10.1.2.3:6881 (compact v4).
        WireMessage::Extended { id: 0, payload: crate::peer::ExtendedHandshake::build(7, None) }.write_to(&mut stream).unwrap();
        let mut pex = Vec::new();
        pex.extend_from_slice(b"d5:added6:");
        pex.extend_from_slice(&[10, 1, 2, 3]);
        pex.extend_from_slice(&6881u16.to_be_bytes());
        pex.push(b'e');
        WireMessage::Extended { id: their_ut_pex, payload: pex }.write_to(&mut stream).unwrap();

        WireMessage::Bitfield(vec![0b1000_0000]).write_to(&mut stream).unwrap();
        WireMessage::Unchoke.write_to(&mut stream).unwrap();
        loop {
            let msg = match WireMessage::read_from(&mut stream) {
                Ok(m) => m,
                Err(_) => return,
            };
            if let WireMessage::Request { index, begin, length } = msg {
                let block = piece0_for_mock[begin as usize..(begin + length) as usize].to_vec();
                WireMessage::Piece { index, begin, block }.write_to(&mut stream).unwrap();
            }
        }
    });

    let work = vec![PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384 }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("pex");
    let files = vec![(vec!["out.bin".to_string()], 16384i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));
    let (tx, _rx) = mpsc::channel();
    let (pex_tx, pex_rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5) };

    run_worker(addr, &config, &queue, &spans, 16384, &tx, Some(&pex_tx)).unwrap();
    let _ = mock.join();

    let pex_peers: Vec<SocketAddr> = pex_rx.try_iter().flatten().collect();
    assert_eq!(pex_peers, vec!["10.1.2.3:6881".parse().unwrap()]);
}
