//! A mock peer on loopback (127.0.0.1) is just a `TcpListener`, no
//! outbound network access needed, so these end-to-end-exercise
//! `run_worker` against fake-but-protocol-correct peers.
use super::*;
use crate::downloader::file_writer::build_file_spans;
use crate::downloader::piece_assembler::PieceWork;
use crate::downloader::Order;
use crate::peer::handshake::Handshake;
use crate::peer::message::Message as WireMessage;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

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
    spawn_mock_peer_with(listener, info_hash, pieces, unchoke_delay, crate::peer::Encryption::Off)
}

/// [`spawn_mock_peer`] that takes encrypted connections too, when `encryption`
/// is not `Off`.
fn spawn_mock_peer_with(listener: TcpListener, info_hash: [u8; 20], pieces: Vec<Vec<u8>>, unchoke_delay: Duration, encryption: crate::peer::Encryption) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        serve_mock_peer(Box::new(tcp), info_hash, pieces, unchoke_delay, encryption);
    })
}

/// What the mock peer does with one connection, over whatever carries it.
fn serve_mock_peer(stream: Box<dyn crate::peer::PeerStream>, info_hash: [u8; 20], pieces: Vec<Vec<u8>>, unchoke_delay: Duration, encryption: crate::peer::Encryption) {
    {
        // Plain or encrypted, whichever the worker begins with.
        let (mut stream, _) = crate::peer::mse::accept(stream, &[info_hash], encryption).unwrap();

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
    }
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
        PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384, merkle: None },
        PieceWork { index: 1, hash: sha1_of(&piece1), length: 16384, merkle: None },
    ];
    let queue = Arc::new(WorkQueue::new(work, 2));

    let dir = tmp_dir("e2e");
    let files = vec![(vec!["out.bin".to_string()], 32768i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));

    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

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

    let work = vec![PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384, merkle: None }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("slow-unchoke");
    let files = vec![(vec!["out.bin".to_string()], 16384i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

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

    let work = vec![PieceWork { index: 0, hash: [0; 20], length: 100, merkle: None }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("never-unchokes");
    let files = vec![(vec!["out.bin".to_string()], 100i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));
    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

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

    let work = vec![PieceWork { index: 0, hash: [0; 20], length: 100, merkle: None }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("no-needed-pieces");
    let files = vec![(vec!["out.bin".to_string()], 100i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));
    let (tx, _rx) = mpsc::channel();
    // Short connect_timeout also governs the per-read timeout on the
    // stream, so this test doesn't take anywhere near 8 real seconds
    // despite the mock peer sleeping that long.
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

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
    let work = vec![PieceWork { index: 0, hash: [0u8; 20], length: 16384, merkle: None }];
    let queue = Arc::new(WorkQueue::new(work, 1));

    let dir = tmp_dir("hash-mismatch");
    let files = vec![(vec!["out.bin".to_string()], 16384i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));

    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x22; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

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

    let work = vec![PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384, merkle: None }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("pex");
    let files = vec![(vec!["out.bin".to_string()], 16384i64)];
    let spans = Arc::new(build_file_spans(&dir, &files));
    let (tx, _rx) = mpsc::channel();
    let (pex_tx, pex_rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    run_worker(addr, &config, &queue, &spans, 16384, &tx, Some(&pex_tx)).unwrap();
    let _ = mock.join();

    let pex_peers: Vec<SocketAddr> = pex_rx.try_iter().flatten().collect();
    assert_eq!(pex_peers, vec!["10.1.2.3:6881".parse().unwrap()]);
}

#[test]
fn a_download_limit_slows_the_worker_but_not_what_it_downloads() {
    // Two 16 KiB pieces at 20,000 B/s: the first fits the burst, the second
    // is on credit and must wait out the rest of a second's worth.
    let piece0 = vec![0xAAu8; 16384];
    let piece1 = vec![0xBBu8; 16384];
    let info_hash = [0x42; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone(), piece1.clone()], Duration::ZERO);
    let work = vec![PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384, merkle: None }, PieceWork { index: 1, hash: sha1_of(&piece1), length: 16384, merkle: None }];
    let queue = Arc::new(WorkQueue::new(work, 2));
    let dir = tmp_dir("limited");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 32768i64)]));
    let (tx, rx) = mpsc::channel();
    let limiter = Arc::new(crate::ratelimit::RateLimiter::new(20_000));
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: Some(limiter), interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    let started = std::time::Instant::now();
    run_worker(addr, &config, &queue, &spans, 16384, &tx, None).unwrap();
    let elapsed = started.elapsed();
    mock.join().unwrap();

    assert!(elapsed >= Duration::from_millis(500), "32 KiB at 20,000 B/s cannot take {:?}", elapsed);
    let mut results: Vec<_> = rx.try_iter().collect();
    results.sort_by_key(|r| r.index);
    assert_eq!((results[0].data.as_slice(), results[1].data.as_slice()), (piece0.as_slice(), piece1.as_slice()), "and every byte is still right");
}

// ---- Interrupt: ending workers that are blocked on a silent peer ----

/// A connected pair on loopback: (client end, server end).
fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn triggering_ends_a_read_that_is_blocked_on_a_registered_connection() {
    let (client, _server) = socket_pair(); // the server end never sends a byte
    let interrupt = Arc::new(Interrupt::default());
    let _registration = interrupt.register(&client);

    let reader = thread::spawn(move || {
        let mut client = client;
        client.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 1];
        let n = client.read(&mut buf);
        (matches!(n, Ok(0)), started.elapsed())
    });
    thread::sleep(Duration::from_millis(150)); // let the read block
    interrupt.trigger();

    let (ended, waited) = reader.join().unwrap();
    assert!(ended, "the read returned end-of-stream");
    assert!(waited < Duration::from_secs(5), "the read was cut short, not left to its 30 s timeout: {:?}", waited);
    assert!(interrupt.is_triggered());
}

#[test]
fn a_connection_registered_after_the_trigger_is_shut_down_at_once() {
    let (mut client, _server) = socket_pair();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap(); // macOS refuses to set it once shut down
    let interrupt = Interrupt::default();
    interrupt.trigger();

    let _registration = interrupt.register(&client);

    let started = Instant::now();
    let mut buf = [0u8; 1];
    let outcome = client.read(&mut buf);
    assert!(outcome.is_ok_and(|n| n == 0), "a shut-down socket reads end-of-stream");
    assert!(started.elapsed() < Duration::from_secs(2), "it did not wait for the read timeout");
}

#[test]
fn triggering_twice_is_harmless() {
    let (client, _server) = socket_pair();
    let interrupt = Interrupt::default();
    let _registration = interrupt.register(&client);
    interrupt.trigger();
    interrupt.trigger();
    assert!(interrupt.is_triggered());
}

#[test]
fn a_dropped_registration_lets_the_connection_really_close() {
    // Registering keeps a second handle on the socket, and a connection
    // only closes once every handle is gone. If the registration outlived
    // its worker the peer would never see the hang-up, and every
    // download that finished would leave its peers waiting.
    let (client, mut server) = socket_pair();
    let interrupt = Interrupt::default();
    let registration = interrupt.register(&client);

    drop(registration);
    drop(client);

    server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut buf = [0u8; 1];
    let outcome = server.read(&mut buf);
    assert!(outcome.is_ok_and(|n| n == 0), "the peer saw end-of-stream rather than a timeout");
}

#[test]
fn a_worker_waiting_on_a_silent_peer_stops_when_interrupted() {
    let info_hash = [0x61; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Handshakes, then says nothing at all: the worker sits in wait_for_unchoke.
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hs = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs).unwrap();
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], false).to_bytes()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(20));
    });

    let queue = Arc::new(WorkQueue::new(vec![PieceWork { index: 0, hash: [0; 20], length: 16384, merkle: None }], 1));
    let dir = tmp_dir("interrupted");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 16384i64)]));
    let (tx, _rx) = mpsc::channel();
    // A 30 s read timeout: only the interrupt can end this in time.
    let config = Arc::new(WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(30), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None });

    let worker = {
        let (config, queue, spans) = (config.clone(), queue.clone(), spans.clone());
        thread::spawn(move || {
            let started = Instant::now();
            let result = run_worker(addr, &config, &queue, &spans, 16384, &tx, None);
            (result, started.elapsed())
        })
    };
    thread::sleep(Duration::from_millis(300)); // connected, handshaken, waiting
    config.interrupt.trigger();

    let (result, took) = worker.join().unwrap();
    assert!(result.is_err(), "an interrupted worker reports a failure, not success");
    assert!(took < Duration::from_secs(5), "the interrupt cut the wait short, not the 30 s read timeout: {:?}", took);
    assert_eq!(queue.len(), 1, "the piece it never got goes back for someone else");
    let _ = release_tx.send(());
    peer.join().unwrap();
}

// ---- how many requests are kept in flight ----

/// A peer with a long round trip: every request is answered `latency`
/// after it arrived, however many are waiting, as a real link would. Tracks
/// how many requests were outstanding at once. With `reqq`, sends an
/// extended handshake saying how many it will queue.
fn spawn_laggy_peer(listener: TcpListener, info_hash: [u8; 20], pieces: Vec<Vec<u8>>, latency: Duration, reqq: Option<u32>, max_outstanding: Arc<std::sync::atomic::AtomicUsize>) -> thread::JoinHandle<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hs_buf = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], reqq.is_some()).to_bytes()).unwrap();
        if let Some(reqq) = reqq {
            let payload = format!("d1:mde4:reqqi{}ee", reqq).into_bytes();
            WireMessage::Extended { id: 0, payload }.write_to(&mut stream).unwrap();
        }
        let mut bits = vec![0u8; pieces.len().div_ceil(8)];
        for i in 0..pieces.len() {
            bits[i / 8] |= 1 << (7 - (i % 8));
        }
        WireMessage::Bitfield(bits).write_to(&mut stream).unwrap();
        WireMessage::Unchoke.write_to(&mut stream).unwrap();

        // One thread reads requests as they come and stamps them; this one
        // answers each when its time is up.
        let outstanding = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let mut reader = stream.try_clone().unwrap();
        let counted = Arc::clone(&outstanding);
        thread::spawn(move || {
            while let Ok(msg) = WireMessage::read_from(&mut reader) {
                if let WireMessage::Request { index, begin, length } = msg {
                    let now = counted.fetch_add(1, Ordering::SeqCst) + 1;
                    max_outstanding.fetch_max(now, Ordering::SeqCst);
                    if tx.send((Instant::now(), index, begin, length)).is_err() {
                        return;
                    }
                }
            }
        });
        while let Ok((arrived, index, begin, length)) = rx.recv() {
            let due = arrived + latency;
            if let Some(wait) = due.checked_duration_since(Instant::now()) {
                thread::sleep(wait);
            }
            let piece = &pieces[index as usize];
            let block = piece[begin as usize..(begin + length) as usize].to_vec();
            let reply = WireMessage::Piece { index, begin, block };
            if reply.write_to(&mut stream).is_err() {
                return;
            }
            outstanding.fetch_sub(1, Ordering::SeqCst);
        }
    })
}

/// Downloads `piece_count` pieces of `piece_len` bytes from a laggy peer,
/// with the given minimum queue depth. Returns how long it took, the most
/// requests the peer ever had waiting, and whether the pieces on disk are right.
fn download_from_laggy_peer(name: &str, piece_count: usize, piece_len: usize, latency: Duration, reqq: Option<u32>, min_depth: usize) -> (Duration, usize, bool) {
    let pieces: Vec<Vec<u8>> = (0..piece_count).map(|i| (0..piece_len).map(|b| (b as u8).wrapping_mul(7).wrapping_add(i as u8)).collect()).collect();
    let info_hash = [0x62; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let max_outstanding = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peer = spawn_laggy_peer(listener, info_hash, pieces.clone(), latency, reqq, Arc::clone(&max_outstanding));

    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: piece_len as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, piece_count));
    let dir = tmp_dir(name);
    let total = (piece_count * piece_len) as i64;
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], total)]));
    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: min_depth, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    let started = Instant::now();
    run_worker(addr, &config, &queue, &spans, piece_len as u64, &tx, None).unwrap();
    let took = started.elapsed();
    peer.join().unwrap();

    let mut on_disk = Vec::new();
    fs::File::open(dir.join("out.bin")).unwrap().read_to_end(&mut on_disk).unwrap();
    (took, max_outstanding.load(std::sync::atomic::Ordering::SeqCst), on_disk == pieces.concat())
}

#[test]
fn a_long_round_trip_is_hidden_by_queueing_more_requests_to_a_peer_that_keeps_up() {
    const LATENCY: Duration = Duration::from_millis(20);
    const MIN_DEPTH: usize = 2;
    let (pieces, piece_len) = (16, 256 * 1024);
    let blocks = pieces * piece_len / 16384;

    let (took, _, correct) = download_from_laggy_peer("adaptive-speed", pieces, piece_len, LATENCY, None, MIN_DEPTH);

    assert!(correct, "every byte arrived intact");
    // Kept at the minimum, one round trip fetches MIN_DEPTH blocks.
    let at_the_minimum = LATENCY * (blocks / MIN_DEPTH) as u32;
    assert!(took < at_the_minimum / 2, "took {:?}; a fixed queue of {} would need {:?}", took, MIN_DEPTH, at_the_minimum);
}

#[test]
fn a_peer_is_never_sent_more_requests_than_it_said_it_will_queue() {
    // A round trip long enough that three requests are in flight together whatever the scheduler does
    // (at 5 ms a busy machine, a CI runner, did not always have them overlap), and enough blocks for
    // the rate to be known and the queue to have grown.
    let (took, most_waiting, correct) = download_from_laggy_peer("reqq", 6, 64 * 1024, Duration::from_millis(30), Some(3), 2);

    assert!(correct);
    assert!(most_waiting <= 3, "the peer had {} requests waiting though it said it queues 3", most_waiting);
    assert_eq!(most_waiting, 3, "and the queue did grow to what the peer allows ({:?})", took);
}

#[test]
fn a_peer_that_says_nothing_is_still_kept_to_a_cautious_queue() {
    // Fast enough and long enough that the rate asks for far more than the
    // default limit; the peer must not be sent more than that.
    let (_, most_waiting, correct) = download_from_laggy_peer("default-limit", 8, 256 * 1024, Duration::from_millis(10), None, 2);

    assert!(correct);
    assert!(most_waiting <= pipeline::DEFAULT_PEER_LIMIT, "{} waiting", most_waiting);
    assert!(most_waiting > 2, "and more than the minimum, or the rate was never used: {}", most_waiting);
}

// ---- a peer that has only some of the pieces ----

/// A peer that has only the pieces in `has`, serves requests for them, and
/// hangs up once it has served `hang_up_after` blocks.
fn spawn_partial_peer(listener: TcpListener, info_hash: [u8; 20], pieces: Vec<Vec<u8>>, has: Vec<usize>, hang_up_after: usize) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hs_buf = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], false).to_bytes()).unwrap();
        let mut bits = vec![0u8; pieces.len().div_ceil(8)];
        for &i in &has {
            bits[i / 8] |= 1 << (7 - (i % 8));
        }
        WireMessage::Bitfield(bits).write_to(&mut stream).unwrap();
        WireMessage::Unchoke.write_to(&mut stream).unwrap();

        let mut served = 0;
        while served < hang_up_after {
            let Ok(msg) = WireMessage::read_from(&mut stream) else { return };
            if let WireMessage::Request { index, begin, length } = msg {
                if !has.contains(&(index as usize)) {
                    continue; // asked for what it never had
                }
                let block = pieces[index as usize][begin as usize..(begin + length) as usize].to_vec();
                if (WireMessage::Piece { index, begin, block }).write_to(&mut stream).is_err() {
                    return;
                }
                served += 1;
            }
        }
    })
}

#[test]
fn a_peer_with_only_common_pieces_is_given_those_even_while_a_rarer_one_is_still_unclaimed() {
    let pieces: Vec<Vec<u8>> = (0..3u8).map(|i| vec![0xA0 + i; 16384]).collect();
    let info_hash = [0x63; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // The peer has pieces 1 and 2, and hangs up after serving them.
    let peer = spawn_partial_peer(listener, info_hash, pieces.clone(), vec![1, 2], 2);

    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: 16384, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, 3));
    // Piece 0 is the rarest by a distance: the swarm has been seen with 1 and 2 twice.
    for piece in [1, 2, 1, 2] {
        queue.note_have(piece);
    }
    let dir = tmp_dir("partial-peer");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 3 * 16384)]));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    let result = run_worker(addr, &config, &queue, &spans, 16384, &tx, None);
    peer.join().unwrap();

    let mut got: Vec<u32> = rx.try_iter().map(|r| r.index).collect();
    got.sort_unstable();
    assert_eq!(got, vec![1, 2], "the pieces it has were downloaded, though piece 0 was rarer and this peer lacks it");
    assert!(matches!(result, Err(WorkerError::Connection { stage: "wait_for_relevant_have", .. })), "then it waited for something more from the peer, and the hang-up ended it: {:?}", result);
    assert_eq!(queue.len(), 1, "piece 0 is untouched, for a peer that has it");
    assert!(!queue.in_endgame(), "and was never claimed");
}

#[test]
fn a_sequential_queue_is_downloaded_in_order_and_a_rarest_first_one_is_not() {
    // Pieces 2 and 3 are the rare ones: the swarm has been seen with 0 and 1.
    let download_order = |name: &str, order: Order| -> Vec<u32> {
        let pieces: Vec<Vec<u8>> = (0..4u8).map(|i| vec![0xD0 + i; 16384]).collect();
        let info_hash = [0x64; 20];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = spawn_mock_peer(listener, info_hash, pieces.clone(), Duration::ZERO);
        let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: 16384, merkle: None }).collect();
        let queue = Arc::new(WorkQueue::new(work, 4).with_order(order));
        queue.note_have(0);
        queue.note_have(1);
        let dir = tmp_dir(name);
        let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 4 * 16384)]));
        let (tx, rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

        run_worker(addr, &config, &queue, &spans, 16384, &tx, None).unwrap();
        mock.join().unwrap();
        rx.try_iter().map(|r| r.index).collect()
    };

    assert_eq!(download_order("order-sequential", Order::Sequential), vec![0, 1, 2, 3]);
    assert_eq!(download_order("order-rarest", Order::RarestFirst), vec![2, 3, 0, 1], "the same swarm, fetched rare pieces first");
}

// ---- a peer that chokes us in the middle of things ----

/// What a choking peer saw.
struct ChokerLog {
    /// Requests that arrived while it had the client choked, and so ignored,
    /// as a real peer does.
    ignored_while_choked: usize,
}

/// A peer that serves `serve_before_choke` blocks, then chokes the client
/// and ignores its requests until `choked_for` has passed (for good, with
/// `None`), and then unchokes it and serves again.
fn spawn_choking_peer(listener: TcpListener, info_hash: [u8; 20], pieces: Vec<Vec<u8>>, serve_before_choke: usize, choked_for: Option<Duration>) -> thread::JoinHandle<ChokerLog> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hs_buf = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], false).to_bytes()).unwrap();
        let mut bits = vec![0u8; pieces.len().div_ceil(8)];
        for i in 0..pieces.len() {
            bits[i / 8] |= 1 << (7 - (i % 8));
        }
        WireMessage::Bitfield(bits).write_to(&mut stream).unwrap();
        WireMessage::Unchoke.write_to(&mut stream).unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(30))).unwrap();

        let mut log = ChokerLog { ignored_while_choked: 0 };
        let (mut served, mut choked_until, mut choke_done) = (0usize, None::<Instant>, false);
        loop {
            if let (Some(until), Some(_)) = (choked_until, choked_for) {
                if Instant::now() >= until {
                    if WireMessage::Unchoke.write_to(&mut stream).is_err() {
                        return log;
                    }
                    choked_until = None;
                }
            }
            match WireMessage::read_from(&mut stream) {
                Ok(WireMessage::Request { index, begin, length }) => {
                    if choked_until.is_some() {
                        log.ignored_while_choked += 1;
                        continue;
                    }
                    let block = pieces[index as usize][begin as usize..(begin + length) as usize].to_vec();
                    if (WireMessage::Piece { index, begin, block }).write_to(&mut stream).is_err() {
                        return log;
                    }
                    served += 1;
                    if !choke_done && served == serve_before_choke {
                        choke_done = true;
                        if WireMessage::Choke.write_to(&mut stream).is_err() {
                            return log;
                        }
                        // "For good" is an hour: longer than any test.
                        choked_until = Some(Instant::now() + choked_for.unwrap_or(Duration::from_secs(3600)));
                    }
                }
                Ok(_) => {}
                Err(WireError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => return log,
            }
        }
    })
}

/// Two pieces of four blocks each, from a peer that chokes after serving
/// `serve_before_choke` blocks for `choked_for`, with a client read timeout
/// of `read_timeout`.
fn download_through_a_choke(name: &str, serve_before_choke: usize, choked_for: Duration, read_timeout: Duration) -> (Result<(), WorkerError>, ChokerLog, Vec<u32>) {
    let pieces: Vec<Vec<u8>> = (0..2u8).map(|i| (0..4 * 16384).map(|b| (b as u8).wrapping_mul(11).wrapping_add(i)).collect()).collect();
    let info_hash = [0x65; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = spawn_choking_peer(listener, info_hash, pieces.clone(), serve_before_choke, Some(choked_for));

    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: p.len() as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, 2));
    let dir = tmp_dir(name);
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 8 * 16384)]));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 4, connect_timeout: read_timeout, down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    let result = run_worker(addr, &config, &queue, &spans, 4 * 16384, &tx, None);
    drop(tx);
    let mut got: Vec<u32> = rx.try_iter().map(|r| r.index).collect();
    got.sort_unstable();
    // Hang up so the peer's loop ends and it can be joined.
    drop(config);
    let log = peer.join().unwrap();
    (result, log, got)
}

#[test]
fn a_choke_at_any_point_is_waited_out_and_the_missing_blocks_are_asked_for_again() {
    // Mid-way through the first piece, exactly between the pieces, and
    // mid-way through the second. The choke lasts three read timeouts.
    for serve_before_choke in [2, 4, 6] {
        let (result, log, got) = download_through_a_choke(&format!("choke-{}", serve_before_choke), serve_before_choke, Duration::from_millis(600), Duration::from_millis(200));

        assert!(result.is_ok(), "choked after {} blocks: {:?}", serve_before_choke, result);
        assert_eq!(got, vec![0, 1], "choked after {} blocks: both pieces arrived and verified", serve_before_choke);
        assert!(log.ignored_while_choked > 0, "choked after {} blocks: the peer discarded requests, so some had to be sent again", serve_before_choke);
        // What was already on its way when the choke came -- with the requests going on across piece boundaries, up to both
        // pieces' worth (8 blocks) -- and no more: a client that kept asking while choked would send that many
        // again on every quiet spell (three of them here).
        assert!(log.ignored_while_choked <= 8, "choked after {} blocks: {} requests reached a peer that had us choked", serve_before_choke, log.ignored_while_choked);
    }
}

#[test]
fn a_peer_that_chokes_and_never_unchokes_is_given_up_on_and_the_piece_goes_back() {
    let pieces: Vec<Vec<u8>> = vec![vec![0x5A; 4 * 16384]];
    let info_hash = [0x66; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _peer = spawn_choking_peer(listener, info_hash, pieces.clone(), 1, None);
    let queue = Arc::new(WorkQueue::new(vec![PieceWork { index: 0, hash: sha1_of(&pieces[0]), length: 4 * 16384, merkle: None }], 1));
    let dir = tmp_dir("choked-for-good");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 4 * 16384)]));
    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 4, connect_timeout: Duration::from_millis(100), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    // Run it where a failure to give up shows as a failed test, not a hung one.
    let (done_tx, done_rx) = mpsc::channel();
    let worker_queue = Arc::clone(&queue);
    thread::spawn(move || {
        let _ = done_tx.send(run_worker(addr, &config, &worker_queue, &spans, 4 * 16384, &tx, None));
    });
    let result = done_rx.recv_timeout(Duration::from_secs(15)).expect("the worker should have given up on a peer that never unchokes");

    assert!(matches!(result, Err(WorkerError::Connection { stage: "peer_choked_us_mid_piece", .. })), "{:?}", result);
    assert_eq!(queue.len(), 1, "the piece is back on the queue for another peer");
    assert!(!queue.in_endgame());
}

#[test]
fn stopping_does_not_wait_for_a_worker_held_back_by_the_download_limit() {
    // 10 B/s: the one 16 KiB block just read must be paid for over about
    // 1600 seconds. The interrupt has to cut that short.
    let piece = vec![0x3Cu8; 16384];
    let info_hash = [0x67; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _mock = spawn_mock_peer(listener, info_hash, vec![piece.clone()], Duration::ZERO);
    let queue = Arc::new(WorkQueue::new(vec![PieceWork { index: 0, hash: sha1_of(&piece), length: 16384, merkle: None }], 1));
    let dir = tmp_dir("limit-interrupt");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 16384)]));
    let (tx, _rx) = mpsc::channel();
    let config = Arc::new(WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: Some(Arc::new(RateLimiter::new(10))), interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None });

    let (done_tx, done_rx) = mpsc::channel();
    let worker_config = Arc::clone(&config);
    thread::spawn(move || {
        let _ = done_tx.send(run_worker(addr, &worker_config, &queue, &spans, 16384, &tx, None));
    });
    thread::sleep(Duration::from_millis(500)); // the block has arrived and the worker is paying for it
    let stopped_at = Instant::now();
    config.interrupt.trigger();

    let ended = done_rx.recv_timeout(Duration::from_secs(5));
    assert!(ended.is_ok(), "the worker should stop within seconds, not sleep out the limit");
    assert!(stopped_at.elapsed() < Duration::from_secs(2), "{:?}", stopped_at.elapsed());
}

// ---- handing a piece on when a peer fails part-way ----

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    /// The first block it sends has a byte wrong.
    FirstBlockWrong,
    /// Every block it sends has a byte wrong.
    EveryBlockWrong,
}

/// A peer that has every piece, records each request it gets as
/// `(piece, begin)`, hangs up after serving `hang_up_after` blocks (never,
/// with `None`), and can send wrong bytes.
fn spawn_recording_peer(listener: TcpListener, info_hash: [u8; 20], pieces: Vec<Vec<u8>>, hang_up_after: Option<usize>, fault: Fault, requests: Arc<std::sync::Mutex<Vec<(u32, u32)>>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut hs_buf = [0u8; 68];
        std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], false).to_bytes()).unwrap();
        let mut bits = vec![0u8; pieces.len().div_ceil(8)];
        for i in 0..pieces.len() {
            bits[i / 8] |= 1 << (7 - (i % 8));
        }
        WireMessage::Bitfield(bits).write_to(&mut stream).unwrap();
        WireMessage::Unchoke.write_to(&mut stream).unwrap();

        let mut served = 0usize;
        while hang_up_after.is_none_or(|limit| served < limit) {
            let Ok(msg) = WireMessage::read_from(&mut stream) else { return };
            if let WireMessage::Request { index, begin, length } = msg {
                requests.lock().unwrap().push((index, begin));
                let mut block = pieces[index as usize][begin as usize..(begin + length) as usize].to_vec();
                if fault == Fault::EveryBlockWrong || (fault == Fault::FirstBlockWrong && served == 0) {
                    block[0] ^= 0xFF;
                }
                if (WireMessage::Piece { index, begin, block }).write_to(&mut stream).is_err() {
                    return;
                }
                served += 1;
            }
        }
        // Hangs up as a peer that closes properly does: FIN after what was sent, then the requests it did not read
        // are read and dropped. Closing with them unread makes Linux send a reset, which discards what the client
        // has been sent and not yet read: the blocks served just before would be lost, not delivered and then cut off.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut sink = [0u8; 4096];
        while std::io::Read::read(&mut stream, &mut sink).is_ok_and(|n| n > 0) {}
    })
}

/// One piece of four blocks; a first peer with `first_fault` that hangs up
/// after `first_serves` blocks, then a second with `second_fault` that stays.
/// Returns what each was asked for, what the workers returned, and whether
/// the piece arrived.
struct HandOver {
    first_asked: Vec<(u32, u32)>,
    second_asked: Vec<(u32, u32)>,
    first_result: Result<(), WorkerError>,
    second_result: Result<(), WorkerError>,
    delivered: bool,
    queue_len_after_first: usize,
}

fn hand_a_piece_over(name: &str, first_serves: usize, first_fault: Fault, second_fault: Fault) -> HandOver {
    let piece: Vec<u8> = (0..4 * 16384).map(|b| (b as u8).wrapping_mul(13).wrapping_add(1)).collect();
    let info_hash = [0x68; 20];
    let queue = Arc::new(WorkQueue::new(vec![PieceWork { index: 0, hash: sha1_of(&piece), length: piece.len() as u32, merkle: None }], 1));
    let dir = tmp_dir(name);
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], piece.len() as i64)]));
    let (tx, rx) = mpsc::channel();
    // Four requests at once, so that whatever the first peer serves is a
    // known prefix of the piece.
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 4, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    let run = |hang_up_after: Option<usize>, fault: Fault| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let peer = spawn_recording_peer(listener, info_hash, vec![piece.clone()], hang_up_after, fault, Arc::clone(&requests));
        let result = run_worker(addr, &config, &queue, &spans, piece.len() as u64, &tx, None);
        peer.join().unwrap();
        let asked = requests.lock().unwrap().clone();
        (result, asked)
    };

    let (first_result, first_asked) = run(Some(first_serves), first_fault);
    let queue_len_after_first = queue.len();
    let (second_result, second_asked) = run(None, second_fault);
    let delivered = rx.try_iter().any(|r| r.index == 0 && r.data == piece);
    HandOver { first_asked, second_asked, first_result, second_result, delivered, queue_len_after_first }
}

#[test]
fn a_piece_a_peer_dropped_part_way_is_finished_by_the_next_asking_only_for_what_is_missing() {
    let h = hand_a_piece_over("hand-over", 2, Fault::None, Fault::None);

    assert!(h.first_result.is_err(), "the first peer hung up");
    assert_eq!(h.queue_len_after_first, 1, "the piece is back on the queue");
    assert!(h.first_asked.len() >= 2, "it was asked for blocks and served the first two before it left");
    let mut second: Vec<u32> = h.second_asked.iter().map(|&(_, begin)| begin).collect();
    second.sort_unstable();
    assert_eq!(second, vec![2 * 16384, 3 * 16384], "the second was asked only for blocks 2 and 3");
    assert!(h.second_result.is_ok());
    assert!(h.delivered, "and the piece verifies and arrives whole");
}

#[test]
fn a_peer_that_dropped_before_any_block_leaves_nothing_and_the_next_asks_for_everything() {
    let h = hand_a_piece_over("hand-over-nothing", 0, Fault::None, Fault::None);

    assert_eq!(h.second_asked.len(), 4);
    assert!(h.delivered);
}

#[test]
fn a_bad_block_from_the_first_peer_costs_the_second_a_refetch_not_its_reputation() {
    // The first peer sends block 0 with a byte wrong, then blocks 1, then leaves.
    let h = hand_a_piece_over("hand-over-bad-block", 2, Fault::FirstBlockWrong, Fault::None);

    assert!(h.second_result.is_ok(), "the second peer is not blamed for the first one's block: {:?}", h.second_result);
    assert!(h.delivered, "the piece was fetched again from the second peer and verified");
    let mut second: Vec<u32> = h.second_asked.iter().map(|&(_, begin)| begin).collect();
    second.sort_unstable();
    assert_eq!(second, vec![0, 16384, 2 * 16384, 2 * 16384, 3 * 16384, 3 * 16384], "blocks 2 and 3 first, then all four again from this peer alone");
}

#[test]
fn a_peer_that_is_itself_wrong_is_blamed_once_the_piece_has_been_fetched_from_it_alone() {
    let h = hand_a_piece_over("hand-over-liar", 2, Fault::None, Fault::EveryBlockWrong);

    assert!(matches!(h.second_result, Err(WorkerError::PieceHashMismatch)), "{:?}", h.second_result);
    assert!(!h.delivered, "nothing unverified was accepted");
    assert_eq!(h.second_asked.len(), 2 + 4, "blocks 2 and 3 on top of the first peer's, then the whole piece again from it alone");
}

// ---- the peer table's numbers ----

#[test]
fn a_worker_is_listed_while_it_runs_with_its_bytes_and_removed_when_it_ends() {
    // A slow peer, so the worker is seen mid-download.
    let pieces: Vec<Vec<u8>> = (0..2u8).map(|i| vec![0x40 + i; 64 * 1024]).collect();
    let info_hash = [0x69; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = spawn_laggy_peer(listener, info_hash, pieces.clone(), Duration::from_millis(150), None, Arc::new(std::sync::atomic::AtomicUsize::new(0)));
    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: p.len() as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, 2));
    let dir = tmp_dir("peer-table");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 128 * 1024)]));
    let (tx, _rx) = mpsc::channel();
    let config = Arc::new(WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 4, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None });

    let worker = {
        let (config, queue, spans) = (Arc::clone(&config), Arc::clone(&queue), Arc::clone(&spans));
        thread::spawn(move || run_worker(addr, &config, &queue, &spans, 64 * 1024, &tx, None))
    };
    let mut seen_downloading_with_bytes = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !worker.is_finished() && Instant::now() < deadline {
        let rows = config.peers.rows(Instant::now());
        if let Some(row) = rows.first() {
            assert_eq!(row.addr, addr.to_string());
            if row.activity == "downloading" && row.bytes > 0 {
                seen_downloading_with_bytes = true;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    worker.join().unwrap().unwrap();
    peer.join().unwrap();

    assert!(seen_downloading_with_bytes, "while it ran the peer was listed as downloading, with bytes");
    assert!(config.peers.is_empty(), "and once it ended it was gone");
}

#[test]
fn a_worker_whose_peer_has_us_choked_is_listed_as_choked() {
    let piece = vec![0x77u8; 4 * 16384];
    let info_hash = [0x6a; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Chokes after one block for good; the worker waits (up to its patience) in that state.
    let _peer = spawn_choking_peer(listener, info_hash, vec![piece.clone()], 1, None);
    let queue = Arc::new(WorkQueue::new(vec![PieceWork { index: 0, hash: sha1_of(&piece), length: piece.len() as u32, merkle: None }], 1));
    let dir = tmp_dir("peer-table-choked");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], piece.len() as i64)]));
    let (tx, _rx) = mpsc::channel();
    let config = Arc::new(WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 4, connect_timeout: Duration::from_millis(300), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None });
    let worker = {
        let (config, queue, spans) = (Arc::clone(&config), Arc::clone(&queue), Arc::clone(&spans));
        thread::spawn(move || run_worker(addr, &config, &queue, &spans, piece.len() as u64, &tx, None))
    };

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut saw_choked = false;
    while Instant::now() < deadline && !worker.is_finished() {
        if config.peers.rows(Instant::now()).first().is_some_and(|row| row.activity == "choked") {
            saw_choked = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    config.interrupt.trigger();
    let _ = worker.join();

    assert!(saw_choked, "a peer that has us choked is shown as choked");
}

#[test]
fn a_worker_with_nothing_to_fetch_from_its_peer_is_listed_as_idle() {
    let pieces: Vec<Vec<u8>> = vec![vec![1u8; 16384], vec![2u8; 16384]];
    let info_hash = [0x6b; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // The peer has only piece 1, and stays connected once it has served it (never hangs up).
    let _peer = spawn_partial_peer(listener, info_hash, pieces.clone(), vec![1], usize::MAX);
    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: p.len() as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, 2));
    let dir = tmp_dir("peer-table-idle");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 32768)]));
    let (tx, _rx) = mpsc::channel();
    let config = Arc::new(WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 4, connect_timeout: Duration::from_millis(300), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None });
    let worker = {
        let (config, queue, spans) = (Arc::clone(&config), Arc::clone(&queue), Arc::clone(&spans));
        thread::spawn(move || run_worker(addr, &config, &queue, &spans, 16384, &tx, None))
    };

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut saw_idle = false;
    while Instant::now() < deadline && !worker.is_finished() {
        if config.peers.rows(Instant::now()).first().is_some_and(|row| row.activity == "idle") {
            saw_idle = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    config.interrupt.trigger();
    let _ = worker.join();

    assert!(saw_idle, "after fetching what the peer had, with piece 0 still wanted and nowhere to get it, the peer is idle");
}

// ---- over an encrypted connection ----

/// Downloads two pieces from a mock peer that takes encrypted connections,
/// with the worker set to `encryption`. Returns the worker's result and
/// whether both pieces arrived intact.
fn download_with_encryption(name: &str, peer_takes: crate::peer::Encryption, worker_uses: crate::peer::Encryption) -> (Result<(), WorkerError>, bool) {
    let pieces: Vec<Vec<u8>> = (0..2u8).map(|i| vec![0x30 + i; 16384]).collect();
    let info_hash = [0x6c; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = spawn_mock_peer_with(listener, info_hash, pieces.clone(), Duration::ZERO, peer_takes);
    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: p.len() as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, 2));
    let dir = tmp_dir(name);
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 32768)]));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: worker_uses, transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    let result = run_worker(addr, &config, &queue, &spans, 16384, &tx, None);
    let _ = mock.join();

    let mut got: Vec<(u32, Vec<u8>)> = rx.try_iter().map(|r| (r.index, r.data)).collect();
    got.sort();
    (result, got.len() == 2 && got.iter().all(|(i, d)| *d == pieces[*i as usize]))
}

#[test]
fn a_worker_downloads_over_an_encrypted_connection() {
    let (result, intact) = download_with_encryption("mse-worker", crate::peer::Encryption::Prefer, crate::peer::Encryption::Require);
    assert!(result.is_ok(), "{:?}", result);
    assert!(intact, "every byte came through the cipher intact");
}

#[test]
fn a_worker_that_prefers_encryption_downloads_from_a_peer_that_only_speaks_plain() {
    // The peer's own accept() is set to Off, so an encrypted attempt is garbage to it and it hangs up.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pieces = [vec![0x44u8; 16384]];
    let info_hash = [0x6d; 20];
    let plain_peer = thread::spawn(move || {
        // The first connection is the encrypted try, which it refuses; the second is plain.
        let (first, _) = listener.accept().unwrap();
        first.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(crate::peer::mse::accept(Box::new(first), &[info_hash], crate::peer::Encryption::Off).is_err());
        let mock = spawn_mock_peer_with(listener, info_hash, vec![vec![0x44u8; 16384]], Duration::ZERO, crate::peer::Encryption::Off);
        mock.join().unwrap();
    });
    let queue = Arc::new(WorkQueue::new(vec![PieceWork { index: 0, hash: sha1_of(&pieces[0]), length: 16384, merkle: None }], 1));
    let dir = tmp_dir("mse-fallback");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 16384)]));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: crate::peer::Encryption::Prefer, transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    run_worker(addr, &config, &queue, &spans, 16384, &tx, None).expect("fell back to a plain connection");
    plain_peer.join().unwrap();

    assert_eq!(rx.try_iter().count(), 1);
}

#[test]
fn a_worker_that_requires_encryption_gives_up_on_a_peer_that_will_not() {
    let (result, _) = download_with_encryption("mse-required", crate::peer::Encryption::Off, crate::peer::Encryption::Require);
    assert!(matches!(result, Err(WorkerError::Connection { stage: "connect_and_handshake", .. })), "{:?}", result);
}

// ---- the Fast Extension (BEP 6) ----

/// A fake peer on the Fast Extension. After the handshake it sends `opening`
/// (each message after its delay), then passes every `Request` to
/// `on_request` -- which answers through the stream, given the request's
/// `(index, begin, length)` and how many came before it -- until that says
/// to stop, the worker hangs up, or a second goes by in silence. Returns
/// every request it saw, in order.
fn spawn_fast_peer<F>(listener: TcpListener, info_hash: [u8; 20], opening: Vec<(Duration, WireMessage)>, mut on_request: F) -> thread::JoinHandle<Vec<(u32, u32, u32)>>
where
    F: FnMut(&mut TcpStream, (u32, u32, u32), usize) -> bool + Send + 'static,
{
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut hs_buf = [0u8; 68];
        stream.read_exact(&mut hs_buf).unwrap();
        assert!(Handshake::from_bytes(&hs_buf).unwrap().supports_fast(), "the worker offers the Fast Extension");
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], false).with_fast(true).to_bytes()).unwrap();
        for (delay, msg) in opening {
            thread::sleep(delay);
            msg.write_to(&mut stream).unwrap();
        }
        stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        let mut seen = Vec::new();
        while let Ok(msg) = WireMessage::read_from(&mut stream) {
            if let WireMessage::Request { index, begin, length } = msg {
                seen.push((index, begin, length));
                if !on_request(&mut stream, (index, begin, length), seen.len() - 1) {
                    break;
                }
            }
        }
        seen
    })
}

/// A worker for a torrent of `pieces` (one file, pieces of `piece_length`) against `addr`, with short timeouts.
fn run_fast_worker(name: &str, addr: std::net::SocketAddr, info_hash: [u8; 20], pieces: &[Vec<u8>], piece_length: u32, pipeline_depth: usize) -> (Result<(), WorkerError>, Arc<WorkQueue>, Vec<crate::downloader::queue::PieceResult>) {
    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: p.len() as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, pieces.len()));
    let total: usize = pieces.iter().map(Vec::len).sum();
    let dir = tmp_dir(name);
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], total as i64)]));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth, connect_timeout: Duration::from_millis(100), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };
    let result = run_worker(addr, &config, &queue, &spans, piece_length as u64, &tx, None);
    drop(tx);
    (result, queue, rx.try_iter().collect())
}

fn serve(stream: &mut TcpStream, pieces: &[Vec<u8>], (index, begin, length): (u32, u32, u32)) {
    let block = pieces[index as usize][begin as usize..(begin + length) as usize].to_vec();
    WireMessage::Piece { index, begin, block }.write_to(stream).unwrap();
}

#[test]
fn a_fast_peer_is_downloaded_from_while_it_still_has_us_choked() {
    // The peer sends HaveAll, allows piece 1 (not piece 0, which the worker
    // would otherwise ask for first) and does not unchoke -- until it has served that piece. A worker that waited for an unchoke first would
    // wait for ever, and one that asked for piece 1 too soon would be rejected.
    let pieces = vec![vec![0xA1u8; 16384], vec![0xB2u8; 16384]];
    let info_hash = [0x51; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = pieces.clone();
    let mut unchoked = false;
    let too_early = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let early = Arc::clone(&too_early);
    let peer = spawn_fast_peer(listener, info_hash, vec![(Duration::ZERO, WireMessage::HaveAll), (Duration::ZERO, WireMessage::AllowedFast { piece_index: 1 })], move |stream, request, _| {
        if request.0 != 1 && !unchoked {
            early.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            WireMessage::RejectRequest { index: request.0, begin: request.1, length: request.2 }.write_to(stream).unwrap();
            return true;
        }
        serve(stream, &served, request);
        if !unchoked {
            unchoked = true;
            WireMessage::Unchoke.write_to(stream).unwrap();
        }
        true
    });

    let (result, queue, results) = run_fast_worker("fast-allowed", addr, info_hash, &pieces, 16384, 2);

    result.expect("the worker finished the torrent");
    let seen = peer.join().unwrap();
    assert_eq!(seen, vec![(1, 0, 16384), (0, 0, 16384)], "the allowed piece first, the other only after the unchoke");
    assert_eq!(too_early.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing asked for while choked that the peer had not allowed");
    assert!(queue.is_empty());
    assert_eq!(results.len(), 2);
}

#[test]
fn a_peer_that_only_says_have_all_has_every_piece() {
    // No bitfield anywhere: the pieces the worker is willing to ask for come from HaveAll alone.
    let pieces = vec![vec![1u8; 16384], vec![2u8; 16384], vec![3u8; 16384]];
    let info_hash = [0x52; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = pieces.clone();
    let peer = spawn_fast_peer(listener, info_hash, vec![(Duration::ZERO, WireMessage::HaveAll), (Duration::ZERO, WireMessage::Unchoke)], move |stream, request, _| {
        serve(stream, &served, request);
        true
    });

    let (result, queue, results) = run_fast_worker("fast-have-all", addr, info_hash, &pieces, 16384, 2);

    result.unwrap();
    assert_eq!(peer.join().unwrap().len(), 3);
    assert!(queue.is_empty());
    assert_eq!(results.len(), 3);
}

#[test]
fn a_peer_that_starts_with_have_none_is_kept_until_it_has_something() {
    let pieces = vec![vec![7u8; 16384]];
    let info_hash = [0x53; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = pieces.clone();
    let opening = vec![(Duration::ZERO, WireMessage::HaveNone), (Duration::ZERO, WireMessage::Unchoke), (Duration::from_millis(250), WireMessage::Have { piece_index: 0 })];
    let peer = spawn_fast_peer(listener, info_hash, opening, move |stream, request, _| {
        serve(stream, &served, request);
        true
    });

    let (result, _, results) = run_fast_worker("fast-have-none", addr, info_hash, &pieces, 16384, 2);

    result.unwrap();
    assert_eq!(peer.join().unwrap().len(), 1);
    assert_eq!(results.len(), 1);
}

#[test]
fn a_request_the_peer_rejects_is_made_again() {
    let pieces = vec![vec![9u8; 16384]];
    let info_hash = [0x54; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = pieces.clone();
    let peer = spawn_fast_peer(listener, info_hash, vec![(Duration::ZERO, WireMessage::HaveAll), (Duration::ZERO, WireMessage::Unchoke)], move |stream, request, nth| {
        if nth < 2 {
            WireMessage::RejectRequest { index: request.0, begin: request.1, length: request.2 }.write_to(stream).unwrap();
        } else {
            serve(stream, &served, request);
        }
        true
    });

    let (result, _, results) = run_fast_worker("fast-reject-retry", addr, info_hash, &pieces, 16384, 2);

    result.expect("two refusals are not the end of the piece");
    assert_eq!(peer.join().unwrap(), vec![(0, 0, 16384); 3], "the same block asked for three times");
    assert_eq!(results[0].data, pieces[0]);
}

#[test]
fn a_peer_that_never_stops_refusing_is_given_up_on_for_that_piece_and_the_piece_goes_back() {
    let pieces = vec![vec![9u8; 16384]];
    let info_hash = [0x55; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = spawn_fast_peer(listener, info_hash, vec![(Duration::ZERO, WireMessage::HaveAll), (Duration::ZERO, WireMessage::Unchoke)], move |stream, request, nth| {
        WireMessage::RejectRequest { index: request.0, begin: request.1, length: request.2 }.write_to(stream).unwrap();
        nth < 40 // a worker that never gives up is cut off here
    });

    let (result, queue, results) = run_fast_worker("fast-reject-forever", addr, info_hash, &pieces, 16384, 2);

    // The worker stopped asking of its own accord, with the piece back in the queue for someone else.
    assert_eq!(peer.join().unwrap().len(), 8, "asked as many times as it puts up with");
    assert!(matches!(result, Err(WorkerError::Connection { stage: "wait_for_relevant_have", .. })), "it went on to wait for something else, not to drop the peer over a piece: {:?}", result);
    assert_eq!(queue.len(), 1, "the piece is still to be had");
    assert!(results.is_empty());
}

#[test]
fn what_a_peer_rejects_after_choking_us_is_not_held_against_it() {
    // BEP 6: a choke no longer discards the peer's queue silently; it rejects each request. The
    // worker has already forgotten those, so the rejections are not news (and a dozen of
    // them are not a peer refusing), and the piece is asked for again once the peer unchokes.
    const BLOCKS: usize = 12;
    let pieces = vec![vec![5u8; 16384 * BLOCKS]];
    let info_hash = [0x56; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = pieces.clone();
    let peer = spawn_fast_peer(listener, info_hash, vec![(Duration::ZERO, WireMessage::HaveAll), (Duration::ZERO, WireMessage::Unchoke)], move |stream, request, nth| {
        if nth < BLOCKS {
            if nth == 0 {
                WireMessage::Choke.write_to(stream).unwrap();
            }
            WireMessage::RejectRequest { index: request.0, begin: request.1, length: request.2 }.write_to(stream).unwrap();
            if nth == BLOCKS - 1 {
                WireMessage::Unchoke.write_to(stream).unwrap();
            }
        } else {
            serve(stream, &served, request);
        }
        true
    });

    let (result, _, results) = run_fast_worker("fast-choke-rejects", addr, info_hash, &pieces, 16384 * BLOCKS as u32, BLOCKS);

    result.expect("the rejections that followed the choke were not counted against the peer");
    assert_eq!(peer.join().unwrap().len(), 2 * BLOCKS, "every block twice: once before the choke, once after");
    assert_eq!(results[0].data, pieces[0]);
}

#[test]
fn a_peer_that_chokes_between_pieces_and_stays_silent_is_kept_alive_for_a_while_and_then_left() {
    // Not mid-piece: the worker has nothing it may ask for, so it waits -- as
    // long as it would have for a first unchoke, telling the peer it is still here.
    let pieces = vec![vec![3u8; 16384], vec![4u8; 16384]];
    let info_hash = [0x57; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = pieces.clone();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut hs_buf = [0u8; 68];
        stream.read_exact(&mut hs_buf).unwrap();
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], false).to_bytes()).unwrap();
        WireMessage::Bitfield(vec![0b1100_0000]).write_to(&mut stream).unwrap();
        WireMessage::Unchoke.write_to(&mut stream).unwrap();
        let mut keepalives = 0;
        while let Ok(msg) = WireMessage::read_from(&mut stream) {
            match msg {
                WireMessage::Request { index, begin, length } => {
                    // The choke goes first, so that the worker has seen it by the time the piece is in.
                    WireMessage::Choke.write_to(&mut stream).unwrap();
                    serve(&mut stream, &served, (index, begin, length));
                }
                WireMessage::KeepAlive => keepalives += 1,
                _ => {}
            }
        }
        keepalives
    });

    let started = Instant::now();
    // (A depth of one: with more, the second piece would be asked for before the choke came, as a pipeline that goes on
    // across pieces does, and there would be no gap between the pieces to be choked in.)
    let (result, queue, results) = run_fast_worker("choked-between-pieces", addr, info_hash, &pieces, 16384, 1);

    assert!(matches!(result, Err(WorkerError::Connection { stage: "peer_has_no_needed_pieces", .. })), "{:?}", result);
    assert!(started.elapsed() < Duration::from_secs(3), "it gave up after the short wait for an unchoke, not the long one for something to be offered: {:?}", started.elapsed());
    assert!(peer.join().unwrap() >= 3, "and the peer heard from it in the meantime");
    assert_eq!(results.len(), 1);
    assert_eq!(queue.len(), 1);
}

// ---- over uTP ----

/// A worker downloading two pieces from a mock peer that is reachable only over uTP.
fn download_over_utp(name: &str, mode: crate::peer::TransportMode, encryption: crate::peer::Encryption) -> (Result<(), WorkerError>, Vec<crate::downloader::queue::PieceResult>, Vec<Vec<u8>>) {
    use crate::utp::UtpSocket;
    let pieces = vec![vec![0x5Au8; 16384], vec![0xA5u8; 16384]];
    let info_hash = [0x71; 20];
    let server = Arc::new(UtpSocket::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0))).unwrap());
    server.listen();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], server.local_addr().unwrap().port()));
    let served = pieces.clone();
    let accepting = Arc::clone(&server);
    let mock = thread::spawn(move || {
        if let Some(stream) = accepting.accept(Duration::from_secs(3)) {
            stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            serve_mock_peer(Box::new(stream), info_hash, served, Duration::ZERO, encryption);
        }
    });

    let client = Arc::new(UtpSocket::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0))).unwrap());
    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: p.len() as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, 2));
    let dir = tmp_dir(name);
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 32768)]));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig {
        info_hash,
        our_peer_id: [0x11; 20],
        pipeline_depth: 2,
        connect_timeout: Duration::from_secs(5),
        down_limit: None,
        interrupt: Default::default(),
        peers: Default::default(),
        encryption,
        transport: crate::peer::Transport { mode, utp: Some(Arc::clone(&client)) },
        upload: None,
        holepunch: Default::default(),
        utp6: None,
    };
    let result = run_worker(addr, &config, &queue, &spans, 16384, &tx, None);
    drop(tx);
    let results: Vec<_> = rx.try_iter().collect();
    drop(config);
    let _ = mock.join();
    (result, results, pieces)
}

#[test]
fn a_worker_downloads_from_a_peer_over_utp() {
    let (result, mut results, pieces) = download_over_utp("utp-worker", crate::peer::TransportMode::Utp, crate::peer::Encryption::Off);
    result.expect("the download works over uTP");
    results.sort_by_key(|r| r.index);
    assert_eq!(results.len(), 2);
    assert_eq!((&results[0].data, &results[1].data), (&pieces[0], &pieces[1]));
}

#[test]
fn a_worker_downloads_over_utp_with_encryption_too() {
    let (result, results, _) = download_over_utp("utp-worker-mse", crate::peer::TransportMode::Utp, crate::peer::Encryption::Require);
    result.expect("encryption runs over uTP as over TCP");
    assert_eq!(results.len(), 2);
}

#[test]
fn a_worker_that_may_use_both_reaches_a_peer_that_only_speaks_utp() {
    let (result, results, _) = download_over_utp("utp-worker-both", crate::peer::TransportMode::Both, crate::peer::Encryption::Off);
    result.expect("TCP is refused, so it goes by uTP");
    assert_eq!(results.len(), 2);
}

#[test]
fn a_tcp_only_worker_cannot_reach_a_peer_that_only_speaks_utp() {
    let (result, results, _) = download_over_utp("utp-worker-tcp", crate::peer::TransportMode::Tcp, crate::peer::Encryption::Off);
    assert!(matches!(result, Err(WorkerError::Connection { stage: "connect_and_handshake", .. })), "{:?}", result);
    assert!(results.is_empty());
}

#[test]
fn a_worker_downloads_the_pieces_of_a_v2_torrent_and_checks_each_by_its_merkle_tree() {
    // Two files of 20000 and 100 bytes in 16 KiB pieces: three pieces, two of them short.
    let piece_length = 16384usize;
    let a: Vec<u8> = (0..20_000u32).map(|i| (i * 5) as u8).collect();
    let b = vec![0x42u8; 100];
    let pieces = vec![a[..piece_length].to_vec(), a[piece_length..].to_vec(), b.clone()];
    let info_hash = [0x73; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = spawn_mock_peer(listener, info_hash, pieces.clone(), Duration::ZERO);

    let work: Vec<PieceWork> = pieces
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let width = (p.len().div_ceil(16384)).next_power_of_two() as u32;
            let root = crate::v2::merkle_root(&crate::v2::block_hashes(p), width as usize, [0u8; 32]);
            PieceWork { index: i as u32, hash: <[u8; 20]>::try_from(&root[..20]).unwrap(), length: p.len() as u32, merkle: Some(crate::downloader::piece_assembler::Merkle { root, width }) }
        })
        .collect();
    let queue = Arc::new(WorkQueue::new(work, 3));
    let dir = tmp_dir("v2-worker");
    let files = vec![(vec!["a".to_string()], 20_000i64), (vec!["b".to_string()], 100)];
    let spans = Arc::new(crate::downloader::file_writer::build_file_spans_aligned(&dir, &files, piece_length as u64));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    run_worker(addr, &config, &queue, &spans, piece_length as u64, &tx, None).unwrap();
    mock.join().unwrap();

    assert_eq!(rx.try_iter().count(), 3);
    assert_eq!(fs::read(dir.join("a")).unwrap(), a);
    assert_eq!(fs::read(dir.join("b")).unwrap(), b, "b begins on a piece boundary of its own");
}

#[test]
fn a_v2_piece_that_does_not_come_to_its_root_is_refused_like_a_v1_one_that_fails_its_hash() {
    let info_hash = [0x74; 20];
    let piece = vec![0x11u8; 16384];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = spawn_mock_peer(listener, info_hash, vec![piece.clone()], Duration::ZERO);
    let wrong_root = crate::v2::merkle_root(&crate::v2::block_hashes(&[0x99u8; 16384]), 1, [0u8; 32]);
    let work = vec![PieceWork { index: 0, hash: [0; 20], length: 16384, merkle: Some(crate::downloader::piece_assembler::Merkle { root: wrong_root, width: 1 }) }];
    let queue = Arc::new(WorkQueue::new(work, 1));
    let dir = tmp_dir("v2-worker-bad");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["f".to_string()], 16384)]));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    let result = run_worker(addr, &config, &queue, &spans, 16384, &tx, None);

    assert!(matches!(result, Err(WorkerError::PieceHashMismatch)), "{:?}", result);
    assert_eq!(rx.try_iter().count(), 0);
    assert!(!dir.join("f").exists(), "nothing unverified reached the disk");
    let _ = mock.join();
}


// ---- requests that go on across pieces ----

#[test]
fn small_pieces_from_a_distant_peer_are_not_a_round_trip_each() {
    const LATENCY: Duration = Duration::from_millis(30);
    let (pieces, piece_len) = (16usize, 64 * 1024); // four blocks each
    // Without the requests going on across pieces, every piece is a round trip on its own: all sixteen wait a latency.
    let one_per_round_trip = LATENCY * pieces as u32;

    // Room for four pieces at once (sixteen blocks): about four round trips for the sixteen, where each on its own is sixteen.
    let (took, _, correct) = download_from_laggy_peer("across-pieces", pieces, piece_len, LATENCY, None, 16);

    assert!(correct, "every byte arrived intact");
    assert!(took < one_per_round_trip / 2, "took {:?}; a round trip a piece would take {:?}", took, one_per_round_trip);
}

/// Four pieces of four blocks from a peer that sends every block wrong, with room for all at once: the worker fails on
/// the first, and the others, which it had asked for, go back too.
#[test]
fn a_piece_asked_for_ahead_goes_back_to_the_queue_when_the_one_before_it_fails() {
    let pieces: Vec<Vec<u8>> = (0..4u8).map(|i| (0..4 * 16384).map(|b| (b as u8).wrapping_mul(7).wrapping_add(i)).collect()).collect();
    let info_hash = [0x6A; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let peer = spawn_recording_peer(listener, info_hash, pieces.clone(), None, Fault::EveryBlockWrong, Arc::clone(&requests));
    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: p.len() as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, 4));
    let dir = tmp_dir("ahead-released");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 16 * 16384)]));
    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 16, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None };

    let result = run_worker(addr, &config, &queue, &spans, 4 * 16384, &tx, None);
    drop(config);
    drop(peer);

    assert!(matches!(result, Err(WorkerError::PieceHashMismatch)));
    let asked: std::collections::BTreeSet<u32> = requests.lock().unwrap().iter().map(|&(piece, _)| piece).collect();
    assert!(asked.len() >= 3, "the pieces after the first were asked for while it was still being fetched: {:?}", asked);
    let mut pending: Vec<u32> = std::iter::from_fn(|| queue.take_pending_for(|_| true)).map(|w| w.index).collect();
    pending.sort_unstable();
    assert_eq!(pending, vec![0, 1, 2, 3], "all are waiting to be taken again, not left claimed by a worker that has gone");
}

/// A peer that has pieces 0 and 2 of three: the worker asks it for those and never for the one it lacks, ahead or not.
#[test]
fn only_a_piece_the_peer_has_is_asked_for_ahead() {
    let pieces: Vec<Vec<u8>> = (0..3u8).map(|i| (0..2 * 16384).map(|b| (b as u8).wrapping_mul(5).wrapping_add(i)).collect()).collect();
    let info_hash = [0x6B; 20];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = pieces.clone();
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&asked);
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut hs_buf = [0u8; 68];
        stream.read_exact(&mut hs_buf).unwrap();
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], false).to_bytes()).unwrap();
        WireMessage::Bitfield(vec![0b1010_0000]).write_to(&mut stream).unwrap();
        WireMessage::Unchoke.write_to(&mut stream).unwrap();
        while let Ok(msg) = WireMessage::read_from(&mut stream) {
            if let WireMessage::Request { index, begin, length } = msg {
                log.lock().unwrap().push(index);
                serve(&mut stream, &served, (index, begin, length));
            }
        }
    });
    let (result, queue, results) = run_fast_worker("ahead-has", addr, info_hash, &pieces, 2 * 16384, 8);
    drop(peer);

    let mut got: Vec<u32> = results.iter().map(|r| r.index).collect();
    got.sort_unstable();
    assert_eq!(got, vec![0, 2], "the two it has arrived");
    assert!(!asked.lock().unwrap().contains(&1), "and the one it lacks was never asked for: {:?}", asked.lock().unwrap());
    assert!(result.is_err(), "the worker then has nothing to get here and leaves: {:?}", result);
    assert_eq!(queue.len(), 1);
}

#[test]
fn one_connection_looks_ahead_only_so_many_pieces() {
    // One-block pieces, so that a block in flight is a piece in flight, and room in the queue for far more than are allowed.
    let (_, most_waiting, correct) = download_from_laggy_peer("lookahead-bound", 32, 16384, Duration::from_millis(20), None, 64);
    assert!(correct);
    // (The piece being fetched and eight more: written out, so that changing the limit means changing this on purpose.)
    assert!(most_waiting <= 9, "{} blocks of different pieces were waiting at the peer at once", most_waiting);
    assert!(most_waiting > 4, "and it did look ahead: {}", most_waiting);
}

// ---- upload on a connection the worker made ----------------------------------------------------------------------------

/// A listener serving `have`'s pieces of `pieces` (written to disk beforehand) for a worker's connections to serve from, with the
/// have-map that says which are verified.
fn upload_for(name: &str, info_hash: [u8; 20], pieces: &[Vec<u8>], have: &[u32]) -> (crate::seeder::SeederHandle, Arc<crate::seeder::HaveMap>) {
    upload_for_with(name, info_hash, pieces, have, Default::default())
}

/// [`upload_for`] with the choking policy chosen.
fn upload_for_with(name: &str, info_hash: [u8; 20], pieces: &[Vec<u8>], have: &[u32], options: crate::seeder::SeederOptions) -> (crate::seeder::SeederHandle, Arc<crate::seeder::HaveMap>) {
    let dir = tmp_dir(name);
    let (total, piece_len): (i64, u64) = (pieces.iter().map(|p| p.len() as i64).sum(), pieces[0].len() as u64);
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["ours.bin".to_string()], total)]));
    let map = Arc::new(crate::seeder::HaveMap::new(pieces.len()));
    for &index in have {
        crate::downloader::file_writer::write_piece(&spans, index, piece_len, &pieces[index as usize]).unwrap();
        map.set(index);
    }
    let handle = crate::seeder::start_with(0, info_hash, [0x11; 20], spans, piece_len, total as u64, Arc::clone(&map), None, options).unwrap();
    (handle, map)
}

/// The peer end of a connection made by a worker: accepts, exchanges handshakes (no extensions, no Fast Extension), and gives the
/// stream to `script`.
fn scripted_peer(listener: TcpListener, info_hash: [u8; 20], script: impl FnOnce(&mut TcpStream) + Send + 'static) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut hs = [0u8; 68];
        stream.read_exact(&mut hs).unwrap();
        std::io::Write::write_all(&mut stream, &Handshake::new(info_hash, [0x99; 20], false).to_bytes()).unwrap();
        script(&mut stream);
    })
}

/// A worker for a torrent of `pieces` (16 KiB each) with `want` still to fetch, against `addr`, with `upload` to serve from.
fn run_uploading_worker(name: &str, addr: std::net::SocketAddr, info_hash: [u8; 20], pieces: &[Vec<u8>], want: &[usize], upload: Option<Arc<crate::seeder::SeederShared>>) -> Result<(), WorkerError> {
    run_uploading_worker_for(name, addr, info_hash, pieces, want, upload, Duration::from_secs(5))
}

/// [`run_uploading_worker`] with the time its reads wait for the peer to say something.
fn run_uploading_worker_for(name: &str, addr: std::net::SocketAddr, info_hash: [u8; 20], pieces: &[Vec<u8>], want: &[usize], upload: Option<Arc<crate::seeder::SeederShared>>, read_timeout: Duration) -> Result<(), WorkerError> {
    let piece_len = pieces[0].len();
    let work = want.iter().map(|&i| PieceWork { index: i as u32, hash: sha1_of(&pieces[i]), length: piece_len as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, pieces.len()));
    let dir = tmp_dir(name);
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], (pieces.len() * piece_len) as i64)]));
    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: read_timeout, down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload , holepunch: Default::default(), utp6: None };
    run_worker(addr, &config, &queue, &spans, piece_len as u64, &tx, None)
}

/// The next message the worker sends that is not a keep-alive.
fn next_message(stream: &mut TcpStream) -> WireMessage {
    loop {
        match WireMessage::read_from(stream).expect("the worker should keep talking") {
            WireMessage::KeepAlive => continue,
            other => return other,
        }
    }
}

#[test]
fn a_peer_the_worker_fetches_from_is_told_what_we_have_and_served_what_it_asks_for() {
    let info_hash = [0x51; 20];
    let pieces = vec![vec![0xA1u8; 16384], vec![0xB2u8; 16384]];
    // We have piece 0 and want piece 1; the peer is the other way about.
    let (mut seeder, _have) = upload_for("upload-us", info_hash, &pieces, &[0]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let theirs = pieces.clone();
    let peer = scripted_peer(listener, info_hash, move |stream| {
        // What we have is the first thing said.
        let WireMessage::Bitfield(bits) = next_message(stream) else { panic!("the first message should be the bitfield") };
        assert_eq!(bits[0] & 0b1100_0000, 0b1000_0000, "piece 0 is ours and piece 1 is not");
        WireMessage::Bitfield(vec![0b0100_0000]).write_to(stream).unwrap();
        WireMessage::Interested.write_to(stream).unwrap();
        // We ask for what we want, and get it once the worker has unchoked us.
        loop {
            match next_message(stream) {
                WireMessage::Unchoke => break,
                WireMessage::Interested => {}
                other => panic!("expected an unchoke, got {:?}", other),
            }
        }
        WireMessage::Request { index: 0, begin: 0, length: 16384 }.write_to(stream).unwrap();
        loop {
            if let WireMessage::Piece { index: 0, begin: 0, block } = next_message(stream) {
                assert_eq!(block, theirs[0], "the block is what is on our disk");
                break;
            }
        }
        // Only now does the peer unchoke the worker, which is still there to fetch the piece it wants.
        WireMessage::Unchoke.write_to(stream).unwrap();
        loop {
            match WireMessage::read_from(stream) {
                Ok(WireMessage::Request { index: 1, begin, length }) => {
                    let block = theirs[1][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index: 1, begin, block }.write_to(stream).unwrap();
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });

    let result = run_uploading_worker("upload-worker", addr, info_hash, &pieces, &[1], Some(seeder.upload()));

    result.expect("the worker fetched its piece");
    peer.join().expect("and the peer was served the one it asked for");
    assert_eq!(seeder.uploaded.load(std::sync::atomic::Ordering::SeqCst), 16384);
    seeder.stop();
}

#[test]
fn a_worker_with_nothing_to_serve_from_says_nothing_of_pieces() {
    let info_hash = [0x52; 20];
    let pieces = vec![vec![0xC3u8; 16384]];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let theirs = pieces.clone();
    let peer = scripted_peer(listener, info_hash, move |stream| {
        WireMessage::Bitfield(vec![0b1000_0000]).write_to(stream).unwrap();
        WireMessage::Unchoke.write_to(stream).unwrap();
        // With no listener behind the worker, its first message is that it is interested: no bitfield.
        assert_eq!(next_message(stream), WireMessage::Interested);
        loop {
            match WireMessage::read_from(stream) {
                Ok(WireMessage::Request { index, begin, length }) => {
                    let block = theirs[index as usize][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(stream).unwrap();
                }
                Ok(WireMessage::Bitfield(_) | WireMessage::HaveAll | WireMessage::HaveNone) => panic!("a worker with nothing to serve announced pieces"),
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    run_uploading_worker("upload-none", addr, info_hash, &pieces, &[0], None).unwrap();
    peer.join().unwrap();
}

#[test]
fn a_piece_verified_while_the_worker_is_connected_is_announced_to_that_peer() {
    let info_hash = [0x53; 20];
    let pieces = vec![vec![0xD4u8; 16384], vec![0xE5u8; 16384]];
    let (mut seeder, have) = upload_for("upload-have", info_hash, &pieces, &[]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let theirs = pieces.clone();
    let peer = scripted_peer(listener, info_hash, move |stream| {
        let WireMessage::Bitfield(bits) = next_message(stream) else { panic!("the bitfield comes first") };
        assert_eq!(bits[0] & 0b1100_0000, 0, "nothing is ours yet");
        WireMessage::Bitfield(vec![0b1100_0000]).write_to(stream).unwrap();
        WireMessage::Unchoke.write_to(stream).unwrap();
        // The worker is fetching. Piece 1 is verified elsewhere (here: by the test), and this peer hears of it.
        have.set(1);
        let mut heard = false;
        loop {
            match WireMessage::read_from(stream) {
                Ok(WireMessage::Have { piece_index: 1 }) => heard = true,
                Ok(WireMessage::Request { index, begin, length }) => {
                    let block = theirs[index as usize][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(stream).unwrap();
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert!(heard, "the peer was told of piece 1 without asking");
    });
    run_uploading_worker("upload-have-worker", addr, info_hash, &pieces, &[0, 1], Some(seeder.upload())).unwrap();
    peer.join().unwrap();
    seeder.stop();
}

#[test]
fn a_piece_verified_in_the_middle_of_a_download_is_announced_between_the_blocks_that_arrive() {
    let info_hash = [0x54; 20];
    let pieces = vec![vec![0xF6u8; 16384], vec![0x17u8; 16384]];
    let (mut seeder, have) = upload_for("upload-mid", info_hash, &pieces, &[]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let theirs = pieces.clone();
    let peer = scripted_peer(listener, info_hash, move |stream| {
        assert!(matches!(next_message(stream), WireMessage::Bitfield(_)));
        WireMessage::Bitfield(vec![0b1100_0000]).write_to(stream).unwrap();
        WireMessage::Unchoke.write_to(stream).unwrap();
        // The worker is unchoked and asking. Only once it has asked does a piece get verified, so that what
        // announces it is not the wait for the unchoke.
        let mut first = true;
        let mut heard = false;
        loop {
            match WireMessage::read_from(stream) {
                Ok(WireMessage::Have { piece_index: 1 }) => heard = true,
                Ok(WireMessage::Request { index, begin, length }) => {
                    if std::mem::take(&mut first) {
                        have.set(1);
                    }
                    let block = theirs[index as usize][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(stream).unwrap();
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert!(heard, "told of piece 1 while the blocks were coming in");
    });
    run_uploading_worker("upload-mid-worker", addr, info_hash, &pieces, &[0, 1], Some(seeder.upload())).unwrap();
    peer.join().unwrap();
    seeder.stop();
}

#[test]
fn a_piece_verified_while_the_worker_waits_for_something_the_peer_has_is_announced_when_it_looks_again() {
    let info_hash = [0x55; 20];
    let pieces = vec![vec![0x28u8; 16384], vec![0x39u8; 16384]];
    let (mut seeder, have) = upload_for("upload-idle", info_hash, &pieces, &[]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let theirs = pieces.clone();
    let peer = scripted_peer(listener, info_hash, move |stream| {
        assert!(matches!(next_message(stream), WireMessage::Bitfield(_)));
        // The peer has piece 0 only, so once that is fetched the worker has nothing more to ask it for.
        WireMessage::Bitfield(vec![0b1000_0000]).write_to(stream).unwrap();
        WireMessage::Unchoke.write_to(stream).unwrap();
        let mut sent_it = false;
        let mut heard = false;
        loop {
            match WireMessage::read_from(stream) {
                Ok(WireMessage::Have { piece_index: 1 }) => {
                    heard = true;
                    break;
                }
                Ok(WireMessage::Request { index, begin, length }) => {
                    let block = theirs[index as usize][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(stream).unwrap();
                    if !std::mem::replace(&mut sent_it, true) {
                        // The worker has its piece, and nothing else to ask this peer for: it waits. Then this piece is verified.
                        thread::sleep(Duration::from_millis(150));
                        have.set(1);
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert!(heard, "told of piece 1 by a worker that was otherwise idle");
        WireMessage::Have { piece_index: 1 }.write_to(stream).unwrap(); // and now it has the other, so the worker can finish
        loop {
            match WireMessage::read_from(stream) {
                Ok(WireMessage::Request { index, begin, length }) => {
                    let block = theirs[index as usize][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(stream).unwrap();
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    run_uploading_worker_for("upload-idle-worker", addr, info_hash, &pieces, &[0, 1], Some(seeder.upload()), Duration::from_millis(100)).unwrap();
    peer.join().unwrap();
    seeder.stop();
}

#[test]
fn a_piece_verified_part_way_through_a_multi_block_piece_is_announced_before_the_piece_is_done() {
    let info_hash = [0x56; 20];
    // A piece of four blocks: with nothing announced until a piece ends, the peer would hear only after all four.
    let pieces = vec![vec![0x4Au8; 65536], vec![0x5Bu8; 65536]];
    let (mut seeder, have) = upload_for("upload-blocks", info_hash, &pieces, &[]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let theirs = pieces.clone();
    let peer = scripted_peer(listener, info_hash, move |stream| {
        assert!(matches!(next_message(stream), WireMessage::Bitfield(_)));
        WireMessage::Bitfield(vec![0b1000_0000]).write_to(stream).unwrap();
        WireMessage::Unchoke.write_to(stream).unwrap();
        let mut blocks_sent = 0;
        let mut heard_after = None;
        loop {
            match WireMessage::read_from(stream) {
                Ok(WireMessage::Have { piece_index: 1 }) => {
                    heard_after.get_or_insert(blocks_sent);
                }
                Ok(WireMessage::Request { index, begin, length }) => {
                    let block = theirs[index as usize][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(stream).unwrap();
                    blocks_sent += 1;
                    if blocks_sent == 1 {
                        have.set(1); // verified elsewhere as the first block goes out
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let after = heard_after.expect("the peer was told of piece 1");
        assert!(after < 4, "told after {} of the 4 blocks, not before the piece was over", after);
    });
    run_uploading_worker("upload-blocks-worker", addr, info_hash, &pieces, &[0], Some(seeder.upload())).unwrap();
    peer.join().unwrap();
    seeder.stop();
}

#[test]
fn a_peer_that_gives_the_worker_data_is_unchoked_ahead_of_one_that_gives_nothing() {
    let info_hash = [0x57; 20];
    let pieces = vec![vec![0x6Cu8; 65536], vec![0x7Du8; 65536]];
    // One slot, and a round that never comes of itself: the test says when.
    let options = crate::seeder::SeederOptions { unchoke_slots: 1, rechoke_interval: Duration::from_secs(3600), ..Default::default() };
    let (mut seeder, have) = upload_for_with("upload-tft", info_hash, &pieces, &[0, 1], options);
    let upload = seeder.upload();
    // A bystander: interested in us, and holding the one slot, having asked first. It gives us nothing.
    let (mut theirs, mut ours) = socket_pair();
    let hs = Handshake::new(info_hash, [0x88; 20], false);
    let mut bystander = crate::serving::Serving::begin(&upload, &hs, None, &mut ours, false).unwrap();
    assert!(bystander.handle(&WireMessage::Interested, &mut ours).unwrap());
    bystander.tick(&mut ours).unwrap();
    assert_eq!(upload.choker.unchoked_count(), 1);
    let _ = (&mut theirs, have);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = pieces.clone();
    let choker = Arc::clone(&upload.choker);
    let peer = scripted_peer(listener, info_hash, move |stream| {
        assert!(matches!(next_message(stream), WireMessage::Bitfield(_)));
        WireMessage::Bitfield(vec![0b1000_0000]).write_to(stream).unwrap();
        WireMessage::Interested.write_to(stream).unwrap();
        WireMessage::Unchoke.write_to(stream).unwrap();
        let mut blocks = 0;
        let mut unchoked_us = false;
        loop {
            match WireMessage::read_from(stream) {
                Ok(WireMessage::Unchoke) => unchoked_us = true,
                Ok(WireMessage::Request { index, begin, length }) => {
                    let block = served[index as usize][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(stream).unwrap();
                    blocks += 1;
                    if blocks == 2 {
                        // A round, now that this peer has given and the bystander has not. (The worker is given a moment to
                        // have read what was sent: it is what is counted.)
                        thread::sleep(Duration::from_millis(300));
                        choker.rechoke();
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert!(unchoked_us, "the peer that gave the worker data won the slot in the round");
    });
    run_uploading_worker("upload-tft-worker", addr, info_hash, &pieces, &[0], Some(Arc::clone(&upload))).unwrap();
    peer.join().unwrap();
    drop(bystander);
    seeder.stop();
}

// ---- a connection the peer made ---------------------------------------------------------------------------------------

/// What a worker is given for a peer that connected: `ours` is its end of a connection, on which our bitfield has been said.
fn adopt_from(name: &str, info_hash: [u8; 20], pieces: &[Vec<u8>], have: &[u32], peer_has: Vec<bool>, read_timeout: Duration) -> (Adopted, TcpStream, crate::seeder::SeederHandle, Arc<WorkQueue>, Arc<Vec<crate::downloader::FileSpan>>, WorkerConfig) {
    let (seeder, _) = upload_for(name, info_hash, pieces, have);
    let upload = seeder.upload();
    let (theirs, mut ours) = socket_pair();
    let their_handshake = Handshake::new(info_hash, [0x99; 20], false);
    let serving = crate::serving::Serving::begin(&upload, &their_handshake, None, &mut ours, false).unwrap();
    let piece_len = pieces[0].len();
    let want: Vec<usize> = (0..pieces.len()).filter(|&i| !have.contains(&(i as u32))).collect();
    let work = want.iter().map(|&i| PieceWork { index: i as u32, hash: sha1_of(&pieces[i]), length: piece_len as u32, merkle: None }).collect();
    let queue = Arc::new(WorkQueue::new(work, pieces.len()));
    let dir = tmp_dir(&format!("{}-out", name));
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], (pieces.len() * piece_len) as i64)]));
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: read_timeout, down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: Some(upload) , holepunch: Default::default(), utp6: None };
    let adopted = Adopted { stream: Box::new(ours), serving, peer: theirs.local_addr().unwrap(), their_handshake, peer_has };
    (adopted, theirs, seeder, queue, spans, config)
}

#[test]
fn a_connection_a_peer_made_is_downloaded_from_and_then_served_on_when_there_is_nothing_more_to_fetch() {
    let info_hash = [0x58; 20];
    let pieces = vec![vec![0x8Eu8; 16384], vec![0x9Fu8; 16384]];
    // We have piece 0 and want piece 1, which the peer says it has; the peer wants piece 0.
    let (adopted, mut theirs, mut seeder, queue, spans, config) = adopt_from("adopt-worker", info_hash, &pieces, &[0], vec![false, true], Duration::from_secs(5));
    let served = pieces.clone();
    let peer = thread::spawn(move || {
        theirs.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let WireMessage::Bitfield(bits) = next_message(&mut theirs) else { panic!("our bitfield was said first") };
        assert_eq!(bits[0] & 0b1100_0000, 0b1000_0000);
        // The worker is interested (in what the peer said it has) as soon as it has the connection.
        assert_eq!(next_message(&mut theirs), WireMessage::Interested);
        WireMessage::Interested.write_to(&mut theirs).unwrap();
        WireMessage::Unchoke.write_to(&mut theirs).unwrap();
        let mut asked_for_ours = false;
        let mut got = 0;
        loop {
            match WireMessage::read_from(&mut theirs) {
                Ok(WireMessage::Unchoke) if !asked_for_ours => {
                    asked_for_ours = true;
                    WireMessage::Request { index: 0, begin: 0, length: 16384 }.write_to(&mut theirs).unwrap();
                }
                Ok(WireMessage::Piece { index: 0, block, .. }) => {
                    assert_eq!(block, served[0]);
                    got += 1;
                    if got == 2 {
                        return; // asked twice: once while it was downloading, once after
                    }
                    // The worker has what it wanted by now; this second ask is answered by whoever serves the connection then.
                    thread::sleep(Duration::from_millis(300));
                    WireMessage::Request { index: 0, begin: 0, length: 16384 }.write_to(&mut theirs).unwrap();
                }
                Ok(WireMessage::Request { index: 1, begin, length }) => {
                    let block = served[1][begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index: 1, begin, block }.write_to(&mut theirs).unwrap();
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    let (tx, rx) = mpsc::channel();
    let outcome = run_adopted(adopted, &config, &queue, &spans, 16384, &tx, None);
    let (stream, serving) = match outcome {
        Adoption::ServeOn(stream, serving) => (stream, serving),
        Adoption::Ended(result) => panic!("with the queue drained the peer is still to be served, not {:?}", result),
    };
    assert_eq!(rx.try_iter().count(), 1, "piece 1 was fetched over the connection the peer made");
    assert!(queue.is_empty());
    let upload = config.upload.clone().unwrap();
    let server = thread::spawn(move || crate::seeder::serve_adopted(stream, serving, &upload));
    peer.join().expect("the peer was served piece 0 twice: while the worker had it, and after");
    seeder.stop();
    let _ = server.join();
}

#[test]
fn an_adopted_peer_that_never_unchokes_is_served_on_not_dropped() {
    let info_hash = [0x59; 20];
    let pieces = vec![vec![0xA0u8; 16384], vec![0xB1u8; 16384]];
    let (adopted, mut theirs, mut seeder, queue, spans, config) = adopt_from("adopt-choked", info_hash, &pieces, &[0], vec![false, true], Duration::from_millis(50));
    let peer = thread::spawn(move || {
        theirs.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        // It is a leecher: interested in us, and never unchokes the worker.
        WireMessage::Interested.write_to(&mut theirs).unwrap();
        loop {
            match WireMessage::read_from(&mut theirs) {
                Ok(WireMessage::Unchoke) => break,
                Ok(_) => {}
                Err(e) => panic!("the connection ended before it was unchoked: {:?}", e),
            }
        }
        theirs
    });
    let (tx, _rx) = mpsc::channel();
    let outcome = run_adopted(adopted, &config, &queue, &spans, 16384, &tx, None);
    assert!(matches!(outcome, Adoption::ServeOn(..)), "given up on for downloading, kept for serving");
    assert_eq!(queue.len(), 1, "and what it was to be fetched from is still to be fetched");
    assert_eq!(queue.availability(), vec![0, 1], "what the peer said it has counts towards how rare a piece is");
    let _theirs = peer.join().unwrap();
    seeder.stop();
}

#[test]
fn an_adopted_connection_that_fails_is_over() {
    let info_hash = [0x5A; 20];
    let pieces = vec![vec![0xC2u8; 16384], vec![0xD3u8; 16384]];
    let (adopted, theirs, mut seeder, queue, spans, config) = adopt_from("adopt-fails", info_hash, &pieces, &[0], vec![false, true], Duration::from_secs(5));
    drop(theirs); // hangs up at once
    let (tx, _rx) = mpsc::channel();
    let outcome = run_adopted(adopted, &config, &queue, &spans, 16384, &tx, None);
    assert!(matches!(outcome, Adoption::Ended(Err(_))), "nothing to serve on");
    assert_eq!(queue.len(), 1, "the piece is back for another peer");
    seeder.stop();
}

// ---- BEP 55: relay_pending_holepunch (the delivery side of the hub) ----

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    client.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    server.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    (client, server)
}

#[test]
fn a_message_queued_before_the_peers_id_is_known_is_kept_for_a_later_pass() {
    let hub = HolepunchHub::default();
    let addr: SocketAddr = "10.0.0.1:1".parse().unwrap();
    let (entry, rx) = hub.enter(addr);
    entry.supports.store(true, std::sync::atomic::Ordering::Relaxed);
    let target: SocketAddr = "10.0.0.2:2".parse().unwrap();
    assert!(hub.relay(addr, crate::peer::HolepunchMessage::Connect { endpoint: target }));

    // `their_id` built as still unknown: in practice it and `supports` are always set together on
    // the owning connection's own thread (see `absorb`'s doc comment), but `relay_pending_holepunch`
    // must not lose the message even in this defensive, otherwise-unreachable state.
    let mut holepunch = Holepunch { their_id: None, supports: entry.supports.clone(), rx, _entry: entry };
    let (mut client, mut server) = tcp_pair();
    relay_pending_holepunch(&mut client, &mut holepunch).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut buf = Vec::new();
    server.read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty(), "their_id is still unknown, so nothing was sent yet");

    // Once the id becomes known, the same still-queued message gets through.
    holepunch.their_id = Some(5);
    let (mut client2, mut server2) = tcp_pair();
    relay_pending_holepunch(&mut client2, &mut holepunch).unwrap();
    let WireMessage::Extended { id, payload } = WireMessage::read_from(&mut server2).unwrap() else { panic!("not an extended message") };
    assert_eq!(id, 5);
    assert_eq!(crate::peer::HolepunchMessage::decode(&payload).unwrap(), crate::peer::HolepunchMessage::Connect { endpoint: target });
}

#[test]
fn a_relayed_message_is_written_to_the_wire_once_the_peers_id_is_known() {
    let hub = HolepunchHub::default();
    let addr: SocketAddr = "10.0.0.3:3".parse().unwrap();
    let (entry, rx) = hub.enter(addr);
    entry.supports.store(true, std::sync::atomic::Ordering::Relaxed);
    let target: SocketAddr = "10.0.0.4:4".parse().unwrap();
    assert!(hub.relay(addr, crate::peer::HolepunchMessage::Connect { endpoint: target }));

    let mut holepunch = Holepunch { their_id: Some(9), supports: entry.supports.clone(), rx, _entry: entry };
    let (mut client, mut server) = tcp_pair();
    relay_pending_holepunch(&mut client, &mut holepunch).unwrap();

    let WireMessage::Extended { id, payload } = WireMessage::read_from(&mut server).unwrap() else { panic!("not an extended message") };
    assert_eq!(id, 9, "tagged with this peer's own chosen id, not ours");
    assert_eq!(crate::peer::HolepunchMessage::decode(&payload).unwrap(), crate::peer::HolepunchMessage::Connect { endpoint: target });
}

