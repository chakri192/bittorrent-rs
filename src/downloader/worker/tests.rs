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
use std::net::TcpListener;
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
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default() };

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
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100), down_limit: None, interrupt: Default::default() };

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
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100), down_limit: None, interrupt: Default::default() };

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
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100), down_limit: None, interrupt: Default::default() };

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
    let config = WorkerConfig { info_hash, our_peer_id: [0x22; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default() };

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
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default() };

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
    let work = vec![PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384 }, PieceWork { index: 1, hash: sha1_of(&piece1), length: 16384 }];
    let queue = Arc::new(WorkQueue::new(work, 2));
    let dir = tmp_dir("limited");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 32768i64)]));
    let (tx, rx) = mpsc::channel();
    let limiter = Arc::new(crate::ratelimit::RateLimiter::new(20_000));
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: Some(limiter), interrupt: Default::default() };

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

    let queue = Arc::new(WorkQueue::new(vec![PieceWork { index: 0, hash: [0; 20], length: 16384 }], 1));
    let dir = tmp_dir("interrupted");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 16384i64)]));
    let (tx, _rx) = mpsc::channel();
    // A 30 s read timeout: only the interrupt can end this in time.
    let config = Arc::new(WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(30), down_limit: None, interrupt: Default::default() });

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

    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: piece_len as u32 }).collect();
    let queue = Arc::new(WorkQueue::new(work, piece_count));
    let dir = tmp_dir(name);
    let total = (piece_count * piece_len) as i64;
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], total)]));
    let (tx, _rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: min_depth, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default() };

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
    let (took, most_waiting, correct) = download_from_laggy_peer("reqq", 4, 64 * 1024, Duration::from_millis(5), Some(3), 2);

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

    let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: 16384 }).collect();
    let queue = Arc::new(WorkQueue::new(work, 3));
    // Piece 0 is the rarest by a distance: the swarm has been seen with 1 and 2 twice.
    for piece in [1, 2, 1, 2] {
        queue.note_have(piece);
    }
    let dir = tmp_dir("partial-peer");
    let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 3 * 16384)]));
    let (tx, rx) = mpsc::channel();
    let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default() };

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
        let work = pieces.iter().enumerate().map(|(i, p)| PieceWork { index: i as u32, hash: sha1_of(p), length: 16384 }).collect();
        let queue = Arc::new(WorkQueue::new(work, 4).with_order(order));
        queue.note_have(0);
        queue.note_have(1);
        let dir = tmp_dir(name);
        let spans = Arc::new(build_file_spans(&dir, &[(vec!["out.bin".to_string()], 4 * 16384)]));
        let (tx, rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5), down_limit: None, interrupt: Default::default() };

        run_worker(addr, &config, &queue, &spans, 16384, &tx, None).unwrap();
        mock.join().unwrap();
        rx.try_iter().map(|r| r.index).collect()
    };

    assert_eq!(download_order("order-sequential", Order::Sequential), vec![0, 1, 2, 3]);
    assert_eq!(download_order("order-rarest", Order::RarestFirst), vec![2, 3, 0, 1], "the same swarm, fetched rare pieces first");
}
