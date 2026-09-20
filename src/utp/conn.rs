//! One uTP connection (BEP 29) as a state machine: it is given packets and
//! the time, and says which datagrams to send. It does no I/O and reads no
//! clock, so loss, reordering and timeouts can be tested by feeding it a
//! simulated network on a virtual clock (see the tests).
//!
//! What it does: the connect/accept handshake, sequence and acknowledgement
//! numbers with 16-bit wrap-around, retransmission (on a timeout, on three
//! duplicate acknowledgements, and when selective acks show a hole), a
//! reorder buffer for packets that arrive early, a receive window, orderly
//! close with FIN, and LEDBAT congestion control: the window grows while the
//! delay the packets see stays under a target of 100 ms and shrinks as it
//! rises, so a transfer yields to whatever else is using the link.

use super::packet::{Packet, PacketType, HEADER_LEN, MAX_SACK_BYTES};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::time::{Duration, Instant};

/// The most bytes in a datagram, header included. Below the smallest
/// Ethernet MTU less IP and UDP headers, so packets are not fragmented.
pub const MAX_PACKET: usize = 1400;
/// The most payload in a packet.
pub const MAX_PAYLOAD: usize = MAX_PACKET - HEADER_LEN;

/// Bytes the application may have queued to send, sent or not.
const SEND_BUFFER: usize = 256 * 1024;
/// Bytes of received data held for the application, in order or not; what
/// the window we advertise is measured against.
const RECEIVE_BUFFER: usize = 512 * 1024;
/// How far ahead of the next expected packet one is kept.
const REORDER_WINDOW: u16 = 64;

const INITIAL_RTO: Duration = Duration::from_secs(1);
const MIN_RTO: Duration = Duration::from_millis(500);
const MAX_RTO: Duration = Duration::from_secs(60);
/// Timeouts in a row on the same data before the connection is given up.
const MAX_TIMEOUTS: u32 = 5;
/// Times a connection request is sent before giving up.
const MAX_SYN_ATTEMPTS: u32 = 3;
/// A quiet connection is kept alive with an empty packet this often...
const KEEPALIVE: Duration = Duration::from_secs(15);
/// ...and given up on after hearing nothing for this long.
const DEAD_AFTER: Duration = Duration::from_secs(90);
/// Duplicate acknowledgements that mean a packet was lost.
const DUP_ACK_THRESHOLD: u32 = 3;

/// LEDBAT: the queuing delay to aim for, and how fast the window may grow.
const TARGET_DELAY_US: f64 = 100_000.0;
const MAX_GROWTH_PER_RTT: f64 = 3000.0;
/// The smallest window: one packet, so there is always progress.
const MIN_WINDOW: f64 = MAX_PACKET as f64;
const INITIAL_WINDOW: f64 = 2.0 * MAX_PACKET as f64;
/// How long a delay sample counts towards the base delay.
const BASE_DELAY_MINUTES: u64 = 2;

/// `a` is not after `b`, counting sequence numbers round the 16-bit circle.
fn seq_le(a: u16, b: u16) -> bool {
    b.wrapping_sub(a) < 0x8000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// A connection request is out, unanswered.
    Connecting,
    Open,
    /// Ended, for the reason `Connection::error` gives (none: an orderly close).
    Ended,
}

#[derive(Debug)]
struct Sent {
    seq: u16,
    kind: PacketType,
    payload: Vec<u8>,
    sent_at: Instant,
    transmissions: u32,
    /// The peer has it (a selective ack), though earlier packets are missing.
    sacked: bool,
    /// Considered lost: to be sent again as the window allows.
    lost: bool,
}

impl Sent {
    fn in_network(&self) -> bool {
        !self.sacked && !self.lost
    }
}

#[derive(Debug)]
pub struct Connection {
    epoch: Instant,
    state: State,
    error: Option<io::ErrorKind>,
    /// Id on packets we send, and on the ones we expect.
    send_id: u16,
    recv_id: u16,

    // ---- sending
    /// The sequence number of the next packet we send.
    seq_nr: u16,
    outbox: VecDeque<u8>,
    in_flight: VecDeque<Sent>,
    /// Payload bytes in the network: sent, not acknowledged, not presumed lost.
    cur_window: usize,
    /// What the peer says it can take.
    peer_window: u32,
    fin_pending: bool,
    fin_sent: bool,
    fin_acked: bool,
    last_data_sent: Option<Instant>,

    // ---- receiving
    /// The last packet received in order.
    ack_nr: u16,
    inbox: VecDeque<u8>,
    reorder: BTreeMap<u16, Vec<u8>>,
    reorder_bytes: usize,
    /// The sequence number of the peer's FIN, once seen.
    fin_seq: Option<u16>,
    peer_closed: bool,
    ack_pending: bool,
    /// Our clock minus the timestamp on the last packet from the peer.
    reply_micro: u32,

    // ---- congestion control and timers
    max_window: f64,
    /// Slow start (the window doubles each round trip) runs until the window
    /// reaches this, the delay nears its target, or a packet is lost.
    ssthresh: f64,
    slow_start: bool,
    rtt: Option<Duration>,
    rtt_var: Duration,
    rto: Duration,
    rto_deadline: Option<Instant>,
    timeouts: u32,
    syn_attempts: u32,
    dup_acks: u32,
    last_ack_nr: u16,
    last_window_cut: Option<Instant>,
    delay_base: Vec<(u64, u32)>,
    last_sent: Instant,
    last_heard: Instant,

    outgoing: VecDeque<Vec<u8>>,
}

impl Connection {
    /// The initiating end: asks for a connection. `recv_id` is what the
    /// peer will address its packets with; ours carry `recv_id + 1`.
    pub fn connect(now: Instant, recv_id: u16) -> Connection {
        Connection::connect_from(now, recv_id, 1)
    }

    fn connect_from(now: Instant, recv_id: u16, initial_seq: u16) -> Connection {
        let mut c = Connection::new(now, State::Connecting, recv_id.wrapping_add(1), recv_id, initial_seq);
        c.send_syn(now);
        c
    }

    /// The accepting end, answering the connection request `syn`. `initial_seq`
    /// is the sequence number of our first packet, which the peer may not
    /// guess.
    pub fn accept(now: Instant, syn: &Packet, initial_seq: u16) -> Connection {
        let mut c = Connection::new(now, State::Open, syn.connection_id, syn.connection_id.wrapping_add(1), initial_seq);
        c.ack_nr = syn.seq_nr;
        c.peer_window = syn.wnd_size;
        c.reply_micro = c.micros(now).wrapping_sub(syn.timestamp);
        c.send_state(now);
        c
    }

    fn new(now: Instant, state: State, send_id: u16, recv_id: u16, seq_nr: u16) -> Connection {
        Connection {
            epoch: now,
            state,
            error: None,
            send_id,
            recv_id,
            seq_nr,
            outbox: VecDeque::new(),
            in_flight: VecDeque::new(),
            cur_window: 0,
            peer_window: RECEIVE_BUFFER as u32,
            fin_pending: false,
            fin_sent: false,
            fin_acked: false,
            last_data_sent: None,
            ack_nr: 0,
            inbox: VecDeque::new(),
            reorder: BTreeMap::new(),
            reorder_bytes: 0,
            fin_seq: None,
            peer_closed: false,
            ack_pending: false,
            reply_micro: 0,
            max_window: INITIAL_WINDOW,
            ssthresh: f64::MAX,
            slow_start: true,
            rtt: None,
            rtt_var: Duration::ZERO,
            rto: INITIAL_RTO,
            rto_deadline: None,
            timeouts: 0,
            syn_attempts: 0,
            dup_acks: 0,
            last_ack_nr: 0,
            last_window_cut: None,
            delay_base: Vec::new(),
            last_sent: now,
            last_heard: now,
            outgoing: VecDeque::new(),
        }
    }

    // ---- what the owner asks of it ----------------------------------

    pub fn state(&self) -> State {
        self.state
    }

    /// Why it ended, if it ended other than by both sides closing.
    pub fn error(&self) -> Option<io::ErrorKind> {
        self.error
    }

    /// The id the peer addresses its packets to us with.
    pub fn recv_id(&self) -> u16 {
        self.recv_id
    }

    /// Datagrams to send, oldest first.
    pub fn take_outgoing(&mut self) -> Vec<Vec<u8>> {
        self.outgoing.drain(..).collect()
    }

    /// Queues up to `data.len()` bytes to send, as many as fit; returns how
    /// many. Zero means the buffer is full, not that the connection failed.
    pub fn write(&mut self, data: &[u8]) -> usize {
        if self.state == State::Ended || self.fin_pending {
            return 0;
        }
        let queued = self.outbox.len() + self.in_flight.iter().map(|p| p.payload.len()).sum::<usize>();
        let take = data.len().min(SEND_BUFFER.saturating_sub(queued));
        self.outbox.extend(&data[..take]);
        take
    }

    /// How many bytes `write` would take now.
    pub fn writable(&self) -> usize {
        if self.state == State::Ended || self.fin_pending {
            return 0;
        }
        SEND_BUFFER.saturating_sub(self.outbox.len() + self.in_flight.iter().map(|p| p.payload.len()).sum::<usize>())
    }

    /// Takes received bytes, in order. Zero with [`is_eof`](Self::is_eof)
    /// false means none have arrived yet.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let before = self.receive_window();
        let n = buf.len().min(self.inbox.len());
        for (slot, byte) in buf.iter_mut().zip(self.inbox.drain(..n)) {
            *slot = byte;
        }
        // The peer stopped when its idea of our window ran out; tell it when there is room.
        if n > 0 && before < MAX_PACKET as u32 && self.receive_window() >= MAX_PACKET as u32 {
            self.ack_pending = true;
        }
        n
    }

    pub fn readable(&self) -> usize {
        self.inbox.len()
    }

    /// The peer has closed its side and everything it sent has been read.
    pub fn is_eof(&self) -> bool {
        self.peer_closed && self.inbox.is_empty()
    }

    /// Nothing more will be sent or received, and everything sent has been
    /// acknowledged: the owner may forget the connection.
    pub fn is_finished(&self) -> bool {
        self.state == State::Ended
    }

    /// Whether every byte given to `write` has been acknowledged.
    pub fn is_flushed(&self) -> bool {
        self.outbox.is_empty() && self.in_flight.iter().all(|p| p.kind != PacketType::Data)
    }

    /// Whether our FIN has been acknowledged.
    pub fn fin_acked(&self) -> bool {
        self.fin_acked
    }

    /// No more will be written. What is queued is sent, then a FIN.
    pub fn close(&mut self) {
        self.fin_pending = true;
    }

    /// Ends the connection at once, telling the peer.
    pub fn abort(&mut self, now: Instant) {
        if self.state != State::Ended {
            self.queue(now, PacketType::Reset, self.seq_nr, Vec::new());
        }
        self.fail(io::ErrorKind::ConnectionAborted);
    }

    /// The soonest time `on_tick` has something to do, if any.
    pub fn next_timeout(&self) -> Option<Instant> {
        if self.state == State::Ended {
            return None;
        }
        let keepalive = self.last_sent + KEEPALIVE;
        let dead = self.last_heard + DEAD_AFTER;
        [self.rto_deadline, Some(keepalive), Some(dead)].into_iter().flatten().min()
    }

    // ---- the clock and the network -----------------------------------

    /// Handles time having passed: timeouts, keep-alives, and anything the
    /// window now lets go.
    pub fn on_tick(&mut self, now: Instant) {
        if self.state == State::Ended {
            return;
        }
        if now.duration_since(self.last_heard) >= DEAD_AFTER {
            self.fail(io::ErrorKind::TimedOut);
            return;
        }
        if let Some(deadline) = self.rto_deadline {
            if now >= deadline {
                self.on_timeout(now);
            }
        }
        if self.state == State::Open && now.duration_since(self.last_sent) >= KEEPALIVE {
            self.send_state(now);
        }
        self.flush(now);
    }

    /// Handles a packet addressed to this connection.
    pub fn on_packet(&mut self, now: Instant, packet: &Packet) {
        if self.state == State::Ended {
            // Both sides have said goodbye, but the peer may not have heard
            // that its FIN arrived: answer, so that it too can finish.
            if self.error.is_none() && matches!(packet.kind, PacketType::Fin | PacketType::Data) {
                self.send_state(now);
            }
            return;
        }
        self.last_heard = now;
        self.reply_micro = self.micros(now).wrapping_sub(packet.timestamp);
        if packet.kind == PacketType::Reset {
            self.in_flight.clear();
            self.cur_window = 0;
            self.fail(if self.state == State::Connecting { io::ErrorKind::ConnectionRefused } else { io::ErrorKind::ConnectionReset });
            return;
        }

        if self.state == State::Connecting {
            // Only the answer to our request means anything yet.
            if packet.kind == PacketType::State {
                self.state = State::Open;
                // A state packet does not use up a sequence number, so the
                // peer's first data packet is numbered as this one is.
                self.ack_nr = packet.seq_nr.wrapping_sub(1);
                self.peer_window = packet.wnd_size;
                self.process_ack(now, packet);
            }
            self.flush(now);
            return;
        }

        self.peer_window = packet.wnd_size;
        self.process_ack(now, packet);
        match packet.kind {
            PacketType::Data | PacketType::Fin => self.receive(packet),
            // Our answer to its request was lost, and it asked again.
            PacketType::Syn => self.ack_pending = true,
            PacketType::State | PacketType::Reset => {}
        }
        self.flush(now);
    }

    // ---- receiving ------------------------------------------------------

    fn receive_window(&self) -> u32 {
        RECEIVE_BUFFER.saturating_sub(self.inbox.len() + self.reorder_bytes) as u32
    }

    fn receive(&mut self, packet: &Packet) {
        let ahead = packet.seq_nr.wrapping_sub(self.ack_nr);
        // Whatever it is, the sender should hear how far we have got.
        self.ack_pending = true;
        if ahead == 0 || ahead > REORDER_WINDOW {
            return; // one already have, or one from far off: only the ack
        }
        if packet.payload.len() > self.receive_window() as usize {
            return; // no room: not acknowledged, so it is sent again
        }
        if packet.kind == PacketType::Fin {
            self.fin_seq = Some(packet.seq_nr);
        }
        if ahead == 1 {
            self.inbox.extend(&packet.payload);
            self.ack_nr = packet.seq_nr;
            while let Some(payload) = self.reorder.remove(&self.ack_nr.wrapping_add(1)) {
                self.reorder_bytes -= payload.len();
                self.inbox.extend(&payload);
                self.ack_nr = self.ack_nr.wrapping_add(1);
            }
        } else if let std::collections::btree_map::Entry::Vacant(slot) = self.reorder.entry(packet.seq_nr) {
            self.reorder_bytes += packet.payload.len();
            slot.insert(packet.payload.clone());
        }
        if self.fin_seq == Some(self.ack_nr) {
            self.peer_closed = true;
        }
    }

    /// The selective-ack mask for what is held out of order: bit `i` for
    /// `ack_nr + 2 + i`.
    fn selective_ack(&self) -> Vec<u8> {
        let Some(&last) = self.reorder.keys().max_by_key(|seq| seq.wrapping_sub(self.ack_nr)) else { return Vec::new() };
        let span = last.wrapping_sub(self.ack_nr) as usize; // >= 2 as ack_nr + 1 is missing
        let bytes = (span - 1).div_ceil(32).max(1) * 4;
        let mut mask = vec![0u8; bytes.min(MAX_SACK_BYTES)];
        for &seq in self.reorder.keys() {
            let bit = seq.wrapping_sub(self.ack_nr) as usize - 2;
            if let Some(byte) = mask.get_mut(bit / 8) {
                *byte |= 1 << (bit % 8);
            }
        }
        mask
    }

    // ---- acknowledgements -----------------------------------------------

    fn process_ack(&mut self, now: Instant, packet: &Packet) {
        let ack = packet.ack_nr;
        // An acknowledgement of what was never sent means nothing.
        if !self.in_flight.is_empty() && !seq_le(ack, self.seq_nr.wrapping_sub(1)) {
            return;
        }
        let mut acked_bytes = 0usize;
        let mut rtt_sample = None;
        while let Some(front) = self.in_flight.front() {
            if !seq_le(front.seq, ack) {
                break;
            }
            let Some(gone) = self.in_flight.pop_front() else { break };
            if gone.in_network() {
                self.cur_window -= gone.payload.len();
            }
            if !gone.sacked {
                acked_bytes += gone.payload.len();
            }
            if gone.transmissions == 1 && !gone.sacked {
                rtt_sample = Some(now.duration_since(gone.sent_at));
            }
            if gone.kind == PacketType::Fin {
                self.fin_acked = true;
            }
        }

        // Selective acks: packets past a hole that the peer has.
        for (i, byte) in packet.sack.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) == 0 {
                    continue;
                }
                let seq = ack.wrapping_add(2).wrapping_add((i * 8 + bit) as u16);
                if let Some(p) = self.in_flight.iter_mut().find(|p| p.seq == seq) {
                    if !p.sacked {
                        if p.in_network() {
                            self.cur_window -= p.payload.len();
                        }
                        p.sacked = true;
                        p.lost = false;
                        acked_bytes += p.payload.len();
                        if p.transmissions == 1 {
                            rtt_sample = Some(now.duration_since(p.sent_at));
                        }
                    }
                }
            }
        }
        // Everything sacked is past the first packet still missing; that many
        // packets arriving after it is as good as three duplicate acks.
        let sacked_after_front = self.in_flight.iter().filter(|p| p.sacked).count();

        if let Some(sample) = rtt_sample {
            self.update_rtt(sample);
        }
        if acked_bytes > 0 {
            self.timeouts = 0;
            self.dup_acks = 0;
            self.update_window(now, acked_bytes, packet.timestamp_diff);
        } else if packet.kind == PacketType::State && ack == self.last_ack_nr && !self.in_flight.is_empty() {
            self.dup_acks += 1;
        }
        if seq_le(self.last_ack_nr, ack) {
            self.last_ack_nr = ack;
        }

        let lost_front = self.dup_acks == DUP_ACK_THRESHOLD || sacked_after_front >= DUP_ACK_THRESHOLD as usize;
        if lost_front {
            if let Some(front) = self.in_flight.iter_mut().find(|p| !p.sacked) {
                if front.transmissions == 1 && !front.lost {
                    front.lost = true;
                    self.cur_window -= front.payload.len();
                    self.cut_window(now);
                }
            }
        }

        // The timer is for the oldest thing still unacknowledged.
        self.rto_deadline = if self.in_flight.is_empty() { None } else { Some(now + self.rto) };
    }

    fn update_rtt(&mut self, sample: Duration) {
        match self.rtt {
            None => {
                self.rtt = Some(sample);
                self.rtt_var = sample / 2;
            }
            Some(rtt) => {
                let error = rtt.abs_diff(sample);
                self.rtt_var = self.rtt_var * 3 / 4 + error / 4;
                self.rtt = Some(rtt * 7 / 8 + sample / 8);
            }
        }
        let rtt = self.rtt.unwrap_or(sample);
        self.rto = (rtt + self.rtt_var * 4).clamp(MIN_RTO, MAX_RTO);
    }

    /// LEDBAT: `delay` is how long the peer measured our packet to take, on
    /// the two clocks' difference; the least seen lately is taken to be the
    /// clocks' difference plus an empty queue, so what is above it is queuing.
    fn update_window(&mut self, now: Instant, acked_bytes: usize, delay: u32) {
        let minute = now.duration_since(self.epoch).as_secs() / 60;
        match self.delay_base.last_mut() {
            Some((m, least)) if *m == minute => {
                if (delay.wrapping_sub(*least) as i32) < 0 {
                    *least = delay;
                }
            }
            _ => {
                self.delay_base.push((minute, delay));
                let keep = BASE_DELAY_MINUTES as usize + 1;
                if self.delay_base.len() > keep {
                    self.delay_base.remove(0);
                }
            }
        }
        let base = self.delay_base.iter().map(|&(_, least)| least).reduce(|a, b| if (a.wrapping_sub(b) as i32) <= 0 { a } else { b }).unwrap_or(delay);
        let queuing = f64::from(delay.wrapping_sub(base) as i32).max(0.0);

        let acked = acked_bytes as f64;
        if self.slow_start {
            if queuing > TARGET_DELAY_US * 0.9 || self.max_window >= self.ssthresh {
                self.slow_start = false;
            } else {
                self.max_window += acked;
            }
        } else {
            let delay_factor = (TARGET_DELAY_US - queuing) / TARGET_DELAY_US;
            let window_factor = (acked / self.max_window).min(1.0);
            self.max_window += MAX_GROWTH_PER_RTT * delay_factor * window_factor;
        }
        // No use having a window far beyond what is being sent.
        let in_use = (self.cur_window + acked_bytes) as f64;
        self.max_window = self.max_window.min(2.0 * in_use + 4.0 * MAX_PACKET as f64).clamp(MIN_WINDOW, 16.0 * 1024.0 * 1024.0);
    }

    /// A loss: halve the window, at most once for each round trip.
    fn cut_window(&mut self, now: Instant) {
        let round_trip = self.rtt.unwrap_or(INITIAL_RTO);
        if self.last_window_cut.is_some_and(|at| now.duration_since(at) < round_trip) {
            return;
        }
        self.last_window_cut = Some(now);
        self.slow_start = false;
        self.max_window = (self.max_window / 2.0).max(MIN_WINDOW);
        self.ssthresh = self.max_window;
    }

    fn on_timeout(&mut self, now: Instant) {
        if self.state == State::Connecting {
            if self.syn_attempts >= MAX_SYN_ATTEMPTS {
                self.fail(io::ErrorKind::TimedOut);
                return;
            }
            self.rto = (self.rto * 2).min(MAX_RTO);
            if let Some(syn) = self.in_flight.front_mut() {
                syn.transmissions += 1;
                syn.sent_at = now;
            }
            self.send_syn_again(now);
            return;
        }
        self.timeouts += 1;
        if self.timeouts > MAX_TIMEOUTS {
            self.fail(io::ErrorKind::TimedOut);
            return;
        }
        // Everything unacknowledged is presumed lost; the window starts again
        // from one packet, and the timer backs off.
        for p in self.in_flight.iter_mut().filter(|p| !p.sacked && !p.lost) {
            p.lost = true;
            self.cur_window -= p.payload.len();
        }
        self.ssthresh = (self.max_window / 2.0).max(2.0 * MIN_WINDOW);
        self.max_window = MIN_WINDOW;
        self.slow_start = true;
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.rto_deadline = Some(now + self.rto);
    }

    // ---- sending ---------------------------------------------------------

    fn micros(&self, now: Instant) -> u32 {
        now.duration_since(self.epoch).as_micros() as u32
    }

    fn header(&self, now: Instant, kind: PacketType, seq_nr: u16) -> Packet {
        Packet {
            kind,
            connection_id: if kind == PacketType::Syn { self.recv_id } else { self.send_id },
            timestamp: self.micros(now),
            timestamp_diff: self.reply_micro,
            wnd_size: self.receive_window(),
            seq_nr,
            ack_nr: self.ack_nr,
            sack: Vec::new(),
            payload: Vec::new(),
        }
    }

    fn queue(&mut self, now: Instant, kind: PacketType, seq_nr: u16, payload: Vec<u8>) {
        let mut packet = self.header(now, kind, seq_nr);
        packet.payload = payload;
        if kind == PacketType::State {
            packet.sack = self.selective_ack();
        }
        self.outgoing.push_back(packet.encode());
        self.last_sent = now;
        if matches!(kind, PacketType::Data | PacketType::Fin | PacketType::State) {
            self.ack_pending = false;
        }
    }

    fn send_syn(&mut self, now: Instant) {
        self.syn_attempts = 1;
        self.in_flight.push_back(Sent { seq: self.seq_nr, kind: PacketType::Syn, payload: Vec::new(), sent_at: now, transmissions: 1, sacked: false, lost: false });
        self.queue(now, PacketType::Syn, self.seq_nr, Vec::new());
        self.seq_nr = self.seq_nr.wrapping_add(1);
        self.rto_deadline = Some(now + self.rto);
    }

    fn send_syn_again(&mut self, now: Instant) {
        self.syn_attempts += 1;
        let seq = self.seq_nr.wrapping_sub(1);
        self.queue(now, PacketType::Syn, seq, Vec::new());
        self.rto_deadline = Some(now + self.rto);
    }

    fn send_state(&mut self, now: Instant) {
        self.queue(now, PacketType::State, self.seq_nr, Vec::new());
    }

    /// Sends whatever the window and the queue allow: packets presumed lost,
    /// then new data, then the FIN; and an acknowledgement if nothing sent
    /// carried one.
    pub fn flush(&mut self, now: Instant) {
        if self.state == State::Open {
            self.send_pending(now);
        }
        if self.ack_pending && self.state != State::Ended {
            self.send_state(now);
        }
        self.finish_if_done();
    }

    fn send_pending(&mut self, now: Instant) {
        let window = (self.max_window as usize).min(self.peer_window as usize);

        // What was lost, first.
        let mut resend = Vec::new();
        for p in self.in_flight.iter_mut().filter(|p| p.lost) {
            if self.cur_window + p.payload.len() > window && self.cur_window > 0 {
                break;
            }
            p.lost = false;
            p.transmissions += 1;
            p.sent_at = now;
            self.cur_window += p.payload.len();
            resend.push((p.kind, p.seq, p.payload.clone()));
        }
        for (kind, seq, payload) in resend {
            self.queue(now, kind, seq, payload);
        }

        // Then what is new.
        while !self.outbox.is_empty() {
            let n = self.outbox.len().min(MAX_PAYLOAD);
            if self.cur_window + n > window {
                // A peer whose window has closed is asked again now and then, so
                // that a window that opens again is noticed.
                let probe = self.cur_window == 0 && self.last_data_sent.is_none_or(|at| now.duration_since(at) >= self.rto);
                if !probe {
                    break;
                }
            }
            let payload: Vec<u8> = self.outbox.drain(..n).collect();
            let seq = self.seq_nr;
            self.seq_nr = self.seq_nr.wrapping_add(1);
            self.cur_window += n;
            self.in_flight.push_back(Sent { seq, kind: PacketType::Data, payload: payload.clone(), sent_at: now, transmissions: 1, sacked: false, lost: false });
            self.last_data_sent = Some(now);
            self.queue(now, PacketType::Data, seq, payload);
        }

        if self.fin_pending && !self.fin_sent && self.outbox.is_empty() {
            let seq = self.seq_nr;
            self.seq_nr = self.seq_nr.wrapping_add(1);
            self.fin_sent = true;
            self.in_flight.push_back(Sent { seq, kind: PacketType::Fin, payload: Vec::new(), sent_at: now, transmissions: 1, sacked: false, lost: false });
            self.queue(now, PacketType::Fin, seq, Vec::new());
        }

        if self.rto_deadline.is_none() && !self.in_flight.is_empty() {
            self.rto_deadline = Some(now + self.rto);
        }
    }

    /// An orderly end: ours is acknowledged, and the peer's has come.
    fn finish_if_done(&mut self) {
        if self.fin_acked && self.peer_closed && self.state == State::Open {
            self.state = State::Ended;
        }
    }

    fn fail(&mut self, error: io::ErrorKind) {
        self.error = Some(error);
        self.state = State::Ended;
        self.rto_deadline = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic random source, so a lossy run is the same run every time.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn permille(&mut self, chance: u32) -> bool {
            (self.next() % 1000) < u64::from(chance)
        }
    }

    /// A link that only carries the traffic from A to B slower than it arrives.
    struct Bottleneck {
        bytes_per_second: u64,
        /// How much may queue, as time to drain it, before packets are dropped.
        limit: Duration,
        free_at: Instant,
    }

    /// Decides whether a packet (and whether it is from A) is lost.
    type DropRule = Box<dyn FnMut(&Packet, bool) -> bool>;

    /// Two connections and the network between them, on a virtual clock that
    /// the tests advance a millisecond at a time.
    struct Sim {
        now: Instant,
        start: Instant,
        rng: Rng,
        latency: Duration,
        jitter_us: u64,
        loss_permille: u32,
        duplicate_permille: u32,
        /// Called with each packet and whether it is from A; true drops it.
        drop_if: DropRule,
        /// Whether packets lose their selective-ack extension in transit.
        strip_sack: bool,
        bottleneck: Option<Bottleneck>,
        to_a: Vec<(Instant, u64, Vec<u8>)>,
        to_b: Vec<(Instant, u64, Vec<u8>)>,
        sent_count: u64,
        a: Connection,
        b: Option<Connection>,
        b_initial_seq: u16,
        /// Every packet that went on the wire, and whether from A.
        wire: Vec<(Packet, bool)>,
        longest_queue: Duration,
    }

    impl Sim {
        fn new() -> Sim {
            Sim::with_seqs(1, 40000)
        }

        fn with_seqs(a_seq: u16, b_seq: u16) -> Sim {
            let start = Instant::now();
            Sim {
                now: start,
                start,
                rng: Rng(0x9E3779B97F4A7C15),
                latency: Duration::from_millis(20),
                jitter_us: 0,
                loss_permille: 0,
                duplicate_permille: 0,
                drop_if: Box::new(|_, _| false),
                strip_sack: false,
                bottleneck: None,
                to_a: Vec::new(),
                to_b: Vec::new(),
                sent_count: 0,
                a: Connection::connect_from(start, 100, a_seq),
                b: None,
                b_initial_seq: b_seq,
                wire: Vec::new(),
                longest_queue: Duration::ZERO,
            }
        }

        fn elapsed(&self) -> Duration {
            self.now.duration_since(self.start)
        }

        fn put_on_wire(&mut self, from_a: bool, mut bytes: Vec<u8>) {
            let Ok(mut packet) = Packet::decode(&bytes) else { return };
            if self.strip_sack && !packet.sack.is_empty() {
                packet.sack.clear();
                bytes = packet.encode();
            }
            self.wire.push((packet.clone(), from_a));
            if (self.drop_if)(&packet, from_a) || self.rng.permille(self.loss_permille) {
                return;
            }
            let copies = if self.rng.permille(self.duplicate_permille) { 2 } else { 1 };
            for _ in 0..copies {
                let mut arrival = self.now + self.latency + Duration::from_micros(if self.jitter_us == 0 { 0 } else { self.rng.next() % self.jitter_us });
                if let (true, Some(link)) = (from_a, self.bottleneck.as_mut()) {
                    let sending = Duration::from_micros(bytes.len() as u64 * 1_000_000 / link.bytes_per_second);
                    let departs = link.free_at.max(self.now) + sending;
                    let queued = departs.duration_since(self.now);
                    if queued > link.limit {
                        return;
                    }
                    link.free_at = departs;
                    self.longest_queue = self.longest_queue.max(queued);
                    arrival = departs + self.latency;
                }
                self.sent_count += 1;
                let queue = if from_a { &mut self.to_b } else { &mut self.to_a };
                queue.push((arrival, self.sent_count, bytes.clone()));
            }
        }

        /// One millisecond: deliver what has arrived, let time pass, send what results.
        fn step(&mut self) {
            self.now += Duration::from_millis(1);
            let now = self.now;

            let mut due: Vec<_> = self.to_b.iter().filter(|(t, _, _)| *t <= now).cloned().collect();
            self.to_b.retain(|(t, _, _)| *t > now);
            due.sort_by_key(|(t, n, _)| (*t, *n));
            for (_, _, bytes) in due {
                let Ok(packet) = Packet::decode(&bytes) else { continue };
                match &mut self.b {
                    None if packet.kind == PacketType::Syn => self.b = Some(Connection::accept(now, &packet, self.b_initial_seq)),
                    Some(b) if packet.connection_id == b.recv_id() => b.on_packet(now, &packet),
                    _ => {}
                }
            }
            let mut due: Vec<_> = self.to_a.iter().filter(|(t, _, _)| *t <= now).cloned().collect();
            self.to_a.retain(|(t, _, _)| *t > now);
            due.sort_by_key(|(t, n, _)| (*t, *n));
            for (_, _, bytes) in due {
                let Ok(packet) = Packet::decode(&bytes) else { continue };
                if packet.connection_id == self.a.recv_id() {
                    self.a.on_packet(now, &packet);
                }
            }

            self.a.on_tick(now);
            if let Some(b) = &mut self.b {
                b.on_tick(now);
            }
            for bytes in self.a.take_outgoing() {
                self.put_on_wire(true, bytes);
            }
            let from_b = self.b.as_mut().map(|b| b.take_outgoing()).unwrap_or_default();
            for bytes in from_b {
                self.put_on_wire(false, bytes);
            }
        }

        fn run_for(&mut self, time: Duration) {
            let until = self.now + time;
            while self.now < until {
                self.step();
            }
        }

        /// A sends `data` and closes, B reads it all and closes. Runs until both ends
        /// are finished or `limit` of virtual time has gone.
        fn transfer(&mut self, data: &[u8], limit: Duration) -> Vec<u8> {
            let (mut sent, mut got, mut a_closed, mut b_closed) = (0usize, Vec::new(), false, false);
            while self.elapsed() < limit {
                if self.a.state() == State::Open && sent < data.len() {
                    sent += self.a.write(&data[sent..]);
                }
                if sent == data.len() && !a_closed && self.a.state() == State::Open {
                    self.a.close();
                    a_closed = true;
                }
                if let Some(b) = &mut self.b {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = b.read(&mut buf);
                        if n == 0 {
                            break;
                        }
                        got.extend_from_slice(&buf[..n]);
                    }
                    if b.is_eof() && !b_closed {
                        b.close();
                        b_closed = true;
                    }
                }
                self.step();
                if self.a.is_finished() && self.b.as_ref().is_some_and(|b| b.is_finished()) {
                    break;
                }
            }
            got
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u32).wrapping_mul(2654435761) as u8 ^ (i >> 8) as u8).collect()
    }

    #[test]
    fn a_connection_is_opened_with_the_ids_the_bep_describes() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));

        assert_eq!((sim.a.state(), sim.b.as_ref().map(|b| b.state())), (State::Open, Some(State::Open)));
        let syn = &sim.wire.iter().find(|(p, _)| p.kind == PacketType::Syn).unwrap().0;
        assert_eq!((syn.connection_id, syn.seq_nr), (100, 1), "the request carries the id the initiator will listen on");
        let answer = &sim.wire.iter().find(|(p, from_a)| !from_a && p.kind == PacketType::State).unwrap().0;
        assert_eq!((answer.connection_id, answer.ack_nr, answer.seq_nr), (100, 1, 40000), "answered on that id, acknowledging the request, with its own first number");
        assert_eq!(sim.b.as_ref().unwrap().recv_id(), 101, "the acceptor listens on the id after");
        sim.a.write(b"x");
        sim.run_for(Duration::from_millis(100));
        let data = sim.wire.iter().find(|(p, from_a)| *from_a && p.kind == PacketType::Data).unwrap().0.clone();
        assert_eq!((data.connection_id, data.seq_nr), (101, 2), "the initiator's later packets use id + 1, and its numbering goes on from the request");
    }

    #[test]
    fn a_megabyte_crosses_a_clean_link_intact_and_both_ends_finish_cleanly() {
        let data = pattern(1 << 20);
        let mut sim = Sim::new();

        let got = sim.transfer(&data, Duration::from_secs(60));

        assert!(got == data, "received {} of {} bytes, intact: {}", got.len(), data.len(), got == data[..got.len().min(data.len())]);
        assert!(sim.a.is_finished() && sim.b.as_ref().unwrap().is_finished());
        assert_eq!((sim.a.error(), sim.b.as_ref().unwrap().error()), (None, None), "an orderly end, not a failure");
        assert!(sim.elapsed() < Duration::from_secs(20), "and not slowly: {:?}", sim.elapsed());
    }

    #[test]
    fn data_in_both_directions_at_once() {
        let (up, down) = (pattern(200_000), pattern(300_000).into_iter().rev().collect::<Vec<u8>>());
        let mut sim = Sim::new();
        let (mut sent_up, mut sent_down, mut got_up, mut got_down) = (0, 0, Vec::new(), Vec::new());
        while sim.elapsed() < Duration::from_secs(60) && (got_up.len() < up.len() || got_down.len() < down.len()) {
            sent_up += if sim.a.state() == State::Open { sim.a.write(&up[sent_up..]) } else { 0 };
            if let Some(b) = &mut sim.b {
                sent_down += b.write(&down[sent_down..]);
                let mut buf = [0u8; 4096];
                loop {
                    let n = b.read(&mut buf);
                    if n == 0 {
                        break;
                    }
                    got_up.extend_from_slice(&buf[..n]);
                }
            }
            let mut buf = [0u8; 4096];
            loop {
                let n = sim.a.read(&mut buf);
                if n == 0 {
                    break;
                }
                got_down.extend_from_slice(&buf[..n]);
            }
            sim.step();
        }
        assert!(got_up == up && got_down == down);
    }

    #[test]
    fn loss_reordering_and_duplication_do_not_corrupt_or_lose_anything() {
        let data = pattern(600_000);
        let mut sim = Sim::new();
        sim.loss_permille = 50;
        sim.duplicate_permille = 30;
        sim.jitter_us = 15_000; // more than a packet's spacing, so they overtake one another

        let got = sim.transfer(&data, Duration::from_secs(600));

        assert!(got == data, "received {} of {} bytes", got.len(), data.len());
        assert!(sim.a.is_finished() && sim.b.as_ref().unwrap().is_finished(), "and both ends finished");
        assert_eq!((sim.a.error(), sim.b.as_ref().unwrap().error()), (None, None));
    }

    #[test]
    fn heavy_loss_still_gets_there() {
        let data = pattern(100_000);
        let mut sim = Sim::new();
        // (Three tries at the connection request is all a connection gets, and at this rate
        // one time in twelve they all fail; the handshake is not what is being tested.)
        sim.run_for(Duration::from_millis(100));
        sim.loss_permille = 250;

        let got = sim.transfer(&data, Duration::from_secs(3000));

        assert!(got == data, "received {} of {}; A {:?} {:?}, B {:?} {:?} at {:?}", got.len(), data.len(), sim.a.state(), sim.a.error(), sim.b.as_ref().map(|b| b.state()), sim.b.as_ref().map(|b| b.error()), sim.elapsed());
    }

    #[test]
    fn sequence_numbers_wrap_round_the_16_bit_circle_without_harm() {
        // Both ends begin a few packets short of the wrap; 600 KB is over four hundred packets each way.
        let data = pattern(600_000);
        let mut sim = Sim::with_seqs(65_500, 65_400);
        sim.loss_permille = 20;
        sim.jitter_us = 5_000;

        let got = sim.transfer(&data, Duration::from_secs(600));

        assert!(got == data, "received {} of {} bytes", got.len(), data.len());
        assert!(sim.wire.iter().any(|(p, from_a)| *from_a && p.seq_nr < 1000 && p.kind == PacketType::Data), "the numbers really did wrap");
    }

    #[test]
    fn a_lost_connection_request_is_sent_again() {
        let mut sim = Sim::new();
        let mut syns = 0;
        sim.drop_if = Box::new(move |p, _| {
            if p.kind == PacketType::Syn {
                syns += 1;
                return syns == 1;
            }
            false
        });
        sim.run_for(Duration::from_millis(500));
        assert_eq!(sim.a.state(), State::Connecting, "the first request was lost and it has not yet given up");
        sim.run_for(Duration::from_millis(1500));
        assert_eq!((sim.a.state(), sim.b.as_ref().map(|b| b.state())), (State::Open, Some(State::Open)), "the second, after the first second, got through");
    }

    #[test]
    fn a_connection_request_nobody_answers_ends_in_a_timeout_after_three_tries() {
        let mut sim = Sim::new();
        sim.drop_if = Box::new(|_, _| true);

        sim.run_for(Duration::from_secs(30));

        assert_eq!((sim.a.state(), sim.a.error()), (State::Ended, Some(io::ErrorKind::TimedOut)));
        assert_eq!(sim.wire.iter().filter(|(p, _)| p.kind == PacketType::Syn).count(), MAX_SYN_ATTEMPTS as usize);
    }

    #[test]
    fn a_reset_ends_the_connection_and_says_why() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        sim.a.write(b"hello");
        sim.b.as_mut().unwrap().abort(sim.now);

        sim.run_for(Duration::from_millis(200));

        assert_eq!((sim.a.state(), sim.a.error()), (State::Ended, Some(io::ErrorKind::ConnectionReset)));
        assert_eq!(sim.b.as_ref().unwrap().error(), Some(io::ErrorKind::ConnectionAborted));
        assert_eq!(sim.a.write(b"more"), 0, "nothing more is taken");
    }

    #[test]
    fn a_reset_in_answer_to_the_request_is_a_refusal() {
        let mut sim = Sim::new();
        let request = sim.a.take_outgoing().remove(0);
        let syn = Packet::decode(&request).unwrap();
        let mut b = Connection::accept(sim.now, &syn, 5);
        b.take_outgoing();
        b.abort(sim.now);
        for bytes in b.take_outgoing() {
            sim.a.on_packet(sim.now + Duration::from_millis(10), &Packet::decode(&bytes).unwrap());
        }
        assert_eq!(sim.a.error(), Some(io::ErrorKind::ConnectionRefused));
    }

    #[test]
    fn a_dropped_packet_is_recovered_by_selective_ack_long_before_the_timeout() {
        let data = pattern(200_000);
        let mut sim = Sim::new();
        let mut seen = 0;
        sim.drop_if = Box::new(move |p, from_a| {
            if from_a && p.kind == PacketType::Data {
                seen += 1;
                return seen == 40; // one packet, once
            }
            false
        });

        let got = sim.transfer(&data, Duration::from_secs(60));

        assert!(got == data);
        let retransmitted = sim.wire.iter().filter(|(p, from_a)| *from_a && p.kind == PacketType::Data).map(|(p, _)| p.seq_nr).fold(std::collections::HashMap::new(), |mut m: std::collections::HashMap<u16, u32>, s| {
            *m.entry(s).or_default() += 1;
            m
        });
        assert_eq!(retransmitted.values().filter(|&&n| n > 1).count(), 1, "exactly the lost packet was sent twice");
        assert!(sim.elapsed() < Duration::from_secs(10), "no stall waiting on a timer: {:?}", sim.elapsed());
    }

    #[test]
    fn without_selective_acks_three_duplicate_acks_trigger_the_resend() {
        let data = pattern(200_000);
        let mut sim = Sim::new();
        sim.strip_sack = true;
        let mut seen = 0;
        sim.drop_if = Box::new(move |p, from_a| {
            if from_a && p.kind == PacketType::Data {
                seen += 1;
                return seen == 40;
            }
            false
        });

        let got = sim.transfer(&data, Duration::from_secs(60));

        assert!(got == data);
        // The timer is half a second at the least; recovering sooner is the duplicate acks' doing.
        let lost_seq = sim.wire.iter().filter(|(p, from_a)| *from_a && p.kind == PacketType::Data).nth(39).unwrap().0.seq_nr;
        let resent = sim.wire.iter().filter(|(p, from_a)| *from_a && p.kind == PacketType::Data && p.seq_nr == lost_seq).count();
        assert_eq!(resent, 2, "sent, lost, sent again");
        assert!(sim.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn the_receiver_reports_what_it_holds_out_of_order_in_the_selective_ack() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        let b = sim.b.as_mut().unwrap();
        // ack_nr is 1 (the request); the next expected is 2. Hand it 3 and 5 and 6.
        let mk = |seq: u16| Packet { kind: PacketType::Data, connection_id: 101, timestamp: 0, timestamp_diff: 0, wnd_size: 1 << 20, seq_nr: seq, ack_nr: 40_000, sack: Vec::new(), payload: vec![seq as u8] };
        for seq in [3, 5, 6] {
            b.on_packet(sim.now, &mk(seq));
        }
        let last = Packet::decode(b.take_outgoing().last().unwrap()).unwrap();
        assert_eq!(last.kind, PacketType::State);
        assert_eq!(last.ack_nr, 1, "still waiting for 2");
        // Bit 0 is ack_nr + 2 = 3, bit 2 is 5, bit 3 is 6.
        assert_eq!(last.sack, vec![0b0000_1101, 0, 0, 0]);
        // And when 2 arrives, everything through 3 is in order, 4 is still missing.
        b.on_packet(sim.now, &mk(2));
        let last = Packet::decode(b.take_outgoing().last().unwrap()).unwrap();
        assert_eq!(last.ack_nr, 3);
        assert_eq!(last.sack, vec![0b0000_0011, 0, 0, 0], "5 and 6 are bits 0 and 1 of what follows the missing 4");
        let mut got = [0u8; 8];
        assert_eq!(b.read(&mut got), 2);
        assert_eq!(&got[..2], &[2, 3], "what was in order, in order");
    }

    #[test]
    fn packets_already_received_or_from_far_ahead_are_answered_but_not_taken() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        let b = sim.b.as_mut().unwrap();
        let mk = |seq: u16| Packet { kind: PacketType::Data, connection_id: 101, timestamp: 0, timestamp_diff: 0, wnd_size: 1 << 20, seq_nr: seq, ack_nr: 40_000, sack: Vec::new(), payload: vec![9; 10] };
        b.on_packet(sim.now, &mk(2));
        b.take_outgoing();
        b.on_packet(sim.now, &mk(2)); // a duplicate
        b.on_packet(sim.now, &mk(2 + REORDER_WINDOW + 5)); // beyond what it will keep
        b.on_packet(sim.now, &mk(1)); // older than anything it is waiting for
        let replies = b.take_outgoing();
        assert_eq!(replies.len(), 3, "each answered, so that the sender learns where things stand");
        assert!(replies.iter().all(|r| Packet::decode(r).unwrap().ack_nr == 2 && Packet::decode(r).unwrap().sack.is_empty()));
        assert_eq!(b.readable(), 10, "and only the first was kept");
    }

    #[test]
    fn an_acknowledgement_of_something_never_sent_is_ignored() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        sim.a.write(&pattern(5000));
        sim.a.flush(sim.now);
        let before = sim.a.cur_window;
        let flight = sim.a.in_flight.len();
        assert!(before > 0 && flight > 0);
        let bogus = Packet { kind: PacketType::State, connection_id: 100, timestamp: 0, timestamp_diff: 0, wnd_size: 1 << 20, seq_nr: 40_000, ack_nr: 30_000, sack: Vec::new(), payload: Vec::new() };
        sim.a.on_packet(sim.now, &bogus);
        assert_eq!(sim.a.cur_window, before, "nothing was taken as acknowledged");
        assert_eq!(sim.a.in_flight.len(), flight, "and none of it was dropped from the record");
    }

    #[test]
    fn a_receiver_that_does_not_read_stops_the_sender_at_its_window_and_reading_starts_it_again() {
        let data = pattern(2 * RECEIVE_BUFFER);
        let mut sim = Sim::new();
        let mut sent = 0;
        // Nothing is read for a good while.
        for _ in 0..8000 {
            if sim.a.state() == State::Open {
                sent += sim.a.write(&data[sent..]);
            }
            sim.step();
        }
        let b = sim.b.as_mut().unwrap();
        assert!(b.readable() > RECEIVE_BUFFER - MAX_PAYLOAD && b.readable() <= RECEIVE_BUFFER, "the receiver holds what its buffer holds, and no more: {}", b.readable());
        assert!(sent < data.len(), "the sender's own buffer filled too");

        // Now it reads, as an application does.
        let mut got = Vec::new();
        while got.len() < data.len() && sim.elapsed() < Duration::from_secs(120) {
            if sim.a.state() == State::Open && sent < data.len() {
                sent += sim.a.write(&data[sent..]);
            }
            let mut buf = [0u8; 8192];
            let n = sim.b.as_mut().unwrap().read(&mut buf);
            got.extend_from_slice(&buf[..n]);
            sim.step();
        }
        assert!(got == data, "received {} of {}", got.len(), data.len());
    }

    #[test]
    fn a_link_slower_than_the_sender_is_not_filled_beyond_the_delay_target() {
        // 1 Mbit/s with room for four seconds of queue. A sender that filled it would wait for
        // seconds; one that keeps to LEDBAT's target stays near a tenth of a second.
        let data = pattern(600_000);
        let mut sim = Sim::new();
        sim.bottleneck = Some(Bottleneck { bytes_per_second: 125_000, limit: Duration::from_secs(4), free_at: sim.now });

        let got = sim.transfer(&data, Duration::from_secs(300));

        assert!(got == data, "received {} of {}", got.len(), data.len());
        assert!(sim.longest_queue < Duration::from_millis(600), "the queue reached {:?}", sim.longest_queue);
        // And it did use the link: 600 KB at 125 KB/s is about five seconds.
        assert!(sim.elapsed() < Duration::from_secs(20), "{:?}", sim.elapsed());
    }

    #[test]
    fn a_stalled_link_is_retried_with_backoff_and_then_given_up_on() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        sim.a.write(&pattern(3000));
        // From now on, nothing gets through.
        sim.drop_if = Box::new(|_, _| true);
        sim.run_for(Duration::from_secs(200));

        assert_eq!((sim.a.state(), sim.a.error()), (State::Ended, Some(io::ErrorKind::TimedOut)));
        let sends: Vec<Duration> = sim.wire.iter().filter(|(p, from_a)| *from_a && p.kind == PacketType::Data && p.seq_nr == 2).map(|_| Duration::ZERO).collect();
        assert!(sends.len() >= 4 && sends.len() <= 1 + MAX_TIMEOUTS as usize, "the first packet was sent {} times", sends.len());
    }

    #[test]
    fn a_quiet_connection_is_kept_alive_and_a_silent_one_is_given_up_on() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_secs(40));
        let keepalives = sim.wire.iter().filter(|(p, from_a)| *from_a && p.kind == PacketType::State && p.wnd_size > 0).count();
        assert!(keepalives >= 2, "an idle connection says so now and then: {}", keepalives);
        assert_eq!((sim.a.state(), sim.b.as_ref().unwrap().state()), (State::Open, State::Open), "and stays up");

        sim.drop_if = Box::new(|_, _| true);
        sim.run_for(Duration::from_secs(100));
        assert_eq!((sim.a.state(), sim.a.error()), (State::Ended, Some(io::ErrorKind::TimedOut)), "hearing nothing for a minute and a half ends it");
    }

    #[test]
    fn close_waits_for_what_is_queued_and_the_reader_sees_the_end_only_after_all_of_it() {
        let data = pattern(50_000);
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        assert_eq!(sim.a.write(&data), data.len());
        sim.a.close();
        assert_eq!(sim.a.write(b"late"), 0, "nothing can be added after close");

        let mut got = Vec::new();
        let mut buf = [0u8; 1000];
        let mut eof_at = None;
        for _ in 0..20_000 {
            sim.step();
            let n = sim.b.as_mut().unwrap().read(&mut buf);
            got.extend_from_slice(&buf[..n]);
            if eof_at.is_none() && sim.b.as_ref().unwrap().is_eof() {
                eof_at = Some(got.len());
            }
        }
        assert_eq!(eof_at, Some(data.len()), "the end is seen after every byte and not before");
        assert!(got == data);
    }

    #[test]
    fn a_fin_whose_acknowledgement_is_lost_is_acknowledged_again_and_both_finish() {
        let data = pattern(3000);
        let mut sim = Sim::new();
        // Lose the first acknowledgement of A's FIN and everything B says for a little after it.
        let mut fin_seen = false;
        sim.drop_if = Box::new(move |p, from_a| {
            if from_a && p.kind == PacketType::Fin {
                fin_seen = true;
            }
            !from_a && fin_seen && p.kind == PacketType::State && !p.sack.is_empty()
        });
        let got = sim.transfer(&data, Duration::from_secs(120));
        assert!(got == data);
        assert!(sim.a.is_finished() && sim.b.as_ref().unwrap().is_finished());
        assert_eq!((sim.a.error(), sim.b.as_ref().unwrap().error()), (None, None));
    }

    #[test]
    fn a_connection_that_has_ended_orderly_still_answers_a_repeated_fin() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        sim.a.close();
        sim.b.as_mut().unwrap().close();
        sim.run_for(Duration::from_secs(1));
        assert!(sim.a.is_finished() && sim.b.as_ref().unwrap().is_finished());
        let fin = Packet { kind: PacketType::Fin, connection_id: 100, timestamp: 0, timestamp_diff: 0, wnd_size: 0, seq_nr: 40_000, ack_nr: 2, sack: Vec::new(), payload: Vec::new() };
        sim.a.take_outgoing();
        sim.a.on_packet(sim.now, &fin);
        assert_eq!(sim.a.take_outgoing().len(), 1, "it answers, though it has ended");
    }

    #[test]
    fn the_window_grows_on_a_clear_link_and_shrinks_when_a_packet_is_lost() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        let start = sim.a.max_window;
        let data = pattern(400_000);
        let (mut sent, mut got) = (0, 0);
        while got < data.len() && sim.elapsed() < Duration::from_secs(30) {
            sent += sim.a.write(&data[sent..]);
            let mut buf = [0u8; 8192];
            got += sim.b.as_mut().unwrap().read(&mut buf);
            sim.step();
        }
        let grown = sim.a.max_window;
        assert!(grown > 10.0 * start, "slow start opened it up: {} from {}", grown, start);

        sim.a.in_flight.clear();
        sim.a.cur_window = 0;
        let mut cut = Connection::connect(sim.now, 1);
        cut.max_window = 100_000.0;
        cut.slow_start = false;
        cut.cut_window(sim.now);
        assert_eq!(cut.max_window, 50_000.0, "halved");
        cut.cut_window(sim.now);
        assert_eq!(cut.max_window, 50_000.0, "but only once a round trip");
        cut.max_window = 2000.0;
        cut.last_window_cut = None;
        cut.cut_window(sim.now);
        assert_eq!(cut.max_window, MIN_WINDOW, "and never below one packet");
    }

    #[test]
    fn a_timeout_puts_the_window_back_to_one_packet_and_doubles_the_timer() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        sim.a.write(&pattern(20_000));
        sim.a.max_window = 50_000.0;
        sim.a.flush(sim.now);
        sim.drop_if = Box::new(|_, _| true);
        let rto = sim.a.rto;

        sim.run_for(rto + Duration::from_millis(50));

        assert_eq!(sim.a.max_window, MIN_WINDOW);
        assert_eq!(sim.a.rto, rto * 2);
        assert_eq!(sim.a.timeouts, 1);
    }

    #[test]
    fn the_round_trip_time_is_measured_and_sets_the_timer_within_bounds() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        let rtt = sim.a.rtt.expect("the request and its answer were timed");
        assert!(rtt >= Duration::from_millis(40) && rtt <= Duration::from_millis(50), "two 20 ms legs: {:?}", rtt);
        sim.a.update_rtt(Duration::from_millis(10));
        for _ in 0..50 {
            sim.a.update_rtt(Duration::from_millis(10));
        }
        assert_eq!(sim.a.rto, MIN_RTO, "however fast, not below the floor");
        sim.a.update_rtt(Duration::from_secs(3600));
        for _ in 0..50 {
            sim.a.update_rtt(Duration::from_secs(3600));
        }
        assert_eq!(sim.a.rto, MAX_RTO, "nor above the ceiling");
    }

    #[test]
    fn sequence_comparison_goes_round_the_circle() {
        assert!(seq_le(5, 5) && seq_le(5, 6) && !seq_le(6, 5));
        assert!(seq_le(65_535, 0), "0 follows 65535");
        assert!(seq_le(65_530, 10) && !seq_le(10, 65_530));
        assert!(seq_le(0, 0x7FFF) && !seq_le(0, 0x8000), "halfway round is the limit of 'after'");
    }

    #[test]
    fn the_queue_of_unsent_data_is_bounded() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        let huge = vec![1u8; 10 * SEND_BUFFER];
        assert_eq!(sim.a.write(&huge), SEND_BUFFER, "no more than the buffer takes");
        assert_eq!(sim.a.write(b"x"), 0);
        assert_eq!(sim.a.writable(), 0);
    }

    fn state_packet(sim: &Sim, wnd_size: u32, ack_nr: u16) -> Packet {
        Packet { kind: PacketType::State, connection_id: 100, timestamp: sim.now.duration_since(sim.start).as_micros() as u32, timestamp_diff: 0, wnd_size, seq_nr: 40_000, ack_nr, sack: Vec::new(), payload: Vec::new() }
    }

    #[test]
    fn a_peer_with_no_room_is_sent_nothing_but_a_probe_now_and_then() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        // The peer says its buffer is full.
        let closed = state_packet(&sim, 0, 1);
        sim.a.on_packet(sim.now, &closed);
        sim.a.take_outgoing();
        sim.a.write(&pattern(5000));
        sim.a.flush(sim.now);
        let first_probe = sim.a.take_outgoing().len();
        assert!(first_probe <= 1, "at most one packet goes, to find out: {}", first_probe);

        // Time passes with the window still shut: the sender does not push more, but does ask again.
        let mut sent = first_probe;
        let mut probes = 0;
        for _ in 0..(sim.a.rto.as_millis() as u64 * 3) {
            sim.now += Duration::from_millis(1);
            let closed = state_packet(&sim, 0, sim.a.seq_nr.wrapping_sub(1));
            sim.a.on_packet(sim.now, &closed);
            sim.a.on_tick(sim.now);
            let out = sim.a.take_outgoing().into_iter().filter(|b| Packet::decode(b).unwrap().kind == PacketType::Data).count();
            sent += out;
            probes += out.min(1);
        }
        assert!(probes >= 1, "a shut window is probed, or it would stay shut for ever");
        assert!(sent <= 8, "and not flooded: {} data packets in three timer periods", sent);
    }

    #[test]
    fn reading_when_the_buffer_was_nearly_full_tells_the_sender_at_once() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        let b = sim.b.as_mut().unwrap();
        let mut seq = 2u16;
        while b.receive_window() >= MAX_PACKET as u32 {
            let p = Packet { kind: PacketType::Data, connection_id: 101, timestamp: 0, timestamp_diff: 0, wnd_size: 1 << 20, seq_nr: seq, ack_nr: 40_000, sack: Vec::new(), payload: vec![7; MAX_PAYLOAD] };
            b.on_packet(sim.now, &p);
            seq += 1;
        }
        let last = Packet::decode(b.take_outgoing().last().unwrap()).unwrap();
        assert!(last.wnd_size < MAX_PACKET as u32, "it says it has no room: {}", last.wnd_size);

        let mut buf = vec![0u8; 100_000];
        assert!(b.read(&mut buf) > 0);
        let update = b.take_outgoing();
        b.flush(sim.now);
        let update: Vec<Packet> = update.iter().chain(b.take_outgoing().iter()).map(|bytes| Packet::decode(bytes).unwrap()).collect();
        assert!(update.iter().any(|p| p.kind == PacketType::State && p.wnd_size >= 100_000), "and, once there is room, says so without being asked: {:?}", update.iter().map(|p| p.wnd_size).collect::<Vec<_>>());
    }

    #[test]
    fn a_round_trip_is_not_timed_from_a_packet_that_was_sent_twice() {
        // Which of the sends an acknowledgement answers is unknowable, so it must not set the timer.
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        let rtt = sim.a.rtt;
        sim.a.write(&pattern(500));
        sim.a.flush(sim.now);
        sim.a.in_flight.front_mut().unwrap().transmissions = 2;
        sim.now += Duration::from_secs(5);
        let ack = state_packet(&sim, 1 << 20, sim.a.seq_nr.wrapping_sub(1));
        sim.a.on_packet(sim.now, &ack);
        assert_eq!(sim.a.rtt, rtt, "the five seconds were not taken for a round trip");
        assert!(sim.a.in_flight.is_empty(), "though it was acknowledged");
    }

    #[test]
    fn a_sender_with_little_to_send_does_not_open_its_window_far_beyond_what_it_uses() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        // A hundred bytes every 50 ms for a minute: nothing that needs a big window.
        for _ in 0..1200 {
            sim.a.write(&[1u8; 100]);
            sim.run_for(Duration::from_millis(50));
            let mut buf = [0u8; 4096];
            sim.b.as_mut().unwrap().read(&mut buf);
        }
        assert!(sim.a.max_window <= 6.0 * MAX_PACKET as f64, "the window drifted up to {}", sim.a.max_window);
    }

    #[test]
    fn a_link_that_stays_slow_holds_the_queue_near_the_target_for_a_long_transfer() {
        let data = pattern(3_000_000);
        let mut sim = Sim::new();
        sim.bottleneck = Some(Bottleneck { bytes_per_second: 250_000, limit: Duration::from_secs(4), free_at: sim.now });

        let got = sim.transfer(&data, Duration::from_secs(600));

        assert!(got == data);
        assert!(sim.longest_queue < Duration::from_millis(400), "the queue reached {:?} over {:?}", sim.longest_queue, sim.elapsed());
    }

    #[test]
    fn out_of_order_packets_are_held_and_delivered_in_order_when_the_gap_fills() {
        let mut sim = Sim::new();
        sim.run_for(Duration::from_millis(100));
        let b = sim.b.as_mut().unwrap();
        let mk = |seq: u16| Packet { kind: PacketType::Data, connection_id: 101, timestamp: 0, timestamp_diff: 0, wnd_size: 1 << 20, seq_nr: seq, ack_nr: 40_000, sack: Vec::new(), payload: vec![seq as u8; 3] };
        for seq in [4, 3, 2] {
            b.on_packet(sim.now, &mk(seq));
        }
        assert_eq!(b.readable(), 9, "all three, once the first arrived");
        let mut got = [0u8; 9];
        b.read(&mut got);
        assert_eq!(got, [2, 2, 2, 3, 3, 3, 4, 4, 4]);
    }
}
