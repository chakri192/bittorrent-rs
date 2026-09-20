//! One connection's upload side: what is said and done for a peer that asks us for pieces.
//!
//! It is the same on every connection that can be asked, whichever side made it and whatever else is
//! going on over it: the seeder's serve loop owns the connections of a client with something to give, and a
//! download worker's connection to a peer it is fetching from is one the peer may ask for pieces on too.
//! Here are the bitfield sent first, the `Have`s that follow as pieces are verified, who is unchoked and
//! when the peer is told, and the answers to `Request`, to a request for the info dictionary (BEP 9) and to
//! a hash request (BEP 52). The caller reads the connection and decides what else it does with each
//! message, and how long it waits for one: [`Serving::handle`] takes what it wants of each, and
//! [`Serving::tick`] is to be called between messages.

use crate::choker::PeerId;
use crate::downloader::file_writer::read_block;
use crate::metadata::{MetadataMessage, METADATA_PIECE_SIZE};
use crate::peer::extension::{ExtendedHandshake, EXTENDED_HANDSHAKE_ID};
use crate::peer::fast::allowed_fast_set;
use crate::peer::handshake::Handshake;
use crate::peer::message::{Message, WireError};
use crate::peer::state::PeerState;
use crate::peer::PeerStream;
use crate::seeder::SeederShared;
use std::collections::HashSet;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

/// Largest `Request.length` honored. BEP 3 clients conventionally use
/// 16 KiB; anything above 128 KiB is either a very old client or an
/// attempt to make us allocate absurd buffers -- those get the
/// connection dropped, matching mainline behavior.
pub(crate) const MAX_REQUEST_LEN: u32 = 128 * 1024;
/// The id peers send `ut_metadata` requests to us under.
pub const UT_METADATA_ID: u8 = 1;
/// How many pieces a peer using the Fast Extension may request while choked.
pub(crate) const ALLOWED_FAST_PIECES: usize = 5;

/// A peer's connection, as far as serving it goes. Forgets the peer, freeing any unchoke slot it
/// held, when dropped.
pub struct Serving {
    shared: Arc<SeederShared>,
    choker_id: PeerId,
    /// The Fast Extension (BEP 6) is in use: only if both sides said so.
    fast: bool,
    /// Pieces the peer may request while choked (`fast` only).
    allowed_fast: HashSet<u32>,
    /// Whether the peer has been told it is unchoked.
    told_unchoked: bool,
    /// The version of the have-map last announced to the peer, and what it has been told of.
    seen_version: u64,
    advertised: Vec<bool>,
    /// Whether the info dictionary is offered to this peer.
    speaks_extensions: bool,
    /// The id the peer wants metadata requests answered under, once it has said, and how many it has made
    /// (bounded).
    peer_metadata_id: Option<u8>,
    metadata_requests: usize,
    /// When something was last written to the peer.
    pub last_sent: Instant,
}

impl std::fmt::Debug for Serving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serving").field("choker_id", &self.choker_id).field("fast", &self.fast).finish_non_exhaustive()
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.shared.choker.unregister(self.choker_id);
    }
}

impl Serving {
    /// Says what there is to serve: the bitfield (or `have all`/`have none`), the pieces the peer may
    /// ask for while choked, and, if `extended_handshake`, the extended handshake that offers the info
    /// dictionary. What we can serve right now is told honestly, as BEP 3 requires; pieces verified
    /// afterwards are announced with `Have` as they appear, by [`tick`](Self::tick). Whoever sends its own
    /// extended handshake passes `false`, and builds it with [`Self::extended_handshake_fields`].
    pub fn begin(shared_arc: &Arc<SeederShared>, their_hs: &Handshake, peer_ip: Option<std::net::IpAddr>, stream: &mut dyn PeerStream, extended_handshake: bool) -> io::Result<Self> {
        let shared = &**shared_arc;
        let fast = their_hs.supports_fast();
        let speaks_extensions = shared.metadata.is_some() && their_hs.supports_extensions();
        // The version is read first: a piece added between the two reads then shows up as a difference to
        // announce, never as one that is missed.
        let seen_version = shared.have.version();
        let advertised = shared.have.snapshot();
        let first = if !fast {
            Message::Bitfield(PeerState::encode_bitfield(&advertised))
        } else if advertised.iter().all(|&has| has) && !advertised.is_empty() {
            Message::HaveAll
        } else if advertised.iter().all(|&has| !has) {
            Message::HaveNone
        } else {
            Message::Bitfield(PeerState::encode_bitfield(&advertised))
        };
        first.write_to(stream).map_err(wire_to_io)?;
        // The BEP 6 recipe, from the peer's address and the torrent, limited to what there is to serve.
        let mut allowed_fast = HashSet::new();
        if let (true, Some(std::net::IpAddr::V4(ip))) = (fast, peer_ip) {
            for piece in allowed_fast_set(ip, &shared.info_hash, advertised.len() as u32, ALLOWED_FAST_PIECES) {
                if advertised[piece as usize] {
                    Message::AllowedFast { piece_index: piece }.write_to(stream).map_err(wire_to_io)?;
                    allowed_fast.insert(piece);
                }
            }
        }
        if let (true, true, Some(metadata)) = (extended_handshake, speaks_extensions, &shared.metadata) {
            // A seed says so (BEP 21): nothing is to be gained by offering it pieces.
            let seed = shared.have.count() == shared.have.total();
            Message::Extended { id: EXTENDED_HANDSHAKE_ID, payload: ExtendedHandshake::build_for_seeding(UT_METADATA_ID, metadata.len(), seed) }.write_to(stream).map_err(wire_to_io)?;
        }
        Ok(Serving { choker_id: shared.choker.register(), shared: Arc::clone(shared_arc), fast, allowed_fast, told_unchoked: false, seen_version, advertised, speaks_extensions, peer_metadata_id: None, metadata_requests: 0, last_sent: Instant::now() })
    }

    /// What a peer that wants the info dictionary from us needs to be told in an extended handshake: its size.
    /// `None` when there is none to give, or when the peer does not speak extensions.
    pub fn metadata_size(&self) -> Option<i64> {
        self.speaks_extensions.then(|| self.shared.metadata.as_ref().map(|m| m.len() as i64)).flatten()
    }

    /// Counts `bytes` the peer sent us. What a peer gives is what earns it an unchoke slot (see [`crate::choker`]).
    pub fn record_download(&self, bytes: u64) {
        self.shared.choker.record_download(self.choker_id, bytes);
    }

    /// Announces what should be told between messages: `Have` for each piece verified since the peer was
    /// last told, and a choke or unchoke if the choice of who is served has changed. Call between messages,
    /// as often as the connection can afford to: it costs a comparison when there is nothing to say.
    pub fn tick(&mut self, stream: &mut dyn PeerStream) -> io::Result<()> {
        if announce_new_pieces(stream, &self.shared.have, &mut self.seen_version, &mut self.advertised)? {
            self.last_sent = Instant::now();
        }
        let allowed = self.shared.choker.is_unchoked(self.choker_id);
        if allowed != self.told_unchoked {
            (if allowed { Message::Unchoke } else { Message::Choke }).write_to(stream).map_err(wire_to_io)?;
            self.told_unchoked = allowed;
            self.last_sent = Instant::now();
        }
        Ok(())
    }

    /// Takes what is for the upload side of `msg`, which the peer sent: says whether it was all there was to do
    /// with it (`true`), or whether the caller is to see it too (`false`, and what a caller that also downloads
    /// wants of it: `have`, `unchoke`, blocks it asked for). Answers a request for a block, for the info dictionary or for hashes,
    /// on `stream`. An error is the connection's: a write that failed, or a peer asking for more than it may.
    pub fn handle(&mut self, msg: &Message, stream: &mut dyn PeerStream) -> io::Result<bool> {
        let shared = &*self.shared;
        match msg {
            Message::Interested => {
                shared.choker.set_interested(self.choker_id, true);
                // A free slot is theirs at once; the next tick tells them.
                shared.choker.grant_if_free(self.choker_id);
                Ok(true)
            }
            Message::NotInterested => {
                shared.choker.set_interested(self.choker_id, false);
                Ok(true)
            }
            &Message::Request { index, begin, length } => {
                // Choked peers get nothing, except the pieces the Fast Extension lets them ask for anyway. A
                // fast peer is told when a request will not be answered; others are left in silence (BEP 3).
                let reject = |stream: &mut dyn PeerStream, fast: bool| -> io::Result<bool> {
                    if fast {
                        Message::RejectRequest { index, begin, length }.write_to(stream).map_err(wire_to_io)?;
                    }
                    Ok(true)
                };
                if !shared.choker.is_unchoked(self.choker_id) && !self.allowed_fast.contains(&index) {
                    return reject(stream, self.fast);
                }
                if length > MAX_REQUEST_LEN {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized block request"));
                }
                let piece_len = shared.piece_len(index);
                let in_bounds = shared.have.get(index) && (begin as u64).saturating_add(length as u64) <= piece_len;
                if !in_bounds {
                    return reject(stream, self.fast); // data we don't have / can't have
                }
                let block = read_block(&shared.spans, index, shared.piece_length, begin, length)?;
                if let Some(limit) = &shared.up_limit {
                    limit.acquire(length as usize);
                }
                Message::Piece { index, begin, block }.write_to(stream).map_err(wire_to_io)?;
                shared.uploaded.fetch_add(length as u64, Ordering::Relaxed);
                shared.choker.record_upload(self.choker_id, length as u64);
                self.last_sent = Instant::now();
                Ok(true)
            }
            Message::Extended { id: EXTENDED_HANDSHAKE_ID, payload } if self.speaks_extensions => {
                self.peer_metadata_id = ExtendedHandshake::parse(payload).ok().and_then(|hs| hs.peer_ut_metadata_id());
                Ok(false) // a downloader wants to read it too, for how many requests the peer takes
            }
            Message::Extended { id: UT_METADATA_ID, payload } if self.speaks_extensions => {
                let (Some(metadata), Some(reply_id)) = (&shared.metadata, self.peer_metadata_id) else { return Ok(true) };
                let Ok(MetadataMessage::Request { piece }) = MetadataMessage::decode(payload) else { return Ok(true) };
                self.metadata_requests += 1;
                // The whole dictionary a few times over is plenty; more is a peer using us to move data for nothing.
                if self.metadata_requests > 2 * metadata.len().div_ceil(METADATA_PIECE_SIZE) + 8 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "too many requests for the metadata"));
                }
                let start = piece as usize * METADATA_PIECE_SIZE;
                let reply = if start < metadata.len() {
                    let chunk = &metadata[start..(start + METADATA_PIECE_SIZE).min(metadata.len())];
                    if let Some(limit) = &shared.up_limit {
                        limit.acquire(chunk.len());
                    }
                    MetadataMessage::Data { piece, total_size: metadata.len() as u32, data: chunk.to_vec() }
                } else {
                    MetadataMessage::Reject { piece }
                };
                Message::Extended { id: reply_id, payload: reply.encode() }.write_to(stream).map_err(wire_to_io)?;
                self.last_sent = Instant::now();
                Ok(true)
            }
            Message::HashRequest(request) => {
                // Answered with the hashes, and the uncles after them, or refused: a request must always be answered.
                let answer = shared.hash_source.as_ref().and_then(|source| {
                    // From the piece layers if that is where the layer is; the 16 KiB leaves are worked out from the pieces.
                    source.answer(&request.root, request.base_layer, request.index, request.length, request.proof_layers).or_else(|| {
                        (request.base_layer == 0)
                            .then(|| {
                                source.answer_leaves(&request.root, request.index, request.length, request.proof_layers, |piece| {
                                    let held = shared.have.get(piece);
                                    held.then(|| read_block(&shared.spans, piece, shared.piece_length, 0, shared.piece_len(piece) as u32).ok()).flatten()
                                })
                            })
                            .flatten()
                    })
                });
                let reply = match answer {
                    Some(range) => Message::Hashes { request: *request, hashes: range.hashes.into_iter().chain(range.uncles).collect() },
                    None => Message::HashReject(*request),
                };
                reply.write_to(stream).map_err(wire_to_io)?;
                self.last_sent = Instant::now();
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// Tells a connected peer about pieces verified since it was last told: a
/// `Have` for each. Without this a peer that connected early would never
/// learn of what this client downloads afterwards, and a client that is
/// still downloading would be a poor source. Returns whether it sent any.
fn announce_new_pieces(stream: &mut dyn PeerStream, have: &crate::seeder::HaveMap, seen_version: &mut u64, advertised: &mut [bool]) -> io::Result<bool> {
    let version = have.version();
    if version == *seen_version {
        return Ok(false);
    }
    *seen_version = version;
    let now = have.snapshot();
    let mut sent = false;
    for (index, (&has, told)) in now.iter().zip(advertised.iter_mut()).enumerate() {
        if has && !*told {
            Message::Have { piece_index: index as u32 }.write_to(stream).map_err(wire_to_io)?;
            *told = true;
            sent = true;
        }
    }
    Ok(sent)
}

pub(crate) fn wire_to_io(e: WireError) -> io::Error {
    match e {
        WireError::Io(io) => io,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}
