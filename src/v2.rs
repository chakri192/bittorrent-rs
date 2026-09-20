//! BitTorrent v2 (BEP 52): SHA-256 merkle trees over 16 KiB blocks, the
//! file tree that replaces the file list, and the piece layers.
//!
//! In a v2 torrent every file has its own merkle tree. The leaves are the
//! SHA-256 hashes of its 16 KiB blocks (the last one hashed as it is, not
//! padded); missing leaves are 32 zero bytes, up to a power of two. The root
//! is the file's `pieces root`. For a file longer than one piece, the tree's
//! layer at the height of a piece has one hash per piece, and those hashes
//! (the "piece layer") are what a piece is checked against; when that layer
//! is padded to a power of two the padding is the root of a piece's worth of
//! zero leaves.
//!
//! This module is the arithmetic and the parsing; it reads no network and
//! writes no files.

use crate::bencode::Bencode;
use crate::sha256::{sha256, Sha256};
use crate::torrent::is_safe_component;
use std::collections::BTreeMap;
use std::io::{self, Read};

/// The size of a block, the unit at the leaves of every tree.
pub const BLOCK: usize = 16 * 1024;

pub type Hash = [u8; 32];

/// Deepest a file tree may nest, and most files it may name: bounds on what
/// an untrusted torrent can make this allocate.
const MAX_DEPTH: usize = 64;
const MAX_FILES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2Error {
    /// The file tree is not shaped as BEP 52 says.
    BadTree(&'static str),
    /// A path component that is not a plain name.
    UnsafePath(String),
    TooDeep,
    TooManyFiles,
    /// A length that is negative or overflows.
    BadLength,
    /// A file that has length but no `pieces root`, or a root that is not 32 bytes.
    BadRoot,
    /// A piece layer whose size, or whose root, does not fit its file.
    BadLayer,
    /// The piece length is not a power of two of at least 16 KiB.
    BadPieceLength,
}

impl std::fmt::Display for V2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            V2Error::BadTree(what) => write!(f, "file tree: {}", what),
            V2Error::UnsafePath(part) => write!(f, "unsafe path in the file tree ({:?}): it could write outside the download directory", part),
            V2Error::TooDeep => write!(f, "file tree nests too deeply"),
            V2Error::TooManyFiles => write!(f, "file tree names too many files"),
            V2Error::BadLength => write!(f, "a file length that is negative or too large"),
            V2Error::BadRoot => write!(f, "a file's 'pieces root' is missing or not 32 bytes"),
            V2Error::BadLayer => write!(f, "a piece layer does not match its file"),
            V2Error::BadPieceLength => write!(f, "piece length is not a power of two of at least 16 KiB"),
        }
    }
}

impl std::error::Error for V2Error {}

// ---- the trees --------------------------------------------------------

fn parent(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

/// The root of a tree of the given `height` whose leaves are all zero: what
/// pads a tree out to a power of two, at whatever level it is padded.
pub fn zero_subtree(height: u32) -> Hash {
    let mut hash = [0u8; 32];
    for _ in 0..height {
        hash = parent(&hash, &hash);
    }
    hash
}

/// The root of a merkle tree `width` leaves wide (a power of two), whose
/// first leaves are `leaves` and whose others are `pad`.
pub fn merkle_root(leaves: &[Hash], width: usize, pad: Hash) -> Hash {
    debug_assert!(width.is_power_of_two() && leaves.len() <= width);
    let mut level: Vec<Hash> = leaves.to_vec();
    level.resize(width.max(1), pad);
    while level.len() > 1 {
        level = level.chunks(2).map(|pair| parent(&pair[0], &pair[1])).collect();
    }
    level[0]
}

/// The hash of each 16 KiB block of `data`, the last block as short as it is.
pub fn block_hashes(data: &[u8]) -> Vec<Hash> {
    data.chunks(BLOCK).map(sha256).collect()
}

/// The hash of one piece of a file longer than a piece: the tree over its
/// blocks, `piece_length / 16 KiB` leaves wide, so a short last piece is
/// padded with zero leaves.
pub fn piece_hash(data: &[u8], piece_length: usize) -> Hash {
    merkle_root(&block_hashes(data), piece_length / BLOCK, [0u8; 32])
}

/// Whether `data` is a piece whose tree, `width` leaves wide, has root `root`.
pub fn merkle_matches(data: &[u8], width: usize, root: &Hash) -> bool {
    if !width.is_power_of_two() || data.len() > width.saturating_mul(BLOCK) {
        return false;
    }
    merkle_root(&block_hashes(data), width, [0u8; 32]) == *root
}

/// One piece of a v2-only torrent. Pieces never span files: each file's
/// tree is cut into pieces of its own, so a file's last piece is short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Piece {
    /// The file it is part of (an index into the torrent's files).
    pub file: usize,
    /// Where in that file it begins.
    pub offset: u64,
    pub length: u32,
    /// What it must come to, from the file's piece layer (or the file's root
    /// if the file fits in one piece).
    pub root: Hash,
    /// Leaves in the tree it is hashed over: a piece's worth, except in a file
    /// smaller than a piece, where the tree is only as wide as the file needs.
    pub width: u32,
}

/// Every piece of the files, in order, with what each must hash to. `None`
/// if a file longer than a piece has no piece layer: without it there is
/// nothing to check that file's pieces against.
pub fn plan_pieces(files: &[V2File], layers: &BTreeMap<Hash, Vec<Hash>>, piece_length: u64) -> Option<Vec<V2Piece>> {
    let mut pieces = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let Some(root) = file.root else { continue };
        if file.length <= piece_length {
            let blocks = file.length.div_ceil(BLOCK as u64) as usize;
            pieces.push(V2Piece { file: index, offset: 0, length: file.length as u32, root, width: blocks.next_power_of_two() as u32 });
            continue;
        }
        let layer = layers.get(&root)?;
        for (n, hash) in layer.iter().enumerate() {
            let offset = n as u64 * piece_length;
            pieces.push(V2Piece { file: index, offset, length: (file.length - offset).min(piece_length) as u32, root: *hash, width: (piece_length / BLOCK as u64) as u32 });
        }
    }
    Some(pieces)
}

/// What a file's tree comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashes {
    /// The `pieces root`. `None` for an empty file, which has none.
    pub root: Option<Hash>,
    /// One hash per piece; empty when the file fits in one piece, since the
    /// root is then the piece's hash.
    pub layer: Vec<Hash>,
}

fn layer_pad(piece_length: usize) -> Hash {
    zero_subtree((piece_length / BLOCK).trailing_zeros())
}

/// Reads `length` bytes from `reader` and builds the file's tree. Fails with
/// `UnexpectedEof` if the file is shorter.
pub fn hash_file<R: Read>(reader: &mut R, length: u64, piece_length: usize) -> io::Result<FileHashes> {
    if length == 0 {
        return Ok(FileHashes { root: None, layer: Vec::new() });
    }
    if length <= piece_length as u64 {
        let mut data = vec![0u8; length as usize];
        reader.read_exact(&mut data)?;
        let leaves = block_hashes(&data);
        let width = leaves.len().next_power_of_two();
        return Ok(FileHashes { root: Some(merkle_root(&leaves, width, [0u8; 32])), layer: Vec::new() });
    }
    let mut layer = Vec::new();
    let mut left = length;
    let mut buf = vec![0u8; piece_length];
    while left > 0 {
        let take = left.min(piece_length as u64) as usize;
        reader.read_exact(&mut buf[..take])?;
        layer.push(piece_hash(&buf[..take], piece_length));
        left -= take as u64;
    }
    let root = merkle_root(&layer, layer.len().next_power_of_two(), layer_pad(piece_length));
    Ok(FileHashes { root: Some(root), layer })
}

/// Whether `piece_length` is a valid v2 piece length.
pub fn valid_piece_length(piece_length: i64) -> bool {
    piece_length >= BLOCK as i64 && (piece_length as u64).is_power_of_two()
}

/// The hash a piece of a file is expected to have: its entry in the file's
/// piece layer, or the file's root if it fits in one piece.
pub fn expected_piece_hash(file: &V2File, layer: Option<&Vec<Hash>>, piece_in_file: usize) -> Option<Hash> {
    match layer {
        Some(hashes) => hashes.get(piece_in_file).copied(),
        None if piece_in_file == 0 => file.root,
        None => None,
    }
}

// ---- the metadata -----------------------------------------------------

/// One file of a v2 torrent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2File {
    pub path: Vec<String>,
    pub length: u64,
    /// Absent for an empty file.
    pub root: Option<Hash>,
}

/// The v2 parts of a torrent's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Meta {
    /// The files, in the order of the tree.
    pub files: Vec<V2File>,
    /// Piece layers by `pieces root`, from the `.torrent` file (a magnet link
    /// does not carry them).
    pub layers: BTreeMap<Hash, Vec<Hash>>,
    /// SHA-256 of the info dictionary. Its first 20 bytes stand for it where a
    /// 20-byte hash is wanted: the handshake, trackers, the DHT.
    pub info_hash: Hash,
}

impl V2Meta {
    /// The 20-byte form of the info hash.
    pub fn short_hash(&self) -> [u8; 20] {
        let mut short = [0u8; 20];
        short.copy_from_slice(&self.info_hash[..20]);
        short
    }

    /// The piece layer for `file`, if the torrent carries one.
    pub fn layer_of(&self, file: &V2File) -> Option<&Vec<Hash>> {
        file.root.as_ref().and_then(|root| self.layers.get(root))
    }
}

/// Reads the `file tree` of an info dictionary.
pub fn parse_file_tree(tree: &Bencode) -> Result<Vec<V2File>, V2Error> {
    let mut files = Vec::new();
    let mut path = Vec::new();
    walk(tree, &mut path, &mut files)?;
    Ok(files)
}

fn walk(node: &Bencode, path: &mut Vec<String>, files: &mut Vec<V2File>) -> Result<(), V2Error> {
    let entries = node.as_dict().ok_or(V2Error::BadTree("an entry is not a dictionary"))?;
    if let Some(leaf) = entries.get(b"".as_slice()) {
        // A file. Nothing else may sit beside its description.
        if entries.len() != 1 || path.is_empty() {
            return Err(V2Error::BadTree("a file entry with other entries beside it, or at the top"));
        }
        if files.len() >= MAX_FILES {
            return Err(V2Error::TooManyFiles);
        }
        let length = leaf.get("length").and_then(Bencode::as_int).ok_or(V2Error::BadTree("a file without a length"))?;
        let length = u64::try_from(length).map_err(|_| V2Error::BadLength)?;
        let root = match leaf.get("pieces root") {
            Some(root) => {
                let bytes = root.as_bytes().ok_or(V2Error::BadRoot)?;
                Some(Hash::try_from(bytes).map_err(|_| V2Error::BadRoot)?)
            }
            None => None,
        };
        if (length > 0) != root.is_some() {
            return Err(V2Error::BadRoot);
        }
        files.push(V2File { path: path.clone(), length, root });
        return Ok(());
    }
    if path.len() >= MAX_DEPTH {
        return Err(V2Error::TooDeep);
    }
    for (name, child) in entries {
        let name = std::str::from_utf8(name).map_err(|_| V2Error::UnsafePath(String::from_utf8_lossy(name).into_owned()))?;
        if !is_safe_component(name) {
            return Err(V2Error::UnsafePath(name.to_string()));
        }
        path.push(name.to_string());
        walk(child, path, files)?;
        path.pop();
    }
    Ok(())
}

/// Reads `piece layers`: for each file root, the hashes of that file's pieces.
pub fn parse_layers(layers: Option<&Bencode>) -> Result<BTreeMap<Hash, Vec<Hash>>, V2Error> {
    let mut out = BTreeMap::new();
    let Some(layers) = layers else { return Ok(out) };
    for (root, hashes) in layers.as_dict().ok_or(V2Error::BadLayer)? {
        let root = Hash::try_from(root.as_slice()).map_err(|_| V2Error::BadLayer)?;
        let bytes = hashes.as_bytes().ok_or(V2Error::BadLayer)?;
        if bytes.len() % 32 != 0 {
            return Err(V2Error::BadLayer);
        }
        out.insert(root, bytes.as_chunks::<32>().0.to_vec());
    }
    Ok(out)
}

/// Checks the layers against the files: a file longer than a piece that has a
/// layer must have exactly one hash per piece, and they must add up (as the
/// tree says) to the file's root. A layer for no file is ignored.
pub fn validate_layers(files: &[V2File], layers: &BTreeMap<Hash, Vec<Hash>>, piece_length: i64) -> Result<(), V2Error> {
    if !valid_piece_length(piece_length) {
        return Err(V2Error::BadPieceLength);
    }
    let piece_length = piece_length as usize;
    for file in files.iter().filter(|f| f.length > piece_length as u64) {
        let (Some(root), Some(layer)) = (file.root, file.root.as_ref().and_then(|r| layers.get(r))) else { continue };
        if layer.len() as u64 != file.length.div_ceil(piece_length as u64) {
            return Err(V2Error::BadLayer);
        }
        if merkle_root(layer, layer.len().next_power_of_two(), layer_pad(piece_length)) != root {
            return Err(V2Error::BadLayer);
        }
    }
    Ok(())
}

// ---- proofs (hash requests) -------------------------------------------

/// The layer of a file's tree, counted up from the leaves (layer 0 is the 16 KiB blocks), whose nodes are the pieces.
pub fn piece_layer(piece_length: u64) -> u32 {
    (piece_length / BLOCK as u64).trailing_zeros()
}

/// How many layers above the leaves the root of a file longer than a piece is: the piece layer, and the pieces
/// (rounded up to a power of two) above it.
pub fn file_height(length: u64, piece_length: u64) -> u32 {
    piece_layer(piece_length) + length.div_ceil(piece_length).next_power_of_two().trailing_zeros()
}

/// The nodes of a layer of `layer_number`, padded out to the whole width of a tree `height` layers high, and every layer
/// above it up to the root. `layers[k]` is the layer `layer_number + k`.
fn upper_layers(layer: &[Hash], layer_number: u32, height: u32) -> Vec<Vec<Hash>> {
    let mut level: Vec<Hash> = layer.to_vec();
    level.resize(1usize << (height - layer_number), zero_subtree(layer_number));
    let mut layers = vec![level];
    while layers[layers.len() - 1].len() > 1 {
        let next = layers[layers.len() - 1].chunks(2).map(|pair| parent(&pair[0], &pair[1])).collect();
        layers.push(next);
    }
    layers
}

/// What answers a hash request (BEP 52): `length` hashes of one layer, then the uncles that carry them to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashRange {
    pub hashes: Vec<Hash>,
    /// The sibling hash in each layer from the one above the range's own subtree to just below the root,
    /// lowest first, as many as `proof_layers` reaches.
    pub uncles: Vec<Hash>,
}

/// Answers a request for `length` hashes from `index` of layer `layer_number` of a file whose tree is `height` layers
/// high, `layer` being that layer's hashes as the file has them (the padding beyond them is worked out), with
/// `proof_layers` layers of uncles. `None` where the request is malformed or asks for what the tree does not have:
/// `length` must be a power of two of at least two, `index` a multiple of it, the range within the layer.
///
/// Of the proof layers, counted from the one above the base layer, the first `log2(length) - 1` are not sent (the
/// hashes themselves make them), and there is none for the root, which has no sibling.
pub fn hash_range(layer: &[Hash], layer_number: u32, height: u32, index: u32, length: u32, proof_layers: u32) -> Option<HashRange> {
    if layer_number >= height || length < 2 || !length.is_power_of_two() || index & (length - 1) != 0 {
        return None;
    }
    let width = 1u64 << (height - layer_number);
    if u64::from(index) + u64::from(length) > width || layer.len() as u64 > width {
        return None;
    }
    let layers = upper_layers(layer, layer_number, height);
    let hashes = layers[0][index as usize..(index + length) as usize].to_vec();
    let below = length.trailing_zeros();
    let uncles = (below..=proof_layers).take_while(|j| layer_number + j < height).map(|j| layers[j as usize][((index >> j) ^ 1) as usize]).collect();
    Some(HashRange { hashes, uncles })
}

/// The most hashes one hash request may ask for (BEP 52 says a requester should not ask for more).
pub const MAX_HASHES_PER_REQUEST: u32 = 512;

/// One file a seeder can answer hash requests for.
#[derive(Debug, Clone)]
struct SourceFile {
    length: u64,
    /// The piece index (in the torrent's flat numbering, which is the order of [`plan_pieces`]) of the file's first piece.
    first_piece: u32,
    /// The file's piece layer; empty for a file no longer than a piece, whose root is its one piece's hash.
    layer: Vec<Hash>,
}

/// What a seeder answers hash requests from: the piece layer of each file longer than a piece, and, to answer for the 16 KiB
/// leaves, a way to read the pieces themselves.
#[derive(Debug, Clone, Default)]
pub struct HashSource {
    piece_length: u64,
    /// By `pieces root`.
    files: BTreeMap<Hash, SourceFile>,
}

impl HashSource {
    /// A source from a torrent's files (in order) and the piece layers it has; none for a torrent with nothing to answer from.
    pub fn new(files: &[V2File], layers: &BTreeMap<Hash, Vec<Hash>>, piece_length: u64) -> Option<HashSource> {
        let mut sources = BTreeMap::new();
        let mut next_piece = 0u32;
        for file in files {
            let Some(root) = file.root else { continue };
            let pieces = file.length.div_ceil(piece_length) as u32;
            let layer = if file.length > piece_length { layers.get(&root) } else { Some(&Vec::new()) };
            if let Some(layer) = layer {
                sources.insert(root, SourceFile { length: file.length, first_piece: next_piece, layer: layer.clone() });
            }
            next_piece += pieces;
        }
        (!sources.is_empty()).then_some(HashSource { piece_length, files: sources })
    }

    /// The answer to a request for `length` hashes from `index` of layer `base_layer` of the file with `root`, with
    /// `proof_layers` of uncles: for the piece layer and those above it, from the piece layers; `None` (to be rejected) for a
    /// file it does not know, a layer below the pieces (see [`answer_leaves`](Self::answer_leaves)), or a request not allowed.
    pub fn answer(&self, root: &Hash, base_layer: u32, index: u32, length: u32, proof_layers: u32) -> Option<HashRange> {
        let file = self.files.get(root)?;
        if file.layer.is_empty() {
            return None; // a file of one piece: its root is that piece's hash, and there is no layer of pieces
        }
        let (height, pieces_at) = (file_height(file.length, self.piece_length), piece_layer(self.piece_length));
        if base_layer < pieces_at || length > MAX_HASHES_PER_REQUEST || base_layer >= height {
            return None;
        }
        if base_layer == pieces_at {
            return hash_range(&file.layer, base_layer, height, index, length, proof_layers);
        }
        let above = upper_layers(&file.layer, pieces_at, height).swap_remove((base_layer - pieces_at) as usize);
        hash_range(&above, base_layer, height, index, length, proof_layers)
    }

    /// The answer to a request for `length` of the 16 KiB leaf hashes (layer 0) from `index`, which has to be worked out from
    /// the data: `read_piece` is given a piece's number in the torrent and returns its bytes if they are to be had.
    /// `None` (to be rejected) if the file is not known, the request is not allowed, or a piece it needs is not there.
    pub fn answer_leaves(&self, root: &Hash, index: u32, length: u32, proof_layers: u32, mut read_piece: impl FnMut(u32) -> Option<Vec<u8>>) -> Option<HashRange> {
        let file = self.files.get(root)?;
        let blocks = file.length.div_ceil(BLOCK as u64);
        let blocks_per_piece = self.piece_length / BLOCK as u64;
        let (single_piece, pieces_at) = (file.layer.is_empty(), piece_layer(self.piece_length));
        let height = if single_piece { blocks.next_power_of_two().trailing_zeros() } else { file_height(file.length, self.piece_length) };
        if height == 0 || length < 2 || !length.is_power_of_two() || length > MAX_HASHES_PER_REQUEST || index & (length - 1) != 0 || u64::from(index) + u64::from(length) > 1u64 << height {
            return None;
        }
        // The hash of block `block`: from the piece that holds it (kept, as the uncles below the pieces are in the same one), or the
        // padding that follows the last block.
        let mut cache: Option<(u64, Vec<Hash>)> = None;
        let mut leaf = |block: u64| -> Option<Hash> {
            if block >= blocks {
                return Some([0u8; 32]);
            }
            let piece = block / blocks_per_piece;
            if cache.as_ref().map(|(held, _)| *held) != Some(piece) {
                let data = read_piece(file.first_piece + piece as u32)?;
                cache = Some((piece, block_hashes(&data)));
            }
            cache.as_ref()?.1.get((block % blocks_per_piece) as usize).copied()
        };
        let hashes: Vec<Hash> = (u64::from(index)..u64::from(index) + u64::from(length)).map(&mut leaf).collect::<Option<_>>()?;
        let below = length.trailing_zeros();
        // Above the pieces the uncles come from the piece layer; below them (or in a file of one piece) from the leaves.
        let pieces_tree = (!single_piece).then(|| upper_layers(&file.layer, pieces_at, height));
        let mut uncles = Vec::new();
        for j in below..=proof_layers {
            if j >= height {
                break;
            }
            let sibling = u64::from((index >> j) ^ 1);
            let uncle = match &pieces_tree {
                Some(tree) if j >= pieces_at => tree[(j - pieces_at) as usize][sibling as usize],
                _ => {
                    let first = sibling << j;
                    let leaves: Vec<Hash> = (first..first + (1u64 << j)).map(&mut leaf).collect::<Option<_>>()?;
                    merkle_root(&leaves, leaves.len(), [0u8; 32])
                }
            };
            uncles.push(uncle);
        }
        Some(HashRange { hashes, uncles })
    }
}

/// Whether `hashes` (from `index` of layer `layer_number`) and the `uncles` after them lead, as far as the top of a tree
/// `height` layers high, to `root`: the check on what a peer answers a hash request with.
pub fn verify_range(root: &Hash, layer_number: u32, height: u32, index: u32, hashes: &[Hash], uncles: &[Hash], proof_layers: u32) -> bool {
    let length = hashes.len() as u32;
    if layer_number >= height || length < 2 || !length.is_power_of_two() || index & (length - 1) != 0 || u64::from(index) + u64::from(length) > 1u64 << (height - layer_number) {
        return false;
    }
    let below = length.trailing_zeros();
    let expected = (below..=proof_layers).take_while(|j| layer_number + j < height).count();
    if uncles.len() != expected {
        return false;
    }
    let mut node = merkle_root(hashes, length as usize, [0u8; 32]);
    let mut position = index >> below;
    for uncle in uncles {
        node = if position & 1 == 0 { parent(&node, uncle) } else { parent(uncle, &node) };
        position >>= 1;
    }
    // The proof has to reach the root: nothing short of it says anything about the file.
    layer_number + below + uncles.len() as u32 == height && node == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(hash: &[u8]) -> String {
        hash.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn data(len: usize, salt: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u32).wrapping_mul(2654435761).wrapping_add(salt as u32) as u8 ^ (i >> 9) as u8).collect()
    }

    // The expected values below come from a Python script that builds these trees with hashlib alone.

    #[test]
    fn the_zero_subtrees_of_each_height() {
        assert_eq!(hex(&zero_subtree(0)), "0".repeat(64));
        assert_eq!(hex(&zero_subtree(1)), "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
        assert_eq!(hex(&zero_subtree(2)), "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71");
    }

    #[test]
    fn a_single_block_file_has_the_hash_of_that_block_as_its_root() {
        let bytes = data(1000, 1);
        let hashes = hash_file(&mut &bytes[..], 1000, 65536).unwrap();
        assert_eq!(hashes.root, Some(sha256(&bytes)));
        assert_eq!(hex(&hashes.root.unwrap()), "c6478b6b7b9dfc6524044f32d1163bfeaad65869cbbfff61f0d138a1addc2cec");
        assert!(hashes.layer.is_empty());
    }

    #[test]
    fn a_file_shorter_than_a_piece_is_padded_to_a_power_of_two_of_blocks_not_to_the_piece() {
        // 40000 bytes = 3 blocks, so a 4-leaf tree, in a torrent whose pieces are 64 blocks.
        let bytes = data(40_000, 2);
        let hashes = hash_file(&mut &bytes[..], 40_000, 64 * BLOCK).unwrap();
        assert_eq!(hex(&hashes.root.unwrap()), "c184ece3b7fba40164ebb5a45163b6f432212d99f6b5b83160ccb5320ebe04fb");
        assert!(hashes.layer.is_empty());
    }

    #[test]
    fn a_file_of_exactly_one_piece_has_no_layer_and_its_root_is_the_pieces_hash() {
        let piece = 4 * BLOCK;
        let bytes = data(piece, 5);
        let hashes = hash_file(&mut &bytes[..], piece as u64, piece).unwrap();
        assert_eq!(hex(&hashes.root.unwrap()), "068d4f1089b31150ee090679f077eda9d90fcbffb4d03d7125719420d41c4c29");
        assert!(hashes.layer.is_empty());
        assert_eq!(hashes.root, Some(piece_hash(&bytes, piece)));
    }

    #[test]
    fn a_file_of_several_pieces_has_a_layer_and_a_root_over_it_padded_with_a_zero_piece() {
        let piece = 4 * BLOCK;
        // 200000 bytes: three full pieces and a partial one.
        let bytes = data(200_000, 3);
        let hashes = hash_file(&mut &bytes[..], 200_000, piece).unwrap();
        let layer: Vec<String> = hashes.layer.iter().map(|h| hex(h)).collect();
        assert_eq!(layer, [
            "c72348d1d7dfa54b8ae1cf1a18c7cdd4e7206f8cb9206bfe74253dcf65c2bff7",
            "716405b7b6148c47afd934b1cbe405856d54a6dc5cc2230d841de0b7243aca2e",
            "c72348d1d7dfa54b8ae1cf1a18c7cdd4e7206f8cb9206bfe74253dcf65c2bff7",
            "0fa040bfa4b763accfdbb0a69aa1be863a571f74a827b620fb424c841fb14dc1",
        ]);
        assert_eq!(hex(&hashes.root.unwrap()), "da7010b7c4c4b69ce253d87f1bd008baaebe9ece53d56ccbf32eb55378713fee");
        // The last piece is hashed over the whole width of a piece, its missing blocks zero.
        assert_eq!(hashes.layer[3], piece_hash(&bytes[3 * piece..], piece));
    }

    #[test]
    fn a_layer_that_is_a_power_of_two_long_needs_no_padding_and_five_pieces_and_a_byte_need_three_pads() {
        let piece = 4 * BLOCK;
        let two = data(2 * piece, 4);
        let hashes = hash_file(&mut &two[..], (2 * piece) as u64, piece).unwrap();
        assert_eq!(hashes.layer.iter().map(|h| hex(h)).collect::<Vec<_>>(), [
            "a7933fe550cf11661b16eb19d0de74245ed39d4df4cc1402c8c0b288b45a8823",
            "b4b23ecbad97f70ae03d31b2349aee017f7e96342caf24bf0d88250cdd214b3e",
        ]);
        assert_eq!(hex(&hashes.root.unwrap()), "c4a52b32e987057a46fc0b80d354fe2b4fe798d139718532c64611608642a537");

        let five = data(5 * piece + 1, 6);
        let hashes = hash_file(&mut &five[..], (5 * piece + 1) as u64, piece).unwrap();
        assert_eq!(hashes.layer.len(), 6);
        assert_eq!(hex(&hashes.root.unwrap()), "45777ec5466f818ec24f625500376153054ed25ebe15ef62f6c79181d57f1df7");
    }

    #[test]
    fn an_empty_file_has_no_root() {
        assert_eq!(hash_file(&mut &b""[..], 0, 65536).unwrap(), FileHashes { root: None, layer: Vec::new() });
    }

    #[test]
    fn a_file_shorter_than_it_says_is_an_error_not_a_hash() {
        let err = hash_file(&mut &data(100, 0)[..], 5000, 65536).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let err = hash_file(&mut &data(100_000, 0)[..], 200_000, 65536).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn only_a_power_of_two_of_at_least_a_block_is_a_piece_length() {
        for ok in [16384i64, 32768, 65536, 1 << 20, 1 << 27] {
            assert!(valid_piece_length(ok), "{}", ok);
        }
        for bad in [0i64, -16384, 8192, 16385, 24576, 100_000] {
            assert!(!valid_piece_length(bad), "{}", bad);
        }
    }

    // A whole torrent, built by the Python script: three levels of directory, an empty file,
    // and files of one, two and three pieces at a piece length of 32 KiB.
    const DEMO_TORRENT: &str = "64383a616e6e6f756e636532353a687474703a2f2f742e6578616d706c652f616e6e6f756e6365343a696e666f64393a66696c65207472656564353a612e62696e64303a64363a6c656e677468693130303030306531313a70696563657320726f6f7433323a8771c94d03f28dd2a91ffef0042232cc7608cb640fb090736eebb718e8a60d5e6565353a656d70747964303a64363a6c656e6774686930656565333a73756264353a622e74787464303a64363a6c656e6774686932303030306531313a70696563657320726f6f7433323ace1eec6f86cc755743b41e86c970743af0b2e9153876ddb4cc3db3b3a1ae192d6565343a6465657064353a632e62696e64303a64363a6c656e6774686937303030306531313a70696563657320726f6f7433323acb1b10965c8e407b28006f0b3b1c6c324b9db099c4b0968479c2d14fe7c60ba6656565656531323a6d6574612076657273696f6e693265343a6e616d65343a64656d6f31323a7069656365206c656e677468693332373638656531323a7069656365206c61796572736433323a8771c94d03f28dd2a91ffef0042232cc7608cb640fb090736eebb718e8a60d5e3132383a179df81fc7395929f8bc691ad04350868aae0e3d768e1f3e43933497eac8fc48545dc7319ad6b9ab25c26eba3cbd4009d4c41d1b9eb127e39e34823bab536c35188a4eba8732a08f813015fffc382d2f55b9c50e076eb5fcfa6400cb8db6653c0129fc530e31bd7c19183e0f142dec28f4227d5f355e19230fe8490d5a9c078733323acb1b10965c8e407b28006f0b3b1c6c324b9db099c4b0968479c2d14fe7c60ba639363a5bc5720dbd2237c013b9593c7d81da8cf3527227c7cca61205bd14526776944f38ca29901487e262e393476b3bb7951e1b4ad7a643a1cd2d6c3bebfad280d729ea980cd289a0d32d58528d94b2b3a89124cd4e06f6aa032bc765863c0320dce46565";
    const DEMO_INFO_HASH: &str = "2e23958a8d7f67c7092333a57158ff2713823e89e9c7c5c2a4e49b70437e4c23";
    const DEMO_ROOTS: [(&str, &str); 3] = [("a.bin", "8771c94d03f28dd2a91ffef0042232cc7608cb640fb090736eebb718e8a60d5e"), ("sub/b.txt", "ce1eec6f86cc755743b41e86c970743af0b2e9153876ddb4cc3db3b3a1ae192d"), ("sub/deep/c.bin", "cb1b10965c8e407b28006f0b3b1c6c324b9db099c4b0968479c2d14fe7c60ba6")];

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn demo() -> (Bencode, Bencode) {
        let torrent = crate::bencode::decode(&unhex(DEMO_TORRENT)).unwrap();
        let info = torrent.get("info").unwrap().clone();
        (torrent, info)
    }

    #[test]
    fn the_file_tree_of_a_torrent_made_elsewhere_is_read_in_order_with_its_roots() {
        let (_, info) = demo();
        let files = parse_file_tree(info.get("file tree").unwrap()).unwrap();
        let listing: Vec<(String, u64)> = files.iter().map(|f| (f.path.join("/"), f.length)).collect();
        assert_eq!(listing, vec![("a.bin".to_string(), 100_000), ("empty".to_string(), 0), ("sub/b.txt".to_string(), 20_000), ("sub/deep/c.bin".to_string(), 70_000)]);
        assert_eq!(files[1].root, None, "an empty file has no root");
        for (path, root) in DEMO_ROOTS {
            let file = files.iter().find(|f| f.path.join("/") == path).unwrap();
            assert_eq!(hex(&file.root.unwrap()), root, "{}", path);
        }
    }

    #[test]
    fn the_torrents_layers_are_read_and_add_up_to_the_roots() {
        let (torrent, info) = demo();
        let files = parse_file_tree(info.get("file tree").unwrap()).unwrap();
        let layers = parse_layers(torrent.get("piece layers")).unwrap();
        assert_eq!(layers.len(), 2, "the two files longer than a piece have one; the small ones have none");
        validate_layers(&files, &layers, 32768).unwrap();
        let a = files.iter().find(|f| f.path == ["a.bin"]).unwrap();
        assert_eq!(layers[&a.root.unwrap()].len(), 4, "100000 bytes in pieces of 32768");
    }

    #[test]
    fn the_files_recomputed_from_their_bytes_have_the_roots_the_torrent_gives() {
        let (torrent, info) = demo();
        let files = parse_file_tree(info.get("file tree").unwrap()).unwrap();
        let layers = parse_layers(torrent.get("piece layers")).unwrap();
        let contents = [("a.bin", data(100_000, 7)), ("sub/b.txt", data(20_000, 8)), ("sub/deep/c.bin", data(70_000, 9))];
        for (path, bytes) in contents {
            let file = files.iter().find(|f| f.path.join("/") == path).unwrap();
            let hashes = hash_file(&mut &bytes[..], bytes.len() as u64, 32768).unwrap();
            assert_eq!(hashes.root, file.root, "{}", path);
            assert_eq!(Some(&hashes.layer).filter(|l| !l.is_empty()), file.root.as_ref().and_then(|r| layers.get(r)), "{}", path);
        }
    }

    #[test]
    fn the_info_hash_is_the_sha256_of_the_info_dictionary_and_its_short_form_the_first_twenty_bytes() {
        let (_, info) = demo();
        let hash = sha256(&crate::bencode::encode(&info));
        assert_eq!(hex(&hash), DEMO_INFO_HASH);
        let meta = V2Meta { files: Vec::new(), layers: BTreeMap::new(), info_hash: hash };
        assert_eq!(hex(&meta.short_hash()), &DEMO_INFO_HASH[..40]);
    }

    #[test]
    fn a_layer_that_does_not_add_up_or_is_the_wrong_size_is_refused() {
        let (torrent, info) = demo();
        let files = parse_file_tree(info.get("file tree").unwrap()).unwrap();
        let good = parse_layers(torrent.get("piece layers")).unwrap();

        let mut tampered = good.clone();
        tampered.values_mut().next().unwrap()[0][0] ^= 1;
        assert_eq!(validate_layers(&files, &tampered, 32768), Err(V2Error::BadLayer), "a hash changed");

        let mut short = good.clone();
        short.values_mut().next().unwrap().pop();
        assert_eq!(validate_layers(&files, &short, 32768), Err(V2Error::BadLayer), "a piece missing");

        // A layer with the padding written out as a piece adds up to the same root, but names a piece that is not there.
        let mut padded = good.clone();
        let c = files.iter().find(|f| f.path == ["sub", "deep", "c.bin"]).unwrap();
        padded.get_mut(&c.root.unwrap()).unwrap().push(zero_subtree(1));
        assert_eq!(validate_layers(&files, &padded, 32768), Err(V2Error::BadLayer), "one hash too many for 70000 bytes in pieces of 32768");

        assert_eq!(validate_layers(&files, &good, 24576), Err(V2Error::BadPieceLength));
        assert!(validate_layers(&files, &BTreeMap::new(), 32768).is_ok(), "no layers at all is allowed: they can be fetched from peers");
    }

    fn tree(text: &str) -> Bencode {
        crate::bencode::decode(text.as_bytes()).unwrap()
    }

    fn file_entry(length: i64, root: &str) -> String {
        format!("d0:d6:lengthi{}e{}ee", length, if root.is_empty() { String::new() } else { format!("11:pieces root{}", root) })
    }

    #[test]
    fn a_malformed_file_tree_is_refused_with_the_reason() {
        let root32 = format!("32:{}", "r".repeat(32));
        let ok = |name: &str, entry: &str| tree(&format!("d{}:{}{}e", name.len(), name, entry));
        assert!(parse_file_tree(&ok("f", &file_entry(5, &root32))).is_ok());

        assert_eq!(parse_file_tree(&ok("f", &file_entry(5, ""))), Err(V2Error::BadRoot), "length but no root");
        assert_eq!(parse_file_tree(&ok("f", &file_entry(0, &root32))), Err(V2Error::BadRoot), "a root for an empty file");
        assert_eq!(parse_file_tree(&ok("f", &file_entry(5, "31:rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"))), Err(V2Error::BadRoot), "a root of the wrong size");
        assert_eq!(parse_file_tree(&ok("f", &file_entry(-1, &root32))), Err(V2Error::BadLength));
        assert!(matches!(parse_file_tree(&tree("i5e")), Err(V2Error::BadTree(_))));
        assert!(matches!(parse_file_tree(&ok("f", "i5e")), Err(V2Error::BadTree(_))), "an entry that is not a dictionary");
        assert!(matches!(parse_file_tree(&ok("f", "d0:d6:lengthi1e11:pieces root32:rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrre1:xdee")), Err(V2Error::BadTree(_))), "a file with something beside it");
        assert!(matches!(parse_file_tree(&tree("d0:d6:lengthi0eee")), Err(V2Error::BadTree(_))), "a file at the top, with no name");
        assert!(matches!(parse_file_tree(&ok("f", "d0:d5:otheri1eee")), Err(V2Error::BadTree(_))), "a file without a length");
    }

    #[test]
    fn a_file_tree_cannot_write_outside_the_download_directory() {
        let root32 = format!("32:{}", "r".repeat(32));
        for bad in ["..", ".", "a/b", "a\\b", "\0"] {
            let text = format!("d{}:{}{}e", bad.len(), bad, file_entry(5, &root32));
            assert!(matches!(parse_file_tree(&tree(&text)), Err(V2Error::UnsafePath(_))), "{:?}", bad);
        }
        // A name that is not UTF-8.
        let mut raw = b"d2:".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(file_entry(5, &root32).as_bytes());
        raw.push(b'e');
        assert!(matches!(parse_file_tree(&crate::bencode::decode(&raw).unwrap()), Err(V2Error::UnsafePath(_))));
    }

    #[test]
    fn a_file_tree_nested_too_deeply_is_refused() {
        let root32 = format!("32:{}", "r".repeat(32));
        let nest = |depth: usize| {
            let mut text = file_entry(5, &root32);
            for _ in 0..depth {
                text = format!("d1:d{}e", text);
            }
            text
        };
        assert!(parse_file_tree(&tree(&nest(MAX_DEPTH))).is_ok());
        assert_eq!(parse_file_tree(&tree(&nest(MAX_DEPTH + 2))), Err(V2Error::TooDeep));
    }

    #[test]
    fn malformed_layers_are_refused() {
        assert!(parse_layers(None).unwrap().is_empty());
        assert_eq!(parse_layers(Some(&tree("i1e"))), Err(V2Error::BadLayer));
        assert_eq!(parse_layers(Some(&tree("d3:abc4:xxxxe"))), Err(V2Error::BadLayer), "a key that is not a 32-byte root");
        let key = "k".repeat(32);
        assert_eq!(parse_layers(Some(&tree(&format!("d32:{}5:xxxxxe", key)))), Err(V2Error::BadLayer), "hashes that do not come in 32s");
        assert_eq!(parse_layers(Some(&tree(&format!("d32:{}i5ee", key)))), Err(V2Error::BadLayer), "not a string");
        assert_eq!(parse_layers(Some(&tree(&format!("d32:{}64:{}e", key, "h".repeat(64))))).unwrap().len(), 1);
    }

    #[test]
    fn the_pieces_of_a_torrent_come_out_file_by_file_with_short_last_pieces_and_the_widths_that_check_them() {
        let (torrent, info) = demo();
        let files = parse_file_tree(info.get("file tree").unwrap()).unwrap();
        let layers = parse_layers(torrent.get("piece layers")).unwrap();
        let pieces = plan_pieces(&files, &layers, 32768).expect("every long file has its layer");
        // a.bin 100000 (4 pieces), empty (none), b.txt 20000 (one, of two blocks), c.bin 70000 (3 pieces).
        let plan: Vec<(usize, u64, u32, u32)> = pieces.iter().map(|p| (p.file, p.offset, p.length, p.width)).collect();
        assert_eq!(plan, vec![(0, 0, 32768, 2), (0, 32768, 32768, 2), (0, 65536, 32768, 2), (0, 98304, 1696, 2), (2, 0, 20000, 2), (3, 0, 32768, 2), (3, 32768, 32768, 2), (3, 65536, 4464, 2)]);
        // The bytes of every piece check against what the plan says, and no other bytes do.
        let a = data(100_000, 7);
        for piece in pieces.iter().filter(|p| p.file == 0) {
            let bytes = &a[piece.offset as usize..piece.offset as usize + piece.length as usize];
            assert!(merkle_matches(bytes, piece.width as usize, &piece.root), "piece at {}", piece.offset);
            let mut wrong = bytes.to_vec();
            wrong[0] ^= 1;
            assert!(!merkle_matches(&wrong, piece.width as usize, &piece.root));
        }
        let b = data(20_000, 8);
        assert!(merkle_matches(&b, pieces[4].width as usize, &pieces[4].root), "the small file's only piece, hashed as its own short tree");
    }

    #[test]
    fn a_torrent_without_the_layer_of_a_long_file_cannot_be_planned() {
        let (torrent, info) = demo();
        let files = parse_file_tree(info.get("file tree").unwrap()).unwrap();
        let mut layers = parse_layers(torrent.get("piece layers")).unwrap();
        let a = files.iter().find(|f| f.path == ["a.bin"]).unwrap();
        layers.remove(&a.root.unwrap());
        assert!(plan_pieces(&files, &layers, 32768).is_none(), "nothing to check a.bin's pieces against");
        let short_only: Vec<V2File> = files.iter().filter(|f| f.length <= 32768).cloned().collect();
        assert!(plan_pieces(&short_only, &BTreeMap::new(), 32768).is_some(), "small files need no layer: their root is their piece's hash");
    }

    #[test]
    fn a_piece_with_too_many_bytes_for_its_tree_or_the_wrong_width_does_not_match() {
        let bytes = data(3 * BLOCK, 1);
        let root4 = merkle_root(&block_hashes(&bytes), 4, [0u8; 32]);
        assert!(merkle_matches(&bytes, 4, &root4));
        assert!(!merkle_matches(&bytes, 8, &root4), "another width is another tree");
        assert!(!merkle_matches(&bytes, 3, &root4), "and a width that is not a power of two is no tree");
        assert!(!merkle_matches(&data(5 * BLOCK, 1), 4, &root4), "more blocks than the tree has leaves");
    }

    #[test]
    fn a_small_files_piece_is_as_wide_as_the_file_needs_not_as_wide_as_a_piece() {
        // 20000 bytes is two blocks; the pieces of this torrent are sixteen blocks wide.
        let file = V2File { path: vec!["f".to_string()], length: 20_000, root: Some([7u8; 32]) };
        let pieces = plan_pieces(&[file], &BTreeMap::new(), 16 * BLOCK as u64).unwrap();
        assert_eq!(pieces, vec![V2Piece { file: 0, offset: 0, length: 20_000, root: [7u8; 32], width: 2 }]);
    }

    // ---- proofs ---------------------------------------------------------

    /// A file of `pieces` pieces of 64 KiB (the last short), its root and its piece layer.
    fn file_of(pieces: usize) -> (Hash, Vec<Hash>, u32) {
        let piece_length = 65536;
        // (Not `data`, whose pieces repeat with a period of two, which makes a tree that cannot tell left from right.)
        let mut state = 9u64;
        let bytes: Vec<u8> = (0..pieces * piece_length - 1000)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect();
        let hashes = hash_file(&mut &bytes[..], bytes.len() as u64, piece_length).unwrap();
        (hashes.root.unwrap(), hashes.layer, file_height(bytes.len() as u64, piece_length as u64))
    }

    #[test]
    fn the_layer_of_pieces_and_the_height_of_a_file() {
        assert_eq!(piece_layer(16384), 0);
        assert_eq!(piece_layer(65536), 2);
        assert_eq!(file_height(65537, 65536), 3, "two pieces: one layer above the piece layer");
        assert_eq!(file_height(3 * 65536, 65536), 4, "three pieces are four wide");
        assert_eq!(file_height(4 * 65536, 65536), 4);
        assert_eq!(file_height(5 * 65536, 65536), 5);
    }

    #[test]
    fn every_range_of_every_size_proves_itself_to_the_root() {
        for pieces in [2usize, 3, 5, 8, 13] {
            let (root, layer, height) = file_of(pieces);
            let layer_number = 2;
            let width = 1u32 << (height - layer_number);
            for length in (1..=width.trailing_zeros()).map(|k| 1u32 << k) {
                for index in (0..width).step_by(length as usize) {
                    // As many proof layers as reach the root, which is what a requester asks for.
                    let proof_layers = height - layer_number - 1;
                    let range = hash_range(&layer, layer_number, height, index, length, proof_layers).unwrap_or_else(|| panic!("{} pieces, {} from {}", pieces, length, index));
                    assert_eq!(range.hashes.len(), length as usize);
                    assert_eq!(range.uncles.len(), (height - layer_number - length.trailing_zeros()) as usize, "one uncle for each layer the range does not fill");
                    assert!(verify_range(&root, layer_number, height, index, &range.hashes, &range.uncles, proof_layers), "{} pieces, {} from {}", pieces, length, index);
                }
            }
        }
    }

    #[test]
    fn the_hashes_of_a_range_are_the_layers_own_and_past_its_end_the_padding() {
        let (_, layer, height) = file_of(5); // 8 wide
        let range = hash_range(&layer, 2, height, 4, 4, 0).unwrap();
        assert_eq!(&range.hashes[..1], &layer[4..5], "the last real piece");
        assert!(range.hashes[1..].iter().all(|h| *h == zero_subtree(2)), "then padding as wide as a piece is");
    }

    #[test]
    fn a_proof_is_only_as_long_as_the_layers_asked_for_reach() {
        let (root, layer, height) = file_of(8); // 8 wide: height 5, piece layer 2
        let full = hash_range(&layer, 2, height, 0, 2, height - 3).unwrap();
        assert_eq!(full.uncles.len(), 2);
        let short = hash_range(&layer, 2, height, 0, 2, 1).unwrap();
        assert_eq!(short.uncles.len(), 1, "one proof layer, one uncle");
        assert!(!verify_range(&root, 2, height, 0, &short.hashes, &short.uncles, 1), "which does not reach the root, and so proves nothing");
        assert!(hash_range(&layer, 2, height, 0, 2, 0).unwrap().uncles.is_empty(), "none asked for, none sent");
        assert_eq!(hash_range(&layer, 2, height, 0, 2, 99).unwrap().uncles.len(), 2, "more than there are layers is as many as there are: the root has no sibling");
        // With the whole layer in the range there is nothing to add.
        let all = hash_range(&layer, 2, height, 0, 8, 5).unwrap();
        assert!(all.uncles.is_empty());
        assert!(verify_range(&root, 2, height, 0, &all.hashes, &all.uncles, 5));
    }

    #[test]
    fn a_request_that_is_not_allowed_or_not_there_is_none() {
        let (_, layer, height) = file_of(8);
        for (layer_number, index, length) in [(2, 0, 1), (2, 0, 3), (2, 2, 4), (2, 4, 8), (2, 8, 2), (5, 0, 2), (6, 0, 2), (2, 0, 0)] {
            assert!(hash_range(&layer, layer_number, height, index, length, 2).is_none(), "{} {} {}", layer_number, index, length);
        }
    }

    #[test]
    fn a_proof_that_is_wrong_in_any_part_does_not_verify() {
        let (root, layer, height) = file_of(8);
        let range = hash_range(&layer, 2, height, 2, 2, 2).unwrap();
        assert!(verify_range(&root, 2, height, 2, &range.hashes, &range.uncles, 2));
        let mut bad = range.clone();
        bad.hashes[0][0] ^= 1;
        assert!(!verify_range(&root, 2, height, 2, &bad.hashes, &bad.uncles, 2), "a hash altered");
        let mut bad = range.clone();
        bad.uncles[0][5] ^= 1;
        assert!(!verify_range(&root, 2, height, 2, &range.hashes, &bad.uncles, 2), "an uncle altered");
        assert!(!verify_range(&root, 2, height, 0, &range.hashes, &range.uncles, 2), "claimed from the wrong place");
        assert!(!verify_range(&root, 2, height, 2, &range.hashes, &range.uncles[..1], 2), "an uncle missing");
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(!verify_range(&wrong_root, 2, height, 2, &range.hashes, &range.uncles, 2), "for another file");
        assert!(!verify_range(&root, 2, height, 2, &range.hashes[..1], &range.uncles, 2), "one hash is not a range");
    }

    #[test]
    fn a_hash_source_answers_for_the_piece_layer_and_those_above_it_and_for_nothing_else() {
        let (root, layer, height) = file_of(8);
        let file = V2File { path: vec!["f".into()], length: 8 * 65536 - 1000, root: Some(root) };
        let source = HashSource::new(std::slice::from_ref(&file), &BTreeMap::from([(root, layer.clone())]), 65536).unwrap();

        let range = source.answer(&root, 2, 0, 4, height - 3).unwrap();
        assert_eq!(range.hashes, layer[..4]);
        assert!(verify_range(&root, 2, height, 0, &range.hashes, &range.uncles, height - 3));
        // A layer above the pieces: its hashes are the pieces' parents.
        let upper = source.answer(&root, 3, 2, 2, height - 4).unwrap();
        assert!(verify_range(&root, 3, height, 2, &upper.hashes, &upper.uncles, height - 4));
        assert!(source.answer(&root, 0, 0, 2, 0).is_none(), "the leaves are not kept");
        assert!(source.answer(&root, height, 0, 2, 0).is_none(), "nor is there a layer at or above the root's");
        assert!(source.answer(&[0xEE; 32], 2, 0, 2, 0).is_none(), "another file's");
        assert!(source.answer(&root, 2, 0, 1024, 0).is_none(), "and no more than 512 hashes at once");
        // A file no longer than a piece has no layer of pieces to answer from (its root is its one piece's hash) but does have leaves.
        let small = HashSource::new(&[V2File { length: 40000, ..file.clone() }], &BTreeMap::new(), 65536).expect("it can answer for its leaves");
        assert!(small.answer(&root, 1, 0, 2, 0).is_none() && small.answer(&root, 0, 0, 2, 0).is_none(), "but not from layers");
        assert!(HashSource::new(&[V2File { root: None, ..file }], &BTreeMap::new(), 65536).is_none(), "and an empty file has nothing at all");
        assert!(HashSource::new(&[], &BTreeMap::new(), 65536).is_none());
    }

    // ---- leaf hashes, from the data ---------------------------------------------

    /// Three files of pieces of 64 KiB (four blocks): five pieces and a bit, one of two blocks and a bit, and three; with the
    /// torrent's flat piece numbers (0-5, 6, 7-9) and the bytes of each.
    type ThreeFiles = (Vec<V2File>, BTreeMap<Hash, Vec<Hash>>, Vec<Vec<u8>>);

    fn three_files() -> ThreeFiles {
        let mut state = 21u64;
        let mut bytes = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    (state >> 56) as u8
                })
                .collect()
        };
        let contents = vec![bytes(5 * 65536 + 3000), bytes(2 * 16384 + 100), bytes(3 * 65536)];
        let mut files = Vec::new();
        let mut layers = BTreeMap::new();
        for (n, content) in contents.iter().enumerate() {
            let hashes = hash_file(&mut &content[..], content.len() as u64, 65536).unwrap();
            let root = hashes.root.unwrap();
            files.push(V2File { path: vec![format!("f{}", n)], length: content.len() as u64, root: Some(root) });
            if !hashes.layer.is_empty() {
                layers.insert(root, hashes.layer);
            }
        }
        (files, layers, contents)
    }

    /// A reader of pieces for the files of [`three_files`], by the torrent's flat numbering.
    fn pieces_of(contents: &[Vec<u8>]) -> impl Fn(u32) -> Option<Vec<u8>> + '_ {
        move |number| {
            let (mut first, piece_length) = (0u32, 65536usize);
            for content in contents {
                let count = content.len().div_ceil(piece_length) as u32;
                if number < first + count {
                    let start = (number - first) as usize * piece_length;
                    return Some(content[start..(start + piece_length).min(content.len())].to_vec());
                }
                first += count;
            }
            None
        }
    }

    #[test]
    fn leaf_hashes_worked_out_from_the_data_agree_with_the_whole_tree_for_every_range_of_every_file() {
        let (files, layers, contents) = three_files();
        let source = HashSource::new(&files, &layers, 65536).unwrap();
        let read = pieces_of(&contents);
        for (file, content) in files.iter().zip(&contents) {
            let root = file.root.unwrap();
            // The whole leaf layer, which the source does not have: what the answer must be the same as.
            let leaves = block_hashes(content);
            let height = if file.length > 65536 { file_height(file.length, 65536) } else { leaves.len().next_power_of_two().trailing_zeros() };
            let width = 1u32 << height;
            let mut asked = 0;
            for length in (1..=height.min(9)).map(|k| 1u32 << k) {
                for index in (0..width).step_by(length as usize) {
                    for proof_layers in [0, height - 1, height + 3] {
                        let wanted = hash_range(&leaves, 0, height, index, length, proof_layers);
                        let got = source.answer_leaves(&root, index, length, proof_layers, &read);
                        assert_eq!(got, wanted, "file of {} bytes: {} leaves from {}, {} proof layers", file.length, length, index, proof_layers);
                        asked += 1;
                    }
                }
            }
            assert!(asked > 3, "the file has ranges to ask for");
            // ... and the whole layer's worth verifies to the root.
            if let Some(range) = source.answer_leaves(&root, 0, width.min(512), height.saturating_sub(1), &read) {
                assert!(verify_range(&root, 0, height, 0, &range.hashes, &range.uncles, height - 1));
            }
        }
    }

    #[test]
    fn a_leaf_request_that_is_not_allowed_or_cannot_be_served_is_none() {
        let (files, layers, contents) = three_files();
        let source = HashSource::new(&files, &layers, 65536).unwrap();
        let read = pieces_of(&contents);
        let root = files[0].root.unwrap(); // 6 pieces, 24 blocks, a tree of height 5 (32 blocks wide)
        for (index, length) in [(0, 1), (0, 3), (2, 4), (32, 2), (0, 64), (0, 0)] {
            assert!(source.answer_leaves(&root, index, length, 0, &read).is_none(), "{} {}", index, length);
        }
        assert!(source.answer_leaves(&[7; 32], 0, 2, 0, &read).is_none(), "another file");
        // A piece it does not have: the second piece, blocks 4-7.
        let missing = |piece: u32| if piece == 1 { None } else { read(piece) };
        assert!(source.answer_leaves(&root, 4, 4, 0, missing).is_none(), "the blocks of a piece it lacks");
        assert!(source.answer_leaves(&root, 0, 4, 0, missing).is_some(), "but the ones it has");
        assert!(source.answer_leaves(&root, 8, 8, 0, |_| None).is_none(), "and none at all without data");
    }
}
