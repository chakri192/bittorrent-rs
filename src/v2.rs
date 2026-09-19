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
        out.insert(root, bytes.chunks_exact(32).map(|c| Hash::try_from(c).unwrap_or([0; 32])).collect());
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
}
