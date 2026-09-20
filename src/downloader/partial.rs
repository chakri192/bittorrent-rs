//! Keeping the blocks of unfinished pieces across a stop.
//!
//! A piece is only written to disk once it is whole and its hash matches, so a run that is stopped with pieces half
//! fetched used to throw those blocks away: on a 16 MiB-piece torrent that is up to 16 MiB per connection. When a run ends
//! with pieces unfinished, what its connections had received of them is written to a sidecar file beside the resume file,
//! and the next run hands those blocks back to the queue, so that only what is missing is asked for.
//!
//! Nothing in the file is trusted. It is only ever blocks that a peer sent; the piece they belong to is checked against its hash
//! when it is whole, as it always is, and a piece resumed this way that fails is fetched again from scratch (see
//! `worker::piece`). A file that cannot be read, or has anything unexpected in it, is ignored.

use crate::downloader::piece_assembler::{PartialPiece, BLOCK_SIZE};
use crate::torrent::info_hash_hex;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"BTRSPRT1";
/// The most such a file may be, and so the most that is read back: what the queue keeps in memory (64 MiB) and a little more.
const MAX_FILE: u64 = 80 << 20;

/// Where the blocks of unfinished pieces of the torrent are kept, beside its resume file.
pub fn partial_file_path(out_dir: &Path, info_hash: &[u8; 20]) -> PathBuf {
    out_dir.join(format!(".{}.partial", info_hash_hex(info_hash)))
}

/// Writes the pieces, whole or not at all; with none, removes the file.
pub fn save(path: &Path, partials: &[(u32, PartialPiece)]) -> io::Result<()> {
    if partials.is_empty() {
        let _ = fs::remove_file(path);
        return Ok(());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(partials.len() as u32).to_be_bytes());
    for (index, partial) in partials {
        let (data, received) = partial.parts();
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(data);
        let mut bitmap = vec![0u8; received.len().div_ceil(8)];
        for (block, _) in received.iter().enumerate().filter(|(_, &got)| got) {
            bitmap[block / 8] |= 0x80 >> (block % 8);
        }
        bytes.extend_from_slice(&bitmap);
    }
    let mut partial_path = path.as_os_str().to_owned();
    partial_path.push(".part");
    let partial_path = PathBuf::from(partial_path);
    let mut file = fs::File::create(&partial_path)?;
    file.write_all(&bytes)?;
    file.flush()?;
    fs::rename(&partial_path, path)
}

/// The pieces in the file, or none if it is not there or is not what `save` writes.
pub fn load(path: &Path) -> Vec<(u32, PartialPiece)> {
    match fs::metadata(path) {
        Ok(meta) if meta.len() <= MAX_FILE => {}
        _ => return Vec::new(),
    }
    fs::read(path).ok().and_then(|bytes| parse(&bytes)).unwrap_or_default()
}

fn parse(bytes: &[u8]) -> Option<Vec<(u32, PartialPiece)>> {
    let rest = bytes.strip_prefix(MAGIC.as_slice())?;
    let (count, mut rest) = take_u32(rest)?;
    let mut pieces = Vec::new();
    for _ in 0..count {
        let (index, r) = take_u32(rest)?;
        let (length, r) = take_u32(r)?;
        let length = length as usize;
        let blocks = length.div_ceil(BLOCK_SIZE as usize);
        let bitmap_len = blocks.div_ceil(8);
        if r.len() < length.checked_add(bitmap_len)? {
            return None;
        }
        let (data, r) = r.split_at(length);
        let (bitmap, r) = r.split_at(bitmap_len);
        let received: Vec<bool> = (0..blocks).map(|block| bitmap[block / 8] & (0x80 >> (block % 8)) != 0).collect();
        pieces.push((index, PartialPiece::from_parts(data.to_vec(), received)?));
        rest = r;
    }
    rest.is_empty().then_some(pieces)
}

fn take_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<4>()?;
    Some((u32::from_be_bytes(*head), rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::piece_assembler::{PieceAssembler, PieceWork};

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bt-partial-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A partial piece of `length` bytes with blocks `have` received, each filled with its own byte.
    fn partial(length: u32, have: &[u32]) -> PartialPiece {
        let mut assembler = PieceAssembler::new(PieceWork { index: 0, hash: [0; 20], length, merkle: None });
        for &block in have {
            let begin = block * BLOCK_SIZE;
            let len = (length - begin).min(BLOCK_SIZE);
            assembler.record_block(begin, &vec![block as u8 + 1; len as usize]).unwrap();
        }
        assembler.into_partial().expect("something received")
    }

    #[test]
    fn what_is_saved_is_loaded_the_same_blocks_and_all() {
        let d = dir("roundtrip");
        let path = partial_file_path(&d, &[0xAB; 20]);
        // A piece of three and a half blocks, its odd blocks received, and another with one.
        let pieces = vec![(4, partial(3 * BLOCK_SIZE + 100, &[0, 2, 3])), (9, partial(BLOCK_SIZE, &[0]))];
        save(&path, &pieces).unwrap();
        assert_eq!(load(&path), pieces);
        assert!(!d.join(format!(".{}.partial.part", "ab".repeat(20))).exists(), "no temporary file left");
    }

    #[test]
    fn saving_nothing_removes_the_file_and_a_missing_file_loads_as_nothing() {
        let d = dir("none");
        let path = partial_file_path(&d, &[1; 20]);
        assert!(load(&path).is_empty());
        save(&path, &[(1, partial(BLOCK_SIZE, &[0]))]).unwrap();
        assert!(path.exists());
        save(&path, &[]).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_file_that_is_not_what_save_writes_loads_as_nothing_and_never_panics() {
        let d = dir("hostile");
        let path = d.join("p");
        save(&path, &[(4, partial(3 * BLOCK_SIZE + 100, &[0, 2, 3])), (9, partial(BLOCK_SIZE, &[0]))]).unwrap();
        let good = fs::read(&path).unwrap();
        // Every prefix (a write cut short), and a byte of each kind changed, and something after the end.
        for cut in 0..good.len() {
            assert!(parse(&good[..cut]).is_none(), "cut at {}", cut);
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_none());
        let mut wrong_magic = good.clone();
        wrong_magic[0] ^= 1;
        assert!(parse(&wrong_magic).is_none());
        // A count or a length that claims far more than is there.
        let mut huge_count = good.clone();
        huge_count[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse(&huge_count).is_none());
        let mut huge_length = good.clone();
        huge_length[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse(&huge_length).is_none());
        fs::write(&path, b"not a partial file").unwrap();
        assert!(load(&path).is_empty());
        // Beyond the size that is ever read.
        let big = d.join("big");
        fs::File::create(&big).unwrap().set_len(MAX_FILE + 1).unwrap();
        assert!(load(&big).is_empty());
    }

    #[test]
    fn a_file_is_named_after_its_torrent_beside_the_resume_file() {
        let d = std::path::Path::new("/out");
        let hash = [0x12; 20];
        assert_eq!(partial_file_path(d, &hash), PathBuf::from(format!("/out/.{}.partial", "12".repeat(20))));
        assert_eq!(partial_file_path(d, &hash).parent(), crate::downloader::progress_file_path(d, &hash).parent());
    }
}
