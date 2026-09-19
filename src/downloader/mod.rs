pub mod file_writer;
pub mod piece_assembler;
pub mod queue;
pub mod resume;
pub mod worker;

pub use file_writer::{build_file_spans, build_file_spans_aligned, create_empty_files, read_at_global_offset, read_block, write_at_global_offset, write_piece, FileSpan};
pub use piece_assembler::{AssemblerError, PartialPiece, PieceAssembler, PieceWork, BLOCK_SIZE};
pub use queue::{Order, PieceResult, Take, WorkQueue};
pub use resume::{any_data_on_disk, load_and_verify, progress_file_path, rewrite_compact, scan_all, ResumeWriter};
pub use worker::{run_worker, Activity, Interrupt, PeerRegistry, PeerRow, PexSender, WorkerConfig, WorkerError};

use crate::torrent::TorrentFile;

/// Builds the full list of `PieceWork` for a torrent: one entry per piece
/// hash, with the correct (possibly-shorter) length for the last piece.
/// This is the one place `TorrentFile` and the downloader's own
/// `PieceWork` type meet, so it works unmodified for both a normally
/// parsed `.torrent` file (Phase 1) and a magnet-derived `TorrentFile`
/// once Phase 4's assembled `info` dict has been run back through
/// `torrent::parse_torrent_file`-style construction -- no separate
/// magnet-specific work-queue builder needed.
pub fn build_work_queue(torrent: &TorrentFile) -> Vec<PieceWork> {
    torrent
        .pieces
        .iter()
        .enumerate()
        .map(|(i, hash)| PieceWork {
            index: i as u32,
            hash: *hash,
            length: torrent.piece_len(i) as u32,
            merkle: torrent.v2_pieces.get(i).map(|p| piece_assembler::Merkle { root: p.root, width: p.width }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::torrent::parse_torrent_file;

    #[test]
    fn build_work_queue_matches_torrent_piece_count_and_last_piece_length() {
        let bytes = b"d4:infod6:lengthi40000e4:name1:a12:piece lengthi16384e6:pieces60:000000000000000000001111111111111111111122222222222222222222ee".to_vec();
        let t = parse_torrent_file(&bytes).unwrap();
        let work = build_work_queue(&t);
        assert_eq!(work.len(), 3);
        assert_eq!(work[0].length, 16384);
        assert_eq!(work[1].length, 16384);
        assert_eq!(work[2].length, 40000 - 16384 * 2);
        assert_eq!(work[2].index, 2);
    }

    #[test]
    fn a_v2_torrents_work_queue_carries_each_pieces_length_and_merkle_check() {
        use crate::create::{create, CreateOptions};
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-queue-v2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("t")).unwrap();
        std::fs::write(dir.join("t/a"), vec![1u8; 20_000]).unwrap();
        std::fs::write(dir.join("t/b"), vec![2u8; 100]).unwrap();
        let made = create(&dir.join("t"), &CreateOptions { piece_length: Some(16384), v2: true, ..Default::default() }, |_, _| {}).unwrap();
        let t = parse_torrent_file(&made.bytes).unwrap();

        let work = build_work_queue(&t);
        assert_eq!(work.iter().map(|w| w.length).collect::<Vec<_>>(), vec![16384, 3616, 100], "a file's last piece is short, and b's piece is not padded out to a full one");
        assert!(work.iter().all(|w| w.merkle.is_some()));
        assert_eq!(work[1].merkle.unwrap().width, 1, "a 16 KiB piece is one block wide, short or not");
        assert!(work[0].matches(&[1u8; 16384]) && !work[0].matches(&[1u8; 16383]));
        assert!(work[2].matches(&[2u8; 100]), "b is checked as the short tree it is");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
