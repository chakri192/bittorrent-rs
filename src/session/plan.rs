//! What a session sets out to download, and how much of that is already
//! done: pure arithmetic over the torrent, the file selection and the
//! pieces resumed from a previous run.

use crate::downloader::{build_work_queue, PieceWork};
use crate::selection;
use crate::torrent::TorrentFile;
use std::collections::HashSet;

/// The subset of the torrent this run wants (all of it, or the pieces
/// overlapping the files chosen with `--only` / `--files`).
///
/// `display_total` and `goal_pieces` describe that subset and drive the
/// progress display. On-disk piece math (file spans, the seeder) always
/// uses the true torrent length, not these.
pub struct DownloadPlan {
    selective: bool,
    selected: HashSet<u32>,
    display_total: u64,
    goal_pieces: usize,
}

/// What is left to fetch once the resumed pieces are accounted for.
pub struct Outstanding {
    /// Wanted pieces not yet on disk: the work queue's contents.
    pub work: Vec<PieceWork>,
    /// Wanted pieces already verified on disk.
    pub pieces_done: usize,
    /// Bytes in those pieces.
    pub bytes_done: u64,
}

impl DownloadPlan {
    /// `mask[i]` says whether file `i` is selected.
    pub fn new(torrent: &TorrentFile, mask: &[bool]) -> Self {
        let selective = !selection::selects_everything(mask);
        let (selected, selected_bytes) = selection::selected_pieces(&torrent.files, torrent.piece_length as u64, mask);
        DownloadPlan {
            selective,
            display_total: if selective { selected_bytes } else { torrent.total_length() },
            goal_pieces: if selective { selected.len() } else { torrent.pieces.len() },
            selected,
        }
    }

    /// True when only some of the files were chosen.
    pub fn is_selective(&self) -> bool {
        self.selective
    }

    /// Bytes in the wanted pieces (piece-granular, so a piece straddling a
    /// selected and an unselected file counts in full).
    pub fn display_total(&self) -> u64 {
        self.display_total
    }

    /// Number of pieces this run must have verified to be complete.
    pub fn goal_pieces(&self) -> usize {
        self.goal_pieces
    }

    pub fn is_wanted(&self, piece: u32) -> bool {
        !self.selective || self.selected.contains(&piece)
    }

    /// Splits the wanted pieces into done and still-to-fetch, given the
    /// pieces (wanted or not) that verified against the disk on resume.
    ///
    /// A resumed piece this run doesn't want, say left over from an
    /// earlier full download, is neither fetched nor counted toward the
    /// goal; the caller still advertises it to peers.
    pub fn outstanding(&self, torrent: &TorrentFile, resumed: &HashSet<u32>) -> Outstanding {
        let all = build_work_queue(torrent);
        let done_wanted: HashSet<u32> = resumed.iter().copied().filter(|&i| self.is_wanted(i)).collect();
        let bytes_done = all.iter().filter(|w| done_wanted.contains(&w.index)).map(|w| w.length as u64).sum();
        let work = all.into_iter().filter(|w| self.is_wanted(w.index) && !resumed.contains(&w.index)).collect();
        Outstanding { work, pieces_done: done_wanted.len(), bytes_done }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::torrent::parse_torrent_file;

    /// Two 300-byte files, 256-byte pieces: 600 bytes, 3 pieces of
    /// 256 / 256 / 88. File `a` covers bytes 0..300 (pieces 0 and 1),
    /// file `b` covers 300..600 (pieces 1 and 2), so piece 1 straddles both.
    fn two_file_torrent() -> TorrentFile {
        let mut b = Vec::new();
        b.extend_from_slice(b"d4:infod5:filesld6:lengthi300e4:pathl1:aeed6:lengthi300e4:pathl1:beee4:name1:t12:piece lengthi256e6:pieces60:");
        for fill in [0x11u8, 0x22, 0x33] {
            b.extend_from_slice(&[fill; 20]);
        }
        b.extend_from_slice(b"ee");
        parse_torrent_file(&b).unwrap()
    }

    fn set(items: &[u32]) -> HashSet<u32> {
        items.iter().copied().collect()
    }

    fn indices(work: &[PieceWork]) -> Vec<u32> {
        work.iter().map(|w| w.index).collect()
    }

    #[test]
    fn selecting_everything_wants_every_piece_and_the_whole_length() {
        let t = two_file_torrent();
        let plan = DownloadPlan::new(&t, &[true, true]);
        assert!(!plan.is_selective());
        assert_eq!(plan.display_total(), 600);
        assert_eq!(plan.goal_pieces(), 3);
        assert!((0..3).all(|i| plan.is_wanted(i)));
    }

    #[test]
    fn selecting_one_file_wants_the_pieces_it_touches_in_full() {
        let t = two_file_torrent();
        let plan = DownloadPlan::new(&t, &[true, false]);
        assert!(plan.is_selective());
        assert_eq!(plan.goal_pieces(), 2, "file a touches pieces 0 and 1");
        assert_eq!(plan.display_total(), 512, "piece 1 counts in full although it also holds file b's first bytes");
        assert!(plan.is_wanted(0) && plan.is_wanted(1) && !plan.is_wanted(2));

        let plan = DownloadPlan::new(&t, &[false, true]);
        assert_eq!(plan.goal_pieces(), 2);
        assert_eq!(plan.display_total(), 256 + 88, "the short last piece counts at its real length");
        assert!(!plan.is_wanted(0) && plan.is_wanted(1) && plan.is_wanted(2));
    }

    #[test]
    fn with_nothing_resumed_all_wanted_work_is_outstanding() {
        let t = two_file_torrent();
        let out = DownloadPlan::new(&t, &[true, true]).outstanding(&t, &HashSet::new());
        assert_eq!(indices(&out.work), vec![0, 1, 2]);
        assert_eq!((out.pieces_done, out.bytes_done), (0, 0));
        assert_eq!(out.work[2].length, 88, "the last piece keeps its short length");
    }

    #[test]
    fn resumed_pieces_are_counted_done_and_dropped_from_the_work() {
        let t = two_file_torrent();
        let out = DownloadPlan::new(&t, &[true, true]).outstanding(&t, &set(&[0, 2]));
        assert_eq!(indices(&out.work), vec![1]);
        assert_eq!(out.pieces_done, 2);
        assert_eq!(out.bytes_done, 256 + 88);
    }

    #[test]
    fn everything_resumed_leaves_no_work() {
        let t = two_file_torrent();
        let out = DownloadPlan::new(&t, &[true, true]).outstanding(&t, &set(&[0, 1, 2]));
        assert!(out.work.is_empty());
        assert_eq!((out.pieces_done, out.bytes_done), (3, 600));
    }

    #[test]
    fn a_resumed_piece_outside_the_selection_is_neither_fetched_nor_counted() {
        let t = two_file_torrent();
        // Only file a (pieces 0, 1) is wanted; piece 2 verified from an earlier full run.
        let out = DownloadPlan::new(&t, &[true, false]).outstanding(&t, &set(&[2]));
        assert_eq!(indices(&out.work), vec![0, 1]);
        assert_eq!(out.pieces_done, 0, "piece 2 isn't part of this run's goal");
        assert_eq!(out.bytes_done, 0);
    }

    #[test]
    fn a_resumed_wanted_piece_is_done_and_an_unwanted_one_is_ignored() {
        let t = two_file_torrent();
        let out = DownloadPlan::new(&t, &[true, false]).outstanding(&t, &set(&[1, 2]));
        assert_eq!(indices(&out.work), vec![0]);
        assert_eq!(out.pieces_done, 1);
        assert_eq!(out.bytes_done, 256);
    }
}
