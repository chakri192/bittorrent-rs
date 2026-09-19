//! Selective-file download: choose which files of a multi-file torrent to
//! fetch. Selection is by 1-based file index and/or case-insensitive path
//! substring; the result is a per-file boolean mask, from which we derive
//! the exact set of pieces to download (any piece overlapping a selected
//! file). Boundary pieces -- ones straddling a selected and an unselected
//! file -- are downloaded in full (they carry bytes for the selected
//! file), which means an unselected neighbour file may end up partially
//! written; that's the standard behaviour and keeps piece hashing and
//! resume simple.

use crate::ui::format_bytes;
use std::collections::HashSet;

/// `(path components, length)` per file -- the shape of `TorrentFile::files`.
pub type Files = [(Vec<String>, i64)];

/// Joins a torrent file's path components the way they appear on disk.
pub fn file_path(parts: &[String]) -> String {
    parts.join("/")
}

/// Builds the per-file selection mask. `indices` are 1-based (as shown by
/// `--list`); `patterns` match as case-insensitive substrings of each
/// file's joined path. An empty selection (no indices, no patterns)
/// selects everything. Errors on an out-of-range index or a pattern that
/// matches nothing, so a typo fails loudly instead of silently selecting
/// zero files.
pub fn build_mask(files: &Files, indices: &[usize], patterns: &[String]) -> Result<Vec<bool>, String> {
    if indices.is_empty() && patterns.is_empty() {
        return Ok(vec![true; files.len()]);
    }
    let mut mask = vec![false; files.len()];

    for &i in indices {
        if i == 0 || i > files.len() {
            return Err(format!("--files: index {} out of range (1..={})", i, files.len()));
        }
        mask[i - 1] = true;
    }

    for pat in patterns {
        let needle = pat.to_lowercase();
        let mut matched = false;
        for (idx, (parts, _)) in files.iter().enumerate() {
            if file_path(parts).to_lowercase().contains(&needle) {
                mask[idx] = true;
                matched = true;
            }
        }
        if !matched {
            return Err(format!("--only {:?}: matched no file in this torrent", pat));
        }
    }

    Ok(mask)
}

/// True when every file is selected (the common, non-selective case --
/// lets callers skip all the filtering work).
pub fn selects_everything(mask: &[bool]) -> bool {
    mask.iter().all(|&b| b)
}

/// Byte range `[start, end)` of each file in the torrent's concatenated
/// address space.
fn file_ranges(files: &Files) -> Vec<(u64, u64)> {
    let mut out = Vec::with_capacity(files.len());
    let mut cursor = 0u64;
    for (_, len) in files {
        let l = *len as u64;
        out.push((cursor, cursor + l));
        cursor += l;
    }
    out
}

fn total_len(files: &Files) -> u64 {
    files.iter().map(|(_, l)| *l as u64).sum()
}

/// The set of piece indices overlapping any selected file, plus the total
/// byte length of those pieces (piece-granular: a boundary piece counts
/// its full length even though it also covers an unselected file). The
/// byte total drives the progress gauge for the selected subset.
pub fn selected_pieces(files: &Files, piece_length: u64, mask: &[bool]) -> (HashSet<u32>, u64) {
    let ranges = file_ranges(files);
    let torrent_len = total_len(files);
    let mut pieces = HashSet::new();

    for (idx, (start, end)) in ranges.iter().enumerate() {
        if !mask.get(idx).copied().unwrap_or(false) || start == end {
            continue; // unselected, or a zero-length file (nothing to fetch)
        }
        let first = start / piece_length;
        let last = (end - 1) / piece_length;
        for p in first..=last {
            pieces.insert(p as u32);
        }
    }

    let mut bytes = 0u64;
    for &p in &pieces {
        let s = p as u64 * piece_length;
        let e = (s + piece_length).min(torrent_len);
        bytes += e.saturating_sub(s);
    }
    (pieces, bytes)
}

/// Renders the file table for `--list`, marking selected files.
pub fn format_list(name: &str, files: &Files, mask: &[bool]) -> String {
    let selected = mask.iter().filter(|&&b| b).count();
    let mut out = format!("{} \u{2014} {} file(s), {} selected:\n", name, files.len(), selected);
    let width = files.len().to_string().len();
    for (idx, (parts, len)) in files.iter().enumerate() {
        let check = if mask.get(idx).copied().unwrap_or(false) { "x" } else { " " };
        out.push_str(&format!("  [{}] {:>width$}  {:>10}  {}\n", check, idx + 1, format_bytes(*len as u64), file_path(parts), width = width));
    }
    out
}

/// `--list --json`: one line per file, `{"event":"file","index":1,
/// "path":"Show/ep1.mkv","bytes":1000,"selected":true}`, with the index
/// counted from 1 as `--files` counts.
pub fn list_events(files: &Files, mask: &[bool]) -> Vec<String> {
    files
        .iter()
        .enumerate()
        .map(|(idx, (parts, len))| {
            crate::json::Object::new()
                .string("event", "file")
                .uint("index", idx as u64 + 1)
                .string("path", &file_path(parts))
                .uint("bytes", (*len).max(0) as u64)
                .boolean("selected", mask.get(idx).copied().unwrap_or(false))
                .finish()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<(Vec<String>, i64)> {
        vec![
            (vec!["Show".into(), "ep1.mkv".into()], 1000),
            (vec!["Show".into(), "ep2.mkv".into()], 1000),
            (vec!["Show".into(), "readme.nfo".into()], 50),
        ]
    }

    #[test]
    fn empty_selection_selects_all() {
        let f = files();
        assert_eq!(build_mask(&f, &[], &[]).unwrap(), vec![true, true, true]);
        assert!(selects_everything(&build_mask(&f, &[], &[]).unwrap()));
    }

    #[test]
    fn selection_by_index_is_one_based() {
        let f = files();
        assert_eq!(build_mask(&f, &[1, 3], &[]).unwrap(), vec![true, false, true]);
    }

    #[test]
    fn out_of_range_index_errors() {
        let f = files();
        assert!(build_mask(&f, &[0], &[]).is_err());
        assert!(build_mask(&f, &[4], &[]).is_err());
    }

    #[test]
    fn selection_by_pattern_is_case_insensitive_substring() {
        let f = files();
        assert_eq!(build_mask(&f, &[], &["EP2".into()]).unwrap(), vec![false, true, false]);
    }

    #[test]
    fn pattern_matching_nothing_errors() {
        let f = files();
        assert!(build_mask(&f, &[], &["nonesuch".into()]).is_err());
    }

    #[test]
    fn indices_and_patterns_union() {
        let f = files();
        assert_eq!(build_mask(&f, &[1], &["nfo".into()]).unwrap(), vec![true, false, true]);
    }

    #[test]
    fn selected_pieces_cover_only_the_selected_file() {
        // 2050 bytes total, piece_length 500 -> 5 pieces (0..=4, last=50B).
        // file0 [0,1000): pieces 0,1 ; file1 [1000,2000): pieces 2,3 (and
        // 4 starts at 2000) ; file2 [2000,2050): piece 4.
        let f = files();
        let (pieces, bytes) = selected_pieces(&f, 500, &[true, false, false]);
        let mut got: Vec<u32> = pieces.into_iter().collect();
        got.sort_unstable();
        assert_eq!(got, vec![0, 1]);
        assert_eq!(bytes, 1000);
    }

    #[test]
    fn boundary_piece_is_shared_between_files() {
        // file1 [1000,2000) with piece_length 600: pieces overlapping are
        // 1 (600..1200), 2 (1200..1800), 3 (1800..2400). Piece 1 also
        // covers file0, piece 3 also covers file2 -- all three are pulled.
        let f = files();
        let (pieces, _) = selected_pieces(&f, 600, &[false, true, false]);
        let mut got: Vec<u32> = pieces.into_iter().collect();
        got.sort_unstable();
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn zero_length_file_contributes_no_pieces() {
        let f = vec![(vec!["a".into()], 0i64), (vec!["b".into()], 500i64)];
        let (pieces, bytes) = selected_pieces(&f, 500, &[true, false]);
        assert!(pieces.is_empty());
        assert_eq!(bytes, 0);
    }

    #[test]
    fn format_list_marks_selection_and_counts() {
        let f = files();
        let listing = format_list("Show", &f, &[true, false, true]);
        assert!(listing.contains("3 file(s), 2 selected"));
        assert!(listing.contains("[x] 1"), "selected file marked and numbered: {:?}", listing);
        assert!(listing.contains("[ ] 2"), "unselected file blank-marked: {:?}", listing);
        assert!(listing.contains("Show/ep1.mkv"));
    }

    #[test]
    fn list_events_describe_each_file_and_whether_it_is_selected() {
        let events = list_events(&files(), &[true, false, true]);

        assert_eq!(events.len(), 3);
        let read: Vec<_> = events.iter().map(|e| crate::json::parse_object(e).unwrap()).collect();
        assert_eq!(read[0]["event"].as_str(), Some("file"));
        assert_eq!((read[0]["index"].as_f64(), read[2]["index"].as_f64()), (Some(1.0), Some(3.0)), "counted from 1, as --files counts");
        assert_eq!(read[1]["path"].as_str(), Some("Show/ep2.mkv"));
        assert_eq!((read[0]["bytes"].as_f64(), read[2]["bytes"].as_f64()), (Some(1000.0), Some(50.0)));
        assert_eq!((read[0]["selected"].as_bool(), read[1]["selected"].as_bool(), read[2]["selected"].as_bool()), (Some(true), Some(false), Some(true)));
    }

    #[test]
    fn a_short_mask_leaves_the_rest_unselected_and_odd_names_are_escaped() {
        let files = vec![(vec!["we\"ird".to_string(), "name\n.bin".to_string()], 5i64)];
        let events = list_events(&files, &[]);
        let read = crate::json::parse_object(&events[0]).unwrap();
        assert_eq!(read["selected"].as_bool(), Some(false));
        assert_eq!(read["path"].as_str(), Some("we\"ird/name\n.bin"));
    }
}
