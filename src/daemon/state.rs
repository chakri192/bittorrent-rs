//! What the daemon remembers between runs: which torrents it was given, and where their files
//! go, in a state directory. A magnet link is kept as the `.torrent` it turned into once its
//! metadata arrived, so a restart does not have to find it again.

use super::job::Source;
use crate::json::{self, Object};
use crate::torrent::info_hash_hex;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The file the entries are in, one flat JSON object to a line.
const ENTRIES_FILE: &str = "torrents.jsonl";
/// Where the `.torrent` files the daemon keeps go, in the state directory.
const TORRENTS_DIR: &str = "torrents";

/// One torrent the daemon has been given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub info_hash: [u8; 20],
    pub source: Source,
    pub out_dir: PathBuf,
}

impl Entry {
    fn to_line(&self) -> String {
        let object = Object::new().string("id", &info_hash_hex(&self.info_hash)).string("out", &self.out_dir.to_string_lossy());
        match &self.source {
            Source::Magnet(uri) => object.string("magnet", uri),
            Source::File(path) => object.string("file", &path.to_string_lossy()),
        }
        .finish()
    }

    fn from_line(line: &str) -> Result<Entry, String> {
        let fields = json::parse_object(line)?;
        let text = |key: &str| fields.get(key).and_then(|v| v.as_str());
        let id = text("id").ok_or("no \"id\"")?;
        let info_hash = parse_hex20(id).ok_or_else(|| format!("\"id\" is not an info hash: {:?}", id))?;
        let out_dir = PathBuf::from(text("out").ok_or("no \"out\"")?);
        let source = match (text("magnet"), text("file")) {
            (Some(uri), None) => Source::Magnet(uri.to_string()),
            (None, Some(path)) => Source::File(PathBuf::from(path)),
            _ => return Err("it needs exactly one of \"magnet\" and \"file\"".to_string()),
        };
        Ok(Entry { info_hash, source, out_dir })
    }
}

/// Forty hex digits as the 20 bytes they are.
pub fn parse_hex20(text: &str) -> Option<[u8; 20]> {
    if text.len() != 40 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 20];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// A state directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Uses `dir`, making it if it is not there.
    pub fn open(dir: &Path) -> io::Result<Store> {
        fs::create_dir_all(dir.join(TORRENTS_DIR))?;
        Ok(Store { dir: dir.to_path_buf() })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the daemon keeps its copy of a torrent's `.torrent` file.
    pub fn torrent_path(&self, info_hash: &[u8; 20]) -> PathBuf {
        self.dir.join(TORRENTS_DIR).join(format!("{}.torrent", info_hash_hex(info_hash)))
    }

    /// The entries, and a warning for each line that could not be read (which is left out).
    pub fn load(&self) -> (Vec<Entry>, Vec<String>) {
        let text = match fs::read_to_string(self.dir.join(ENTRIES_FILE)) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return (Vec::new(), Vec::new()),
            Err(e) => return (Vec::new(), vec![format!("reading {}: {}", ENTRIES_FILE, e)]),
        };
        let (mut entries, mut warnings) = (Vec::new(), Vec::new());
        for (number, line) in text.lines().enumerate().filter(|(_, line)| !line.trim().is_empty()) {
            match Entry::from_line(line) {
                Ok(entry) if entries.iter().any(|e: &Entry| e.info_hash == entry.info_hash) => warnings.push(format!("{} line {}: {} is there twice; the second is ignored", ENTRIES_FILE, number + 1, info_hash_hex(&entry.info_hash))),
                Ok(entry) => entries.push(entry),
                Err(reason) => warnings.push(format!("{} line {}: {}", ENTRIES_FILE, number + 1, reason)),
            }
        }
        (entries, warnings)
    }

    /// Replaces the entries with `entries`, all at once: a crash leaves the old ones or the new.
    pub fn save(&self, entries: &[Entry]) -> io::Result<()> {
        let mut text = String::new();
        for entry in entries {
            text.push_str(&entry.to_line());
            text.push('\n');
        }
        let path = self.dir.join(ENTRIES_FILE);
        let partial = self.dir.join(format!("{}.part", ENTRIES_FILE));
        fs::write(&partial, text)?;
        fs::rename(&partial, &path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-state-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn entry(byte: u8, source: Source) -> Entry {
        Entry { info_hash: [byte; 20], source, out_dir: PathBuf::from("/downloads/some place") }
    }

    #[test]
    fn what_is_saved_is_loaded_again_in_order() {
        let store = Store::open(&dir("roundtrip")).unwrap();
        let entries = vec![entry(1, Source::Magnet("magnet:?xt=urn:btih:0101&dn=a \"b\"".to_string())), entry(2, Source::File(PathBuf::from("/state/torrents/x.torrent")))];
        store.save(&entries).unwrap();
        assert_eq!(store.load(), (entries, Vec::new()));
    }

    #[test]
    fn a_new_state_directory_has_nothing() {
        assert_eq!(Store::open(&dir("new")).unwrap().load(), (Vec::new(), Vec::new()));
    }

    #[test]
    fn saving_replaces_what_was_there_and_leaves_no_partial_file() {
        let d = dir("replace");
        let store = Store::open(&d).unwrap();
        store.save(&[entry(1, Source::Magnet("m".into())), entry(2, Source::Magnet("n".into()))]).unwrap();
        store.save(&[entry(3, Source::Magnet("o".into()))]).unwrap();
        assert_eq!(store.load().0, vec![entry(3, Source::Magnet("o".into()))]);
        assert!(!d.join("torrents.jsonl.part").exists());
    }

    #[test]
    fn a_line_that_cannot_be_read_is_reported_and_the_others_are_kept() {
        let d = dir("damaged");
        let store = Store::open(&d).unwrap();
        let good = entry(1, Source::Magnet("m".into()));
        let twice = good.to_line();
        let lines = [
            good.to_line(),
            "not json".to_string(),
            "{\"id\":\"zz\",\"out\":\"/o\",\"magnet\":\"m\"}".to_string(),
            format!("{{\"id\":\"{}\",\"out\":\"/o\"}}", "02".repeat(20)),
            format!("{{\"id\":\"{}\",\"out\":\"/o\",\"magnet\":\"m\",\"file\":\"f\"}}", "03".repeat(20)),
            String::new(),
            twice,
        ];
        fs::write(d.join("torrents.jsonl"), lines.join("\n")).unwrap();

        let (entries, warnings) = store.load();

        assert_eq!(entries, vec![good]);
        assert_eq!(warnings.len(), 5, "{:?}", warnings);
        assert!(warnings[0].contains("line 2") && warnings[1].contains("not an info hash") && warnings[2].contains("exactly one") && warnings[3].contains("exactly one") && warnings[4].contains("twice"), "{:?}", warnings);
    }

    #[test]
    fn an_info_hash_is_forty_hex_digits_and_nothing_else() {
        assert_eq!(parse_hex20(&"ab".repeat(20)), Some([0xAB; 20]));
        assert_eq!(parse_hex20(&"AB".repeat(20)), Some([0xAB; 20]), "either case");
        for bad in ["", "ab", &"ab".repeat(21), &"zz".repeat(20), &format!("{}é", "a".repeat(38))] {
            assert_eq!(parse_hex20(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn a_torrent_file_is_kept_under_its_info_hash() {
        let store = Store::open(&dir("path")).unwrap();
        let path = store.torrent_path(&[0xAB; 20]);
        assert_eq!(path.parent().unwrap(), store.dir().join("torrents"));
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), format!("{}.torrent", "ab".repeat(20)));
        assert!(path.parent().unwrap().is_dir(), "in a directory that exists");
    }
}
