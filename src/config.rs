//! Optional TOML config for default flags, loaded from
//! `$XDG_CONFIG_HOME/bittorrent-rs.toml` (or `~/.config/bittorrent-rs.toml`).
//! Every field is optional and acts only as a default; any CLI flag
//! overrides its config value, and any config value overrides the built-in
//! default. A missing file is fine (all-defaults); a malformed one is a
//! hard error so a typo doesn't silently do the wrong thing.
//!
//! Example `~/.config/bittorrent-rs.toml`:
//! ```toml
//! out = "/data/torrents"
//! peers = 60
//! port = 51413
//! seed = true
//! dht = true
//! ipv6 = "auto"      # "auto" | "always" | "never"
//! reannounce = 900
//! tui = true
//! ```

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub out: Option<PathBuf>,
    pub peers: Option<usize>,
    pub port: Option<u16>,
    pub seed: Option<bool>,
    /// DHT on/off (default on). `false` is equivalent to `--no-dht`.
    pub dht: Option<bool>,
    /// `"auto"` | `"always"` | `"never"`.
    pub ipv6: Option<String>,
    pub reannounce: Option<u64>,
    pub log: Option<PathBuf>,
    /// Live dashboard on/off (default on). `false` is equivalent to `--no-tui`.
    pub tui: Option<bool>,
}

impl Config {
    /// The default config location per the XDG base-directory spec, or
    /// `None` if neither `$XDG_CONFIG_HOME` nor `$HOME` is set.
    pub fn default_path() -> Option<PathBuf> {
        if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
            if !x.is_empty() {
                return Some(PathBuf::from(x).join("bittorrent-rs.toml"));
            }
        }
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("bittorrent-rs.toml"))
    }

    /// Loads config from `path`. A missing file yields defaults (not an
    /// error); a malformed file is an error.
    pub fn load_optional(path: &Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).map_err(|e| format!("parsing config {}: {}", path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("reading config {}: {}", path.display(), e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_partial_config() {
        let cfg: Config = toml::from_str("peers = 80\nseed = true\nipv6 = \"never\"\n").unwrap();
        assert_eq!(cfg.peers, Some(80));
        assert_eq!(cfg.seed, Some(true));
        assert_eq!(cfg.ipv6.as_deref(), Some("never"));
        assert_eq!(cfg.port, None);
    }

    #[test]
    fn empty_config_is_all_none() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.peers.is_none() && cfg.port.is_none() && cfg.out.is_none());
    }

    #[test]
    fn unknown_key_is_rejected() {
        assert!(toml::from_str::<Config>("nonsense = 1\n").is_err());
    }

    #[test]
    fn wrong_type_is_rejected() {
        assert!(toml::from_str::<Config>("peers = \"lots\"\n").is_err());
    }

    #[test]
    fn missing_file_yields_defaults() {
        let cfg = Config::load_optional(Path::new("/nonexistent/dir/bittorrent-rs.toml")).unwrap();
        assert!(cfg.peers.is_none());
    }

    #[test]
    fn malformed_file_is_an_error() {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "this is = = not toml").unwrap();
        assert!(Config::load_optional(&path).is_err());
    }
}
