//! Makes a `.torrent` file from a file or a directory.
//!
//!   create_torrent <file-or-directory> [options]
//!
//! The counterpart of `download`: what this writes, `download` reads (with
//! the peers and the trackers, of course, to be supplied by you).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use bittorrent_rs::create::{create, parse_size, CreateOptions};
use bittorrent_rs::torrent::info_hash_hex;
use bittorrent_rs::ui::format_bytes;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct Args {
    source: PathBuf,
    /// Where to write; by default `<name>.torrent` in the current directory.
    out: Option<PathBuf>,
    options: CreateOptions,
    force: bool,
    quiet: bool,
}

fn usage() -> String {
    "usage: create_torrent <file | directory> [--out FILE] [--announce URL[,URL...]]... [--web-seed URL]... [--piece-length SIZE] [--private] [--comment TEXT] [--name NAME] [--no-date] [--force] [--quiet]\n\
     \n\
     Each --announce is one tier of trackers (BEP 12): trackers within a tier are separated by commas, and tiers are tried in the order given."
        .to_string()
}

fn parse_args(argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut argv = argv;
    let source = argv.next().ok_or_else(usage)?;
    if source == "--help" || source == "-h" {
        return Err(usage());
    }
    let mut args = Args { source: PathBuf::from(source), out: None, options: CreateOptions::default(), force: false, quiet: false };
    let mut no_date = false;

    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--out" | "-o" => args.out = Some(PathBuf::from(argv.next().ok_or("--out requires a file name")?)),
            "--announce" | "-a" => {
                let list = argv.next().ok_or("--announce requires a tracker URL (or several, separated by commas)")?;
                let tier: Vec<String> = list.split(',').map(str::trim).filter(|url| !url.is_empty()).map(str::to_string).collect();
                if tier.is_empty() {
                    return Err("--announce: no URL given".to_string());
                }
                args.options.trackers.push(tier);
            }
            "--web-seed" | "-w" => args.options.web_seeds.push(argv.next().ok_or("--web-seed requires a URL")?),
            "--piece-length" | "-l" => {
                let v = argv.next().ok_or("--piece-length requires a size such as 256K or 1M")?;
                args.options.piece_length = Some(parse_size(&v).map_err(|e| format!("--piece-length: {}", e))?);
            }
            "--private" => args.options.private = true,
            "--comment" | "-c" => args.options.comment = Some(argv.next().ok_or("--comment requires some text")?),
            "--name" | "-n" => args.options.name = Some(argv.next().ok_or("--name requires a name")?),
            "--no-date" => no_date = true,
            "--force" | "-f" => args.force = true,
            "--quiet" | "-q" => args.quiet = true,
            other => return Err(format!("unrecognized argument: {}", other)),
        }
    }

    args.options.created_by = Some(format!("bittorrent-rs {}", env!("CARGO_PKG_VERSION")));
    if !no_date {
        args.options.creation_date = SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
    }
    Ok(args)
}

/// `<name>.torrent` in the current directory, the name being the one the
/// torrent will have.
fn default_out(source: &Path, name: Option<&str>) -> Result<PathBuf, String> {
    let name = match name {
        Some(name) => name.to_string(),
        None => {
            let resolved = source.canonicalize().map_err(|e| format!("{}: {}", source.display(), e))?;
            resolved.file_name().and_then(|n| n.to_str()).map(str::to_string).ok_or_else(|| format!("{}: cannot name a torrent after this; give --name", source.display()))?
        }
    };
    Ok(PathBuf::from(format!("{}.torrent", name)))
}

fn run(args: Args) -> Result<(), String> {
    let out = match &args.out {
        Some(out) => out.clone(),
        None => default_out(&args.source, args.options.name.as_deref())?,
    };
    // Before the hashing, which may take a while, not after it.
    if out.exists() && !args.force {
        return Err(format!("{} already exists (--force to replace it)", out.display()));
    }

    let show_progress = !args.quiet && std::io::stderr().is_terminal();
    let mut last_percent = None;
    let created = create(&args.source, &args.options, |done, total| {
        if show_progress {
            let percent = done * 100 / total.max(1);
            if last_percent != Some(percent) {
                last_percent = Some(percent);
                eprint!("\rhashing: {}%", percent);
                let _ = std::io::stderr().flush();
            }
        }
    })
    .map_err(|e| e.to_string())?;
    if show_progress {
        eprintln!();
    }

    fs::write(&out, &created.bytes).map_err(|e| format!("writing {}: {}", out.display(), e))?;
    if !args.quiet {
        println!("{}", out.display());
        println!("  {}: {} in {} file(s), {} pieces of {}", created.name, format_bytes(created.total_length), created.file_count, created.piece_count, format_bytes(created.piece_length));
        println!("  info hash {}", info_hash_hex(&created.info_hash));
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{}", message);
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {}", message);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn a_bare_source_gets_the_defaults() {
        let args = parse(&["some/dir"]).unwrap();
        assert_eq!(args.source, PathBuf::from("some/dir"));
        assert_eq!(args.out, None);
        assert_eq!(args.options.piece_length, None);
        assert!(args.options.trackers.is_empty() && args.options.web_seeds.is_empty());
        assert!(!args.options.private && !args.force && !args.quiet);
        assert!(args.options.creation_date.is_some(), "dated unless told not to");
        assert!(args.options.created_by.as_deref().is_some_and(|c| c.starts_with("bittorrent-rs ")));
    }

    #[test]
    fn every_option_lands_where_it_belongs() {
        let args = parse(&[
            "d", "--out", "x.torrent", "--announce", "http://a/announce, http://b/announce", "--announce", "udp://c:1", "--web-seed", "http://m/", "--web-seed", "http://n/", "--piece-length",
            "256K", "--private", "--comment", "hi there", "--name", "release", "--force", "--quiet",
        ])
        .unwrap();
        assert_eq!(args.out, Some(PathBuf::from("x.torrent")));
        assert_eq!(args.options.trackers, vec![vec!["http://a/announce".to_string(), "http://b/announce".to_string()], vec!["udp://c:1".to_string()]], "one tier per --announce, split on commas");
        assert_eq!(args.options.web_seeds, vec!["http://m/".to_string(), "http://n/".to_string()]);
        assert_eq!(args.options.piece_length, Some(256 * 1024));
        assert!(args.options.private && args.force && args.quiet);
        assert_eq!(args.options.comment.as_deref(), Some("hi there"));
        assert_eq!(args.options.name.as_deref(), Some("release"));
    }

    #[test]
    fn no_date_leaves_the_date_out() {
        assert_eq!(parse(&["d", "--no-date"]).unwrap().options.creation_date, None);
    }

    #[test]
    fn bad_arguments_are_refused() {
        assert!(parse(&[]).unwrap_err().starts_with("usage:"));
        assert!(parse(&["--help"]).unwrap_err().starts_with("usage:"));
        assert!(parse(&["d", "--bogus"]).unwrap_err().contains("unrecognized"));
        assert!(parse(&["d", "--piece-length", "big"]).unwrap_err().starts_with("--piece-length:"));
        for flag in ["--out", "--announce", "--web-seed", "--piece-length", "--comment", "--name"] {
            assert!(parse(&["d", flag]).unwrap_err().contains("requires"), "{} with no value", flag);
        }
        assert!(parse(&["d", "--announce", " , "]).unwrap_err().contains("no URL"));
    }

    #[test]
    fn the_default_file_is_named_after_the_torrent() {
        assert_eq!(default_out(Path::new("."), Some("release")).unwrap(), PathBuf::from("release.torrent"));
        let here = std::env::current_dir().unwrap();
        let expected = format!("{}.torrent", here.file_name().unwrap().to_str().unwrap());
        assert_eq!(default_out(Path::new("."), None).unwrap(), PathBuf::from(expected), "`.` is resolved to the directory's real name");
        assert!(default_out(Path::new("/definitely/not/here"), None).is_err());
    }
}
