//! A BitTorrent client written from the specifications.
//!
//! Untrusted input reaches almost every module, so production code must not
//! panic on it: `unwrap()` and `expect()` are linted against outside tests
//! (CI runs clippy with warnings as errors).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

pub mod bencode;
pub mod bytes;
pub mod choker;
pub mod config;
pub mod create;
pub mod dht;
pub mod downloader;
pub mod json;
pub mod lsd;
#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod robustness;
pub mod magnet;
pub mod magnet_fetch;
pub mod metadata;
pub mod peer;
pub mod portmap;
pub mod ratelimit;
pub mod seeder;
pub mod selection;
pub mod session;
pub mod sha256;
pub mod signal;
pub mod torrent;
pub mod tracker;
pub mod tracker_discovery;
pub mod tui;
pub mod sync;
pub mod ui;
pub mod v2;
pub mod utp;
pub mod webseed;
