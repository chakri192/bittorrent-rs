//! The pieces of one download session, kept out of the `download` binary
//! so each can be unit-tested without a network or a terminal.
//!
//! `bin/download.rs` used to hold all of this in one long function; the
//! parts that had no reason to live in a binary move here one at a time.

pub mod announce;
pub mod metadata;
pub mod peer_pool;
pub mod plan;
pub mod progress;
pub mod rate;
pub mod run;
pub mod services;
pub mod sink;
pub mod workers;

pub use announce::{Announcer, NetworkTrackers, TrackerClient};
pub use metadata::{fetch_metadata, resolve_magnet, Fetched, MetadataConfig};
pub use peer_pool::PeerPool;
pub use plan::{DownloadPlan, Outstanding};
pub use progress::Progress;
pub use rate::RateSampler;
pub use run::{Report, Session, Setup};
pub use services::Services;
pub use sink::ProgressSink;
pub use workers::{Log, Workers};
