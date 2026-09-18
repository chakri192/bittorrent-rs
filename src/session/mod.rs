//! The pieces of one download session, kept out of the `download` binary
//! so each can be unit-tested without a network or a terminal.
//!
//! `bin/download.rs` used to hold all of this in one long function; the
//! parts that had no reason to live in a binary move here one at a time.

pub mod peer_pool;
pub mod plan;
pub mod rate;
pub mod services;

pub use peer_pool::PeerPool;
pub use plan::{DownloadPlan, Outstanding};
pub use rate::RateSampler;
pub use services::Services;
