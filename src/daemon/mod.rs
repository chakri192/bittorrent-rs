//! A daemon that downloads and seeds any number of torrents at once, on one port, and is told
//! what to do over a local socket.
//!
//! The pieces: a [`SharedNetwork`](crate::session::SharedNetwork) that the torrents share (one
//! listener, DHT node, uTP socket, port mapping and pair of rate limits); a [`Job`] for each
//! torrent, which is the `download` client's session on that network; a [`Manager`] that adds,
//! removes and lists the jobs and remembers them in a state directory; and, on Unix, a
//! [`control`] socket that takes commands, one JSON object to a line.

pub mod job;
pub mod manager;
pub mod state;

#[cfg(unix)]
pub mod control;

pub use job::{Job, JobContext, JobDefaults, JobOptions, JobSpec, JobState, JobStatus, Source};
pub use manager::Manager;
