//! The torrents a daemon is running: adding, removing and listing them, and remembering them.

use super::job::{FinishedHook, Job, JobContext, JobDefaults, JobOptions, JobSpec, JobState, JobStatus, Source};
use super::state::{Dormant, Entry, Store};
use crate::magnet::parse_magnet_uri;
use crate::session::SharedNetwork;
use crate::sync::lock;
use crate::torrent::{self, info_hash_hex, TorrentFile};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

/// How many hex digits of an info hash tell one torrent from another, when they are given short.
const MIN_ID_LEN: usize = 4;

/// Runs torrents on a shared network. Nothing here deletes a download: removing a torrent stops it
/// and forgets it, and its files stay where they are.
pub struct Manager {
    context: Arc<JobContext>,
    store: Option<Store>,
    /// The torrents that are running or have ended, in the order they were added.
    jobs: Mutex<Vec<Arc<Job>>>,
    /// What is remembered: the same torrents, as they are to be started again.
    entries: Mutex<Vec<Entry>>,
}

impl Manager {
    /// A manager whose torrents share `network` and are run as `defaults` says, remembered in
    /// `store` if there is one. Nothing is started until [`restore`](Self::restore) or
    /// [`add`](Self::add).
    pub fn new(network: Arc<SharedNetwork>, peer_id: [u8; 20], defaults: JobDefaults, store: Option<Store>) -> Arc<Manager> {
        Arc::new_cyclic(|this: &Weak<Manager>| {
            let (resolved, finished) = (Weak::clone(this), Weak::clone(this));
            let on_resolved: Box<dyn Fn(&TorrentFile) + Send + Sync> = Box::new(move |torrent| {
                if let Some(manager) = resolved.upgrade() {
                    manager.resolved(torrent);
                }
            });
            let on_finished: FinishedHook = Box::new(move |info_hash, reason| {
                if let Some(manager) = finished.upgrade() {
                    manager.finished(info_hash, reason);
                }
            });
            Manager { context: Arc::new(JobContext { network, peer_id, defaults, on_resolved, on_finished }), store, jobs: Mutex::new(Vec::new()), entries: Mutex::new(Vec::new()) }
        })
    }

    /// The job for what is remembered: running, unless it was set aside or had finished.
    fn job_for(&self, entry: &Entry) -> Job {
        let spec = JobSpec { info_hash: entry.info_hash, source: entry.source.clone(), out_dir: entry.out_dir.clone(), options: entry.options.clone() };
        match &entry.dormant {
            Some(dormant) => Job::dormant(spec, dormant.state()),
            None => Job::start(spec, Arc::clone(&self.context)),
        }
    }

    /// Starts again the torrents the state directory remembers (those that were not set aside or
    /// finished). What could not be read comes back as warnings.
    pub fn restore(&self) -> Vec<String> {
        let Some(store) = &self.store else { return Vec::new() };
        let (entries, warnings) = store.load();
        let mut jobs = lock(&self.jobs);
        let mut all = lock(&self.entries);
        for entry in entries {
            jobs.push(Arc::new(self.job_for(&entry)));
            all.push(entry);
        }
        warnings
    }

    /// Adds a torrent, given as a magnet link or as the path of a `.torrent` file, to be
    /// downloaded into `out_dir` (a torrent of several files goes in a directory of its name
    /// under it) and then seeded. Both paths must be absolute: the daemon does not share its
    /// working directory with whoever is asking. A pattern in `options` that matches none of a
    /// `.torrent`'s files is refused here; for a magnet link it is found out when the torrent is.
    pub fn add(&self, source: &str, out_dir: PathBuf, options: JobOptions) -> Result<JobStatus, String> {
        if !out_dir.is_absolute() {
            return Err(format!("the output directory must be an absolute path: {}", out_dir.display()));
        }
        let (info_hash, source) = if source.starts_with("magnet:?") {
            let magnet = parse_magnet_uri(source).map_err(|e| format!("parsing the magnet link: {}", e))?;
            (magnet.info_hash, Source::Magnet(source.to_string()))
        } else {
            let path = PathBuf::from(source);
            if !path.is_absolute() {
                return Err(format!("a .torrent file must be given by absolute path: {}", source));
            }
            let bytes = fs::read(&path).map_err(|e| format!("reading {}: {}", path.display(), e))?;
            let torrent = torrent::parse_torrent_file(&bytes).map_err(|e| format!("parsing {}: {}", path.display(), e))?;
            crate::selection::build_mask_for(&torrent, &[], &options.only)?;
            if !options.prefer.is_empty() {
                crate::selection::build_prefer_mask_for(&torrent, &options.prefer)?;
            }
            // Kept, so that the torrent does not depend on the file staying where it was.
            let kept = match &self.store {
                Some(store) => {
                    let kept = store.torrent_path(&torrent.info_hash);
                    fs::write(&kept, &bytes).map_err(|e| format!("keeping a copy of the torrent in {}: {}", kept.display(), e))?;
                    kept
                }
                None => path,
            };
            (torrent.info_hash, Source::File(kept))
        };

        let mut jobs = lock(&self.jobs);
        if let Some(existing) = jobs.iter().find(|job| job.info_hash() == info_hash) {
            return Err(format!("already added: {} ({})", info_hash_hex(&info_hash), existing.status().name));
        }
        let entry = Entry { info_hash, source, out_dir, options, dormant: None };
        let job = Arc::new(self.job_for(&entry));
        {
            let mut entries = lock(&self.entries);
            entries.push(entry);
            self.save(&entries)?;
        }
        let status = job.status();
        jobs.push(job);
        Ok(status)
    }

    /// Stops a torrent and forgets it. Waits for it to be over, which takes as long as telling
    /// its trackers takes. Its files are left alone.
    pub fn remove(&self, id: &str) -> Result<JobStatus, String> {
        let job = {
            let mut jobs = lock(&self.jobs);
            let index = Self::find(&jobs, id)?;
            jobs.remove(index)
        };
        let hash = job.info_hash();
        {
            let mut entries = lock(&self.entries);
            entries.retain(|entry| entry.info_hash != hash);
            self.save(&entries)?;
        }
        job.stop();
        if let Some(store) = &self.store {
            // The daemon's own copy; the one the user gave it is theirs.
            let _ = fs::remove_file(store.torrent_path(&hash));
        }
        Ok(job.status())
    }

    /// Sets a torrent aside: it is stopped, taken off the shared port and the DHT, and told to its
    /// trackers, and kept, with what it has downloaded, until it is resumed. It stays paused
    /// through a restart.
    pub fn pause(&self, id: &str) -> Result<JobStatus, String> {
        let job = {
            let jobs = lock(&self.jobs);
            Arc::clone(&jobs[Self::find(&jobs, id)?])
        };
        if job.status().state == JobState::Paused {
            return Err("it is paused already".to_string());
        }
        job.stop(); // (with no lock held: the job may be telling us it has finished)
        self.replace(&job, Some(Dormant::Paused))
    }

    /// Starts a torrent that was paused again, or one that had finished (to seed it again) or
    /// failed (to try again). One that is running is refused.
    pub fn resume(&self, id: &str) -> Result<JobStatus, String> {
        let job = {
            let jobs = lock(&self.jobs);
            Arc::clone(&jobs[Self::find(&jobs, id)?])
        };
        if !job.status().state.is_over() {
            return Err("it is running".to_string());
        }
        job.stop(); // (it is over: this only collects its thread)
        self.replace(&job, None)
    }

    /// Puts in the place of `old` a job made from what is remembered of it once its `dormant` is as given.
    fn replace(&self, old: &Arc<Job>, dormant: Option<Dormant>) -> Result<JobStatus, String> {
        let mut jobs = lock(&self.jobs);
        let hash = old.info_hash();
        let mut entries = lock(&self.entries);
        let (Some(at), Some(entry)) = (jobs.iter().position(|j| Arc::ptr_eq(j, old)), entries.iter_mut().find(|e| e.info_hash == hash)) else {
            return Err("it was removed".to_string());
        };
        entry.dormant = dormant;
        let job = Arc::new(self.job_for(entry));
        self.save(&entries)?;
        let status = job.status();
        jobs[at] = job;
        Ok(status)
    }

    pub fn list(&self) -> Vec<JobStatus> {
        lock(&self.jobs).iter().map(|job| job.status()).collect()
    }

    pub fn status(&self, id: &str) -> Result<JobStatus, String> {
        let jobs = lock(&self.jobs);
        Ok(jobs[Self::find(&jobs, id)?].status())
    }

    /// Ends every torrent, all at once. They are still remembered: the next run starts them again.
    pub fn shutdown(&self) {
        let jobs: Vec<Arc<Job>> = lock(&self.jobs).drain(..).collect();
        for job in &jobs {
            job.signal_stop();
        }
        for job in &jobs {
            job.stop();
        }
    }

    /// The torrent `id` names: its info hash in hex, or the start of it if that is enough to tell.
    fn find(jobs: &[Arc<Job>], id: &str) -> Result<usize, String> {
        let id = id.trim().to_ascii_lowercase();
        if id.len() < MIN_ID_LEN {
            return Err(format!("{:?} is too short to name a torrent (give at least {} digits of its info hash)", id, MIN_ID_LEN));
        }
        let matching: Vec<usize> = (0..jobs.len()).filter(|&i| info_hash_hex(&jobs[i].info_hash()).starts_with(&id)).collect();
        match matching.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!("no torrent {}", id)),
            _ => Err(format!("{} names more than one torrent; give more of its info hash", id)),
        }
    }

    fn save(&self, entries: &[Entry]) -> Result<(), String> {
        match &self.store {
            Some(store) => store.save(entries).map_err(|e| format!("saving the state: {}", e)),
            None => Ok(()),
        }
    }

    /// A torrent's metadata has arrived: keep it, and from now on remember the torrent as that
    /// file and not as the magnet link.
    fn resolved(&self, torrent: &TorrentFile) {
        let Some(store) = &self.store else { return };
        let path = store.torrent_path(&torrent.info_hash);
        if crate::create::save_torrent(torrent, &path).is_err() {
            return; // still remembered as the link, which works, if slower
        }
        let mut entries = lock(&self.entries);
        if let Some(entry) = entries.iter_mut().find(|e| e.info_hash == torrent.info_hash && matches!(e.source, Source::Magnet(_))) {
            entry.source = Source::File(path);
            let _ = store.save(&entries);
        }
    }

    /// A torrent has been seeded up to a limit: a restart is not to start it again.
    fn finished(&self, info_hash: &[u8; 20], reason: &str) {
        let mut entries = lock(&self.entries);
        if let Some(entry) = entries.iter_mut().find(|e| &e.info_hash == info_hash) {
            entry.dormant = Some(Dormant::Finished(reason.to_string()));
            let _ = self.save(&entries);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{create, CreateOptions};
    use crate::daemon::JobState;
    use crate::session::network::tests::{no_dht, quiet_network};
    use crate::session::testing::tracker;
    use crate::session::Ipv6Mode;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bt-daemon-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Settings that keep a job on loopback: no local discovery, no IPv6, quick to retry.
    fn defaults() -> JobDefaults {
        JobDefaults { lsd: None, ipv6: Ipv6Mode::Never, retry_delay: Duration::from_millis(200), connect_timeout: Duration::from_secs(2), ..Default::default() }
    }

    fn content(len: usize, salt: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt)).collect()
    }

    /// A one-file torrent of `len` bytes, its file written under `seed_dir`, its `.torrent` under
    /// `torrent_dir`, announcing to `announce`.
    fn make_torrent(name: &str, len: usize, salt: u8, seed_dir: &std::path::Path, torrent_dir: &std::path::Path, announce: &str) -> (PathBuf, [u8; 20], Vec<u8>) {
        let data = content(len, salt);
        let file = seed_dir.join(name);
        fs::write(&file, &data).unwrap();
        let created = create(&file, &CreateOptions { piece_length: Some(16384), trackers: vec![vec![announce.to_string()]], ..Default::default() }, |_, _| {}).unwrap();
        let path = torrent_dir.join(format!("{}.torrent", name));
        fs::write(&path, &created.bytes).unwrap();
        (path, created.info_hash, data)
    }

    fn wait_for(manager: &Manager, id: &[u8; 20], what: &str, done: impl Fn(&JobStatus) -> bool) -> JobStatus {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let status = manager.status(&info_hash_hex(id)).unwrap();
            if done(&status) {
                return status;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {}: {:?} {:?}", what, status.state, status.log);
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn manager_on(network: &Arc<SharedNetwork>, store: Option<Store>) -> Arc<Manager> {
        Manager::new(Arc::clone(network), [9; 20], defaults(), store)
    }

    /// A seeding daemon with two torrents, and the trackers that point at it.
    struct Seeder {
        manager: Arc<Manager>,
        network: Arc<SharedNetwork>,
        torrents: Vec<(PathBuf, [u8; 20], Vec<u8>, &'static str)>,
    }

    fn seeder(name: &str) -> Seeder {
        seeder_with(name, None)
    }

    fn seeder_with(name: &str, store: Option<Store>) -> Seeder {
        let root = dir(name);
        let network = quiet_network(no_dht());
        let (announce, _) = tracker(SocketAddr::from(([127, 0, 0, 1], network.port)));
        let (seed_dir, torrent_dir) = (root.join("seed"), root.join("torrents"));
        fs::create_dir_all(&seed_dir).unwrap();
        fs::create_dir_all(&torrent_dir).unwrap();
        let torrents = vec![
            {
                let (path, hash, data) = make_torrent("first.bin", 70_000, 1, &seed_dir, &torrent_dir, &announce);
                (path, hash, data, "first.bin")
            },
            {
                let (path, hash, data) = make_torrent("second.bin", 50_000, 2, &seed_dir, &torrent_dir, &announce);
                (path, hash, data, "second.bin")
            },
        ];
        let manager = manager_on(&network, store);
        for (path, _, _, _) in &torrents {
            manager.add(path.to_str().unwrap(), seed_dir.clone(), JobOptions::default()).unwrap();
        }
        for (_, hash, _, _) in &torrents {
            wait_for(&manager, hash, "the seeder to be seeding", |s| s.state == JobState::Seeding);
        }
        Seeder { manager, network, torrents }
    }

    #[test]
    fn a_daemon_seeds_two_torrents_on_one_port_and_another_downloads_both_at_once() {
        let s = seeder("two");
        assert_eq!(s.network.torrent_count(), 2, "both are on the one listener");

        let root = dir("two-leech");
        let leech_network = quiet_network(no_dht());
        let leech = manager_on(&leech_network, None);
        let out = root.join("out");
        fs::create_dir_all(&out).unwrap();
        for (path, _, _, _) in &s.torrents {
            leech.add(path.to_str().unwrap(), out.clone(), JobOptions::default()).unwrap();
        }
        assert_eq!(leech.list().len(), 2);

        for (_, hash, data, name) in &s.torrents {
            let status = wait_for(&leech, hash, "the download to finish", |st| matches!(st.state, JobState::Seeding | JobState::Failed(_)));
            assert_eq!(status.state, JobState::Seeding, "{}: {:?}", name, status.log);
            assert_eq!(&fs::read(out.join(name)).unwrap(), data, "{} arrived intact", name);
            assert_eq!(status.name, *name);
        }
        assert_eq!(leech_network.torrent_count(), 2, "and the downloader serves both on its one port, too");

        leech.shutdown();
        leech_network.shutdown();
        s.manager.shutdown();
        s.network.shutdown();
    }

    #[test]
    fn removing_a_torrent_stops_it_and_leaves_its_files_and_the_others_running() {
        let s = seeder("remove");
        let (_, hash, data, name) = &s.torrents[0];
        let (_, other, _, _) = &s.torrents[1];
        let seed_dir = s.manager.status(&info_hash_hex(hash)).unwrap().out_dir;

        let removed = s.manager.remove(&info_hash_hex(hash)[..8]).expect("a start of the info hash is enough");

        assert_eq!(removed.state, JobState::Stopped);
        assert_eq!(s.manager.list().len(), 1);
        assert_eq!(s.network.torrent_count(), 1, "it is off the shared port");
        assert_eq!(&fs::read(seed_dir.join(name)).unwrap(), data, "its files are still there");
        assert_eq!(s.manager.status(&info_hash_hex(other)).unwrap().state, JobState::Seeding, "the other carries on");
        assert!(s.manager.remove(&info_hash_hex(hash)).unwrap_err().starts_with("no torrent"), "and it is gone");

        s.manager.shutdown();
        s.network.shutdown();
    }

    #[test]
    fn adding_needs_absolute_paths_a_torrent_that_parses_and_one_not_already_added() {
        let network = quiet_network(no_dht());
        let manager = manager_on(&network, None);
        let root = dir("add-errors");
        assert!(manager.add("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567", PathBuf::from("out"), JobOptions::default()).unwrap_err().contains("absolute"));
        assert!(manager.add("some.torrent", root.clone(), JobOptions::default()).unwrap_err().contains("absolute"));
        assert!(manager.add(root.join("missing.torrent").to_str().unwrap(), root.clone(), JobOptions::default()).unwrap_err().starts_with("reading"));
        fs::write(root.join("bad.torrent"), b"not a torrent").unwrap();
        assert!(manager.add(root.join("bad.torrent").to_str().unwrap(), root.clone(), JobOptions::default()).unwrap_err().starts_with("parsing"));
        assert!(manager.add("magnet:?xt=nothing", root.clone(), JobOptions::default()).unwrap_err().starts_with("parsing the magnet link"));

        let magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&tr=http%3A%2F%2F127.0.0.1%3A9%2Fannounce";
        manager.add(magnet, root.clone(), JobOptions::default()).unwrap();
        assert!(manager.add(magnet, root.clone(), JobOptions::default()).unwrap_err().starts_with("already added: 0123456789abcdef"));
        assert_eq!(manager.list().len(), 1, "and that made no second job");

        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn a_torrent_is_named_by_the_start_of_its_info_hash_if_that_is_enough() {
        let network = quiet_network(no_dht());
        let manager = manager_on(&network, None);
        let root = dir("ids");
        for hash in ["0123456789abcdef0123456789abcdef01234567", "0123ffffffffffffffffffffffffffffffffffff"] {
            manager.add(&format!("magnet:?xt=urn:btih:{}&tr=http%3A%2F%2F127.0.0.1%3A9%2Fannounce", hash), root.clone(), JobOptions::default()).unwrap();
        }
        assert!(manager.status("0123").unwrap_err().contains("more than one"));
        assert!(manager.status("012").unwrap_err().contains("too short"));
        assert!(manager.status("0123ff").is_ok());
        assert!(manager.status("0123FF").is_ok(), "in either case");
        assert!(manager.status("4567").unwrap_err().contains("no torrent"));
        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn what_was_added_is_remembered_across_a_restart_and_what_was_removed_is_not() {
        let s = seeder("restart-seed");
        let root = dir("restart");
        let state = root.join("state");
        let out = root.join("out");
        fs::create_dir_all(&out).unwrap();
        let network = quiet_network(no_dht());
        let manager = manager_on(&network, Some(Store::open(&state).unwrap()));
        for (path, _, _, _) in &s.torrents {
            manager.add(path.to_str().unwrap(), out.clone(), JobOptions::default()).unwrap();
        }
        for (_, hash, _, _) in &s.torrents {
            wait_for(&manager, hash, "the download", |st| st.state == JobState::Seeding);
        }
        manager.remove(&info_hash_hex(&s.torrents[1].1)).unwrap();
        manager.shutdown();
        network.shutdown();
        assert!(!Store::open(&state).unwrap().torrent_path(&s.torrents[1].1).exists(), "the copy of a removed torrent is gone");

        // A new daemon on the same state directory.
        let network = quiet_network(no_dht());
        let manager = manager_on(&network, Some(Store::open(&state).unwrap()));
        assert_eq!(manager.restore(), Vec::<String>::new());
        assert_eq!(manager.list().len(), 1, "the torrent that stayed, and only it");
        let status = wait_for(&manager, &s.torrents[0].1, "the restored torrent to seed", |st| matches!(st.state, JobState::Seeding | JobState::Failed(_)));
        assert_eq!(status.state, JobState::Seeding, "found complete on disk: {:?}", status.log);
        assert_eq!(status.out_dir, out);
        assert!(status.log.iter().any(|l| l.contains("resuming") || l.contains("checking")), "{:?}", status.log);

        manager.shutdown();
        network.shutdown();
        s.manager.shutdown();
        s.network.shutdown();
    }

    #[test]
    fn a_magnet_link_that_resolves_is_remembered_as_the_torrent_it_turned_into() {
        let s = seeder("magnet-seed");
        let (_, hash, data, name) = &s.torrents[0];
        let root = dir("magnet");
        let state = root.join("state");
        let out = root.join("out");
        fs::create_dir_all(&out).unwrap();
        let network = quiet_network(no_dht());
        let manager = manager_on(&network, Some(Store::open(&state).unwrap()));

        // The seeder is named in the link, as x.pe (BEP 9): the metadata comes from it.
        let magnet = format!("magnet:?xt=urn:btih:{}&x.pe=127.0.0.1:{}", info_hash_hex(hash), s.network.port);
        manager.add(&magnet, out.clone(), JobOptions::default()).unwrap();
        let status = wait_for(&manager, hash, "the magnet link to become a download", |st| matches!(st.state, JobState::Seeding | JobState::Failed(_)));
        assert_eq!(status.state, JobState::Seeding, "{:?}", status.log);
        assert_eq!(&fs::read(out.join(name)).unwrap(), data);

        let (entries, warnings) = Store::open(&state).unwrap().load();
        assert!(warnings.is_empty());
        assert!(matches!(&entries[0].source, Source::File(path) if path.exists()), "now a file, not the link: {:?}", entries);

        manager.shutdown();
        network.shutdown();
        s.manager.shutdown();
        s.network.shutdown();
    }

    #[test]
    fn a_remembered_torrent_whose_file_has_gone_fails_and_says_why_without_stopping_the_others() {
        let root = dir("vanished");
        let state = root.join("state");
        let store = Store::open(&state).unwrap();
        let missing = Entry::new([0x11; 20], Source::File(root.join("gone.torrent")), root.clone());
        let fine = Entry::new([0x22; 20], Source::Magnet("magnet:?xt=urn:btih:2222222222222222222222222222222222222222&tr=http%3A%2F%2F127.0.0.1%3A9%2Fannounce".to_string()), root.clone());
        store.save(&[missing, fine]).unwrap();
        let network = quiet_network(no_dht());
        let manager = manager_on(&network, Some(store));

        assert!(manager.restore().is_empty());

        let status = wait_for(&manager, &[0x11; 20], "the missing file to be noticed", |st| st.state.is_over());
        assert!(matches!(&status.state, JobState::Failed(reason) if reason.starts_with("reading ")), "{:?}", status.state);
        assert_eq!(manager.list().len(), 2, "it is still listed, to be seen and removed");
        assert!(!manager.status(&"22".repeat(20)).unwrap().state.is_over(), "the other torrent is unaffected");
        manager.remove(&"11".repeat(20)).expect("a failed torrent can be removed");
        manager.shutdown();
        network.shutdown();
    }

    use crate::session::network::tests::handshake;

    #[test]
    fn a_paused_torrent_is_off_the_port_and_stays_so_until_resumed() {
        let s = seeder("pause");
        let ((_, first, _, _), (_, second, _, _)) = (&s.torrents[0], &s.torrents[1]);

        let paused = s.manager.pause(&info_hash_hex(first)).unwrap();

        assert_eq!(paused.state, JobState::Paused);
        assert_eq!(s.manager.status(&info_hash_hex(first)).unwrap().state, JobState::Paused);
        assert_eq!(s.network.torrent_count(), 1, "it is off the shared port");
        assert_eq!(handshake(s.network.port, *first), None);
        assert_eq!(handshake(s.network.port, *second), Some(*second), "the other is served as before");
        assert!(s.manager.pause(&info_hash_hex(first)).unwrap_err().contains("already"));
        assert!(s.manager.resume(&info_hash_hex(second)).unwrap_err().contains("running"), "a running torrent is not resumed");
        assert_eq!(s.manager.list().len(), 2, "still listed");

        s.manager.resume(&info_hash_hex(first)).unwrap();
        wait_for(&s.manager, first, "the resumed torrent to seed again", |st| st.state == JobState::Seeding);
        assert_eq!(handshake(s.network.port, *first), Some(*first), "and served");
        assert_eq!(s.network.torrent_count(), 2);

        s.manager.shutdown();
        s.network.shutdown();
    }

    #[test]
    fn a_torrent_paused_stays_paused_through_a_restart() {
        let root = dir("pause-restart");
        let state = root.join("state");
        let s = seeder_with("pause-restart-seed", Some(Store::open(&state).unwrap()));
        let hash = s.torrents[0].1;
        s.manager.pause(&info_hash_hex(&hash)).unwrap();
        s.manager.shutdown();
        s.network.shutdown();

        let network = quiet_network(no_dht());
        let manager = manager_on(&network, Some(Store::open(&state).unwrap()));
        assert!(manager.restore().is_empty());
        assert_eq!(manager.status(&info_hash_hex(&hash)).unwrap().state, JobState::Paused, "at once, not started and then stopped");
        assert_ne!(manager.status(&info_hash_hex(&s.torrents[1].1)).unwrap().state, JobState::Paused, "and only that one");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(handshake(network.port, hash), None, "it is not served");

        manager.resume(&info_hash_hex(&hash)).unwrap();
        wait_for(&manager, &hash, "the resumed torrent to seed", |st| st.state == JobState::Seeding);
        assert!(Store::open(&state).unwrap().load().0.iter().all(|e| e.dormant.is_none()), "and it is remembered as running");
        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn a_torrent_seeded_up_to_its_limit_is_remembered_as_finished_and_a_restart_does_not_seed_it_again() {
        let root = dir("finished");
        let (state, files) = (root.join("state"), root.join("files"));
        fs::create_dir_all(&files).unwrap();
        let (path, hash, _) = make_torrent("done.bin", 40_000, 4, &files, &root, "http://127.0.0.1:9/announce");
        let network = quiet_network(no_dht());
        let limits = JobDefaults { seed_limits: crate::session::SeedLimits { ratio: None, time: Some(Duration::ZERO) }, ..defaults() };
        let manager = Manager::new(Arc::clone(&network), [9; 20], limits.clone(), Some(Store::open(&state).unwrap()));
        manager.add(path.to_str().unwrap(), files.clone(), JobOptions::default()).unwrap();

        let status = wait_for(&manager, &hash, "the seeding to reach its limit", |st| matches!(st.state, JobState::Finished(_) | JobState::Failed(_)));
        assert!(matches!(&status.state, JobState::Finished(why) if why.contains("seed time")), "{:?} {:?}", status.state, status.log);
        // (What the job says on its way out is written by the time it is seen to be over.)
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(Store::open(&state).unwrap().load().0[0].dormant, Some(Dormant::Finished(_))) {
            assert!(Instant::now() < deadline, "the finish was never remembered");
            std::thread::sleep(Duration::from_millis(20));
        }
        manager.shutdown();
        network.shutdown();

        let network = quiet_network(no_dht());
        let manager = Manager::new(Arc::clone(&network), [9; 20], limits, Some(Store::open(&state).unwrap()));
        manager.restore();
        let status = manager.status(&info_hash_hex(&hash)).unwrap();
        assert!(matches!(&status.state, JobState::Finished(_)), "finished at once, and not run again: {:?}", status.state);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(network.torrent_count(), 0, "so it is not served");

        manager.resume(&info_hash_hex(&hash)).expect("but it can be started to seed again");
        wait_for(&manager, &hash, "the seeding to start again", |st| matches!(st.state, JobState::Seeding | JobState::Finished(_)));
        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn a_failed_torrent_is_tried_again_by_resuming_it() {
        let root = dir("retry");
        let state = root.join("state");
        let files = root.join("files");
        fs::create_dir_all(&files).unwrap();
        let (made, hash, _) = make_torrent("late.bin", 30_000, 5, &files, &root, "http://127.0.0.1:9/announce");
        let store = Store::open(&state).unwrap();
        let missing = root.join("not-yet.torrent");
        store.save(&[Entry::new(hash, Source::File(missing.clone()), files.clone())]).unwrap();
        let network = quiet_network(no_dht());
        let manager = manager_on(&network, Some(store));
        manager.restore();
        wait_for(&manager, &hash, "the missing file to be noticed", |st| matches!(st.state, JobState::Failed(_)));

        fs::copy(&made, &missing).unwrap();
        manager.resume(&info_hash_hex(&hash)).unwrap();

        wait_for(&manager, &hash, "the retry to work", |st| matches!(st.state, JobState::Seeding | JobState::Failed(_)));
        assert_eq!(manager.status(&info_hash_hex(&hash)).unwrap().state, JobState::Seeding);
        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn only_some_of_a_torrents_files_can_be_asked_for_and_only_those_are_fetched() {
        let root = dir("only");
        let network = quiet_network(no_dht());
        let (announce, _) = tracker(SocketAddr::from(([127, 0, 0, 1], network.port)));
        // Two files of whole pieces, so that no piece is shared between them.
        let (seed_dir, out) = (root.join("seed"), root.join("out"));
        fs::create_dir_all(seed_dir.join("multi")).unwrap();
        fs::create_dir_all(&out).unwrap();
        let (a, b) = (content(32_768, 1), content(32_768, 2));
        fs::write(seed_dir.join("multi/a.bin"), &a).unwrap();
        fs::write(seed_dir.join("multi/b.bin"), &b).unwrap();
        let created = create(&seed_dir.join("multi"), &CreateOptions { piece_length: Some(16384), trackers: vec![vec![announce]], ..Default::default() }, |_, _| {}).unwrap();
        let torrent = root.join("multi.torrent");
        fs::write(&torrent, &created.bytes).unwrap();

        let seeding = manager_on(&network, None);
        seeding.add(torrent.to_str().unwrap(), seed_dir.clone(), JobOptions::default()).unwrap();
        wait_for(&seeding, &created.info_hash, "the seeder to seed", |st| st.state == JobState::Seeding);

        let leech_network = quiet_network(no_dht());
        let leech = manager_on(&leech_network, None);
        let wrong = JobOptions { only: vec!["zzz".into()], ..Default::default() };
        assert!(leech.add(torrent.to_str().unwrap(), out.clone(), wrong).unwrap_err().contains("zzz"), "a pattern that matches nothing is refused at once");
        assert_eq!(leech.list().len(), 0, "and nothing is added");
        leech.add(torrent.to_str().unwrap(), out.clone(), JobOptions { only: vec!["A.BIN".into()], ..Default::default() }).unwrap();

        let status = wait_for(&leech, &created.info_hash, "the wanted file to arrive", |st| matches!(st.state, JobState::Seeding | JobState::Failed(_)));
        assert_eq!(status.state, JobState::Seeding, "{:?}", status.log);
        assert_eq!(fs::read(out.join("multi/a.bin")).unwrap(), a);
        assert!(!out.join("multi/b.bin").exists() || fs::read(out.join("multi/b.bin")).unwrap() != b, "the other file was not fetched");

        leech.shutdown();
        seeding.shutdown();
        leech_network.shutdown();
        network.shutdown();
    }
}
