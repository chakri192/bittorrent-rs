//! Locking that survives a panicked thread.
//!
//! A lock is *poisoned* when a thread panics while holding it, and the
//! standard `lock()` then fails for every thread that touches it after. One
//! thread's panic would become a panic in all of them, or, where the
//! failure was quietly ignored, a silent loss of updates: a poisoned
//! progress display never learns the download finished.
//!
//! Every lock in this client guards plain data (a queue, a set of
//! addresses, a bitfield, the numbers on the dashboard) that each critical
//! section leaves consistent at every step, so the data is still good and
//! carrying on with it is the right thing to do.

use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Locks `mutex`, using the data even if a panicking thread poisoned it.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read-locks `rwlock`, using the data even if it was poisoned.
pub fn read<T>(rwlock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    rwlock.read().unwrap_or_else(PoisonError::into_inner)
}

/// Write-locks `rwlock`, using the data even if it was poisoned.
pub fn write<T>(rwlock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    rwlock.write().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn poisoned_mutex() -> Mutex<Vec<u32>> {
        let m = Mutex::new(vec![1, 2, 3]);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let mut guard = m.lock().unwrap();
            guard.push(4);
            panic!("a thread died holding the lock");
        }));
        assert!(m.is_poisoned(), "the setup must really poison it");
        m
    }

    #[test]
    fn a_healthy_mutex_locks_normally() {
        let m = Mutex::new(5);
        *lock(&m) += 1;
        assert_eq!(*lock(&m), 6);
    }

    #[test]
    fn a_poisoned_mutex_still_gives_up_its_data() {
        let m = poisoned_mutex();
        assert!(m.lock().is_err(), "std would refuse");
        assert_eq!(*lock(&m), vec![1, 2, 3, 4], "including the change made before the panic");
        lock(&m).push(5);
        assert_eq!(lock(&m).len(), 5, "and it stays usable");
    }

    #[test]
    fn a_poisoned_rwlock_can_still_be_read_and_written() {
        let rw = RwLock::new(vec![false; 3]);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = rw.write().unwrap();
            panic!("a thread died holding the write lock");
        }));
        assert!(rw.is_poisoned());

        write(&rw)[1] = true;
        assert_eq!(*read(&rw), vec![false, true, false]);
    }
}
