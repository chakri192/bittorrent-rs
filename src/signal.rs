//! Turning SIGINT and SIGTERM into a request to stop.
//!
//! With a terminal, the dashboard catches `q` and Ctrl-C itself and the
//! client winds down: the listener and DHT stop and the router's port
//! mapping is removed. Without one (output piped, `nohup`, a service
//! manager) nothing did, so a signal killed the process outright, skipping
//! all of that and leaving the mapping on the router until its lease ran
//! out. This gives those runs the same clean exit.
//!
//! The handler does one atomic store, which is safe in a signal handler. A
//! second signal exits at once with status 130, so a shutdown that has got
//! stuck can always be overridden from the keyboard.

#[cfg(unix)]
mod imp {
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use std::sync::Arc;

    /// The flag to set. Points at an `AtomicBool` kept alive on purpose by
    /// leaking one `Arc` reference, since a handler cannot own anything.
    static TARGET: AtomicPtr<AtomicBool> = AtomicPtr::new(std::ptr::null_mut());
    static RECEIVED: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_signal(_signal: libc::c_int) {
        if RECEIVED.swap(true, Ordering::SeqCst) {
            // A second signal: the user has waited long enough.
            // SAFETY: `_exit` is async-signal-safe.
            unsafe { libc::_exit(130) };
        }
        let target = TARGET.load(Ordering::SeqCst);
        if !target.is_null() {
            // SAFETY: the pointer came from a leaked `Arc<AtomicBool>` and is never freed.
            unsafe { (*target).store(true, Ordering::SeqCst) };
        }
    }

    pub fn install(stop: Arc<AtomicBool>) {
        TARGET.store(Arc::into_raw(stop) as *mut AtomicBool, Ordering::SeqCst);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: `on_signal` only touches atomics, and the function
            // pointer has the signature `signal` expects.
            unsafe { libc::signal(signal, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t) };
        }
    }

    pub fn received() -> bool {
        RECEIVED.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn raise(signal: libc::c_int) {
        // SAFETY: raising a signal we have installed a handler for.
        unsafe { libc::raise(signal) };
    }

    #[cfg(test)]
    pub fn reset_for_test() {
        RECEIVED.store(false, Ordering::SeqCst);
    }
}

#[cfg(not(unix))]
mod imp {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    pub fn install(_stop: Arc<AtomicBool>) {}

    pub fn received() -> bool {
        false
    }
}

pub use imp::{install, received};

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // The handler and its state are process-wide, so one test walks through
    // the whole life of them rather than several racing over it.
    #[test]
    fn a_signal_sets_the_stop_flag_and_is_remembered() {
        let stop = Arc::new(AtomicBool::new(false));
        install(Arc::clone(&stop));
        assert!(!stop.load(Ordering::SeqCst) && !received());

        imp::raise(libc::SIGTERM);

        assert!(stop.load(Ordering::SeqCst), "the client is asked to stop");
        assert!(received(), "and main can tell it was a signal, not a user quitting the dashboard");
        imp::reset_for_test(); // so a later test's signal is a first signal too

        stop.store(false, Ordering::SeqCst);
        imp::raise(libc::SIGINT);
        assert!(stop.load(Ordering::SeqCst), "SIGINT does the same");
        imp::reset_for_test();
    }
}
