//! Sync-over-async bridging for the [`Store`](super::Store) implementations that talk to a network
//! service.
//!
//! The `Store` trait is synchronous and the gateway runs inside a Tokio runtime, so an async driver
//! has to be driven from a sync call without starting a nested runtime. Getting either primitive
//! wrong wedged the hosted worker once already (a store call that parked a runtime worker
//! instead of donating it deadlocked on one vCPU), so they live here as one implementation for
//! every store that needs them.

use tokio::runtime::{Handle, RuntimeFlavor};

/// Run a future to completion from a synchronous context inside the Tokio runtime. `block_in_place`
/// donates this worker (the runtime spins up a replacement) so `block_on` can drive the future:
/// the canonical sync-over-async bridge on the multi-threaded runtime.
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    blocking_section(|| Handle::current().block_on(fut))
}

/// Run `f` with this thread released from the runtime's worker pool.
///
/// Anything that parks a runtime worker without donating it (waiting on a `std::sync::Mutex`, an
/// upload, a `VACUUM`) removes a thread the in-flight work needs to finish, which is how one vCPU
/// and two concurrent callers deadlocked the hosted worker before. Outside a multi-threaded runtime
/// there is no worker to donate and `block_in_place` would panic, so the closure just runs.
pub(crate) fn blocking_section<R>(f: impl FnOnce() -> R) -> R {
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Take `m`, giving this runtime worker back first when another thread holds it.
///
/// The holder may be waiting on something only a runtime worker can finish (a store upload, a generation check), and a waiter parked on a `std::sync::Mutex` without donating takes away the worker that would finish it: on one vCPU that is the whole runtime.
pub(crate) fn lock_donating<T>(m: &std::sync::Mutex<T>) -> std::sync::LockResult<std::sync::MutexGuard<'_, T>> {
    match m.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::Poisoned(p)) => Err(p),
        Err(std::sync::TryLockError::WouldBlock) => blocking_section(|| m.lock()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The narrow property behind that wedge, pinned on the primitive rather than on a store.
    ///
    /// `store::persisted::tests::concurrent_callers_outnumbering_worker_threads_do_not_wedge` covers
    /// the same regression through `PersistedSqliteStore`, but only because the object-store double
    /// it uses bridges back into async: remove the donation and that test fails on the nested
    /// `block_on` rather than on the donation itself. This one fails on exactly the thing that
    /// changed, on one worker, which is the configuration a 1 vCPU hosted worker runs.
    ///
    /// Stated as a property here rather than as a `cfg(test)` switch inside `blocking_section`,
    /// because a switch would be process-wide and this suite runs in parallel: one test's
    /// deliberately broken bridge would be every other test's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_blocking_section_donates_its_worker_so_other_tasks_still_run() {
        // Both halves are spawned, and that is load-bearing: `#[tokio::test]` drives the test body
        // on the CALLING thread through `Runtime::block_on`, not on a worker, so a blocking section
        // written inline here would block a thread the runtime was not using and would pass whether
        // it donated or not.
        let blocked = tokio::spawn(async {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            // Queued, not run: the task holding the only worker is this one, until it blocks below.
            tokio::spawn(async move {
                let _ = tx.send(());
            });
            // Donated, the runtime spins up a replacement worker and the task above is polled.
            // Parked, the only worker is gone, nothing else is ever polled, and this waits out the
            // full timeout: that is the wedge, in miniature.
            blocking_section(|| rx.recv_timeout(std::time::Duration::from_secs(10)))
        })
        .await
        .expect("the blocking task joins");
        assert!(
            blocked.is_ok(),
            "the spawned task was never polled, so the worker was parked rather than donated"
        );
    }

    /// On a current-thread runtime there is no worker to donate and `block_in_place` would panic, so
    /// the closure has to run in place. Every unit test that opens a store without a multi-threaded
    /// runtime depends on this arm.
    #[tokio::test(flavor = "current_thread")]
    async fn a_blocking_section_runs_in_place_where_there_is_nothing_to_donate() {
        assert_eq!(blocking_section(|| 7), 7);
    }
}
