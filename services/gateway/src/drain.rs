//! Stopping without stranding an execution, and settling the ones a previous process stranded.
//!
//! Two halves of one rule: every execution that began ends with a terminal audit event, and every
//! approval whose execution began ends in a status a client can read.
//!
//! **The drain.** On SIGTERM, SIGHUP, an interrupt or an authenticated `POST /v1/shutdown`, the gateway stops
//! admitting executions, lets the ones already running finish inside [`DRAIN_WINDOW`], gives the
//! store one bounded chance to carry a commit its last upload left behind, and exits. Refusing a new
//! execution happens before its approval claim and before its `attempt`, so a refused approve is
//! still pending and a refused invoke wrote nothing.
//!
//! **The settlement.** Anything still running at the deadline, and anything a crash, a `SIGKILL` or a
//! replaced Cloud Run instance cut off, is found on the next boot by
//! [`EnforcementService::settle_interrupted_approvals`]: an approval whose execution recorded an
//! `attempt` and never a terminal event is closed with an `error` whose outcome is `unknown`, and
//! the row moves to [`crate::store::APPROVAL_UNRESOLVED`], the state every client knows how to
//! render. Nothing is run again: the claim stays spent. A plain call cut off the same way is closed by
//! [`EnforcementService::settle_interrupted_invokes`] and charged to its grant.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{watch, Notify};
use tokio::time::Instant;

use crate::error::GatewayError;
use crate::service::EnforcementService;

/// How long a stopping gateway gives in-flight requests and executions to finish.
///
/// Cloud Run sends `SIGKILL` 10 seconds after `SIGTERM`. Eight seconds for the work leaves two for
/// the final upload of anything a refused upload left pending and for the process to exit. It covers
/// an ordinary execution (a load test measured p95 at 1.2 s, and 4 s while Cloud Storage was refusing writes)
/// but not a slow upstream at its 30 second connector ceiling; whatever is still running at the
/// deadline is settled by the next boot rather than waited for.
pub const DRAIN_WINDOW: Duration = Duration::from_secs(8);

/// The most the final carry of a pending store commit may add after [`DRAIN_WINDOW`].
pub const CARRY_BUDGET: Duration = Duration::from_millis(1500);

/// When the first settlement pass runs, counted from the moment this process bound its address.
///
/// A predecessor that was asked to stop gives its address up as its drain begins and can go on
/// executing for up to [`DRAIN_WINDOW`] after that, against the same store. Waiting here does not
/// make its late endings visible: a store process reads its chain once, at open. On a self-run store
/// what does is the store lock ([`crate::store::lock`]): this process did not open the store until the
/// predecessor had exited, so its chain already holds every ending the predecessor recorded. A hosted
/// worker has [`interrupted_min_age`] instead. The wait is kept as margin.
pub const SETTLE_AFTER_BOOT: Duration = Duration::from_secs(DRAIN_WINDOW.as_secs() + 2);

/// What a refused caller is told to wait: a stopping gateway is gone or back within about this long.
pub const DRAINING_RETRY_AFTER_SECS: u64 = 10;

/// The admission reason a draining gateway refuses with, beside the limits' `rate`, `queue` and `busy`.
pub const DRAINING_REASON: &str = "draining";

/// The refusal a new execution meets once the drain has begun.
///
/// A 429 with `Retry-After` rather than a new status, because every client already reads that as
/// "busy, try again at this time", which is exactly what a restarting gateway is. It is raised before
/// any audit event or claim exists, the contract every 429 here keeps.
pub fn draining_refusal() -> GatewayError {
    GatewayError::TooManyRequests {
        reason: DRAINING_REASON.into(),
        message: "this gateway is shutting down and is finishing the calls already running; nothing was run, so try again once it is back".into(),
        retry_after_secs: DRAINING_RETRY_AFTER_SECS,
        scope: None,
    }
}

/// The executions this process has admitted and not yet finished, and whether it still admits any.
#[derive(Debug)]
pub struct Executions {
    state: Mutex<State>,
    running: watch::Sender<usize>,
}

#[derive(Debug, Default)]
struct State {
    draining: bool,
    running: usize,
    /// Approvals whose resolution this process is running now, with how many resolutions of each are
    /// admitted: a second approve of one already running is admitted until its claim refuses it, and
    /// its end must not take the first off this list. The settlement skips them: their `attempt` has no
    /// terminal event yet because they have not ended, not because they were cut off.
    approvals: HashMap<String, usize>,
}

impl Default for Executions {
    fn default() -> Self {
        Executions { state: Mutex::new(State::default()), running: watch::Sender::new(0) }
    }
}

impl Executions {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding this lock leaves counts that are still the best answer there is, and
        // refusing every later execution over a poisoned lock would turn one panic into an outage.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Admit one execution, or refuse it because the drain has begun. The permit is held until the
    /// execution has recorded its terminal event and settled its row, and dropping it is the release.
    pub fn admit(self: &Arc<Self>, approval: Option<&str>) -> Result<ExecutionPermit, GatewayError> {
        let mut state = self.lock();
        if state.draining {
            return Err(draining_refusal());
        }
        state.running += 1;
        if let Some(id) = approval {
            *state.approvals.entry(id.to_string()).or_default() += 1;
        }
        self.running.send_replace(state.running);
        Ok(ExecutionPermit { executions: self.clone(), approval: approval.map(str::to_string) })
    }

    /// Stop admitting. Returns how many executions were running at that moment.
    pub fn begin_drain(&self) -> usize {
        let mut state = self.lock();
        state.draining = true;
        state.running
    }

    /// Whether the drain has begun.
    pub fn is_draining(&self) -> bool {
        self.lock().draining
    }

    /// How many admitted executions have not finished.
    pub fn running(&self) -> usize {
        self.lock().running
    }

    /// The approvals this process is resolving now.
    pub fn in_flight_approvals(&self) -> HashSet<String> {
        self.lock().approvals.keys().cloned().collect()
    }

    /// Whether this process is resolving approval `id` now.
    pub fn is_resolving(&self, id: &str) -> bool {
        self.lock().approvals.contains_key(id)
    }

    /// Wait until nothing is running, or `deadline`. `true` when nothing was left running.
    pub async fn idle_by(&self, deadline: Instant) -> bool {
        let mut running = self.running.subscribe();
        // The `Ref` the wait returns holds the value's read lock, which a finishing permit needs to
        // write, so it is dropped inside this statement.
        let idle = matches!(tokio::time::timeout_at(deadline, running.wait_for(|n| *n == 0)).await, Ok(Ok(_)));
        idle
    }
}

/// One admitted execution. See [`Executions::admit`].
#[derive(Debug)]
pub struct ExecutionPermit {
    executions: Arc<Executions>,
    approval: Option<String>,
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        let mut state = self.executions.lock();
        state.running = state.running.saturating_sub(1);
        if let Some(id) = &self.approval {
            if let Some(admitted) = state.approvals.get_mut(id) {
                *admitted -= 1;
                if *admitted == 0 {
                    state.approvals.remove(id);
                }
            }
        }
        self.executions.running.send_replace(state.running);
    }
}

/// Resolve when this process is asked to stop, naming what asked: `POST /v1/shutdown` (`requested`),
/// an interrupt, or on Unix `SIGTERM` or `SIGHUP`.
///
/// The `SIGTERM` handler is installed here, when this is called, rather than when the future is
/// first polled, so a signal that arrives before the server starts polling is still caught. Without a
/// handler the default action kills the process, and as PID 1 in a container the default is to
/// ignore it until Cloud Run's `SIGKILL`; either way nothing drained.
pub fn stop_requested(requested: Arc<Notify>) -> impl Future<Output = &'static str> + Send + 'static {
    #[cfg(unix)]
    let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(signal) => Some(signal),
        Err(e) => {
            tracing::warn!(error = %e, "could not install a SIGTERM handler; SIGTERM will stop this gateway without draining");
            None
        }
    };
    #[cfg(unix)]
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    async move {
        #[cfg(unix)]
        let hung_up = async move {
            match hangup.as_mut() {
                Some(signal) => { signal.recv().await; }
                None => std::future::pending::<()>().await,
            }
        };
        #[cfg(not(unix))]
        let hung_up = std::future::pending::<()>();
        #[cfg(unix)]
        let terminated = async move {
            match terminate.as_mut() {
                Some(signal) => {
                    signal.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        #[cfg(not(unix))]
        let terminated = std::future::pending::<()>();
        tokio::select! {
            _ = requested.notified() => "graceful shutdown requested",
            _ = tokio::signal::ctrl_c() => "interrupt received",
            _ = terminated => "SIGTERM received",
            _ = hung_up => "SIGHUP received",
        }
    }
}

/// What a drain managed before it returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drained {
    /// What asked this process to stop.
    pub reason: &'static str,
    /// Every open request finished inside the window.
    pub requests_finished: bool,
    /// Every admitted execution finished inside the window, terminal event and row included.
    pub executions_finished: bool,
    /// Executions still running when the window closed. The next boot settles any approval among them.
    pub still_running: usize,
    /// Nothing the store committed is waiting on an upload. Always `true` on a store that uploads nothing.
    pub store_carried: bool,
}

/// Serve `app` on `listener` until `stop` resolves, then drain within `window` and return.
///
/// The order is the point. The service stops admitting executions first, so nothing new starts while
/// the rest winds down. Open requests then finish, which is how an approve whose approver is still
/// waiting gets its answer. Executions detached from their request (a caller that hung up) are
/// waited for next, because a request finishing is not an execution finishing. Last, a commit a
/// refused upload left behind gets one bounded chance to be carried, because a terminal event that
/// exists only on this instance is lost with it. Everything shares one deadline.
pub async fn serve_until_stopped<S>(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    service: Arc<EnforcementService>,
    stop: S,
    window: Duration,
) -> std::io::Result<Drained>
where
    S: Future<Output = &'static str> + Send + 'static,
{
    let (began_tx, began_rx) = tokio::sync::oneshot::channel::<(Instant, &'static str)>();
    let draining = service.clone();
    let serve = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            let reason = stop.await;
            let running = draining.begin_drain();
            tracing::info!(running, window_ms = window.as_millis() as u64, "{reason}: draining");
            let _ = began_tx.send((Instant::now(), reason));
        });
    let mut serve = std::pin::pin!(std::future::IntoFuture::into_future(serve));
    let mut began_rx = began_rx;

    let (began, reason, mut requests_finished) = tokio::select! {
        served = &mut serve => {
            served?;
            // The server only returns once the shutdown signal has fired and every connection has
            // closed, so the drain has begun and the requests are done.
            let (at, reason) = began_rx.try_recv().unwrap_or((Instant::now(), "server stopped"));
            (at, reason, true)
        }
        began = &mut began_rx => {
            let (at, reason) = began.unwrap_or((Instant::now(), "server stopped"));
            (at, reason, false)
        }
    };
    let deadline = began + window;
    if !requests_finished {
        requests_finished = match tokio::time::timeout_at(deadline, &mut serve).await {
            Ok(served) => {
                served?;
                true
            }
            Err(_) => false,
        };
    }
    let executions_finished = service.executions().idle_by(deadline).await;
    let still_running = service.executions().running();
    if !requests_finished || !executions_finished {
        tracing::warn!(
            still_running,
            requests_finished,
            "the drain window closed with work still running; the next boot settles any approval it leaves unfinished"
        );
    }

    let store = service.store().clone();
    let carry = tokio::spawn(async move { store.carry_before_exit() });
    let store_carried = match tokio::time::timeout(CARRY_BUDGET, carry).await {
        Ok(Ok(Ok(carried))) => carried,
        Ok(Ok(Err(e))) => {
            tracing::warn!(error = %e, "a store commit could not be carried before exit");
            false
        }
        Ok(Err(_)) | Err(_) => false,
    };
    if !store_carried {
        tracing::warn!("exiting with a store commit not yet uploaded; anything it held is settled by the next boot");
    }
    tracing::info!(reason, still_running, store_carried, "drain finished");
    Ok(Drained { reason, requests_finished, executions_finished, still_running, store_carried })
}

/// The youngest an interrupted execution's `attempt` may be before it is settled.
///
/// Zero on a gateway its owner runs, where [`SETTLE_AFTER_BOOT`] already outlasts any predecessor.
/// A hosted worker has one more case: Cloud Run keeps the previous instance serving through a
/// rollout, so an execution in the restored snapshot may still be running there. Nothing runs past
/// the execution ceiling, and its fence upload can stall before it starts, so an attempt older than
/// both can only belong to an instance that is gone. When the ceiling is switched off, the ten
/// minutes `PERMAURA_LIMIT_EXECUTION_MS` cannot be set above stands in for it.
pub fn interrupted_min_age(hosted: bool) -> Duration {
    if !hosted {
        return Duration::ZERO;
    }
    let ceiling = crate::limits::execution_budget().unwrap_or(Duration::from_secs(600));
    ceiling + Duration::from_secs(30)
}

/// Settle what an earlier process left interrupted, once [`SETTLE_AFTER_BOOT`] has passed, and again
/// for any execution that was too recent to settle on the first pass.
///
/// Started by `permaura start` once the listener is bound, so a second `permaura start` that loses
/// the bind never touches a live gateway's executions. Before it returns, and so before the gateway
/// serves a request, it holds the grant budget of every execution it will settle
/// ([`EnforcementService::carry_interrupted_budget`]), and each pass gives back what it charged.
pub fn spawn_interrupted_settlement(
    service: Arc<EnforcementService>,
    hosted: bool,
) -> tokio::task::JoinHandle<()> {
    // Read before this process serves anything, so every event below it was recorded by another.
    let recorded_before = match service.store().audit_events(Some(1)) {
        Ok(last) => last.last().map_or(0, |event| event.seq + 1),
        Err(e) => {
            tracing::warn!(error = %e, "could not read the audit head at boot; interrupted approvals are settled by a later boot");
            0
        }
    };
    match service.carry_interrupted_budget(recorded_before) {
        Ok(0) => {}
        Ok(n) => tracing::warn!(executions = n, "holding the grant budget of calls an earlier gateway process left unfinished until they are settled"),
        Err(e) => tracing::warn!(error = %e, "could not read which calls an earlier gateway process left unfinished; their budget is charged when they are settled"),
    }
    tokio::spawn(async move {
        tokio::time::sleep(SETTLE_AFTER_BOOT).await;
        let min_age = interrupted_min_age(hosted);
        // Bounded so a store that keeps refusing cannot keep a task alive for the life of the process;
        // the next boot tries again from the start.
        for _ in 0..8 {
            let settled = service.settle_interrupted_approvals(min_age, recorded_before).and_then(|mut report| {
                let invokes = service.settle_interrupted_invokes(min_age, recorded_before)?;
                report.invokes = invokes.invokes;
                report.deferred += invokes.deferred;
                report.retry_in = match (report.retry_in, invokes.retry_in) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                Ok(report)
            });
            if settled.is_ok() {
                if let Err(e) = service.release_settled_budget(recorded_before) {
                    tracing::warn!(error = %e, "could not release the budget held for settled calls; it is held until the next pass");
                }
            }
            let wait = match settled {
                Ok(report) => {
                    if !report.interrupted.is_empty() || !report.reconciled.is_empty() {
                        tracing::warn!(
                            interrupted = ?report.interrupted,
                            reconciled = ?report.reconciled,
                            "settled approvals an earlier gateway process left unfinished: each is unresolved, its outcome unknown, and nothing was run again"
                        );
                    }
                    if !report.invokes.is_empty() {
                        tracing::warn!(
                            executions = ?report.invokes,
                            "settled calls an earlier gateway process left unfinished: each is recorded with its outcome unknown and charged to its grant, and nothing was run again"
                        );
                    }
                    match report.retry_in {
                        Some(wait) => wait + Duration::from_secs(1),
                        None => return,
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not settle interrupted executions; retrying");
                    Duration::from_secs(30)
                }
            };
            tokio::time::sleep(wait).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second approve of an approval already running is admitted until its claim refuses it, and its end leaves the first on the list the settlement and the approver's rendering read.
    #[test]
    fn a_second_resolution_ending_leaves_the_first_in_flight() {
        let executions = Arc::new(Executions::default());
        let first = executions.admit(Some("appr_1")).unwrap();
        let second = executions.admit(Some("appr_1")).unwrap();
        drop(second);
        assert!(executions.is_resolving("appr_1"));
        assert!(executions.in_flight_approvals().contains("appr_1"));
        drop(first);
        assert!(!executions.is_resolving("appr_1"));
        assert!(executions.in_flight_approvals().is_empty());
        assert_eq!(executions.running(), 0);
    }
}
