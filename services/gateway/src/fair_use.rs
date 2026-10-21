//! The monthly fair-use ceiling on a hosted worker.
//!
//! Agents and calls are never billed. Every mutating request on a hosted worker uploads a snapshot of the store to its bucket, so that is what this counts: requests that changed at least one row, per calendar month in UTC.
//! That includes a read whose bearer's session row was touched, which `authenticate` does at most once a minute per session.
//! Past the soft threshold the worker says so; past the hard one [`crate::limits`] lowers the worker-wide rate for the rest of the month, and a request above that rate gets a 429.
//! Nothing is deleted, nothing is charged, and on the first of the month the counter starts again without anyone doing anything.
//!
//! **The counter costs no upload.** It is a `gateway_meta` row written just before the snapshot a
//! counted request uploads anyway ([`crate::store::SnapshotMeter`]), so it survives a cold start and a
//! new revision, and a ceiling that exists to bound snapshot uploads never adds one. Only the persisted
//! store uploads snapshots, so only it counts: a gateway with no bucket has nothing this bounds.
//!
//! **The worker never emails anyone.** It announces a change of state to the control plane
//! ([`crate::announce`]) at a moment it is awake anyway, and permaura.com sends the mail. Asking every
//! worker instead would keep a scale-to-zero fleet permanently warm.

use std::cell::Cell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::store::{SnapshotMeter, Store};
use crate::AppState;

/// The page the pricing page, the terms and every worker-wide 429 point at. One URL, so the numbers
/// are published in exactly one place.
pub const DOCS_URL: &str = "https://docs.permaura.com/billing/rate-limits";

/// The `gateway_meta` key the month's count is kept under, as `{"month":"YYYY-MM","mutating_calls":N}`.
pub const META_KEY: &str = "fair_use";

/// Mutating calls in a month before the worker reports `warned` (250,000).
pub const DEFAULT_SOFT_CALLS: u64 = 250_000;

/// Mutating calls in a month before the worker throttles itself (500,000). Past it the worker-wide
/// rate is [`DEFAULT_THROTTLED_RATE_PER_MIN`] until the month ends.
pub const DEFAULT_HARD_CALLS: u64 = 500_000;

/// The worker-wide sustained rate for the rest of a month once the hard threshold is crossed. Below the
/// hosted worker rate (30 a minute), so a throttled worker is slower than a normal one.
pub const DEFAULT_THROTTLED_RATE_PER_MIN: u32 = 10;

/// How often a worker in `warned` or `throttled` re-announces while it is busy, so a lost announcement
/// or a fresh instance is corrected within the hour rather than never.
const REANNOUNCE_INTERVAL: Duration = Duration::from_secs(3600);

/// The ceiling's numbers, resolved once at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairUseConfig {
    /// Counting at all. Only a hosted worker counts: a self-run gateway is the customer's own machine,
    /// and the ceiling does not apply to it.
    pub active: bool,
    /// `PERMAURA_FAIRUSE_DISABLED`: Enterprise. Still counted and reported, never throttled.
    pub disabled: bool,
    /// `PERMAURA_FAIRUSE_SOFT_CALLS`.
    pub soft_calls: u64,
    /// `PERMAURA_FAIRUSE_HARD_CALLS`.
    pub hard_calls: u64,
    /// `PERMAURA_FAIRUSE_THROTTLED_RATE_PER_MIN`.
    pub throttled_rate_per_min: u32,
}

impl Default for FairUseConfig {
    fn default() -> Self {
        FairUseConfig {
            active: false,
            disabled: false,
            soft_calls: DEFAULT_SOFT_CALLS,
            hard_calls: DEFAULT_HARD_CALLS,
            throttled_rate_per_min: DEFAULT_THROTTLED_RATE_PER_MIN,
        }
    }
}

impl FairUseConfig {
    /// Read the environment. Unparseable values fall back to the default and out-of-range ones are
    /// clamped, as in [`crate::limits::LimitsConfig::from_env`]; a soft threshold above the hard one is
    /// pulled down to it, so the worker is never throttled without having warned first.
    pub fn from_env(hosted: bool) -> Self {
        let num = |var: &str, default: u64| -> u64 {
            std::env::var(var).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
        };
        let hard = num("PERMAURA_FAIRUSE_HARD_CALLS", DEFAULT_HARD_CALLS).clamp(1, 1_000_000_000_000);
        let soft = num("PERMAURA_FAIRUSE_SOFT_CALLS", DEFAULT_SOFT_CALLS).clamp(1, hard);
        let throttled = num(
            "PERMAURA_FAIRUSE_THROTTLED_RATE_PER_MIN",
            DEFAULT_THROTTLED_RATE_PER_MIN as u64,
        )
        .clamp(1, 60_000) as u32;
        FairUseConfig {
            active: hosted,
            disabled: std::env::var("PERMAURA_FAIRUSE_DISABLED")
                .map(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            soft_calls: soft,
            hard_calls: hard,
            throttled_rate_per_min: throttled,
        }
    }
}

/// Where a worker stands this month. The label is a wire format: the control plane stores it and
/// mails on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairUseState {
    /// Under the soft threshold.
    Ok,
    /// Past the soft threshold. Nothing changes except that the owner is told.
    Warned,
    /// Past the hard threshold: the worker-wide rate is the throttled rate until the month ends.
    Throttled,
    /// The ceiling is off for this worker (Enterprise).
    Disabled,
}

impl FairUseState {
    /// The stable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            FairUseState::Ok => "ok",
            FairUseState::Warned => "warned",
            FairUseState::Throttled => "throttled",
            FairUseState::Disabled => "disabled",
        }
    }
}

/// A calendar month in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Month {
    year: i32,
    month: u8,
}

impl Month {
    /// The UTC month containing a unix timestamp in seconds.
    pub fn from_unix(secs: i64) -> Self {
        let at = time::OffsetDateTime::from_unix_timestamp(secs)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        Month { year: at.year(), month: at.month() as u8 }
    }

    /// Parse `YYYY-MM`.
    pub fn parse(value: &str) -> Option<Self> {
        let (year, month) = value.split_once('-')?;
        let (year, month) = (year.parse().ok()?, month.parse().ok()?);
        (year > 0 && (1..=12).contains(&month) && value.len() == 7).then_some(Month { year, month })
    }
}

impl std::fmt::Display for Month {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}", self.year, self.month)
    }
}

/// What the worker reports about the month, on `/health` and in an announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The month being counted.
    pub month: Month,
    /// Mutating calls so far this month.
    pub mutating_calls: u64,
    /// The soft threshold.
    pub soft: u64,
    /// The hard threshold.
    pub hard: u64,
    /// Where that leaves the worker.
    pub state: FairUseState,
    /// The worker-wide rate once throttled.
    pub throttled_rate_per_min: u32,
}

impl Report {
    /// The `fair_use` block of `/health`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "month": self.month.to_string(),
            "mutating_calls": self.mutating_calls,
            "soft": self.soft,
            "hard": self.hard,
            "state": self.state.as_str(),
            "throttled_rate_per_min": self.throttled_rate_per_min,
        })
    }
}

struct Counter {
    month: Month,
    calls: u64,
    /// What the `gateway_meta` row last said, so a snapshot only carries a write when it changed.
    stamped: Option<(Month, u64)>,
    /// The last state announced by this process, and when.
    announced: Option<(Month, FairUseState, Instant)>,
    /// An announcement is owed; the request scope sends it once the response exists.
    due: bool,
}

/// The ceiling itself: one per process, shared by the store (which counts), the limiter (which
/// throttles) and `/health` (which reports).
pub struct FairUse {
    config: FairUseConfig,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
    counter: Mutex<Counter>,
}

impl std::fmt::Debug for FairUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FairUse").field("config", &self.config).finish_non_exhaustive()
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl FairUse {
    /// A ceiling over a configuration, on the wall clock.
    pub fn new(config: FairUseConfig) -> Self {
        Self::with_clock(config, unix_now)
    }

    /// A ceiling on a supplied clock (unix seconds), so a test can cross a month boundary.
    pub fn with_clock(config: FairUseConfig, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        let month = Month::from_unix(clock());
        FairUse {
            config,
            clock: Box::new(clock),
            counter: Mutex::new(Counter { month, calls: 0, stamped: None, announced: None, due: false }),
        }
    }

    /// The ceiling a gateway assembled from the environment gets.
    pub fn from_env(hosted: bool) -> Self {
        Self::new(FairUseConfig::from_env(hosted))
    }

    /// The resolved configuration.
    pub fn config(&self) -> &FairUseConfig {
        &self.config
    }

    /// Whether this process counts at all.
    pub fn is_active(&self) -> bool {
        self.config.active
    }

    /// Pick up the month's count from the store and have the store carry it from now on.
    ///
    /// A no-op on a gateway that is not hosted. A count from an earlier month is left behind, which is
    /// the whole of the monthly reset: nothing has to run on the first. A row that cannot be read or
    /// parsed starts the month at zero and says so, because refusing to boot over a usage ceiling would be
    /// a worse failure than forgiving one month.
    pub fn attach(self: &Arc<Self>, store: &dyn Store) {
        if !self.config.active {
            return;
        }
        match store.get_meta(META_KEY) {
            Ok(Some(raw)) => match parse_stamp(&raw) {
                Some((month, calls)) => {
                    let mut c = self.lock();
                    if month == c.month {
                        c.calls = calls;
                    }
                    c.stamped = Some((month, calls));
                }
                None => tracing::warn!("the stored fair-use counter is unreadable; counting this month from zero"),
            },
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "could not read the fair-use counter; counting this month from zero"),
        }
        let meter: Arc<dyn SnapshotMeter> = self.clone();
        if !store.attach_meter(meter) {
            tracing::warn!(
                store = store.kind(),
                "this store uploads no snapshots, so the fair-use ceiling has nothing to count"
            );
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Counter> {
        let mut c = self.counter.lock().unwrap_or_else(|p| p.into_inner());
        let now = Month::from_unix((self.clock)());
        if now != c.month {
            c.month = now;
            c.calls = 0;
        }
        c
    }

    fn state_of(&self, calls: u64) -> FairUseState {
        if self.config.disabled {
            FairUseState::Disabled
        } else if calls >= self.config.hard_calls {
            FairUseState::Throttled
        } else if calls >= self.config.soft_calls {
            FairUseState::Warned
        } else {
            FairUseState::Ok
        }
    }

    fn report_from(&self, c: &Counter) -> Report {
        Report {
            month: c.month,
            mutating_calls: c.calls,
            soft: self.config.soft_calls,
            hard: self.config.hard_calls,
            state: self.state_of(c.calls),
            throttled_rate_per_min: self.config.throttled_rate_per_min,
        }
    }

    /// Count one mutating request and decide whether the control plane needs telling.
    fn record(&self) {
        let mut c = self.lock();
        c.calls = c.calls.saturating_add(1);
        let state = self.state_of(c.calls);
        let month = c.month;
        let owed = match (state, c.announced) {
            (FairUseState::Disabled, _) => false,
            (FairUseState::Ok, None) => false,
            (_, None) => true,
            (state, Some((m, s, at))) if (m, s) == (month, state) => {
                state != FairUseState::Ok && at.elapsed() >= REANNOUNCE_INTERVAL
            }
            (FairUseState::Ok, Some((_, s, _))) => s != FairUseState::Ok,
            _ => true,
        };
        if owed {
            c.announced = Some((month, state, Instant::now()));
            c.due = true;
        }
    }

    /// This month so far.
    pub fn report(&self) -> Report {
        let c = self.lock();
        self.report_from(&c)
    }

    /// Whether the worker-wide rate is the throttled one right now.
    pub fn throttled(&self) -> bool {
        self.config.active && self.report().state == FairUseState::Throttled
    }

    /// The `fair_use` block of `/health`: `null` on a gateway that does not count.
    pub fn health(&self) -> serde_json::Value {
        if !self.config.active {
            return serde_json::Value::Null;
        }
        self.report().to_json()
    }

    /// The announcement owed, if any, taken so it is sent once.
    pub fn take_announcement(&self) -> Option<Report> {
        let mut c = self.lock();
        if !std::mem::take(&mut c.due) {
            return None;
        }
        Some(self.report_from(&c))
    }
}

fn parse_stamp(raw: &str) -> Option<(Month, u64)> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    Some((Month::parse(v.get("month")?.as_str()?)?, v.get("mutating_calls")?.as_u64()?))
}

impl SnapshotMeter for FairUse {
    fn note_mutation(&self) {
        if self.config.active && claim_request() {
            self.record();
        }
    }

    fn pending_stamp(&self) -> Option<(&'static str, String)> {
        if !self.config.active {
            return None;
        }
        let c = self.lock();
        if c.stamped == Some((c.month, c.calls)) {
            return None;
        }
        let value = serde_json::json!({ "month": c.month.to_string(), "mutating_calls": c.calls });
        Some((META_KEY, value.to_string()))
    }

    fn stamped(&self, value: &str) {
        if let Some(stamp) = parse_stamp(value) {
            self.counter.lock().unwrap_or_else(|p| p.into_inner()).stamped = Some(stamp);
        }
    }
}

tokio::task_local! {
    /// Whether the request running on this task has already been counted.
    static REQUEST: Cell<bool>;
}

/// Claim the current request for counting: true exactly once per request, and never outside one.
///
/// Outside a request (a boot-time reconcile, a background archive pass) nothing is counted, because
/// the ceiling is about what callers make the worker do.
fn claim_request() -> bool {
    REQUEST.try_with(|counted| !counted.replace(true)).unwrap_or(false)
}

/// Run `f` as though it were one request, for tests that drive a store directly.
#[cfg(test)]
pub(crate) fn in_request<R>(f: impl FnOnce() -> R) -> R {
    REQUEST.sync_scope(Cell::new(false), f)
}

/// The async form of [`in_request`], the shape [`scope_request`] runs a handler in.
#[cfg(all(test, feature = "sqlite"))]
pub(crate) async fn in_request_async<F: std::future::Future>(f: F) -> F::Output {
    REQUEST.scope(Cell::new(false), f).await
}

/// The per-request scope every route runs inside.
///
/// It makes a request countable (the persisted store reaches the task-local through its
/// `block_in_place`, which runs on this same task) and, once the response exists, sends any
/// announcement the request made owed. Detached and best-effort like every announcement: the ceiling
/// is enforced here whether or not permaura.com hears about it.
pub async fn scope_request(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let response = REQUEST.scope(Cell::new(false), next.run(req)).await;
    if let Some(report) = state.fair_use.take_announcement() {
        let links = state.service.announce_links();
        if !links.is_empty() {
            tokio::spawn(crate::announce::announce_fair_use(links, report));
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    // 2026-09-30T23:59:00Z and a minute later.
    const END_OF_SEPTEMBER: i64 = 1_790_812_740;
    const START_OF_OCTOBER: i64 = END_OF_SEPTEMBER + 60;

    fn cfg(soft: u64, hard: u64) -> FairUseConfig {
        FairUseConfig { active: true, disabled: false, soft_calls: soft, hard_calls: hard, throttled_rate_per_min: 60 }
    }

    fn at(clock: &Arc<AtomicI64>, config: FairUseConfig) -> Arc<FairUse> {
        let clock = clock.clone();
        Arc::new(FairUse::with_clock(config, move || clock.load(Ordering::SeqCst)))
    }

    fn requests(fu: &FairUse, n: u64) {
        for _ in 0..n {
            in_request(|| fu.note_mutation());
        }
    }

    #[test]
    fn the_month_is_the_utc_calendar_month() {
        assert_eq!(Month::from_unix(END_OF_SEPTEMBER).to_string(), "2026-09");
        assert_eq!(Month::from_unix(START_OF_OCTOBER).to_string(), "2026-10");
        assert_eq!(Month::parse("2026-09"), Some(Month::from_unix(END_OF_SEPTEMBER)));
        assert_eq!(Month::parse("2026-13"), None);
        assert_eq!(Month::parse("2026-9"), None);
    }

    #[test]
    fn the_state_follows_the_thresholds() {
        let clock = Arc::new(AtomicI64::new(END_OF_SEPTEMBER));
        let fu = at(&clock, cfg(3, 5));
        requests(&fu, 2);
        assert_eq!(fu.report().state, FairUseState::Ok);
        requests(&fu, 1);
        assert_eq!(fu.report().state, FairUseState::Warned);
        assert!(!fu.throttled(), "warned changes nothing");
        requests(&fu, 2);
        assert_eq!(fu.report().state, FairUseState::Throttled);
        assert!(fu.throttled());
    }

    #[test]
    fn a_request_counts_once_however_many_writes_it_makes() {
        let clock = Arc::new(AtomicI64::new(END_OF_SEPTEMBER));
        let fu = at(&clock, cfg(10, 20));
        in_request(|| {
            fu.note_mutation();
            fu.note_mutation();
            fu.note_mutation();
        });
        assert_eq!(fu.report().mutating_calls, 1);
    }

    #[test]
    fn nothing_outside_a_request_is_counted() {
        let clock = Arc::new(AtomicI64::new(END_OF_SEPTEMBER));
        let fu = at(&clock, cfg(10, 20));
        fu.note_mutation();
        assert_eq!(fu.report().mutating_calls, 0);
    }

    #[test]
    fn the_month_rollover_resets_the_count_and_lifts_the_throttle() {
        let clock = Arc::new(AtomicI64::new(END_OF_SEPTEMBER));
        let fu = at(&clock, cfg(1, 2));
        requests(&fu, 2);
        assert!(fu.throttled());
        clock.store(START_OF_OCTOBER, Ordering::SeqCst);
        let report = fu.report();
        assert_eq!(report.month.to_string(), "2026-10");
        assert_eq!(report.mutating_calls, 0);
        assert_eq!(report.state, FairUseState::Ok);
        assert!(!fu.throttled(), "the first of the month lifts the throttle with nothing else happening");
    }

    #[test]
    fn disabled_is_counted_but_never_throttled() {
        let clock = Arc::new(AtomicI64::new(END_OF_SEPTEMBER));
        let fu = at(&clock, FairUseConfig { disabled: true, ..cfg(1, 2) });
        requests(&fu, 10);
        let report = fu.report();
        assert_eq!(report.mutating_calls, 10);
        assert_eq!(report.state, FairUseState::Disabled);
        assert!(!fu.throttled());
        assert!(fu.take_announcement().is_none(), "there is nothing to tell anyone");
    }

    #[test]
    fn a_gateway_that_is_not_hosted_neither_counts_nor_reports() {
        let clock = Arc::new(AtomicI64::new(END_OF_SEPTEMBER));
        let fu = at(&clock, FairUseConfig { active: false, ..cfg(1, 2) });
        requests(&fu, 5);
        assert_eq!(fu.report().mutating_calls, 0);
        assert!(!fu.throttled());
        assert!(fu.health().is_null());
        assert!(fu.pending_stamp().is_none());
    }

    #[test]
    fn each_change_of_state_is_announced_once() {
        let clock = Arc::new(AtomicI64::new(END_OF_SEPTEMBER));
        let fu = at(&clock, cfg(2, 4));
        requests(&fu, 1);
        assert!(fu.take_announcement().is_none(), "ok is not news");
        requests(&fu, 1);
        assert_eq!(fu.take_announcement().map(|r| r.state), Some(FairUseState::Warned));
        requests(&fu, 1);
        assert!(fu.take_announcement().is_none(), "still warned, and it was said inside the hour");
        requests(&fu, 1);
        assert_eq!(fu.take_announcement().map(|r| r.state), Some(FairUseState::Throttled));
        clock.store(START_OF_OCTOBER, Ordering::SeqCst);
        requests(&fu, 1);
        let back = fu.take_announcement().expect("returning to ok after a throttle is news");
        assert_eq!((back.state, back.month.to_string().as_str()), (FairUseState::Ok, "2026-10"));
    }

    #[test]
    fn the_stamp_is_owed_only_when_the_count_moved() {
        let clock = Arc::new(AtomicI64::new(END_OF_SEPTEMBER));
        let fu = at(&clock, cfg(10, 20));
        requests(&fu, 3);
        let (key, value) = fu.pending_stamp().expect("three uncarried calls");
        assert_eq!(key, META_KEY);
        assert_eq!(parse_stamp(&value), Some((Month::from_unix(END_OF_SEPTEMBER), 3)));
        fu.stamped(&value);
        assert!(fu.pending_stamp().is_none(), "nothing new to carry");
        requests(&fu, 1);
        assert!(fu.pending_stamp().is_some());
    }
}
