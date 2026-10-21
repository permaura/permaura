//! The hot audit store's warning band and hard ceiling.
//!
//! The hot audit window is resident in memory, replayed at every cold start and re-uploaded whole on every mutation.
//! The archive writer ([`crate::archive`]) prunes it once its oldest events are published, where an archive is configured; this
//! ceiling is the protection when none is, or when the archive falls behind, so it says so early and stops admitting new executions
//! before the instance is in trouble.
//!
//! Two bands, both in [`AuditCeilingConfig`]:
//!
//! - **soft**: a throttled `WARN` per interval, an `audit_pressure` block on `/health`, and a line
//!   in what the store reports as degraded. Execution continues untouched. The point is that the
//!   refusal below is the end of a long-signalled condition rather than the first anyone hears of
//!   it.
//! - **ceiling**: a new execution is refused with [`GatewayError::TooManyRequests`] under the
//!   reason [`REASON`], which is what distinguishes it from the admission limiter's 429.
//!
//! **What the ceiling bounds, and what it does not.** It gates the decision to execute, at the same
//! fence as the pre-execution `"attempt"` append and after the execution hold. It never gates the
//! recording of anything. A denial, a held approval, a control-plane mutation, an approval a human
//! resolves and the terminal event of an execution already under way are all appended at any
//! pressure, because "an audit event is never dropped, at any pressure, for any reason" is a
//! standing protection. So the chain can and will pass the ceiling; what the ceiling removes is the one
//! contributor that an agent can drive at machine speed and that writes two events per call.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::GatewayError;

// ── Defaults ────────────────────────────────────────────────────────────────────
//
// Both come from `services/gateway/tests/audit_scale.rs`, which fills a real SQLite store with
// realistic `"allow"` events and reports snapshot bytes, cold-open time and live heap. The binding
// term is NOT the snapshot: it is that the chain is resident in memory, and until
// `Store::count_grant_usage` landed it was also cloned whole on every invocation and held for the
// length of the execution.

/// Events at which the operator is warned (32,500), half the ceiling.
///
/// Half rather than a rounder fraction because the archive may be off or behind: the gap has to be a real
/// amount of runway, and at the sustained execution rate `limits` allows it is a couple of hours of
/// flat-out use and months of ordinary use.
/// *Measure:* the same as the ceiling. This is a fraction of it, not an independent number.
pub const DEFAULT_HOT_SOFT: u64 = 32_500;

/// Events at which new executions are refused (65,000).
///
/// Measured, not chosen, and **re-derived** when the per-invocation clone was removed. The method is
/// unchanged: `tests/audit_scale.rs` fills a real store with realistic `"allow"` events and counts
/// live heap with an allocator of its own, and the budget is the same 313 MB of a 537 MB instance
/// that 15,000 events used to occupy. Only the cost of one event moved.
///
/// It is linear, and at 10k / 100k / 250k events it reports about **822 bytes an event** of
/// snapshot and **2,050 to 2,230 bytes an event** resident. What changed is the third term: the
/// clone `service.rs` took on every invocation to compute grant budgets, **2,034 bytes an event**
/// held for the length of the execution, is gone. `Store::count_grant_usage` tallies in place under
/// the store's own lock and returns a handful of integers, which the measurement reports as
/// **0 bytes an event**.
///
/// So one event now costs, on a 512 MiB instance: one resident copy plus the snapshot triple (the
/// database, the `VACUUM INTO` copy and the upload buffer), which is 2,131 + 3 x 822 = about
/// **4,597 bytes**, against 2,131 + 8 x 2,034 + 3 x 822 = about **20,869 bytes** before. The same
/// 313 MB budget therefore carries 68,000 events; 65,000 is that rounded down, and puts the chain
/// at about 299 MB.
///
/// **What this changes about the shape of the failure.** At 15,000 events, memory arrived five
/// times sooner than `store::persisted::DEFAULT_WARN_BYTES` (64 MiB, about 78,000 events). At
/// 65,000 the snapshot is about 53 MB, so the two are now within 20% of each other: memory still
/// binds first, but only just, and a tenant whose events are larger than these synthetic ones could
/// meet the snapshot warning first. That warning only warns, and warns after the upload.
///
/// *Measure:* peak RSS of a real hosted worker at N events with eight concurrent invocations, and
/// cold-start time to first served request at the same N. Both replace this outright. The cold-open
/// half is cheap (135 ms to replay 100,000 events, 855 ms for 250,000), so memory is still the
/// binding term on both counts.
///
/// **Re-derive this again when the archive writer and prune land (slice 9)**, which is what makes
/// the hot window bounded by something other than a refusal.
pub const DEFAULT_HOT_CEILING: u64 = 65_000;

/// Minimum gap between two pressure log lines for the same band (60 s).
///
/// Longer than the admission limiter's second, because this condition changes over hours and a line
/// per execution at the ceiling would be a logging bill for information that has not moved.
/// *Measure:* the log ingestion budget against the observed execution rate of a pressured tenant.
pub const DEFAULT_LOG_INTERVAL_MS: u64 = 60_000;

/// What a refused caller is told to wait, in seconds (300).
///
/// Unlike the rate limiter's, this condition does not clear on its own until something archives or
/// an operator intervenes, so the number is a politeness rather than a promise. Five minutes is long
/// enough that a retrying agent is not the reason the operator cannot read their logs.
pub const DEFAULT_RETRY_AFTER_SECS: u64 = 300;

/// The `reason` on the 429, and the label a metric groups by.
///
/// It exists so a caller and an operator can tell this refusal from the admission limiter's `rate`,
/// `queue` and `busy`: one says "slow down and you will get through", this one says "this gateway's
/// hot store is full", and the responses to them are nothing alike.
pub const REASON: &str = "audit_backlog";

/// The `reason` on the 429 a session gets once its denials have run out ([`AuditCeiling::admit_session`]).
pub const DENIAL_REASON: &str = "denials";

/// Denials one session may have recorded back to back (30) before its calls are refused unrecorded.
///
/// Sized like the admission limiter's self-run burst: an agent that hits a run of denials while finding its way around a grant has room to, and one looping on a refusal stops writing to the chain within seconds. *Measure:* the longest run of denials a well-behaved agent produces against a narrow grant.
pub const DEFAULT_DENIAL_BURST: u32 = 30;

/// Denials one session may have recorded a minute once its burst is spent (6, one every ten seconds).
///
/// A session pinned at this rate adds about 8,600 events a day, against the 120 a minute (172,800 a day) the admission limiter alone allowed, which carried a self-run gateway to the ceiling in nine hours. *Measure:* denials per minute of a stuck agent against the hot window the archive keeps.
pub const DEFAULT_DENIALS_PER_MIN: u32 = 6;

/// How many sessions the denial limiter tracks before it forgets the ones whose budget has refilled.
const MAX_TRACKED_SESSIONS: usize = 10_000;

/// The stable log message the pressure signal emits. A log-based metric is built on this
/// exact string, so it is a wire format: do not reword it, and do not fold another condition into it.
///
/// The full line is a `WARN` from `permaura_gateway::audit_ceiling` carrying:
///
/// ```text
/// gateway_id=<id> band=<soft|ceiling> events=<n> soft=<n> ceiling=<n> suppressed=<n>
///   gateway audit hot store is under pressure
/// ```
///
/// Every field renders through `Display`, so a `&str` field is unquoted (`band=soft`, not
/// `band="soft"`) and a label extractor can match the documented form. `band` is the label worth
/// grouping by: `soft` is a condition to plan around and `ceiling` is one that is already refusing
/// work, and a single alert on the message with no band cannot tell them apart.
///
/// **A counter built on this message adds `suppressed + 1` per line, not one per line.** Lines are
/// throttled to one per band per [`AuditCeilingConfig::log_interval`], and `suppressed` is how many
/// evaluations in that band the throttle swallowed since the previous line. This is the same rule as
/// [`crate::limits::REJECTION_LOG_MESSAGE`], deliberately, so one extractor pattern serves both.
pub const PRESSURE_LOG_MESSAGE: &str = "gateway audit hot store is under pressure";

// ── Configuration ───────────────────────────────────────────────────────────────

/// The two thresholds and the signal's throttle, resolved once at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCeilingConfig {
    /// Events at which the operator signal fires. Execution continues.
    pub soft: u64,
    /// Events at which a new execution is refused.
    pub ceiling: u64,
    /// Minimum gap between two pressure lines for the same band.
    pub log_interval: Duration,
}

impl Default for AuditCeilingConfig {
    fn default() -> Self {
        AuditCeilingConfig {
            soft: DEFAULT_HOT_SOFT,
            ceiling: DEFAULT_HOT_CEILING,
            log_interval: Duration::from_millis(DEFAULT_LOG_INTERVAL_MS),
        }
    }
}

impl AuditCeilingConfig {
    /// Resolve from the environment, clamping every value.
    ///
    /// An unparseable value takes the default rather than refusing to boot, matching
    /// [`crate::limits::LimitsConfig::from_env`]: a typo in one variable must not be why a gateway
    /// will not start.
    ///
    /// There is no "off". The ceiling clamps up to ten million events, which is far past anything a
    /// 512 MiB instance survives and is the honest way to say "effectively disabled" on a machine
    /// that is not one. A flag that turned the bound off entirely would be a flag whose only use is
    /// to remove the protection on the deployment that needs it most.
    pub fn from_env() -> Self {
        let d = AuditCeilingConfig::default();
        let ceiling = u64_env("PERMAURA_AUDIT_HOT_CEILING", d.ceiling).clamp(100, 10_000_000);
        // The soft band is pulled below the ceiling rather than refused: a pair that crosses is a
        // misconfiguration, and the safe reading of it is "warn at the moment you refuse" rather
        // than "never warn".
        let soft = u64_env("PERMAURA_AUDIT_HOT_SOFT", d.soft).clamp(1, ceiling);
        AuditCeilingConfig {
            soft,
            ceiling,
            log_interval: Duration::from_millis(
                u64_env("PERMAURA_AUDIT_LOG_INTERVAL_MS", DEFAULT_LOG_INTERVAL_MS)
                    .clamp(0, 3_600_000),
            ),
        }
    }
}

fn u64_env(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

// ── Bands ───────────────────────────────────────────────────────────────────────

/// Which band the hot store is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    /// Below the soft threshold. Nothing to say.
    Normal,
    /// At or above soft, below the ceiling. Signalled, still executing.
    Soft,
    /// At or above the ceiling. New executions refused.
    Ceiling,
}

impl Band {
    /// The stable label, for the log line and `/health`.
    pub fn as_str(self) -> &'static str {
        match self {
            Band::Normal => "normal",
            Band::Soft => "soft",
            Band::Ceiling => "ceiling",
        }
    }
}

// ── The ceiling ─────────────────────────────────────────────────────────────────

/// The instance's audit-pressure state: its thresholds, its throttled signal and its refusal count.
#[derive(Debug)]
pub struct AuditCeiling {
    config: AuditCeilingConfig,
    /// Stamped into the pressure line so a fleet-wide log query can group by tenant. Empty on a
    /// gateway that was never told its id, which a self-run one has not been.
    gateway_id: String,
    log_state: Mutex<HashMap<&'static str, LogThrottle>>,
    /// Executions refused at the ceiling since this instance started. Per-instance and reset by a
    /// cold start, like everything in [`crate::limits`].
    refused: AtomicU64,
    denials: DenialLimiter,
}

/// A token bucket of recorded denials per session.
///
/// The ceiling never gates the recording of a decision, and this does not either: it refuses a call before any gate has decided it, as the admission limiter does, so there is no decision to record. What it removes is the one way an agent could grow the chain at machine speed without ever executing, a denial per call at its admission rate. Per-instance and in memory, like [`crate::limits`].
#[derive(Debug)]
struct DenialLimiter {
    burst: f64,
    per_sec: f64,
    sessions: Mutex<HashMap<String, Bucket>>,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl DenialLimiter {
    fn new(burst: u32, per_min: u32) -> Self {
        DenialLimiter {
            burst: f64::from(burst.max(1)),
            per_sec: f64::from(per_min.max(1)) / 60.0,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn from_env() -> Self {
        let burst = u64_env("PERMAURA_DENIAL_BURST", u64::from(DEFAULT_DENIAL_BURST)).clamp(1, 100_000);
        let per_min = u64_env("PERMAURA_DENIALS_PER_MIN", u64::from(DEFAULT_DENIALS_PER_MIN)).clamp(1, 100_000);
        DenialLimiter::new(burst as u32, per_min as u32)
    }

    fn refilled(&self, bucket: &Bucket, now: Instant) -> f64 {
        (bucket.tokens + now.saturating_duration_since(bucket.at).as_secs_f64() * self.per_sec).min(self.burst)
    }

    /// `Err` with the seconds until one more denial may be recorded, when none may be now. Consumes nothing: only a denial does.
    fn admit(&self, session_id: &str) -> Result<(), u64> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(bucket) = sessions.get(session_id) else { return Ok(()) };
        let tokens = self.refilled(bucket, Instant::now());
        if tokens >= 1.0 {
            return Ok(());
        }
        Err((((1.0 - tokens) / self.per_sec).ceil() as u64).max(1))
    }

    fn record(&self, session_id: &str) {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if sessions.len() >= MAX_TRACKED_SESSIONS && !sessions.contains_key(session_id) {
            sessions.retain(|_, bucket| self.refilled(bucket, now) < self.burst);
        }
        let bucket = sessions.entry(session_id.to_string()).or_insert(Bucket { tokens: self.burst, at: now });
        bucket.tokens = (self.refilled(bucket, now) - 1.0).max(0.0);
        bucket.at = now;
    }
}

#[derive(Debug)]
struct LogThrottle {
    last: Instant,
    suppressed: u64,
}

impl Default for AuditCeiling {
    fn default() -> Self {
        AuditCeiling::new(AuditCeilingConfig::default())
    }
}

impl AuditCeiling {
    /// Build one for a configuration.
    pub fn new(config: AuditCeilingConfig) -> Self {
        AuditCeiling {
            config,
            gateway_id: String::new(),
            log_state: Mutex::new(HashMap::new()),
            refused: AtomicU64::new(0),
            denials: DenialLimiter::new(DEFAULT_DENIAL_BURST, DEFAULT_DENIALS_PER_MIN),
        }
    }

    /// The same, with a per-session denial budget other than the default.
    pub fn with_denial_limit(mut self, burst: u32, per_min: u32) -> Self {
        self.denials = DenialLimiter::new(burst, per_min);
        self
    }

    /// Refuse a call from `session_id` when the session has had more denials recorded than its budget allows. Called before any gate, so a refusal records nothing; see [`DenialLimiter`].
    pub fn admit_session(&self, session_id: &str) -> Result<(), GatewayError> {
        self.denials.admit(session_id).map_err(|retry_after_secs| GatewayError::TooManyRequests {
            reason: DENIAL_REASON.to_string(),
            message: "this session's calls have been denied faster than this gateway records denials, so its calls are refused for now; fix the grant or the agent".to_string(),
            retry_after_secs,
            scope: Some("session"),
        })
    }

    /// Count one recorded denial against `session_id`.
    pub fn record_denial(&self, session_id: &str) {
        self.denials.record(session_id);
    }

    /// Name the gateway this ceiling belongs to, for the pressure line.
    pub fn with_gateway_id(mut self, gateway_id: impl Into<String>) -> Self {
        self.gateway_id = gateway_id.into();
        self
    }

    /// The ceiling a gateway assembled from the environment gets.
    pub fn from_env() -> Self {
        let mut ceiling = AuditCeiling::new(AuditCeilingConfig::from_env())
            .with_gateway_id(std::env::var("PERMAURA_GATEWAY_ID").unwrap_or_default());
        ceiling.denials = DenialLimiter::from_env();
        ceiling
    }

    /// The resolved configuration, for `/health` and for tests.
    pub fn config(&self) -> &AuditCeilingConfig {
        &self.config
    }

    /// Executions refused at the ceiling since this instance started.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Which band `events` falls in. Pure; signals nothing.
    pub fn band(&self, events: u64) -> Band {
        if events >= self.config.ceiling {
            Band::Ceiling
        } else if events >= self.config.soft {
            Band::Soft
        } else {
            Band::Normal
        }
    }

    /// Admit one new execution, or refuse it because the hot store is full.
    ///
    /// Called at the fence, before the `"attempt"` append and after the execution hold, so a refusal
    /// appends nothing and mutates nothing, which on a hosted worker is the difference between a
    /// refusal that costs a lock and one that costs a full snapshot upload.
    pub fn admit(&self, events: u64) -> Result<(), GatewayError> {
        let band = self.band(events);
        if band != Band::Normal {
            self.signal(band, events);
        }
        if band != Band::Ceiling {
            return Ok(());
        }
        self.refused.fetch_add(1, Ordering::Relaxed);
        Err(GatewayError::TooManyRequests {
            reason: REASON.to_string(),
            message: format!(
                "this gateway's audit store holds {events} events, at its {} ceiling; \
                 new executions are refused until it is archived",
                self.config.ceiling
            ),
            retry_after_secs: DEFAULT_RETRY_AFTER_SECS,
            scope: None,
        })
    }

    /// What `/health` reports. `null` is never right here: every gateway has a hot store and a
    /// ceiling, so the block is always a document.
    pub fn health_snapshot(&self, events: u64) -> serde_json::Value {
        serde_json::json!({
            "events": events,
            "soft": self.config.soft,
            "ceiling": self.config.ceiling,
            "band": self.band(events).as_str(),
            // Per-instance and reset on a cold start, like `limits`.
            "refused": self.refused(),
        })
    }

    /// One sentence for whoever asks the gateway what is wrong with it, or `None` below the soft
    /// band. Joined with the store's own durability note, because a console showing one condition
    /// and hiding the other would be showing half the answer.
    pub fn degraded_note(&self, events: u64) -> Option<String> {
        match self.band(events) {
            Band::Normal => None,
            Band::Soft => Some(format!(
                "audit pressure: the hot store holds {events} events against a {} ceiling; \
                 execution continues, and the audit archive prunes it where one is configured",
                self.config.ceiling
            )),
            Band::Ceiling => Some(format!(
                "audit ceiling reached: the hot store holds {events} events against a {} ceiling; \
                 new executions are refused, while reads, the console, revocation, approval \
                 resolution and recovery keep working",
                self.config.ceiling
            )),
        }
    }

    /// One stable line per band per interval. Returns the suppressed count it carried when it
    /// emitted, and `None` when the throttle swallowed it, so the throttle is testable without
    /// capturing a tracing subscriber.
    fn signal(&self, band: Band, events: u64) -> Option<u64> {
        let suppressed = {
            let now = Instant::now();
            let mut state = self.log_state.lock().unwrap_or_else(|e| e.into_inner());
            match state.get_mut(band.as_str()) {
                Some(entry)
                    if now.saturating_duration_since(entry.last) < self.config.log_interval =>
                {
                    entry.suppressed += 1;
                    return None;
                }
                Some(entry) => {
                    let suppressed = entry.suppressed;
                    entry.last = now;
                    entry.suppressed = 0;
                    suppressed
                }
                None => {
                    state.insert(band.as_str(), LogThrottle { last: now, suppressed: 0 });
                    0
                }
            }
        };
        tracing::warn!(
            gateway_id = %self.gateway_id,
            // Display, not the default Debug: a `&str` field renders quoted (`band="soft"`), and the log-based metric's label extractor matches the documented `band=soft`.
            band = %band.as_str(),
            events,
            soft = self.config.soft,
            ceiling = self.config.ceiling,
            suppressed,
            "{PRESSURE_LOG_MESSAGE}"
        );
        Some(suppressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceiling(soft: u64, ceiling: u64) -> AuditCeiling {
        AuditCeiling::new(AuditCeilingConfig {
            soft,
            ceiling,
            log_interval: Duration::from_millis(DEFAULT_LOG_INTERVAL_MS),
        })
    }

    #[test]
    fn a_session_is_refused_once_its_denials_run_out_and_others_are_not() {
        let c = ceiling(10, 20).with_denial_limit(3, 6);
        for _ in 0..3 {
            c.admit_session("sess_a").unwrap();
            c.record_denial("sess_a");
        }
        match c.admit_session("sess_a") {
            Err(GatewayError::TooManyRequests { reason, retry_after_secs, .. }) => {
                assert_eq!(reason, DENIAL_REASON);
                assert!((1..=10).contains(&retry_after_secs), "one more denial in ten seconds at 6 a minute: {retry_after_secs}");
            }
            other => panic!("expected the denial limit, got {other:?}"),
        }
        c.admit_session("sess_b").expect("another session has its own budget");
    }

    #[test]
    fn the_bands_are_inclusive_at_their_lower_edge() {
        let c = ceiling(10, 20);
        assert_eq!(c.band(9), Band::Normal);
        assert_eq!(c.band(10), Band::Soft);
        assert_eq!(c.band(19), Band::Soft);
        assert_eq!(c.band(20), Band::Ceiling);
        assert_eq!(c.band(u64::MAX), Band::Ceiling);
    }

    #[test]
    fn the_refusal_names_its_own_reason_and_never_says_retry_now() {
        let c = ceiling(10, 20);
        c.admit(19).expect("below the ceiling execution continues");
        let err = c.admit(20).expect_err("at the ceiling it refuses");
        match err {
            GatewayError::TooManyRequests { reason, retry_after_secs, .. } => {
                assert_eq!(reason, REASON, "a caller must tell this from rate limiting");
                assert!(retry_after_secs > 0);
            }
            other => panic!("the ceiling must refuse with a 429: {other:?}"),
        }
        assert_eq!(c.refused(), 1, "and it is counted for /health");
    }

    /// The throttle is the whole reason the line is safe to emit from the execution path: at the
    /// ceiling, every refused retry evaluates it, and an unthrottled line per retry turns a capacity
    /// problem into a logging bill.
    #[test]
    fn the_pressure_line_is_one_per_band_per_interval_and_carries_what_it_swallowed() {
        let c = ceiling(10, 20);
        assert_eq!(c.signal(Band::Soft, 12), Some(0), "the first line in a band always emits");
        assert_eq!(c.signal(Band::Soft, 13), None);
        assert_eq!(c.signal(Band::Soft, 14), None);
        // A different band is a different line: one is a condition to plan around and the other is
        // already refusing work.
        assert_eq!(c.signal(Band::Ceiling, 20), Some(0));

        let fast = AuditCeiling::new(AuditCeilingConfig {
            soft: 10,
            ceiling: 20,
            log_interval: Duration::ZERO,
        });
        assert_eq!(fast.signal(Band::Soft, 12), Some(0));
        assert_eq!(fast.signal(Band::Soft, 13), Some(0), "a zero interval never suppresses");
    }

    /// A soft band above the ceiling is a misconfiguration whose safe reading is "warn at the moment
    /// you refuse", never "never warn".
    #[test]
    fn a_soft_band_set_above_the_ceiling_is_pulled_down_to_it() {
        let guard = EnvGuard::set(&[
            ("PERMAURA_AUDIT_HOT_CEILING", "5000"),
            ("PERMAURA_AUDIT_HOT_SOFT", "900000"),
        ]);
        let config = AuditCeilingConfig::from_env();
        drop(guard);
        assert_eq!(config.ceiling, 5_000);
        assert_eq!(config.soft, 5_000);
    }

    /// A typo must not be why a gateway will not start.
    #[test]
    fn an_unparseable_value_takes_the_default() {
        let guard = EnvGuard::set(&[("PERMAURA_AUDIT_HOT_CEILING", "lots")]);
        let config = AuditCeilingConfig::from_env();
        drop(guard);
        assert_eq!(config.ceiling, DEFAULT_HOT_CEILING);
    }

    /// The environment is process-wide and the suite runs in parallel, so the two tests that read it
    /// take a lock of their own and put it back exactly as they found it.
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        restore: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&'static str, &str)]) -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let restore = pairs
                .iter()
                .map(|(k, v)| {
                    let previous = std::env::var(k).ok();
                    std::env::set_var(k, v);
                    (*k, previous)
                })
                .collect();
            EnvGuard { _lock: lock, restore }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, previous) in &self.restore {
                match previous {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}
