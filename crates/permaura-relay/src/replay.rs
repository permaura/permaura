//! Replay / idempotency guards.
//!
//! Two mechanisms: [`NonceWindow`], a per-connection monotonic `seq` guard the worker does not
//! use today, and [`JobLedger`], which the worker uses for cross-reconnect idempotency: a
//! `job_id` re-delivered within five minutes, and among the last 1024 jobs, returns its cached
//! result instead of executing again. A re-delivery outside that window runs again.

use std::collections::HashMap;

use crate::error::RelayError;
use crate::frames::InvokeResult;

/// Per-(connection, direction) monotonic guard: `Envelope.seq` must strictly increase. A
/// regression or repeat is a replay.
#[derive(Debug, Default)]
pub struct NonceWindow {
    highest_seen: u64,
}

impl NonceWindow {
    /// A fresh window (no frames seen). `seq` 0 is never valid: the first accepted frame is 1.
    pub fn new() -> Self {
        NonceWindow { highest_seen: 0 }
    }

    /// Accept `seq` iff it is strictly greater than every prior value; else a replay error.
    pub fn accept(&mut self, seq: u64) -> Result<(), RelayError> {
        if seq <= self.highest_seen {
            return Err(RelayError::replayed(seq));
        }
        self.highest_seen = seq;
        Ok(())
    }
}

/// State of a job in the [`JobLedger`].
#[derive(Debug, Clone)]
pub enum JobState {
    /// Accepted and executing.
    InFlight,
    /// Completed; the terminal result is cached for idempotent re-delivery.
    Done(InvokeResult),
}

struct Entry {
    state: JobState,
    at_ms: i64,
}

/// Cross-reconnect idempotency for `job_id`. A duplicate that already completed returns the
/// cached [`InvokeResult`]; one still in flight is rejected. Bounded by a capacity (oldest
/// evicted) and a TTL.
pub struct JobLedger {
    seen: HashMap<String, Entry>,
    cap: usize,
    ttl_ms: i64,
}

impl JobLedger {
    /// A ledger holding up to `cap` recent jobs, each remembered for `ttl_ms`.
    pub fn new(cap: usize, ttl_ms: i64) -> Self {
        JobLedger {
            seen: HashMap::new(),
            cap,
            ttl_ms,
        }
    }

    /// Look up a job:
    /// - `Ok(Some(result))` → already done; return the cached result, do not re-execute.
    /// - `Ok(None)` → unseen (or expired); the caller should [`mark_inflight`](Self::mark_inflight)
    ///   then execute.
    /// - `Err(DuplicateJob)` → currently in flight (a duplicate delivery).
    pub fn check(&self, job_id: &str, now_ms: i64) -> Result<Option<&InvokeResult>, RelayError> {
        match self.seen.get(job_id) {
            None => Ok(None),
            Some(e) if self.is_expired(e, now_ms) => Ok(None),
            Some(e) => match &e.state {
                JobState::Done(r) => Ok(Some(r)),
                JobState::InFlight => Err(RelayError::DuplicateJob(job_id.to_string())),
            },
        }
    }

    /// Record a job as in-flight. Errors if it is already live (use [`check`](Self::check)
    /// first). Evicts expired entries and enforces the capacity bound before inserting.
    pub fn mark_inflight(&mut self, job_id: &str, now_ms: i64) -> Result<(), RelayError> {
        if let Some(e) = self.seen.get(job_id) {
            if !self.is_expired(e, now_ms) {
                return Err(RelayError::DuplicateJob(job_id.to_string()));
            }
        }
        self.make_room(now_ms);
        self.seen.insert(
            job_id.to_string(),
            Entry {
                state: JobState::InFlight,
                at_ms: now_ms,
            },
        );
        Ok(())
    }

    /// Record a job's terminal result for idempotent re-delivery.
    pub fn complete(&mut self, job_id: String, result: InvokeResult, now_ms: i64) {
        self.seen.insert(
            job_id,
            Entry {
                state: JobState::Done(result),
                at_ms: now_ms,
            },
        );
    }

    /// Number of remembered jobs (for diagnostics/tests).
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True if the ledger holds no jobs.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn is_expired(&self, e: &Entry, now_ms: i64) -> bool {
        now_ms.saturating_sub(e.at_ms) > self.ttl_ms
    }

    /// Drop expired entries, then evict the oldest until there is room for one more.
    fn make_room(&mut self, now_ms: i64) {
        self.seen
            .retain(|_, e| now_ms.saturating_sub(e.at_ms) <= self.ttl_ms);
        let cap = self.cap.max(1);
        while self.seen.len() >= cap {
            let oldest = self
                .seen
                .iter()
                .min_by_key(|(_, e)| e.at_ms)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.seen.remove(&k);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::RelayOutcome;
    use permaura_core::Decision;

    fn result(job: &str) -> InvokeResult {
        InvokeResult {
            job_id: job.into(),
            outcome: RelayOutcome::Denied {
                decision: Decision::deny("nope"),
            },
        }
    }

    #[test]
    fn nonce_window_rejects_regression_and_repeat() {
        let mut w = NonceWindow::new();
        assert!(w.accept(1).is_ok());
        assert!(w.accept(2).is_ok());
        assert!(w.accept(2).is_err(), "repeat is a replay");
        assert!(w.accept(1).is_err(), "regression is a replay");
        assert!(w.accept(3).is_ok());
    }

    #[test]
    fn job_ledger_dedupes_with_cached_result() {
        let mut l = JobLedger::new(8, 60_000);
        assert!(matches!(l.check("j1", 0), Ok(None)));
        l.mark_inflight("j1", 0).unwrap();
        assert!(matches!(l.check("j1", 0), Err(RelayError::DuplicateJob(_))));
        assert!(l.mark_inflight("j1", 0).is_err(), "cannot re-mark an in-flight job");
        l.complete("j1".into(), result("j1"), 0);
        assert_eq!(l.check("j1", 0).unwrap().unwrap().job_id, "j1", "returns cached, no re-exec");
    }

    #[test]
    fn job_ledger_expires() {
        let mut l = JobLedger::new(8, 1000);
        l.complete("j".into(), result("j"), 0);
        assert!(l.check("j", 500).unwrap().is_some());
        assert!(l.check("j", 2000).unwrap().is_none(), "past ttl → unseen");
    }

    #[test]
    fn job_ledger_is_capacity_bounded() {
        let mut l = JobLedger::new(3, 1_000_000);
        for i in 0..10 {
            l.mark_inflight(&format!("j{i}"), i as i64).unwrap();
        }
        assert!(l.len() <= 3, "ledger stays within capacity, evicting oldest");
    }
}
