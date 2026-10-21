//! Per-tenant count ceilings on the things a gateway holds: agents, secrets, grants, connections.
//!
//! These are the plan allowances the console's `lib/billing/plans.ts` defines. Until this module they were enforced
//! in the console and nowhere else, and the console is not on the agent path: a hosted worker has
//! Cloud Run ingress `all` and an `allUsers` invoker binding, so an agent holding a valid token
//! reaches `/mcp` and `/v1/invoke` without passing through permaura.com at all. A limit the console
//! draws is a limit an agent does not meet.
//!
//! **Unset means unlimited**, and every variable is unset unless a provisioner sets it. A self-hosted
//! gateway is therefore untouched by this file: it boots with four `None`s and every check returns
//! `Ok` without reading the store. The hosted provisioner is what turns them on, from the plan.
//!
//! **A refusal is a read.** The count comes from the store's own list, so refusing costs a store read
//! and nothing else. That matters because on a hosted worker every store *mutation* is a full
//! snapshot upload, and a control that made refusing more expensive than complying would be a new way
//! to hit the write ceiling rather than a protection from it. The audited denial that follows a
//! refusal is one append, which is the same cost as the create it refused. Three of the four creates are operator-authenticated; the fourth, a new agent, can be driven by an enrolment-code holder or an OAuth client with a valid token, so its refusals are bounded only by the admission limits in `crate::limits`.
//!
//! **Not a rate limit, and deliberately not a 429.** `crate::limits` and `crate::audit_ceiling` both
//! answer 429 because their condition clears on its own if the caller waits. This one does not: the
//! tenant is at its ceiling and waiting changes nothing. See [`GatewayError::AllowanceExceeded`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::GatewayError;

/// Minimum gap between two refusal lines for the same allowance (60 s).
///
/// The audit-ceiling interval rather than the admission limiter's second: a tenant at its ceiling
/// stays there until somebody deletes something or upgrades, so the condition changes over hours and
/// a line per attempt would be a logging bill for a fact that has not moved.
pub const DEFAULT_LOG_INTERVAL_MS: u64 = 60_000;

/// The stable log message every allowance refusal emits. A log-based metric is built on
/// this exact string, so it is a wire format: do not reword it, and do not fold another condition
/// into it.
///
/// The full line is a `WARN` from `permaura_gateway::allowances` carrying:
///
/// ```text
/// gateway_id=<id> allowance=<agents|secrets|grants|connections> current=<n> limit=<n>
///   suppressed=<n>
///   gateway plan allowance refused a create
/// ```
///
/// Every field renders through `Display`, so a `&str` field is unquoted (`allowance=agents`, not
/// `allowance="agents"`), matching [`crate::limits::REJECTION_LOG_MESSAGE`] and
/// [`crate::audit_ceiling::PRESSURE_LOG_MESSAGE`] so one extractor pattern serves all three.
///
/// **A counter built on this message adds `suppressed + 1` per line, not one per line.**
pub const REFUSAL_LOG_MESSAGE: &str = "gateway plan allowance refused a create";

/// The audit `action` an allowance denial is recorded under, and the `resource` it names.
///
/// One action rather than four, with the allowance in the summary, because an operator reading the
/// chain wants "what did this gateway refuse" as one query and the four are the same event.
pub const AUDIT_ACTION: &str = "permaura.allowance.create";

/// The resource every allowance denial is recorded against. No connection is involved: the subject
/// is the gateway's own capacity, in the same way [`AUDIT_ACTION`] is not a capability.
pub const AUDIT_RESOURCE: &str = "allowance";

// ── The four allowances ─────────────────────────────────────────────────────────

/// A countable resource with a plan ceiling.
///
/// Four rather than the seven in `plans.ts` because the other three are control-plane shapes the
/// gateway has no word for: `workspaces` and `members` are permaura.com concepts a gateway never
/// sees, and `gateways_per_workspace` is a count of gateways, which no single gateway can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Allowance {
    /// Registered agents, however they arrived: operator-created, enrolment code, or an OAuth client
    /// reaching `/mcp` directly. The last of those is the one the console could never bind.
    Agents,
    /// Sealed secrets in the vault.
    Secrets,
    /// Grants, the authorization root.
    Grants,
    /// Configured connections.
    Connections,
}

impl Allowance {
    /// Every allowance, for iteration in `/health` and in tests.
    pub const ALL: [Allowance; 4] = [
        Allowance::Agents,
        Allowance::Secrets,
        Allowance::Grants,
        Allowance::Connections,
    ];

    /// The stable label used in the log line, the error body and `/health`.
    pub fn as_str(self) -> &'static str {
        match self {
            Allowance::Agents => "agents",
            Allowance::Secrets => "secrets",
            Allowance::Grants => "grants",
            Allowance::Connections => "connections",
        }
    }

    /// The environment variable that sets this ceiling.
    pub fn env_var(self) -> &'static str {
        match self {
            Allowance::Agents => "PERMAURA_LIMIT_MAX_AGENTS",
            Allowance::Secrets => "PERMAURA_LIMIT_MAX_SECRETS",
            Allowance::Grants => "PERMAURA_LIMIT_MAX_GRANTS",
            Allowance::Connections => "PERMAURA_LIMIT_MAX_CONNECTIONS",
        }
    }
}

// ── Configuration ───────────────────────────────────────────────────────────────

/// The four ceilings, resolved once at startup. `None` is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AllowancesConfig {
    /// Ceiling on registered agents.
    pub agents: Option<u64>,
    /// Ceiling on sealed secrets.
    pub secrets: Option<u64>,
    /// Ceiling on grants.
    pub grants: Option<u64>,
    /// Ceiling on connections.
    pub connections: Option<u64>,
}

impl AllowancesConfig {
    /// Resolve from the environment. An unset variable is unlimited.
    ///
    /// An unparseable value is also unlimited, and says so once in a `WARN` naming the variable.
    /// Every other limit in this gateway falls back to a shipped default on a typo; here there is no
    /// default to fall back to, and the two remaining options are to refuse to boot or to behave as
    /// the gateway did before the variable existed. Refusing to boot would turn one bad character in
    /// a provisioning payload into a dead worker, which is a worse failure than an uncapped one, and
    /// it would be silent to everyone except whoever reads the container log. `0` is a real value
    /// meaning none, matching `plans.ts` where `0` is none and `null` is unlimited.
    pub fn from_env() -> Self {
        AllowancesConfig {
            agents: limit_env(Allowance::Agents),
            secrets: limit_env(Allowance::Secrets),
            grants: limit_env(Allowance::Grants),
            connections: limit_env(Allowance::Connections),
        }
    }

    /// The ceiling for one allowance.
    pub fn limit(&self, allowance: Allowance) -> Option<u64> {
        match allowance {
            Allowance::Agents => self.agents,
            Allowance::Secrets => self.secrets,
            Allowance::Grants => self.grants,
            Allowance::Connections => self.connections,
        }
    }

    /// True when no allowance is set, which is every self-hosted gateway.
    pub fn is_unlimited(&self) -> bool {
        Allowance::ALL.iter().all(|a| self.limit(*a).is_none())
    }
}

fn limit_env(allowance: Allowance) -> Option<u64> {
    let raw = std::env::var(allowance.env_var()).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<u64>() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(
                var = allowance.env_var(),
                "gateway allowance value is not a number; this allowance is unlimited"
            );
            None
        }
    }
}

// ── The gate ────────────────────────────────────────────────────────────────────

/// This instance's allowance ceilings, its throttled refusal signal and its refusal counts.
#[derive(Debug)]
pub struct Allowances {
    config: AllowancesConfig,
    /// Stamped into the refusal line so a fleet-wide log query can group by tenant. Empty on a
    /// gateway that was never told its id, which a self-run one has not been.
    gateway_id: String,
    log_state: Mutex<HashMap<&'static str, LogThrottle>>,
    refused: Mutex<HashMap<&'static str, u64>>,
    log_interval: Duration,
    /// Total refusals across all four, so a caller can read one number without walking the map.
    refused_total: AtomicU64,
}

#[derive(Debug)]
struct LogThrottle {
    last: Instant,
    suppressed: u64,
}

impl Default for Allowances {
    fn default() -> Self {
        Allowances::new(AllowancesConfig::default())
    }
}

impl Allowances {
    /// Build one for a configuration.
    pub fn new(config: AllowancesConfig) -> Self {
        Allowances {
            config,
            gateway_id: String::new(),
            log_state: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
            log_interval: Duration::from_millis(DEFAULT_LOG_INTERVAL_MS),
            refused_total: AtomicU64::new(0),
        }
    }

    /// Name the gateway these allowances belong to, for the refusal line.
    pub fn with_gateway_id(mut self, gateway_id: impl Into<String>) -> Self {
        self.gateway_id = gateway_id.into();
        self
    }

    /// Shorten the log throttle, so a test that drives several refusals is not also testing a clock.
    pub fn with_log_interval(mut self, interval: Duration) -> Self {
        self.log_interval = interval;
        self
    }

    /// The allowances a gateway assembled from the environment gets.
    pub fn from_env() -> Self {
        Allowances::new(AllowancesConfig::from_env())
            .with_gateway_id(std::env::var("PERMAURA_GATEWAY_ID").unwrap_or_default())
    }

    /// The resolved configuration, for `/health` and for tests.
    pub fn config(&self) -> &AllowancesConfig {
        &self.config
    }

    /// Creates refused since this instance started, across all four allowances. Per-instance and
    /// reset by a cold start, like every counter in [`crate::limits`].
    pub fn refused_total(&self) -> u64 {
        self.refused_total.load(Ordering::Relaxed)
    }

    /// Admit one new row of `allowance`, given how many live ones there already are.
    ///
    /// `current` is what the store holds *now*, counted by the caller immediately before this call
    /// and immediately before the write it guards. Nothing is cached: a count that could go stale
    /// would let a tenant past its ceiling after a delete-and-recreate, and counting is a read.
    ///
    /// Refusing writes nothing. The audited denial is the caller's to append, because appending is a
    /// store mutation and this module does not hold a store.
    pub fn admit(&self, allowance: Allowance, current: u64) -> Result<(), GatewayError> {
        let Some(limit) = self.config.limit(allowance) else {
            return Ok(());
        };
        if current < limit {
            return Ok(());
        }
        self.refused_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut counts) = self.refused.lock() {
            *counts.entry(allowance.as_str()).or_insert(0) += 1;
        }
        self.signal(allowance, current, limit);
        Err(GatewayError::AllowanceExceeded {
            allowance: allowance.as_str().to_string(),
            current,
            limit,
            message: format!(
                "this gateway holds {current} {} and its plan allows {limit}; \
                 remove one or upgrade the plan",
                allowance.as_str()
            ),
        })
    }

    /// One throttled `WARN` per allowance per interval, carrying what the throttle swallowed.
    fn signal(&self, allowance: Allowance, current: u64, limit: u64) {
        let label = allowance.as_str();
        let suppressed = {
            let Ok(mut state) = self.log_state.lock() else {
                return;
            };
            match state.get_mut(label) {
                Some(t) if t.last.elapsed() < self.log_interval => {
                    t.suppressed += 1;
                    return;
                }
                Some(t) => std::mem::replace(&mut t.suppressed, 0),
                None => {
                    state.insert(
                        label,
                        LogThrottle {
                            last: Instant::now(),
                            suppressed: 0,
                        },
                    );
                    0
                }
            }
        };
        if let Ok(mut state) = self.log_state.lock() {
            if let Some(t) = state.get_mut(label) {
                t.last = Instant::now();
            }
        }
        tracing::warn!(
            gateway_id = %self.gateway_id,
            allowance = label,
            current = current,
            limit = limit,
            suppressed = suppressed,
            "{REFUSAL_LOG_MESSAGE}"
        );
    }

    /// The `/health` block: every allowance with its live count, its ceiling and its refusals.
    ///
    /// `counts` is what the caller read from the store, passed in rather than read here for the same
    /// reason [`crate::audit_ceiling::AuditCeiling::health_snapshot`] takes its event count: a status
    /// document must not be the thing that goes and reads the store a second time.
    ///
    /// A ceiling of `null` is unlimited, which is what the console must render as "no limit" rather
    /// than as zero. This is the block that makes the admin page's claim checkable instead of
    /// asserted: it reports what the worker is actually enforcing, not what a plan row says.
    pub fn health_snapshot(&self, counts: &[(Allowance, u64)]) -> serde_json::Value {
        let refused = self.refused.lock().ok();
        let mut out = serde_json::Map::new();
        for (allowance, current) in counts {
            out.insert(
                allowance.as_str().to_string(),
                serde_json::json!({
                    "current": current,
                    "limit": self.config.limit(*allowance),
                    "refused": refused
                        .as_ref()
                        .and_then(|m| m.get(allowance.as_str()).copied())
                        .unwrap_or(0),
                }),
            );
        }
        serde_json::Value::Object(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capped(limit: u64) -> Allowances {
        Allowances::new(AllowancesConfig {
            agents: Some(limit),
            ..AllowancesConfig::default()
        })
        .with_log_interval(Duration::ZERO)
    }

    #[test]
    fn an_unset_allowance_admits_anything() {
        let a = Allowances::default();
        assert!(a.config().is_unlimited());
        a.admit(Allowance::Agents, u64::MAX).expect("unlimited");
        assert_eq!(a.refused_total(), 0);
    }

    #[test]
    fn a_create_at_the_ceiling_is_refused_and_one_below_it_is_not() {
        let a = capped(3);
        a.admit(Allowance::Agents, 2).expect("the third agent");
        let err = a.admit(Allowance::Agents, 3).unwrap_err();
        match err {
            GatewayError::AllowanceExceeded {
                allowance,
                current,
                limit,
                ..
            } => {
                assert_eq!(allowance, "agents");
                assert_eq!(current, 3);
                assert_eq!(limit, 3);
            }
            other => panic!("expected AllowanceExceeded, got {other:?}"),
        }
        assert_eq!(a.refused_total(), 1);
    }

    /// `0` is none, not unlimited. The convention is `plans.ts`'s, where Free has `agents: 0`, and
    /// reading it the other way would hand the free tier the uncapped gateway.
    #[test]
    fn a_ceiling_of_zero_admits_nothing() {
        let a = capped(0);
        assert!(a.admit(Allowance::Agents, 0).is_err());
    }

    /// One capped allowance must not cap the other three.
    #[test]
    fn allowances_are_independent() {
        let a = capped(1);
        assert!(a.admit(Allowance::Agents, 5).is_err());
        a.admit(Allowance::Secrets, 5).expect("secrets are unset");
        a.admit(Allowance::Grants, 5).expect("grants are unset");
        a.admit(Allowance::Connections, 5)
            .expect("connections are unset");
    }

    #[test]
    fn the_health_block_reports_unlimited_as_null() {
        let a = capped(2);
        let snap = a.health_snapshot(&[(Allowance::Agents, 1), (Allowance::Secrets, 9)]);
        assert_eq!(snap["agents"]["current"], 1);
        assert_eq!(snap["agents"]["limit"], 2);
        assert!(snap["secrets"]["limit"].is_null());
        assert_eq!(snap["secrets"]["current"], 9);
    }

    #[test]
    fn the_health_block_counts_refusals_per_allowance() {
        let a = capped(1);
        let _ = a.admit(Allowance::Agents, 1);
        let _ = a.admit(Allowance::Agents, 1);
        let snap = a.health_snapshot(&[(Allowance::Agents, 1)]);
        assert_eq!(snap["agents"]["refused"], 2);
    }
}
