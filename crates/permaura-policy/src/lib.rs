//! # permaura-policy
//!
//! The deterministic authorization engine for Permaura. It takes a [`DecisionInput`]
//! (which agent, what action, against which connection, in what context) plus the
//! [`Policy`]s and [`Grant`]s in scope, and resolves a [`Decision`]
//! (`allow` / `deny` / `requires_approval`), together with the grant and policy that
//! produced it, as a [`Resolution`].
//!
//! ## The four objects
//!
//! - A **[`Connection`](permaura_core::Connection)** is a configured integration
//!   instance. It is checked *before* the engine (the caller verifies the connection
//!   exists and the capability is not switched off); the engine reasons over the rest.
//! - A **[`Policy`]** is a reusable template *scoped to a connection*: per-action `allow` /
//!   `notify` / `requires_approval` / `device_signed` / `deny` lists, a `device_signed_quorum`,
//!   and extra `redact_fields`. It names no agent and no call limits.
//! - A **[`Grant`]** (v2) *binds a set of policies to a set of agents* (or to all agents)
//!   under two-tier limits: an optional `overall_limit` across all its agents and an optional
//!   per-agent limit, both per `period`, plus an `enabled` pause switch and an `expires_at`.
//! - An **agent** is the caller; the engine is told its id and trusts the caller to have
//!   confirmed the agent is approved.
//!
//! ## Cardinal rule: deny by default
//!
//! Nothing is permitted unless an enabled, live grant (covering this agent or all agents)
//! holds a policy (scoped to this connection) that lists the action on a non-deny rung
//! (`allow`, `notify`, `requires_approval` or `device_signed`), and no candidate policy denies
//! it. The resolution order:
//!
//! 1. **Gather** the *enabled, non-expired* grants covering this agent that hold ≥1 policy scoped
//!    to this connection. None → **deny by default**. (A disabled/expired grant is fully inert.)
//! 2. **Deny wins.** Any candidate policy that denies the action → **deny**.
//! 3. **Permitted.** The action must sit on a non-deny rung of at least one candidate policy,
//!    else **deny by default**.
//! 4. **Two-tier budget.** Keep only grants with headroom in **both** tiers: the
//!    `overall_limit` (rules all when set) and the agent's effective per-agent limit. None →
//!    **deny** (budget exhausted). On overlap, charge the most-permissive surviving grant.
//! 5. **Rung.** The effective rung is the most restrictive one any permitting policy assigns
//!    (`notify`, then `approve`, then `device_signed`), floored at `approve` when the capability
//!    self-declares approval or its risk is `High`/`Critical`. `approve` and `device_signed` →
//!    **requires_approval**, `device_signed` with the highest quorum any permitting policy sets,
//!    counted in distinct people. An operator bearer resolves `approve` (unless the gateway's
//!    approval floor is raised to `device_signed`); only paired-device signatures resolve
//!    `device_signed`.
//! 6. Otherwise → **allow**, with an after-the-fact push for `notify`.
//!
//! ## Cedar: a possible future path
//!
//! The MVP implements this as an internal, structured model in Rust, covered by the unit tests
//! below. A Cedar-compatible policy language is a possible future direction; until then this
//! engine is the source of truth.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use permaura_core::{
    ApprovalKind, ApprovalRequirement, Decision, ExecutionLocation, Grant, Policy, RiskTier, Rung,
};

// Re-export the stored policy model so callers can keep importing it from this crate.
pub use permaura_core::{GrantPeriod, GrantTarget};

/// The runtime context of a request: session, time, and where it would execute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    /// The agent session id.
    pub session_id: String,
    /// When the request was made.
    #[serde(with = "rfc3339")]
    pub requested_at: OffsetDateTime,
    /// Where the request came from (see [`ExecutionLocation`]). The engine does not read it.
    #[serde(default)]
    pub execution_location: ExecutionLocation,
    /// Monetary amount read from `params.amount`, if any. Nothing reads it: not the engine, not
    /// the audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
}

impl RequestContext {
    /// Construct a minimal context at a given time.
    pub fn new(session_id: impl Into<String>, requested_at: OffsetDateTime) -> Self {
        RequestContext {
            session_id: session_id.into(),
            requested_at,
            execution_location: ExecutionLocation::LocalOnly,
            amount: None,
        }
    }
}

/// Everything the engine needs to render one decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionInput {
    /// The capability action id being invoked, e.g. `transactions.refund` (the capability
    /// id minus its connector prefix).
    pub capability_id: String,
    /// The normalized risk-bearing verb behind the capability.
    pub action: permaura_core::Action,
    /// The connection id being touched (e.g. `braintree_production`).
    pub connection_id: String,
    /// The risk tier of the capability (from its connector definition).
    #[serde(default)]
    pub risk: RiskTier,
    /// Whether the capability *itself* declares that it always needs approval.
    #[serde(default)]
    pub capability_requires_approval: bool,
    /// The id of the agent making the call.
    pub agent_id: String,
    /// Request context.
    pub context: RequestContext,
}

/// A decision plus the grant and policy that produced it, so the caller can audit the
/// exact authorization chain and apply post-decision bookkeeping.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    /// The verdict.
    pub decision: Decision,
    /// The effective ladder rung, the most restrictive across every policy that permitted the
    /// action, floored by the capability/risk escalation rules. The service reads this to set a
    /// held approval's tier and to fire the `notify` push; it is richer than `decision.kind`
    /// (which cannot distinguish `auto` from `notify`, or `approve` from `device_signed`).
    pub rung: Rung,
    /// The grant that authorized (or would authorize) the action, if any.
    pub matched_grant_id: Option<String>,
    /// The most restrictive policy of the matched grant that permits the action (the first of equals), if any.
    pub matched_policy_id: Option<String>,
    /// How many **distinct people's** device signatures a held approval needs before it runs (two
    /// devices bound to one person count once). Always `1`
    /// except on the `device_signed` rung, where it is the **highest** quorum any permitting
    /// policy demands: most-restrictive-wins, exactly like [`Resolution::rung`], so a
    /// permissive policy can never talk a two-person action down to one signature.
    pub quorum: u8,
    /// The `redact_fields` of **every** policy that permits the action for this agent, across every
    /// live grant that binds one, sorted and deduplicated. Empty on a denial. The same
    /// most-restrictive-wins rule as [`Resolution::rung`]: a second, laxer policy bound beside a
    /// redacting one cannot switch its redaction off. The service adds these to the connection's and
    /// the manifest's lists and the gateway defaults.
    pub redact_fields: Vec<String>,
}

impl Resolution {
    fn deny(reason: impl Into<String>) -> Self {
        Resolution {
            decision: Decision::deny(reason),
            rung: Rung::Deny,
            matched_grant_id: None,
            matched_policy_id: None,
            quorum: 1,
            redact_fields: Vec::new(),
        }
    }
}

/// How many calls a grant (and a specific agent within it) has already consumed in the grant's
/// current period: the two counters the two-tier budget reads. The gateway supplies an
/// implementation over a counter table charged in the same transaction as each `allow` or
/// `approved` audit append, plus the reservations held by executions still in flight.
pub trait GrantUsage {
    /// Calls charged to this grant across **all** its agents in the grant's current period.
    fn grant_total(&self, grant_id: &str) -> u64;
    /// Calls charged to the `(grant, agent)` pair in the grant's current period.
    fn grant_agent(&self, grant_id: &str, agent_id: &str) -> u64;
}

/// A zero-usage stand-in: every grant looks unused. Backs [`PolicyEngine::evaluate`] and any
/// caller that does not meter budget (dry-run explanations, tests).
pub struct Unmetered;

impl GrantUsage for Unmetered {
    fn grant_total(&self, _: &str) -> u64 {
        0
    }
    fn grant_agent(&self, _: &str, _: &str) -> u64 {
        0
    }
}

/// Remaining headroom in the grant's most-binding tier for `agent` (unlimited = [`u64::MAX`]). Used
/// to pick the most-permissive grant to charge when several allow the same action.
fn grant_remaining(g: &Grant, agent: &str, usage: &dyn GrantUsage) -> u64 {
    let overall = g
        .overall_limit
        .map(|l| l.saturating_sub(usage.grant_total(&g.grant_id)))
        .unwrap_or(u64::MAX);
    let per_agent = g
        .effective_per_agent_limit(agent)
        .map(|l| l.saturating_sub(usage.grant_agent(&g.grant_id, agent)))
        .unwrap_or(u64::MAX);
    overall.min(per_agent)
}

/// True if the grant has budget left in **both** tiers for `agent`.
fn grant_has_headroom(g: &Grant, agent: &str, usage: &dyn GrantUsage) -> bool {
    if let Some(l) = g.overall_limit {
        if usage.grant_total(&g.grant_id) >= l {
            return false;
        }
    }
    if let Some(l) = g.effective_per_agent_limit(agent) {
        if usage.grant_agent(&g.grant_id, agent) >= l {
            return false;
        }
    }
    true
}

/// Explain which tier of a grant is exhausted for `agent`: the overall ceiling rules first.
fn budget_exhausted_reason(g: &Grant, agent: &str, usage: &dyn GrantUsage) -> String {
    if let Some(l) = g.overall_limit {
        let used = usage.grant_total(&g.grant_id);
        if used >= l {
            return format!(
                "Grant {} overall budget exhausted ({used} of {l} used this period).",
                g.grant_id
            );
        }
    }
    let used = usage.grant_agent(&g.grant_id, agent);
    let lim = g.effective_per_agent_limit(agent).unwrap_or(0);
    format!(
        "Grant {} per-agent budget exhausted for '{agent}' ({used} of {lim} used this period).",
        g.grant_id
    )
}

/// Whether `p` lists `cap` on a rung that lets it run (anything but deny).
fn permits(p: &Policy, cap: &str) -> bool {
    matches!(p.rung_for(cap), Some(r) if r != Rung::Deny)
}

/// `p`'s bar for `cap` as (rung, quorum), ordered least to most restrictive.
fn bar(p: &Policy, cap: &str) -> (Rung, u8) {
    (p.rung_for(cap).unwrap_or(Rung::Auto), p.quorum_for(cap).unwrap_or(1))
}

/// The most restrictive policy among `pols` that permits `cap`, the first of equals.
fn strictest<'a>(pols: impl Iterator<Item = &'a Policy>, cap: &str) -> Option<&'a Policy> {
    pols.filter(|p| permits(p, cap))
        .fold(None, |best: Option<&Policy>, p| match best {
            Some(b) if bar(b, cap) >= bar(p, cap) => Some(b),
            _ => Some(p),
        })
}

/// The rung and quorum `permitting` puts on `cap`: the most restrictive of each over every policy,
/// so neither the number of policies nor their order can lower the bar any one of them sets. A
/// quorum is only counted where a policy holds the action at `device_signed`.
fn standing_over<'a>(permitting: impl Iterator<Item = &'a Policy>, cap: &str) -> (Rung, u8) {
    permitting.fold((Rung::Auto, 1), |(rung, quorum), p| {
        let rung = p.rung_for(cap).filter(|r| *r != Rung::Deny).map_or(rung, |r| rung.max(r));
        (rung, p.quorum_for(cap).map_or(quorum, |q| quorum.max(q)))
    })
}

/// The policy engine. Holds the policies and grants in scope and resolves decisions.
#[derive(Debug, Default)]
pub struct PolicyEngine {
    policies: Vec<Policy>,
    grants: Vec<Grant>,
}

impl PolicyEngine {
    /// Construct an empty engine. With no grants, *everything* is denied.
    pub fn new() -> Self {
        PolicyEngine::default()
    }

    /// Construct an engine from grants and policies.
    pub fn with(grants: Vec<Grant>, policies: Vec<Policy>) -> Self {
        PolicyEngine { grants, policies }
    }

    /// Add a grant.
    pub fn add_grant(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    /// Add a policy.
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }

    fn policy_by_id(&self, id: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.id == id)
    }

    /// Resolve a request, treating every grant as having unlimited budget. Convenience for
    /// callers that do not track per-grant call counts (tests, dry-run explanations).
    pub fn evaluate(&self, input: &DecisionInput) -> Decision {
        self.resolve(input, &Unmetered).decision
    }

    /// Resolve a request to a full [`Resolution`]. `usage` reports how many calls each grant
    /// (and each agent within it) has already consumed in the grant's current period, so the
    /// engine can apply the two-tier budget. See the module docs for the ordering.
    pub fn resolve(&self, input: &DecisionInput, usage: &dyn GrantUsage) -> Resolution {
        let cap = input.capability_id.as_str();
        let agent = input.agent_id.as_str();
        let now = input.context.requested_at;

        // ── Step 1: gather ENABLED, live grants covering this agent that hold ≥1 policy scoped
        // to this connection, paired with those policies. A disabled or expired grant is fully
        // inert: it contributes neither allows, denies, nor budget. ─────────────────
        let candidates: Vec<(&Grant, Vec<&Policy>)> = self
            .grants
            .iter()
            .filter(|g| g.is_live(now) && g.targets(agent))
            .filter_map(|g| {
                let pols: Vec<&Policy> = g
                    .policy_ids
                    .iter()
                    .filter_map(|pid| self.policy_by_id(pid))
                    .filter(|p| p.connection_id == input.connection_id)
                    .collect();
                (!pols.is_empty()).then_some((g, pols))
            })
            .collect();

        if candidates.is_empty() {
            return Resolution::deny(format!(
                "No enabled grant authorizes '{cap}' on connection '{}' for agent '{agent}'. Denied by default.",
                input.connection_id
            ));
        }

        // ── Step 2: deny wins. An explicit deny on ANY candidate policy → deny. ──────────────
        for (_, pols) in &candidates {
            if let Some(p) = pols.iter().find(|p| p.denies(cap)) {
                return Resolution {
                    decision: Decision::deny(format!("Action '{cap}' is denied by policy {}.", p.id)),
                    rung: Rung::Deny,
                    matched_grant_id: None,
                    matched_policy_id: Some(p.id.clone()),
                    quorum: 1,
                    redact_fields: Vec::new(),
                };
            }
        }

        // ── Step 3: the action must be PERMITTED by ≥1 candidate policy. An action is permitted
        // when any policy lists it on a non-deny rung (allow / notify / requires_approval /
        // device_signed): the `approve`/`device_signed`/`notify` rungs no longer require the
        // action to also sit in `allow`. EVERY permitting policy of every candidate grant
        // contributes its rung and quorum; the most restrictive is applied in step 5. ─────────
        let permitting: Vec<&Policy> = candidates
            .iter()
            .flat_map(|(_, pols)| pols.iter().copied())
            .filter(|p| permits(p, cap))
            .collect();
        // One entry per permitting grant, for budget and charging: the grant and its strictest
        // permitting policy, so the policy a resolution names never depends on `policy_ids` order.
        let allowing: Vec<(&Grant, &Policy)> = candidates
            .iter()
            .filter_map(|(g, pols)| strictest(pols.iter().copied(), cap).map(|p| (*g, p)))
            .collect();
        if allowing.is_empty() {
            return Resolution::deny(format!(
                "No policy on connection '{}' permits '{cap}'. Denied by default.",
                input.connection_id
            ));
        }

        // ── Step 4: two-tier budget. Keep grants with headroom in BOTH tiers. ───────
        let with_budget: Vec<(&Grant, &Policy)> = allowing
            .iter()
            .copied()
            .filter(|(g, _)| grant_has_headroom(g, agent, usage))
            .collect();
        if with_budget.is_empty() {
            // Every allowing grant is over a ceiling. Report the binding limit on the
            // most-permissive one so the operator sees a representative cap, not an arbitrary grant.
            let (g, p) = allowing
                .iter()
                .copied()
                .max_by_key(|(g, _)| grant_remaining(g, agent, usage))
                .unwrap_or(allowing[0]);
            return Resolution {
                decision: Decision::deny(budget_exhausted_reason(g, agent, usage)),
                rung: Rung::Deny,
                matched_grant_id: Some(g.grant_id.clone()),
                matched_policy_id: Some(p.id.clone()),
                quorum: 1,
                redact_fields: Vec::new(),
            };
        }

        // On overlap, charge the most-permissive grant that still has headroom.
        let (grant, policy) = with_budget
            .iter()
            .copied()
            .max_by_key(|(g, _)| grant_remaining(g, agent, usage))
            .unwrap_or(with_budget[0]);

        // ── Step 5: the effective ladder rung, the most restrictive verdict across EVERY
        // permitting policy (not just the charged one), floored by the capability/risk escalation
        // rules. `max` over `Rung` implements "most restrictive wins", so a permissive policy can
        // never lower an action another policy holds at `device_signed`. ────────────────────────
        let (policy_rung, policy_quorum) = standing_over(permitting.iter().copied(), cap);
        // Capability self-declaration and High/Critical risk both floor the rung at `approve`.
        let floor = if input.capability_requires_approval || input.risk >= RiskTier::High {
            Rung::Approve
        } else {
            Rung::Auto
        };
        let rung = policy_rung.max(floor);

        // Every permitting policy, the same set the rung and quorum are read from: a grant binding
        // two policies that both permit the action gets both policies' redactions.
        let mut redact_fields: Vec<String> =
            permitting.iter().flat_map(|p| p.redact_fields.iter().cloned()).collect();
        redact_fields.sort();
        redact_fields.dedup();

        match rung {
            Rung::Approve | Rung::DeviceSigned => {
                // ── Step 6a: hold for a human. ──────────────────────────────────────────────
                let reason = if input.capability_requires_approval {
                    format!("Capability '{cap}' always requires human approval.")
                } else if input.risk >= RiskTier::High && policy_rung < Rung::Approve {
                    format!("Action '{cap}' is classified '{}' risk and requires approval.", input.risk)
                } else if rung == Rung::DeviceSigned {
                    format!("Action '{cap}' requires a device-signed approval per policy {}.", policy.id)
                } else {
                    format!("Action '{cap}' requires approval per policy {}.", policy.id)
                };
                let kind = if rung == Rung::DeviceSigned {
                    ApprovalKind::DeviceSigned
                } else {
                    ApprovalKind::Push
                };
                let approval = ApprovalRequirement::single_use(
                    kind,
                    format!("Approve '{cap}' on '{}'?", input.connection_id),
                );
                let quorum = if rung == Rung::DeviceSigned { policy_quorum } else { 1 };
                Resolution {
                    decision: Decision::requires_approval(reason, approval),
                    rung,
                    matched_grant_id: Some(grant.grant_id.clone()),
                    matched_policy_id: Some(policy.id.clone()),
                    quorum,
                    redact_fields,
                }
            }
            // ── Step 6b: allow (silently for `auto`, with an after-the-fact push for `notify`;
            // the service reads `rung` to fire the notification, so the engine stays pure). ───
            _ => Resolution {
                decision: Decision::allow(format!(
                    "Action '{cap}' allowed by grant {} (policy {}).",
                    grant.grant_id, policy.id
                )),
                rung,
                matched_grant_id: Some(grant.grant_id.clone()),
                matched_policy_id: Some(policy.id.clone()),
                quorum: 1,
                redact_fields,
            },
        }
    }
}

/// serde helper for RFC3339 `OffsetDateTime`.
mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&s, &Rfc3339).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permaura_core::{Action, DecisionKind, GrantAgent, GrantAgents, GrantTarget};
    use time::macros::datetime;

    const CONN: &str = "braintree_production";

    /// Fixed two-tier usage for tests: every grant reads `total` overall and `per_agent` per agent.
    struct FixedUsage {
        total: u64,
        per_agent: u64,
    }
    impl GrantUsage for FixedUsage {
        fn grant_total(&self, _: &str) -> u64 {
            self.total
        }
        fn grant_agent(&self, _: &str, _: &str) -> u64 {
            self.per_agent
        }
    }
    /// Both counters at `n`.
    fn used(n: u64) -> FixedUsage {
        FixedUsage {
            total: n,
            per_agent: n,
        }
    }

    fn policy(id: &str, allow: &[&str], deny: &[&str], approval: &[&str]) -> Policy {
        Policy {
            id: id.into(),
            connection_id: CONN.into(),
            name: id.into(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            requires_approval: approval.iter().map(|s| s.to_string()).collect(),
            notify: vec![],
            device_signed: vec![],
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        }
    }

    /// Build a policy with every ladder list explicitly, for the rung-precedence tests.
    fn policy_rungs(
        id: &str,
        allow: &[&str],
        deny: &[&str],
        approval: &[&str],
        notify: &[&str],
        device_signed: &[&str],
    ) -> Policy {
        Policy {
            id: id.into(),
            connection_id: CONN.into(),
            name: id.into(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            requires_approval: approval.iter().map(|s| s.to_string()).collect(),
            notify: notify.iter().map(|s| s.to_string()).collect(),
            device_signed: device_signed.iter().map(|s| s.to_string()).collect(),
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        }
    }

    /// Build a v2 grant binding one policy to a [`GrantTarget`] (kept for the legacy call sites).
    fn grant(id: &str, policy_id: &str, target: GrantTarget) -> Grant {
        let agents = match target {
            GrantTarget::AllAgents => GrantAgents::AllAgents,
            GrantTarget::Agent(a) => GrantAgents::Agents(vec![GrantAgent::new(a)]),
        };
        Grant {
            grant_id: id.into(),
            name: id.into(),
            enabled: true,
            is_default: false,
            policy_ids: vec![policy_id.into()],
            agents,
            period: GrantPeriod::Total,
            overall_limit: None,
            default_per_agent_limit: None,
            expires_at: None,
        }
    }

    fn input(cap: &str, action: Action, risk: RiskTier) -> DecisionInput {
        DecisionInput {
            capability_id: cap.into(),
            action,
            connection_id: CONN.into(),
            risk,
            capability_requires_approval: false,
            agent_id: "codex-cli".into(),
            context: RequestContext::new("sess_456", datetime!(2026-06-22 15:24:00 +10:00)),
        }
    }

    fn engine(policies: Vec<Policy>, grants: Vec<Grant>) -> PolicyEngine {
        PolicyEngine::with(grants, policies)
    }

    #[test]
    fn read_is_allowed_within_policy_and_grant() {
        let e = engine(
            vec![policy("pol_ro", &["transactions.search"], &[], &[])],
            vec![grant("gr_1", "pol_ro", GrantTarget::Agent("codex-cli".into()))],
        );
        let d = e.evaluate(&input("transactions.search", Action::Search, RiskTier::Medium));
        assert_eq!(d.kind, DecisionKind::Allow);
    }

    #[test]
    fn no_grant_is_denied_by_default() {
        let e = engine(vec![policy("pol_ro", &["transactions.search"], &[], &[])], vec![]);
        let d = e.evaluate(&input("transactions.search", Action::Search, RiskTier::Low));
        assert_eq!(d.kind, DecisionKind::Deny);
        assert!(d.reason.contains("Denied by default"));
    }

    #[test]
    fn action_not_in_allow_list_is_denied_by_default() {
        let e = engine(
            vec![policy("pol_ro", &["transactions.search"], &[], &[])],
            vec![grant("gr_1", "pol_ro", GrantTarget::AllAgents)],
        );
        let d = e.evaluate(&input("transactions.refund", Action::Refund, RiskTier::Critical));
        assert_eq!(d.kind, DecisionKind::Deny);
    }

    #[test]
    fn policy_deny_wins_over_allow() {
        let e = engine(
            vec![policy("pol", &["transactions.refund"], &["transactions.refund"], &[])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        let d = e.evaluate(&input("transactions.refund", Action::Refund, RiskTier::Critical));
        assert_eq!(d.kind, DecisionKind::Deny);
        assert!(d.reason.contains("denied by policy"));
    }

    #[test]
    fn all_agents_grant_covers_any_agent() {
        let e = engine(
            vec![policy("pol_ro", &["transactions.search"], &[], &[])],
            vec![grant("gr_all", "pol_ro", GrantTarget::AllAgents)],
        );
        let mut inp = input("transactions.search", Action::Search, RiskTier::Low);
        inp.agent_id = "some-other-agent".into();
        let d = e.evaluate(&inp);
        assert_eq!(d.kind, DecisionKind::Allow);
    }

    #[test]
    fn specific_grant_does_not_cover_other_agents() {
        let e = engine(
            vec![policy("pol_ro", &["transactions.search"], &[], &[])],
            vec![grant("gr_1", "pol_ro", GrantTarget::Agent("codex-cli".into()))],
        );
        let mut inp = input("transactions.search", Action::Search, RiskTier::Low);
        inp.agent_id = "claude-code".into();
        assert_eq!(e.evaluate(&inp).kind, DecisionKind::Deny);
    }

    #[test]
    fn high_risk_escalates_even_when_allowed() {
        let e = engine(
            vec![policy("pol", &["pull_requests.create"], &[], &[])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        let d = e.evaluate(&input("pull_requests.create", Action::Create, RiskTier::High));
        assert_eq!(d.kind, DecisionKind::RequiresApproval);
    }

    #[test]
    fn policy_requires_approval_escalates_low_risk() {
        let e = engine(
            vec![policy("pol", &["transactions.refund"], &[], &["transactions.refund"])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        // Force Medium risk so the only escalation source is the policy's requires_approval.
        let d = e.evaluate(&input("transactions.refund", Action::Refund, RiskTier::Medium));
        assert_eq!(d.kind, DecisionKind::RequiresApproval);
        assert!(d.approval.is_some());
    }

    // ── Approval ladder: rung precedence ────────────────────────────────────────────────
    // A helper that resolves and returns the effective rung (unmetered budget).
    fn rung_of(e: &PolicyEngine, cap: &str, action: Action, risk: RiskTier) -> Rung {
        e.resolve(&input(cap, action, risk), &Unmetered).rung
    }

    #[test]
    fn notify_rung_allows_but_flags() {
        let e = engine(
            vec![policy_rungs("pol", &[], &[], &[], &["deploy"], &[])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        // A notify action executes (Allow) but carries the Notify rung so the service pushes.
        let res = e.resolve(&input("deploy", Action::Create, RiskTier::Medium), &Unmetered);
        assert_eq!(res.decision.kind, DecisionKind::Allow);
        assert_eq!(res.rung, Rung::Notify);
    }

    #[test]
    fn device_signed_rung_holds_with_device_signed_kind() {
        let e = engine(
            vec![policy_rungs("pol", &[], &[], &[], &[], &["refund"])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        let res = e.resolve(&input("refund", Action::Refund, RiskTier::Medium), &Unmetered);
        assert_eq!(res.decision.kind, DecisionKind::RequiresApproval);
        assert_eq!(res.rung, Rung::DeviceSigned);
        assert_eq!(
            res.decision.approval.map(|a| a.kind),
            Some(permaura_core::ApprovalKind::DeviceSigned)
        );
    }

    #[test]
    fn device_signed_action_need_not_also_be_in_allow() {
        // The action sits ONLY in device_signed, and is still permitted (the old allow-redundancy
        // requirement is gone), and resolves at the DeviceSigned rung.
        let e = engine(
            vec![policy_rungs("pol", &[], &[], &[], &[], &["refund"])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        assert_eq!(rung_of(&e, "refund", Action::Refund, RiskTier::Medium), Rung::DeviceSigned);
    }

    #[test]
    fn in_policy_precedence_takes_most_restrictive_listing() {
        // One action listed on several rungs of one policy resolves to the most restrictive.
        let e = engine(
            vec![policy_rungs("pol", &["act"], &[], &["act"], &["act"], &["act"])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        // deny not present, device_signed wins over approve/notify/auto.
        assert_eq!(rung_of(&e, "act", Action::Create, RiskTier::Low), Rung::DeviceSigned);
    }

    #[test]
    fn most_restrictive_rung_wins_across_policies() {
        // Two policies (via two grants) permit the same action at different rungs; the effective
        // rung is the most restrictive: a permissive policy cannot lower a device_signed one.
        let e = engine(
            vec![
                policy_rungs("pol_lax", &["refund"], &[], &[], &[], &[]),
                policy_rungs("pol_strict", &[], &[], &[], &[], &["refund"]),
            ],
            vec![
                grant("gr_lax", "pol_lax", GrantTarget::AllAgents),
                grant("gr_strict", "pol_strict", GrantTarget::AllAgents),
            ],
        );
        assert_eq!(rung_of(&e, "refund", Action::Refund, RiskTier::Low), Rung::DeviceSigned);
    }

    /// A policy holding `action` at device_signed with an explicit quorum.
    fn policy_quorum(id: &str, action: &str, quorum: u8) -> Policy {
        let mut p = policy_rungs(id, &[], &[], &[], &[], &[action]);
        p.device_signed_quorum = quorum;
        p
    }

    fn quorum_of(e: &PolicyEngine, cap: &str) -> u8 {
        e.resolve(&input(cap, Action::Refund, RiskTier::Low), &used(0)).quorum
    }

    #[test]
    fn the_highest_quorum_wins_across_policies() {
        // Same most-restrictive-wins rule as the rung itself: a second, laxer policy must not be
        // able to talk a two-person action down to one signature.
        let e = engine(
            vec![
                policy_quorum("pol_one", "refund", 1),
                policy_quorum("pol_two", "refund", 2),
            ],
            vec![
                grant("gr_one", "pol_one", GrantTarget::AllAgents),
                grant("gr_two", "pol_two", GrantTarget::AllAgents),
            ],
        );
        assert_eq!(quorum_of(&e, "refund"), 2);
    }

    /// One grant binding `policy_ids`, in that order, for every agent.
    fn grant_of(id: &str, policy_ids: &[&str]) -> Grant {
        let mut g = grant(id, policy_ids[0], GrantTarget::AllAgents);
        g.policy_ids = policy_ids.iter().map(|p| p.to_string()).collect();
        g
    }

    #[test]
    fn a_stricter_policy_added_to_the_same_grant_raises_the_rung() {
        // Attaching a policy appends it, so the guard lands after the base policy that already
        // permits the action. Reading only the first permitting policy ran the refund at auto.
        let e = engine(
            vec![
                policy_rungs("pol_base", &["refund"], &[], &[], &[], &[]),
                policy_rungs("pol_guard", &[], &[], &[], &[], &["refund"]),
            ],
            vec![grant_of("gr", &["pol_base", "pol_guard"])],
        );
        let r = e.resolve(&input("refund", Action::Refund, RiskTier::Low), &used(0));
        assert_eq!(r.rung, Rung::DeviceSigned);
        assert_eq!(r.decision.kind, DecisionKind::RequiresApproval);
        assert_eq!(r.matched_policy_id.as_deref(), Some("pol_guard"));
    }

    #[test]
    fn the_highest_quorum_wins_within_one_grant() {
        let e = engine(
            vec![policy_quorum("pol_one", "refund", 1), policy_quorum("pol_two", "refund", 2)],
            vec![grant_of("gr", &["pol_one", "pol_two"])],
        );
        assert_eq!(quorum_of(&e, "refund"), 2);
    }

    #[test]
    fn the_order_of_a_grants_policies_never_changes_the_rung_or_quorum() {
        let policies = || {
            vec![
                policy_rungs("pol_auto", &["refund"], &[], &[], &[], &[]),
                policy_rungs("pol_notify", &[], &[], &[], &["refund"], &[]),
                policy_quorum("pol_two", "refund", 2),
                policy_rungs("pol_appr", &[], &[], &["refund"], &[], &[]),
            ]
        };
        let ids = ["pol_auto", "pol_notify", "pol_two", "pol_appr"];
        let orders: [[usize; 4]; 4] = [[0, 1, 2, 3], [3, 2, 1, 0], [2, 0, 3, 1], [1, 3, 0, 2]];
        for order in orders {
            let bound: Vec<&str> = order.iter().map(|i| ids[*i]).collect();
            let e = engine(policies(), vec![grant_of("gr", &bound)]);
            let r = e.resolve(&input("refund", Action::Refund, RiskTier::Low), &used(0));
            assert_eq!((r.rung, r.quorum), (Rung::DeviceSigned, 2), "order {bound:?}");
        }
    }

    #[test]
    fn a_quorum_only_applies_to_the_device_signed_rung() {
        // The same action held at `approve` has nothing to count signatures for, so the quorum a
        // policy carries must not leak into a rung that a bearer can resolve.
        let mut lax = policy_rungs("pol_appr", &[], &[], &["refund"], &[], &[]);
        lax.device_signed_quorum = 5;
        let e = engine(vec![lax], vec![grant("gr", "pol_appr", GrantTarget::AllAgents)]);
        let r = e.resolve(&input("refund", Action::Refund, RiskTier::Low), &used(0));
        assert_eq!(r.rung, Rung::Approve);
        assert_eq!(r.quorum, 1);
    }

    #[test]
    fn a_zero_quorum_still_means_one_signature() {
        // Deny-by-default in miniature: a zero would mean a device-signed action that runs with
        // no signature at all, so it floors at one wherever it is read.
        let e = engine(
            vec![policy_quorum("pol_zero", "refund", 0)],
            vec![grant("gr", "pol_zero", GrantTarget::AllAgents)],
        );
        assert_eq!(quorum_of(&e, "refund"), 1);
    }

    #[test]
    fn deny_still_wins_over_any_rung() {
        let e = engine(
            vec![
                policy_rungs("pol_ds", &[], &[], &[], &[], &["refund"]),
                policy_rungs("pol_deny", &[], &["refund"], &[], &[], &[]),
            ],
            vec![
                grant("gr_ds", "pol_ds", GrantTarget::AllAgents),
                grant("gr_deny", "pol_deny", GrantTarget::AllAgents),
            ],
        );
        assert_eq!(rung_of(&e, "refund", Action::Refund, RiskTier::Low), Rung::Deny);
    }

    #[test]
    fn risk_floor_still_escalates_to_approve_not_device_signed() {
        // High risk floors at Approve (unchanged), and never auto-derives DeviceSigned.
        let e = engine(
            vec![policy_rungs("pol", &["create"], &[], &[], &[], &[])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        assert_eq!(rung_of(&e, "create", Action::Create, RiskTier::High), Rung::Approve);
    }

    #[test]
    fn device_signed_policy_beats_high_risk_floor() {
        // When both the risk floor (Approve) and a policy (DeviceSigned) apply, the max wins.
        let e = engine(
            vec![policy_rungs("pol", &[], &[], &[], &[], &["create"])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        assert_eq!(rung_of(&e, "create", Action::Create, RiskTier::High), Rung::DeviceSigned);
    }

    #[test]
    fn expired_grant_is_denied() {
        let mut g = grant("gr_1", "pol_ro", GrantTarget::AllAgents);
        g.expires_at = Some(datetime!(2026-06-22 14:00:00 +10:00)); // before requested_at 15:24
        let e = engine(vec![policy("pol_ro", &["transactions.search"], &[], &[])], vec![g]);
        let d = e.evaluate(&input("transactions.search", Action::Search, RiskTier::Low));
        // An expired grant is inert: it simply doesn't count, so the verdict is deny-by-default.
        assert_eq!(d.kind, DecisionKind::Deny);
        assert!(d.reason.contains("Denied by default"));
    }

    #[test]
    fn exhausted_per_agent_budget_is_denied() {
        let mut g = grant("gr_1", "pol_ro", GrantTarget::AllAgents);
        g.default_per_agent_limit = Some(5);
        let e = engine(vec![policy("pol_ro", &["transactions.search"], &[], &[])], vec![g]);
        let res = e.resolve(
            &input("transactions.search", Action::Search, RiskTier::Low),
            &used(5),
        );
        assert_eq!(res.decision.kind, DecisionKind::Deny);
        assert!(res.decision.reason.contains("per-agent budget"));
    }

    #[test]
    fn budget_under_max_is_allowed_and_reports_chain() {
        let mut g = grant("gr_1", "pol_ro", GrantTarget::AllAgents);
        g.default_per_agent_limit = Some(5);
        let e = engine(vec![policy("pol_ro", &["transactions.search"], &[], &[])], vec![g]);
        let res = e.resolve(
            &input("transactions.search", Action::Search, RiskTier::Low),
            &used(4),
        );
        assert_eq!(res.decision.kind, DecisionKind::Allow);
        assert_eq!(res.matched_grant_id.as_deref(), Some("gr_1"));
        assert_eq!(res.matched_policy_id.as_deref(), Some("pol_ro"));
    }

    #[test]
    fn overall_limit_rules_all_even_with_per_agent_headroom() {
        // If the overall limit is set, that rules all. Per-agent has room, overall is hit.
        let mut g = grant("gr_1", "pol_ro", GrantTarget::AllAgents);
        g.overall_limit = Some(10);
        g.default_per_agent_limit = Some(100);
        let e = engine(vec![policy("pol_ro", &["transactions.search"], &[], &[])], vec![g]);
        let res = e.resolve(
            &input("transactions.search", Action::Search, RiskTier::Low),
            &FixedUsage { total: 10, per_agent: 1 },
        );
        assert_eq!(res.decision.kind, DecisionKind::Deny);
        assert!(res.decision.reason.contains("overall budget"));
    }

    #[test]
    fn per_agent_override_beats_default() {
        // claude-code has its own ceiling of 2; codex-cli falls back to the default of 100.
        let mut g = grant("gr_1", "pol_ro", GrantTarget::AllAgents);
        g.agents = GrantAgents::Agents(vec![
            GrantAgent { agent_id: "claude-code".into(), per_agent_limit: Some(2) },
            GrantAgent::new("codex-cli"),
        ]);
        g.default_per_agent_limit = Some(100);
        let e = engine(vec![policy("pol_ro", &["transactions.search"], &[], &[])], vec![g]);
        // claude-code at 2/2 used → denied.
        let mut inp = input("transactions.search", Action::Search, RiskTier::Low);
        inp.agent_id = "claude-code".into();
        assert_eq!(
            e.resolve(&inp, &FixedUsage { total: 0, per_agent: 2 }).decision.kind,
            DecisionKind::Deny
        );
        // codex-cli at 2 used is still well under its 100 default → allowed.
        let inp2 = input("transactions.search", Action::Search, RiskTier::Low); // agent codex-cli
        assert_eq!(
            e.resolve(&inp2, &FixedUsage { total: 0, per_agent: 2 }).decision.kind,
            DecisionKind::Allow
        );
    }

    #[test]
    fn disabled_grant_is_inert() {
        let mut g = grant("gr_1", "pol_ro", GrantTarget::AllAgents);
        g.enabled = false;
        let e = engine(vec![policy("pol_ro", &["transactions.search"], &[], &[])], vec![g]);
        let d = e.evaluate(&input("transactions.search", Action::Search, RiskTier::Low));
        assert_eq!(d.kind, DecisionKind::Deny);
        assert!(d.reason.contains("Denied by default"));
    }

    #[test]
    fn overlapping_grants_charge_the_one_with_headroom() {
        // Two grants allow the same action: a small one (exhausted) and a large one (has room).
        // The decision is allow, charged to the grant that still has budget.
        let mut small = grant("gr_small", "pol_ro", GrantTarget::AllAgents);
        small.default_per_agent_limit = Some(5);
        let mut big = grant("gr_big", "pol_ro2", GrantTarget::AllAgents);
        big.default_per_agent_limit = Some(1000);
        let e = engine(
            vec![
                policy("pol_ro", &["transactions.search"], &[], &[]),
                policy("pol_ro2", &["transactions.search"], &[], &[]),
            ],
            vec![small, big],
        );
        let res = e.resolve(
            &input("transactions.search", Action::Search, RiskTier::Low),
            &FixedUsage { total: 5, per_agent: 5 }, // small is exhausted, big has 995 left
        );
        assert_eq!(res.decision.kind, DecisionKind::Allow);
        assert_eq!(res.matched_grant_id.as_deref(), Some("gr_big"));
    }

    #[test]
    fn multi_policy_grant_resolves_the_connection_scoped_policy() {
        // One grant bundles two policies on two connections; only the matching connection's
        // policy is consulted.
        let other = Policy {
            id: "pol_other".into(),
            connection_id: "github_acme".into(),
            name: "gh".into(),
            allow: vec!["pull_requests.read".into()],
            deny: vec![],
            requires_approval: vec![],
            notify: vec![],
            device_signed: vec![],
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        };
        let here = policy("pol_ro", &["transactions.search"], &[], &[]);
        let mut g = grant("gr_bundle", "pol_ro", GrantTarget::AllAgents);
        g.policy_ids = vec!["pol_ro".into(), "pol_other".into()];
        let e = engine(vec![here, other], vec![g]);
        // The braintree action resolves via pol_ro (github policy is out of scope here).
        let d = e.evaluate(&input("transactions.search", Action::Search, RiskTier::Low));
        assert_eq!(d.kind, DecisionKind::Allow);
    }

    /// The signature demo: a prompt-injection makes the agent attempt a refund it was never
    /// granted. With a read-only policy that denies refunds, it must be a hard deny.
    #[test]
    fn prompt_injection_refund_is_not_silently_allowed() {
        let e = engine(
            vec![policy(
                "pol_ro",
                &["transactions.search", "transactions.read", "customers.read"],
                &["transactions.refund", "transactions.sale", "transactions.void"],
                &[],
            )],
            vec![grant("gr_1", "pol_ro", GrantTarget::Agent("codex-cli".into()))],
        );
        let d = e.evaluate(&input("transactions.refund", Action::Refund, RiskTier::Critical));
        assert_eq!(d.kind, DecisionKind::Deny);
        assert_ne!(d.kind, DecisionKind::Allow);
    }

    #[test]
    fn empty_engine_denies_everything() {
        let e = PolicyEngine::new();
        assert_eq!(
            e.evaluate(&input("transactions.search", Action::Search, RiskTier::Low)).kind,
            DecisionKind::Deny
        );
    }

    fn redacting(mut p: Policy, fields: &[&str]) -> Policy {
        p.redact_fields = fields.iter().map(|s| s.to_string()).collect();
        p
    }

    #[test]
    fn redaction_unions_every_permitting_policy_across_grants() {
        // The charged grant's policy redacts nothing; a second permitting policy on another grant
        // redacts email. The laxer one cannot switch the other's redaction off.
        let mut small = grant("gr_small", "pol_a", GrantTarget::AllAgents);
        small.default_per_agent_limit = Some(1000);
        let mut big = grant("gr_big", "pol_b", GrantTarget::AllAgents);
        big.default_per_agent_limit = Some(5);
        let e = engine(
            vec![
                policy("pol_a", &["transactions.search"], &[], &[]),
                redacting(policy("pol_b", &["transactions.search"], &[], &[]), &["email", "card.number"]),
            ],
            vec![small, big],
        );
        let res = e.resolve(&input("transactions.search", Action::Search, RiskTier::Low), &used(0));
        assert_eq!(res.decision.kind, DecisionKind::Allow);
        assert_eq!(res.matched_grant_id.as_deref(), Some("gr_small"));
        assert_eq!(res.redact_fields, vec!["card.number".to_string(), "email".to_string()]);
    }

    #[test]
    fn redaction_includes_a_second_permitting_policy_on_the_same_grant() {
        let mut g = grant("gr_1", "pol_a", GrantTarget::AllAgents);
        g.policy_ids.push("pol_b".into());
        let e = engine(
            vec![
                redacting(policy("pol_a", &["transactions.search"], &[], &[]), &["phone"]),
                redacting(policy("pol_b", &["transactions.search"], &[], &[]), &["email", "phone"]),
            ],
            vec![g],
        );
        let res = e.resolve(&input("transactions.search", Action::Search, RiskTier::Low), &used(0));
        assert_eq!(res.redact_fields, vec!["email".to_string(), "phone".to_string()]);
    }

    #[test]
    fn redaction_rides_along_on_a_held_call() {
        let e = engine(
            vec![redacting(policy("pol", &[], &[], &["transactions.refund"]), &["email"])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        let res = e.resolve(&input("transactions.refund", Action::Refund, RiskTier::Critical), &used(0));
        assert_eq!(res.decision.kind, DecisionKind::RequiresApproval);
        assert_eq!(res.redact_fields, vec!["email".to_string()]);
    }

    #[test]
    fn a_policy_silent_on_the_action_contributes_no_redaction() {
        let mut g = grant("gr_1", "pol_a", GrantTarget::AllAgents);
        g.policy_ids.push("pol_other".into());
        let e = engine(
            vec![
                policy("pol_a", &["transactions.search"], &[], &[]),
                redacting(policy("pol_other", &["customers.read"], &[], &[]), &["email"]),
            ],
            vec![g],
        );
        let res = e.resolve(&input("transactions.search", Action::Search, RiskTier::Low), &used(0));
        assert_eq!(res.decision.kind, DecisionKind::Allow);
        assert!(res.redact_fields.is_empty());
    }

    #[test]
    fn a_denial_carries_no_redaction() {
        let e = engine(
            vec![redacting(policy("pol", &[], &["transactions.refund"], &[]), &["email"])],
            vec![grant("gr_1", "pol", GrantTarget::AllAgents)],
        );
        let res = e.resolve(&input("transactions.refund", Action::Refund, RiskTier::Critical), &used(0));
        assert_eq!(res.decision.kind, DecisionKind::Deny);
        assert!(res.redact_fields.is_empty());
    }
}
