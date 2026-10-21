//! Property tests for every "is this change a tightening?" classifier in [`crate::policy_guard`].
//!
//! Each test enumerates a small domain exhaustively and checks one classifier against [`access`], an effective-access oracle written from the engine's documented semantics (deny wins, every permitting policy of every live grant that reaches the agent sets the bar, each such grant meters in two tiers, every permitting policy adds its redaction), never from the guard's own helpers. The property is the same throughout: whenever a classifier calls a change tightening, no principal can do anything afterwards, at any moment from now on, that it could not do before. [`the_oracle_agrees_with_the_engine`] keeps the oracle honest against `permaura_policy`.

use super::*;
use crate::error::GatewayError;
use crate::store::AgentStatus;
use permaura_core::{GrantAgent, GrantAgents, GrantPeriod};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

const CONN: &str = "c";
const OTHER_CONN: &str = "d";
const CONNS: [&str; 2] = [CONN, OTHER_CONN];
const ACTIONS: [&str; 2] = ["x", "y"];
/// `a` and `b` are named by grants, `u` is approved and named by none (only an all-agents grant reaches it), and
/// `n` has never been seen, so it lands approved on its first call exactly when the new-agent gate is off.
const AGENTS: [&str; 4] = ["a", "b", "u", "n"];

// ── The oracle ──────────────────────────────────────────────────────────────────────────────────

/// Everything that decides what an agent may do: the store, plus the runtime switches above policy.
#[derive(Clone, Debug)]
struct World {
    policies: Vec<Policy>,
    grants: Vec<Grant>,
    connections: Vec<Connection>,
    agents: Vec<Agent>,
    /// Agents removed by a delete. A tombstone keeps each from registering again on its own.
    removed: Vec<String>,
    /// How many times each connection's SSH target was changed: where its credential goes.
    retargeted: BTreeMap<String, u32>,
    paused: bool,
    require_agent_approval: bool,
}

/// One grant's budget for one agent, as the engine meters it.
#[derive(Clone, Debug, PartialEq)]
struct Budget {
    grant_id: String,
    overall: Option<u64>,
    per_agent: Option<u64>,
    period: GrantPeriod,
}

/// What an agent may do with one action at one moment.
#[derive(Clone, Debug, PartialEq)]
enum Access {
    Denied,
    Permitted {
        rung: Rung,
        quorum: u8,
        redact: BTreeSet<String>,
        budgets: Vec<Budget>,
        target: u32,
    },
}

fn capability_id(conn: &str, action: &str) -> String {
    format!("{conn}.{action}")
}

/// One policy's verdict on an action, read straight off its lists, the most restrictive listing first.
fn verdict(p: &Policy, action: &str) -> Option<(Rung, u8)> {
    let on = |list: &[String]| list.iter().any(|a| a == action);
    if on(&p.deny) {
        Some((Rung::Deny, 1))
    } else if on(&p.device_signed) {
        Some((Rung::DeviceSigned, p.device_signed_quorum.max(1)))
    } else if on(&p.requires_approval) {
        Some((Rung::Approve, 1))
    } else if on(&p.notify) {
        Some((Rung::Notify, 1))
    } else if on(&p.allow) {
        Some((Rung::Auto, 1))
    } else {
        None
    }
}

fn reaches(g: &Grant, agent: &str) -> bool {
    match &g.agents {
        GrantAgents::AllAgents => true,
        GrantAgents::Agents(members) => members.iter().any(|m| m.agent_id == agent),
    }
}

/// The agent's own ceiling in `g`: the first row naming it, if that row sets one, else the grant's default.
fn per_agent(g: &Grant, agent: &str) -> Option<u64> {
    let own = match &g.agents {
        GrantAgents::AllAgents => None,
        GrantAgents::Agents(members) => members.iter().find(|m| m.agent_id == agent).and_then(|m| m.per_agent_limit),
    };
    own.or(g.default_per_agent_limit)
}

fn live(g: &Grant, at: OffsetDateTime) -> bool {
    g.enabled && g.expires_at.map_or(true, |e| at < e)
}

fn access(w: &World, agent: &str, conn: &str, action: &str, at: OffsetDateTime) -> Access {
    let approved = match w.agents.iter().find(|a| a.id == agent) {
        Some(a) => a.status == AgentStatus::Approved,
        None => !w.removed.iter().any(|r| r == agent) && !w.require_agent_approval,
    };
    let Some(c) = w.connections.iter().find(|c| c.id == conn) else { return Access::Denied };
    if w.paused || !approved || c.disabled || c.disabled_capabilities.contains(&capability_id(conn, action)) {
        return Access::Denied;
    }
    let mut bars = Vec::new();
    let mut budgets = Vec::new();
    let mut redact = BTreeSet::new();
    for g in w.grants.iter().filter(|g| live(g, at) && reaches(g, agent)) {
        let mut permits = false;
        for id in &g.policy_ids {
            let Some(p) = w.policies.iter().find(|p| &p.id == id) else { continue };
            if p.connection_id != conn {
                continue;
            }
            match verdict(p, action) {
                Some((Rung::Deny, _)) => return Access::Denied,
                Some(bar) => {
                    bars.push(bar);
                    permits = true;
                    redact.extend(p.redact_fields.iter().map(|f| f.trim().to_ascii_lowercase()).filter(|f| !f.is_empty()));
                }
                None => {}
            }
        }
        if permits {
            budgets.push(Budget {
                grant_id: g.grant_id.clone(),
                overall: g.overall_limit,
                per_agent: per_agent(g, agent),
                period: g.period,
            });
        }
    }
    // A grant whose ceiling is zero still sets the bar but can never pay for a call.
    budgets.retain(|b| b.overall != Some(0) && b.per_agent != Some(0));
    match bars.iter().max() {
        Some(&(rung, quorum)) if !budgets.is_empty() => Access::Permitted {
            rung,
            quorum,
            redact,
            budgets,
            target: w.retargeted.get(conn).copied().unwrap_or(0),
        },
        _ => Access::Denied,
    }
}

/// `new` at most `old`, where `None` is unlimited.
fn at_most(new: Option<u64>, old: Option<u64>) -> bool {
    match (new, old) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(n), Some(o)) => n <= o,
    }
}

fn budget_within(new: &Budget, old: &Budget) -> bool {
    let unlimited = new.overall.is_none() && new.per_agent.is_none();
    new.grant_id == old.grant_id
        && at_most(new.overall, old.overall)
        && at_most(new.per_agent, old.per_agent)
        && (unlimited || new.period == old.period)
}

/// Whether `after` lets the agent do nothing `before` did not: no lower bar, no lost redaction, no new or larger
/// budget, and its credential still goes where it went.
fn within(after: &Access, before: &Access) -> bool {
    match (after, before) {
        (Access::Denied, _) => true,
        (Access::Permitted { .. }, Access::Denied) => false,
        (
            Access::Permitted { rung, quorum, redact, budgets, target },
            Access::Permitted { rung: rung0, quorum: quorum0, redact: redact0, budgets: budgets0, target: target0 },
        ) => {
            (rung, quorum) >= (rung0, quorum0)
                && redact.is_superset(redact0)
                && target == target0
                && budgets.iter().all(|b| budgets0.iter().any(|b0| budget_within(b, b0)))
        }
    }
}

/// The bar alone, for the classifiers that leave budget and redaction to others by contract.
fn bar(a: &Access) -> Option<(Rung, u8)> {
    match a {
        Access::Denied => None,
        Access::Permitted { rung, quorum, .. } => Some((*rung, *quorum)),
    }
}

fn bar_within(after: &Access, before: &Access) -> bool {
    match (bar(after), bar(before)) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => a >= b,
    }
}

/// Now, and every later moment a grant in either world expires. What is in force only changes at those moments,
/// so checking each is checking every moment from now on.
fn instants(worlds: &[&World]) -> Vec<OffsetDateTime> {
    let now = OffsetDateTime::now_utc();
    let mut at: Vec<OffsetDateTime> =
        worlds.iter().flat_map(|w| w.grants.iter().filter_map(|g| g.expires_at)).filter(|e| *e > now).collect();
    at.push(now);
    at.sort();
    at.dedup();
    at
}

/// Every (agent, connection, action, moment) at which `after` lets someone do more than `before`, as
/// `(description, the quorum the action took before)`.
fn widenings(before: &World, after: &World, compare: fn(&Access, &Access) -> bool) -> Vec<(String, u8)> {
    let now = OffsetDateTime::now_utc();
    let mut out = Vec::new();
    for at in instants(&[before, after]) {
        for agent in AGENTS {
            for conn in CONNS {
                for action in ACTIONS {
                    let was = access(before, agent, conn, action, at);
                    let is = access(after, agent, conn, action, at);
                    if !compare(&is, &was) {
                        let quorum = bar(&was).map_or(1, |(_, q)| q);
                        let when = (at - now).whole_minutes();
                        out.push((format!("{agent} on {conn}.{action} at now+{when}min: {was:?} became {is:?}"), quorum));
                    }
                }
            }
        }
    }
    out
}

fn widened(before: &World, after: &World) -> Option<String> {
    widenings(before, after, within).into_iter().next().map(|(why, _)| why)
}

/// Collects the cases a property fails on, and refuses to pass a test whose property no case reached.
#[derive(Default)]
struct Verdicts {
    checked: usize,
    failures: Vec<String>,
}

impl Verdicts {
    fn fail(&mut self, case: String) {
        self.failures.push(case);
    }

    fn finish(self, what: &str) {
        assert!(self.checked > 0, "{what}: no case reached the property, so it was never exercised");
        assert!(
            self.failures.is_empty(),
            "{what}: {} of {} cases checked break the property. First ones:\n{}",
            self.failures.len(),
            self.checked,
            self.failures.iter().take(5).cloned().collect::<Vec<_>>().join("\n\n")
        );
    }
}

/// The store change a mutation makes, written from `apply_mutation`'s arms rather than from the guard.
fn apply(w: &World, m: &Mutation) -> World {
    let mut w = w.clone();
    match m {
        Mutation::PolicyUpsert { policy, grant_ids } => {
            w.policies.retain(|p| p.id != policy.id);
            w.policies.push(policy.clone());
            if let Some(ids) = grant_ids {
                for g in &mut w.grants {
                    let want = ids.contains(&g.grant_id);
                    let has = g.policy_ids.contains(&policy.id);
                    if want && !has {
                        g.policy_ids.push(policy.id.clone());
                    } else if !want && has {
                        g.policy_ids.retain(|p| p != &policy.id);
                    }
                }
            }
        }
        Mutation::PolicyDelete { policy_id } => {
            w.policies.retain(|p| &p.id != policy_id);
            for g in &mut w.grants {
                g.policy_ids.retain(|p| p != policy_id);
            }
        }
        Mutation::GrantUpsert { grant } => {
            match w.grants.iter_mut().find(|g| g.grant_id == grant.grant_id) {
                Some(slot) => *slot = grant.clone(),
                None => w.grants.push(grant.clone()),
            }
            if grant.is_default {
                for g in w.grants.iter_mut().filter(|g| g.grant_id != grant.grant_id) {
                    g.is_default = false;
                }
            }
        }
        Mutation::GrantDelete { grant_id } => w.grants.retain(|g| &g.grant_id != grant_id),
        Mutation::CapabilityEnable { connection_id, capability } => {
            for c in w.connections.iter_mut().filter(|c| &c.id == connection_id) {
                c.disabled_capabilities.retain(|d| d != capability);
            }
        }
        Mutation::ConnectionPatch { connection_id, patch } => {
            if let Some(c) = w.connections.iter_mut().find(|c| &c.id == connection_id) {
                if let Some(disabled) = patch.disabled {
                    c.disabled = disabled;
                }
                if let Some(label) = &patch.label {
                    c.label = label.clone();
                }
                if let Some(name) = &patch.name {
                    c.name = name.clone();
                }
                if patch.ssh.is_some() {
                    *w.retargeted.entry(connection_id.clone()).or_default() += 1;
                }
            }
        }
        Mutation::AgentApprove { agent_id } => {
            for a in w.agents.iter_mut().filter(|a| &a.id == agent_id) {
                a.status = AgentStatus::Approved;
            }
        }
        Mutation::AgentUpsert { agent } => match w.agents.iter_mut().find(|a| a.id == agent.id) {
            Some(slot) => *slot = agent.clone(),
            None => w.agents.push(agent.clone()),
        },
        Mutation::AgentDelete { agent_id } => {
            if w.agents.iter().any(|a| &a.id == agent_id) {
                w.agents.retain(|a| &a.id != agent_id);
                w.removed.push(agent_id.clone());
                w.grants.retain_mut(|g| match &mut g.agents {
                    GrantAgents::Agents(members) if members.iter().any(|m| &m.agent_id == agent_id) => {
                        members.retain(|m| &m.agent_id != agent_id);
                        !members.is_empty() || g.is_default
                    }
                    _ => true,
                });
            }
        }
        Mutation::ConnectionDelete { connection_id } => {
            if w.connections.iter().any(|c| &c.id == connection_id) {
                let gone: Vec<String> =
                    w.policies.iter().filter(|p| &p.connection_id == connection_id).map(|p| p.id.clone()).collect();
                for g in &mut w.grants {
                    g.policy_ids.retain(|p| !gone.contains(p));
                }
                w.policies.retain(|p| &p.connection_id != connection_id);
                w.connections.retain(|c| &c.id != connection_id);
            }
        }
        Mutation::SecretDelete { .. } => {}
        Mutation::BrokerToggle { toggle, value } => match toggle {
            BrokerToggleKind::Pause => w.paused = *value,
            BrokerToggleKind::RequireAgentApproval => w.require_agent_approval = *value,
        },
        other => unreachable!("not a change the oracle models: {other:?}"),
    }
    w
}

fn ctx(w: &World) -> GuardContext<'_> {
    GuardContext { policies: &w.policies, grants: &w.grants, connections: &w.connections, agents: &w.agents }
}

// ── Building worlds ─────────────────────────────────────────────────────────────────────────────

/// Where a policy puts one action.
#[derive(Clone, Copy, Debug)]
enum On {
    Silent,
    Deny,
    Auto,
    Notify,
    Approve,
    Signed(u8),
}

const EVERY_RUNG: [On; 8] =
    [On::Silent, On::Deny, On::Auto, On::Notify, On::Approve, On::Signed(1), On::Signed(2), On::Signed(3)];
const FEW_RUNGS: [On; 4] = [On::Silent, On::Deny, On::Auto, On::Signed(2)];

fn policy(id: &str, conn: &str, on: &[(&str, On)], redact: &[&str]) -> Policy {
    let mut p = Policy {
        id: id.into(),
        connection_id: conn.into(),
        name: id.into(),
        device_signed_quorum: 1,
        redact_fields: redact.iter().map(|s| s.to_string()).collect(),
        ..Policy::default()
    };
    for (action, rung) in on {
        let a = action.to_string();
        match rung {
            On::Silent => {}
            On::Deny => p.deny.push(a),
            On::Auto => p.allow.push(a),
            On::Notify => p.notify.push(a),
            On::Approve => p.requires_approval.push(a),
            On::Signed(q) => {
                p.device_signed.push(a);
                p.device_signed_quorum = p.device_signed_quorum.max(*q);
            }
        }
    }
    p
}

/// Every way of putting each of `actions` on one of `rungs`.
fn shapes<'a>(actions: &[&'a str], rungs: &[On]) -> Vec<Vec<(&'a str, On)>> {
    actions.iter().fold(vec![Vec::new()], |acc, action| {
        acc.iter()
            .flat_map(|shape| {
                rungs.iter().map(move |r| {
                    let mut s = shape.clone();
                    s.push((*action, *r));
                    s
                })
            })
            .collect()
    })
}

fn grant(id: &str, policies: &[&str], agents: GrantAgents) -> Grant {
    Grant {
        grant_id: id.into(),
        name: id.into(),
        enabled: true,
        is_default: false,
        policy_ids: policies.iter().map(|s| s.to_string()).collect(),
        agents,
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    }
}

fn members(rows: &[(&str, Option<u64>)]) -> GrantAgents {
    GrantAgents::Agents(rows.iter().map(|(id, limit)| GrantAgent { agent_id: id.to_string(), per_agent_limit: *limit }).collect())
}

fn connection(id: &str) -> Connection {
    Connection {
        id: id.into(),
        connector: "generic-http".into(),
        name: id.into(),
        label: id.into(),
        secret_id: String::new(),
        capabilities: ACTIONS.iter().map(|a| capability_id(id, a)).collect(),
        disabled_capabilities: Vec::new(),
        disabled: false,
        allowed_hosts: Vec::new(),
        created_at: 0,
        redact_fields: Vec::new(),
        source: None,
        made_from: None,
    }
}

fn agent(id: &str, status: AgentStatus) -> Agent {
    Agent { id: id.into(), name: id.into(), status, enrolled_at: 0 }
}

fn world(policies: Vec<Policy>, grants: Vec<Grant>) -> World {
    World {
        policies,
        grants,
        connections: CONNS.iter().map(|c| connection(c)).collect(),
        agents: ["a", "b", "u"].iter().map(|id| agent(id, AgentStatus::Approved)).collect(),
        removed: Vec::new(),
        retargeted: BTreeMap::new(),
        paused: false,
        require_agent_approval: true,
    }
}

fn hours(n: i64) -> Option<OffsetDateTime> {
    Some(OffsetDateTime::now_utc() + Duration::hours(n))
}

/// The edited grant's possible shapes for the estate tests: which of `p` and `q` it binds, who it reaches (with a
/// member raised above the default of 5), whether it is on, and when it ends (or ended).
fn estate_grants() -> Vec<Grant> {
    let mut out = Vec::new();
    for policies in [&[][..], &["p"], &["q"], &["p", "q"]] {
        for agents in [GrantAgents::AllAgents, members(&[("a", None)]), members(&[("a", Some(10))]), members(&[("b", None)])] {
            for enabled in [true, false] {
                for expires_at in [None, hours(-1), hours(1), hours(2)] {
                    out.push(Grant {
                        enabled,
                        expires_at,
                        default_per_agent_limit: Some(5),
                        ..grant("g1", policies, agents.clone())
                    });
                }
            }
        }
    }
    out
}

/// Estates around the edited grant `g1`: `p` is a deny, a two- or three-person rule, an approval or a redacting
/// permit, `q` a plain permit, and `g2` binds `q` beside `g1` for every agent, for every agent until an hour from
/// now, or for `a` alone, or is absent.
fn estates() -> Vec<(World, Grant)> {
    let ps = [
        policy("p", CONN, &[("x", On::Deny)], &[]),
        policy("p", CONN, &[("x", On::Signed(2))], &[]),
        policy("p", CONN, &[("x", On::Signed(3))], &[]),
        policy("p", CONN, &[("x", On::Approve)], &[]),
        policy("p", CONN, &[("x", On::Auto)], &["Token"]),
    ];
    let q = policy("q", CONN, &[("x", On::Auto), ("y", On::Auto)], &[]);
    let besides = [
        None,
        Some(grant("g2", &["q"], GrantAgents::AllAgents)),
        Some(Grant { expires_at: hours(1), ..grant("g2", &["q"], GrantAgents::AllAgents) }),
        Some(grant("g2", &["q"], members(&[("a", None)]))),
    ];
    let mut out = Vec::new();
    for p in &ps {
        for beside in &besides {
            for g1 in estate_grants() {
                let grants = std::iter::once(g1.clone()).chain(beside.clone()).collect();
                out.push((world(vec![p.clone(), q.clone()], grants), g1));
            }
        }
    }
    out
}

// ── Policy classifiers ──────────────────────────────────────────────────────────────────────────

/// The domains the policy tests run over: one action across every rung with up to two other policies beside it,
/// and two actions across fewer rungs with up to one.
fn policy_domains() -> Vec<(Vec<&'static str>, Vec<On>, usize)> {
    vec![(vec!["x"], EVERY_RUNG.to_vec(), 2), (vec!["x", "y"], FEW_RUNGS.to_vec(), 1)]
}

/// Every set of up to `max` other policies on [`CONN`], from `shapes`.
fn others(shapes: &[Vec<(&str, On)>], max: usize) -> Vec<Vec<Policy>> {
    let mut out: Vec<Vec<Policy>> = vec![Vec::new()];
    for n in 1..=max {
        let mut next = Vec::new();
        for set in out.iter().filter(|s| s.len() == n - 1) {
            for s in shapes {
                let mut more = set.clone();
                more.push(policy(&format!("o{n}"), CONN, s, &[]));
                next.push(more);
            }
        }
        out.extend(next);
    }
    out
}

/// Every way of binding `p` and `others` to two all-agents grants, `ga` metered at 5 calls and `gb` unmetered:
/// `p` in one of them, each other policy in one or in neither.
fn bindings(others: &[Policy]) -> Vec<Vec<Grant>> {
    let mut out = Vec::new();
    let ways = 3usize.pow(others.len() as u32);
    for p_in_a in [true, false] {
        for mut way in 0..ways {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            if p_in_a { a.push("p") } else { b.push("p") }
            for o in others {
                match way % 3 {
                    0 => a.push(o.id.as_str()),
                    1 => b.push(o.id.as_str()),
                    _ => {}
                }
                way /= 3;
            }
            out.push(vec![
                Grant { overall_limit: Some(5), ..grant("ga", &a, GrantAgents::AllAgents) },
                grant("gb", &b, GrantAgents::AllAgents),
            ]);
        }
    }
    out
}

/// `policy_upsert_is_tightening` says it is sound whichever grants bind which policies, so it is checked against
/// every binding of the edited policy beside every set of others.
#[test]
fn policy_upsert_is_tightening_never_widens_any_binding() {
    let mut v = Verdicts::default();
    for (actions, rungs, max) in policy_domains() {
        let shapes = shapes(&actions, &rungs);
        let mut olds: Vec<Option<Policy>> = vec![None];
        let mut news = Vec::new();
        for s in &shapes {
            for redact in [&[][..], &["Token"]] {
                olds.push(Some(policy("p", CONN, s, redact)));
                for conn in CONNS {
                    news.push(policy("p", conn, s, redact));
                }
            }
        }
        for others in others(&shapes, max) {
            for old in &olds {
                let current: Vec<Policy> = others.iter().cloned().chain(old.clone()).collect();
                for new in &news {
                    if !policy_upsert_is_tightening(&current, new) {
                        continue;
                    }
                    v.checked += 1;
                    let after: Vec<Policy> = others.iter().cloned().chain(Some(new.clone())).collect();
                    for grants in bindings(&others) {
                        let before = world(current.clone(), grants.clone());
                        if let Some(why) = widened(&before, &world(after.clone(), grants)) {
                            v.fail(format!("old {old:?}\nnew {new:?}\nothers {others:?}\nbound {:?}\n{why}", before.grants));
                        }
                    }
                }
            }
        }
    }
    v.finish("policy_upsert_is_tightening");
}

#[test]
fn policy_delete_is_tightening_never_widens_any_binding() {
    let mut v = Verdicts::default();
    for (actions, rungs, max) in policy_domains() {
        let shapes = shapes(&actions, &rungs);
        for others in others(&shapes, max) {
            for s in &shapes {
                for redact in [&[][..], &["Token"]] {
                    let old = policy("p", CONN, s, redact);
                    let current: Vec<Policy> = others.iter().cloned().chain(Some(old.clone())).collect();
                    if !policy_delete_is_tightening(&current, "p") {
                        continue;
                    }
                    v.checked += 1;
                    for grants in bindings(&others) {
                        let before = world(current.clone(), grants.clone());
                        let after = apply(&before, &Mutation::PolicyDelete { policy_id: "p".into() });
                        if let Some(why) = widened(&before, &after) {
                            v.fail(format!("deleted {old:?}\nothers {others:?}\n{why}"));
                        }
                    }
                }
            }
        }
    }
    v.finish("policy_delete_is_tightening");
}

/// `policy_edit_loosens` decides the bar alone (budget and redaction are other checks), for any co-binding.
#[test]
fn policy_edit_loosens_misses_no_lowered_bar_in_any_binding() {
    let mut v = Verdicts::default();
    for (actions, rungs, max) in policy_domains() {
        let shapes = shapes(&actions, &rungs);
        let mut sides: Vec<Option<Policy>> = vec![None];
        for s in &shapes {
            for conn in CONNS {
                sides.push(Some(policy("p", conn, s, &[])));
            }
        }
        for others in others(&shapes, max) {
            for old in &sides {
                for new in &sides {
                    if policy_edit_loosens(&others, old.as_ref(), new.as_ref()) {
                        continue;
                    }
                    v.checked += 1;
                    let current: Vec<Policy> = others.iter().cloned().chain(old.clone()).collect();
                    let after: Vec<Policy> = others.iter().cloned().chain(new.clone()).collect();
                    for grants in bindings(&others) {
                        let before = world(current.clone(), grants.clone());
                        if let Some((why, _)) = widenings(&before, &world(after.clone(), grants), bar_within).into_iter().next() {
                            v.fail(format!("old {old:?}\nnew {new:?}\nothers {others:?}\n{why}"));
                        }
                    }
                }
            }
        }
    }
    v.finish("policy_edit_loosens");
}

// ── Grant classifiers ───────────────────────────────────────────────────────────────────────────

/// What one grant alone gives an agent at one moment: the policies it activates and its two ceilings.
type Share = (BTreeSet<String>, Option<u64>, Option<u64>, GrantPeriod);

fn share(g: &Grant, agent: &str, at: OffsetDateTime) -> Option<Share> {
    (live(g, at) && reaches(g, agent))
        .then(|| (g.policy_ids.iter().cloned().collect(), g.overall_limit, per_agent(g, agent), g.period))
}

fn share_within(new: &Option<Share>, old: &Option<Share>) -> bool {
    match (new, old) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some((p1, o1, a1, t1)), Some((p0, o0, a0, t0))) => {
            p1.is_subset(p0)
                && at_most(*o1, *o0)
                && at_most(*a1, *a0)
                && (t1 == t0 || (o1.is_none() && a1.is_none()))
        }
    }
}

/// `grant_upsert_is_tightening` judges the grant on its own: what it gives each agent, at every moment, only
/// shrinks. What dropping one of its policies or ending it sooner does to the bar the rest of the estate sets is
/// `any_principal_loosens`'s to decide, checked through `is_strictly_tightening` below.
#[test]
fn grant_upsert_is_tightening_never_widens_what_the_grant_gives() {
    let mut variants = Vec::new();
    for enabled in [true, false] {
        for policies in [&[][..], &["p"], &["p", "q"]] {
            for agents in [
                GrantAgents::AllAgents,
                members(&[]),
                members(&[("a", None)]),
                members(&[("a", Some(3))]),
                members(&[("a", Some(10))]),
                members(&[("b", None)]),
                members(&[("a", None), ("b", Some(10))]),
            ] {
                for overall_limit in [None, Some(5)] {
                    for default_per_agent_limit in [None, Some(5)] {
                        for period in [GrantPeriod::Total, GrantPeriod::Day] {
                            for expires_at in [None, hours(-1), hours(1), hours(2)] {
                                variants.push(Grant {
                                    enabled,
                                    overall_limit,
                                    default_per_agent_limit,
                                    period,
                                    expires_at,
                                    ..grant("g1", policies, agents.clone())
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    let now = OffsetDateTime::now_utc();
    let mut v = Verdicts::default();
    for existing in &variants {
        for proposed in &variants {
            if !grant_upsert_is_tightening(std::slice::from_ref(existing), proposed) {
                continue;
            }
            v.checked += 1;
            let moments: Vec<OffsetDateTime> = std::iter::once(now)
                .chain([existing.expires_at, proposed.expires_at].into_iter().flatten().filter(|e| *e > now))
                .collect();
            'case: for at in moments {
                for agent in AGENTS {
                    let (was, is) = (share(existing, agent, at), share(proposed, agent, at));
                    if !share_within(&is, &was) {
                        v.fail(format!("existing {existing:?}\nproposed {proposed:?}\n{agent}: {was:?} became {is:?}"));
                        break 'case;
                    }
                }
            }
        }
    }
    v.finish("grant_upsert_is_tightening");
}

/// The whole decision for a grant edit, against the whole estate: a grant that carries a deny, a two-person rule
/// or a redaction beside a laxer grant, narrowed, unbound, switched off or ended sooner.
#[test]
fn is_strictly_tightening_never_lets_a_grant_edit_widen_anyone() {
    let mut v = Verdicts::default();
    for (before, _) in estates() {
        for proposed in estate_grants() {
            let m = Mutation::GrantUpsert { grant: proposed };
            if !is_strictly_tightening(&m, &ctx(&before)) {
                continue;
            }
            v.checked += 1;
            if let Some(why) = widened(&before, &apply(&before, &m)) {
                v.fail(format!("estate {:?}\n{:?}\nchange {m:?}\n{why}", before.policies, before.grants));
            }
        }
    }
    v.finish("is_strictly_tightening on a grant edit");
}

/// A policy edit with each `grant_ids` sync, against estates where the edited policy is bound beside a deny, a
/// two-person rule or a permit in another grant, which either stays or ends in an hour.
fn policy_edit_cases() -> Vec<(World, Mutation)> {
    let mut olds = Vec::new();
    let mut news = Vec::new();
    for on in EVERY_RUNG {
        for redact in [&[][..], &["Token"]] {
            olds.push(policy("p", CONN, &[("x", on)], redact));
            for conn in CONNS {
                news.push(policy("p", conn, &[("x", on)], redact));
            }
        }
    }
    let syncs: [Option<&[&str]>; 5] = [None, Some(&[]), Some(&["g1"]), Some(&["g2"]), Some(&["g1", "g2"])];
    let mut out = Vec::new();
    for q in [On::Auto, On::Deny, On::Signed(2)] {
        for audience in [GrantAgents::AllAgents, members(&[("a", None)])] {
            for q_ends in [None, hours(1)] {
                for old in &olds {
                    let g2 = Grant { expires_at: q_ends, ..grant("g2", &["q"], GrantAgents::AllAgents) };
                    let before = world(
                        vec![old.clone(), policy("q", CONN, &[("x", q)], &[])],
                        vec![grant("g1", &["p"], audience.clone()), g2],
                    );
                    for new in &news {
                        for sync in syncs {
                            let grant_ids = sync.map(|ids| ids.iter().map(|s| s.to_string()).collect());
                            out.push((before.clone(), Mutation::PolicyUpsert { policy: new.clone(), grant_ids }));
                        }
                    }
                }
            }
        }
    }
    out
}

#[test]
fn is_strictly_tightening_never_lets_a_policy_edit_widen_anyone() {
    let mut v = Verdicts::default();
    for (before, m) in policy_edit_cases() {
        if !is_strictly_tightening(&m, &ctx(&before)) {
            continue;
        }
        v.checked += 1;
        if let Some(why) = widened(&before, &apply(&before, &m)) {
            v.fail(format!("estate {:?}\n{:?}\nchange {m:?}\n{why}", before.policies, before.grants));
        }
    }
    v.finish("is_strictly_tightening on a policy edit");
}

/// The deletes the permission axis calls tightening (the destructive axis holds them separately), each against
/// every estate.
fn delete_cases() -> Vec<(World, Mutation)> {
    let deletes = [
        Mutation::PolicyDelete { policy_id: "p".into() },
        Mutation::PolicyDelete { policy_id: "q".into() },
        Mutation::GrantDelete { grant_id: "g1".into() },
        Mutation::GrantDelete { grant_id: "g2".into() },
        Mutation::AgentDelete { agent_id: "a".into() },
        Mutation::AgentDelete { agent_id: "b".into() },
        Mutation::ConnectionDelete { connection_id: CONN.into() },
        Mutation::SecretDelete { secret_id: "sec".into() },
    ];
    estates().into_iter().flat_map(|(w, _)| deletes.clone().into_iter().map(move |m| (w.clone(), m))).collect()
}

#[test]
fn is_strictly_tightening_never_lets_a_delete_widen_anyone() {
    let mut v = Verdicts::default();
    for (before, m) in delete_cases() {
        if !is_strictly_tightening(&m, &ctx(&before)) {
            continue;
        }
        v.checked += 1;
        if let Some(why) = widened(&before, &apply(&before, &m)) {
            v.fail(format!("estate {:?}\n{:?}\nchange {m:?}\n{why}", before.policies, before.grants));
        }
    }
    v.finish("is_strictly_tightening on a delete");
}

/// Every policy, grant and delete case above, as the (before, after) pair the change makes.
fn binding_changes() -> Vec<(World, Mutation)> {
    let grant_edits = estates()
        .into_iter()
        .flat_map(|(w, _)| estate_grants().into_iter().map(move |g| (w.clone(), Mutation::GrantUpsert { grant: g })));
    grant_edits.chain(policy_edit_cases()).chain(delete_cases().into_iter().filter(|(_, m)| {
        matches!(m, Mutation::PolicyDelete { .. } | Mutation::GrantDelete { .. })
    }))
    .collect()
}

/// `any_principal_loosens` is budget-blind and redaction-blind by contract, so it is held to the bar alone, for
/// every agent, at every moment from now on.
#[test]
fn any_principal_loosens_misses_no_lowered_bar_at_any_moment() {
    let mut v = Verdicts::default();
    for (before, m) in binding_changes() {
        let after = apply(&before, &m);
        if any_principal_loosens((&before.policies, &before.grants), (&after.policies, &after.grants)) {
            continue;
        }
        v.checked += 1;
        if let Some((why, _)) = widenings(&before, &after, bar_within).into_iter().next() {
            v.fail(format!("estate {:?}\n{:?}\nchange {m:?}\n{why}", before.policies, before.grants));
        }
    }
    v.finish("any_principal_loosens");
}

// ── Quorum classifiers ──────────────────────────────────────────────────────────────────────────

/// A held change that lowers the bar on an action needs as many devices as that action took, at whichever moment
/// it lowers it.
#[test]
fn hold_quorum_covers_every_quorum_a_change_lowers() {
    let mut v = Verdicts::default();
    for (before, m) in binding_changes() {
        let after = apply(&before, &m);
        let lowered = widenings(&before, &after, bar_within);
        let Some(needed) = lowered.iter().map(|(_, q)| *q).max() else { continue };
        v.checked += 1;
        let got = hold_quorum(&m, &ctx(&before));
        if got < needed {
            let why = lowered.iter().find(|(_, q)| *q == needed).map(|(w, _)| w.clone()).unwrap_or_default();
            v.fail(format!("estate {:?}\n{:?}\nchange {m:?}\nneeds {needed}, hold_quorum gave {got}: {why}", before.policies, before.grants));
        }
    }
    v.finish("hold_quorum");
}

/// A change that puts an action back below a high-water mark, for any agent at any moment, needs the mark's quorum.
#[test]
fn high_water_quorum_covers_every_mark_a_change_goes_below() {
    let marks: BTreeMap<ActionKey, u8> = [((CONN.to_string(), "x".to_string()), 2)].into();
    let mut v = Verdicts::default();
    for (before, m) in binding_changes() {
        let after = apply(&before, &m);
        let now = OffsetDateTime::now_utc();
        let below = instants(&[&before, &after]).into_iter().find_map(|at| {
            AGENTS.iter().find_map(|agent| {
                let was = access(&before, agent, CONN, "x", at);
                let is = access(&after, agent, CONN, "x", at);
                let under = bar(&is).is_some_and(|(rung, q)| rung < Rung::DeviceSigned || q < 2);
                (!bar_within(&is, &was) && under)
                    .then(|| format!("{agent} at now+{}min: {was:?} became {is:?}", (at - now).whole_minutes()))
            })
        });
        let Some(why) = below else { continue };
        v.checked += 1;
        let (got, _) = high_water_quorum(&m, &ctx(&before), &marks);
        if got < 2 {
            v.fail(format!("estate {:?}\n{:?}\nchange {m:?}\nhigh_water_quorum gave {got}: {why}", before.policies, before.grants));
        }
    }
    v.finish("high_water_quorum");
}

#[test]
fn action_wide_marks_require_extra_signatures_for_another_agent() {
    let mut before = world(
        vec![policy("p_rule", CONN, &[("x", On::Signed(2))], &[]), policy("p_lax", CONN, &[("x", On::Auto)], &[])],
        vec![grant("g_rule", &["p_rule"], members(&[("a", None)]))],
    );
    let marks = crate::policy_guard::quorums_in_force(&before.policies, &before.grants);
    assert_eq!(marks.get(&(CONN.to_string(), "x".to_string())), Some(&2));
    before.policies.push(policy("p_freeze", CONN, &[("x", On::Deny)], &[]));
    before.grants.push(grant("g_freeze", &["p_freeze"], members(&[("a", None)])));
    let permit_b = Mutation::GrantUpsert { grant: grant("g_b", &["p_lax"], members(&[("b", None)])) };
    assert_eq!(hold_quorum(&permit_b, &ctx(&before)), 1);
    assert_eq!(high_water_quorum(&permit_b, &ctx(&before), &marks).0, 2);
}

// ── Two changes in a row, with the marks threaded as the gateway threads them ───────────────────

/// Applies `m` as the gateway does: at once when the guard calls it tightening, otherwise as a held change confirmed
/// by exactly the signatures it asks for, reading the marks it lowers before it applies and settling them after, as
/// the confirm path does.
/// Answers the signatures it took, `None` when it applied unheld, and `Err` when the store refused it.
async fn gateway_step(svc: &crate::service::EnforcementService, m: &Mutation) -> Result<Option<u8>, GatewayError> {
    let store = svc.store();
    let (policies, grants) = (store.list_policies()?, store.list_grants()?);
    let ctx = GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
    if is_strictly_tightening(m, &ctx) {
        crate::rest::apply_mutation(store.as_ref(), svc, m)?;
        return Ok(None);
    }
    let (signed, lowered, _) = svc.held_change_bar(m, true, None).await?;
    crate::rest::apply_mutation(store.as_ref(), svc, m)?;
    svc.settle_quorum_marks(&lowered, signed)?;
    Ok(Some(signed))
}

/// Estates where a rule takes two or three people, a freeze denies the action for everyone until it ends (or for
/// good), the rule reaches everyone or one agent, and a lax permit sits beside it or not; with every change that
/// moves the rule, the freeze or the rule's grant.
fn two_step_cases() -> Vec<(World, Vec<Mutation>)> {
    let mut out = Vec::new();
    for quorum in [2, 3] {
        for freeze_ends in [hours(1), None] {
            for audience in [GrantAgents::AllAgents, members(&[("a", None)])] {
                for lax in [true, false] {
                    let rule = policy("p_rule", CONN, &[("x", On::Signed(quorum))], &[]);
                    let mut policies = vec![rule.clone(), policy("p_freeze", CONN, &[("x", On::Deny)], &[])];
                    let g_rule = grant("g_rule", &["p_rule"], audience.clone());
                    let g_freeze = Grant { expires_at: freeze_ends, ..grant("g_freeze", &["p_freeze"], GrantAgents::AllAgents) };
                    let mut grants = vec![g_rule.clone(), g_freeze.clone()];
                    if lax {
                        policies.push(policy("p_lax", CONN, &[("x", On::Auto)], &[]));
                        grants.push(grant("g_lax", &["p_lax"], GrantAgents::AllAgents));
                    }
                    let upsert = |on: &[(&str, On)]| Mutation::PolicyUpsert { policy: policy("p_rule", CONN, on, &[]), grant_ids: None };
                    let moves = vec![
                        upsert(&[("x", On::Deny)]),
                        upsert(&[("x", On::Auto)]),
                        upsert(&[("x", On::Signed(1))]),
                        upsert(&[]),
                        Mutation::PolicyUpsert { policy: rule.clone(), grant_ids: None },
                        Mutation::PolicyUpsert { policy: policy("p_freeze", CONN, &[], &[]), grant_ids: None },
                        Mutation::GrantUpsert { grant: Grant { enabled: false, ..g_rule.clone() } },
                        Mutation::GrantUpsert { grant: g_rule.clone() },
                        Mutation::GrantUpsert { grant: Grant { expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(30)), ..g_rule.clone() } },
                        Mutation::GrantUpsert { grant: Grant { expires_at: None, ..g_freeze.clone() } },
                        Mutation::GrantUpsert { grant: Grant { expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(30)), ..g_freeze.clone() } },
                        Mutation::GrantDelete { grant_id: "g_freeze".into() },
                    ];
                    out.push((world(policies, grants), moves));
                }
            }
        }
    }
    let original = out.clone();
    for (w, moves) in original {
        for freeze_named in [true, false] {
            let mut varied = w.clone();
            if freeze_named { varied.grants[1].agents = members(&[("b", None)]); }
            varied.policies.push(policy("p_other", OTHER_CONN, &[("x", On::Signed(3))], &[]));
            varied.grants.push(grant("g_other", &["p_other"], members(&[("b", None)])));
            if let Some(lax) = varied.grants.iter_mut().find(|g| g.grant_id == "g_lax") { lax.expires_at = hours(1); }
            let mut changes = moves.clone();
            changes.push(Mutation::PolicyUpsert { policy: policy("p_lax", OTHER_CONN, &[("x", On::Auto)], &[]), grant_ids: None });
            out.push((varied, changes));
        }
    }
    out
}

/// The two-step loosening, at every moment from now on: whatever two changes do between them, an action a rule held
/// at more than one person's signature is put back below that rule only by a held change signed by that many people,
/// and two changes that each applied unheld leave nobody able to do more than before.
#[tokio::test]
async fn no_two_changes_put_a_rule_back_below_its_people_on_fewer_signatures() {
    let mut v = Verdicts::default();
    for (start, moves) in two_step_cases() {
        for first in &moves {
            for second in &moves {
                let store: Arc<dyn crate::store::Store> = Arc::new(crate::store::memory::MemoryStore::new());
                for p in &start.policies {
                    store.put_policy(p.clone()).unwrap();
                }
                for g in &start.grants {
                    store.put_grant(g.clone()).unwrap();
                }
                let svc = crate::service::EnforcementService::new(store.clone(), Arc::new(crate::connectors::MockHttpClient::new()));
                let Ok(one) = gateway_step(&svc, first).await else { continue };
                let Ok(two) = gateway_step(&svc, second).await else { continue };
                v.checked += 1;
                let end = world(store.list_policies().unwrap(), store.list_grants().unwrap());
                let took = one.unwrap_or(0).max(two.unwrap_or(0));
                let case = || format!("estate {:?}\n{:?}\nfirst {first:?} ({one:?})\nsecond {second:?} ({two:?})", start.policies, start.grants);
                if one.is_none() && two.is_none() {
                    if let Some(why) = widened(&start, &end) {
                        v.fail(format!("{}\nboth unheld, yet {why}", case()));
                    }
                    continue;
                }
                let moments = instants(&[&start, &end]);
                let people = moments
                    .iter()
                    .flat_map(|at| AGENTS.iter().map(move |agent| (agent, *at)))
                    .filter_map(|(agent, at)| match bar(&access(&start, agent, CONN, "x", at)) {
                        Some((Rung::DeviceSigned, q)) => Some(q),
                        _ => None,
                    })
                    .max()
                    .unwrap_or(1);
                if people < 2 || took >= people {
                    continue;
                }
                let below = moments.iter().find_map(|at| {
                    AGENTS.iter().find_map(|agent| {
                        let (was, is) = (access(&start, agent, CONN, "x", *at), access(&end, agent, CONN, "x", *at));
                        let under = bar(&is).is_some_and(|(rung, q)| rung < Rung::DeviceSigned || q < people);
                        (!bar_within(&is, &was) && under).then(|| format!("{agent}: {was:?} became {is:?}"))
                    })
                });
                if let Some(why) = below {
                    v.fail(format!("{}\nthe rule took {people} and the changes took {took}: {why}", case()));
                }
            }
        }
    }
    v.finish("two changes with the marks threaded");
}

// ── Connection, agent and switch classifiers ────────────────────────────────────────────────────

/// An estate where every switch above policy matters: `a` has its own grant, everyone reaches both connections.
fn switchboard() -> World {
    let pc = policy("pc", CONN, &[("x", On::Auto), ("y", On::Auto)], &[]);
    let pd = policy("pd", OTHER_CONN, &[("x", On::Auto), ("y", On::Auto)], &[]);
    world(
        vec![pc, pd],
        vec![grant("g_all", &["pc", "pd"], GrantAgents::AllAgents), grant("g_a", &["pc"], members(&[("a", None)]))],
    )
}

fn check_switch(v: &mut Verdicts, before: &World, m: &Mutation, standalone: bool) {
    let composite = is_strictly_tightening(m, &ctx(before));
    assert_eq!(standalone, composite, "the standalone classifier and the guard disagree on {m:?}");
    if !composite {
        return;
    }
    v.checked += 1;
    if let Some(why) = widened(before, &apply(before, m)) {
        v.fail(format!("connections {:?}\nchange {m:?}\n{why}", before.connections));
    }
}

#[test]
fn capability_enable_is_tightening_never_reopens_a_capability() {
    let mut v = Verdicts::default();
    let x = capability_id(CONN, "x");
    let y = capability_id(CONN, "y");
    for disabled in [vec![], vec![x.clone()], vec![y.clone()], vec![x.clone(), x.clone()], vec![x.clone(), y.clone()]] {
        let mut before = switchboard();
        before.connections[0].disabled_capabilities = disabled;
        for (conn, cap) in [(CONN, &x), (CONN, &y), ("missing", &x)] {
            let m = Mutation::CapabilityEnable { connection_id: conn.into(), capability: cap.clone() };
            let standalone = capability_enable_is_tightening(&before.connections, conn, cap);
            check_switch(&mut v, &before, &m, standalone);
        }
    }
    v.finish("capability_enable_is_tightening");
}

#[test]
fn connection_patch_is_tightening_never_reopens_or_retargets_a_connection() {
    let mut v = Verdicts::default();
    for paused in [false, true] {
        let mut before = switchboard();
        before.connections[0].disabled = paused;
        for disabled in [None, Some(true), Some(false)] {
            for label in [None, Some("Renamed".to_string())] {
                for ssh in [None, Some(SshPatch { host: Some("elsewhere.example".into()), ..SshPatch::default() })] {
                    for conn in [CONN, "missing"] {
                        let patch = ConnPatch { disabled, label: label.clone(), name: None, ssh: ssh.clone() };
                        let standalone = connection_patch_is_tightening(&before.connections, conn, &patch);
                        let m = Mutation::ConnectionPatch { connection_id: conn.into(), patch };
                        check_switch(&mut v, &before, &m, standalone);
                    }
                }
            }
        }
    }
    v.finish("connection_patch_is_tightening");
}

#[test]
fn agent_approve_is_tightening_never_approves_anyone_new() {
    let mut v = Verdicts::default();
    for status in [None, Some(AgentStatus::Pending), Some(AgentStatus::Approved)] {
        let mut before = switchboard();
        before.agents.retain(|a| a.id != "a");
        before.agents.extend(status.map(|s| agent("a", s)));
        let standalone = agent_approve_is_tightening(&before.agents, "a");
        check_switch(&mut v, &before, &Mutation::AgentApprove { agent_id: "a".into() }, standalone);
    }
    v.finish("agent_approve_is_tightening");
}

#[test]
fn agent_upsert_is_tightening_never_approves_anyone_new() {
    let mut v = Verdicts::default();
    for gate in [true, false] {
        for id in ["a", "n"] {
            for status in [None, Some(AgentStatus::Pending), Some(AgentStatus::Approved)] {
                let mut before = switchboard();
                before.require_agent_approval = gate;
                before.agents.retain(|a| a.id != id);
                before.agents.extend(status.map(|s| agent(id, s)));
                for proposed in [AgentStatus::Pending, AgentStatus::Approved] {
                    for name in [id, "Renamed"] {
                        let candidate = Agent { name: name.into(), ..agent(id, proposed.clone()) };
                        let standalone = agent_upsert_is_tightening(&before.agents, &candidate);
                        check_switch(&mut v, &before, &Mutation::AgentUpsert { agent: candidate }, standalone);
                    }
                }
            }
        }
    }
    v.finish("agent_upsert_is_tightening");
}

#[test]
fn broker_toggle_is_tightening_never_releases_a_switch() {
    let mut v = Verdicts::default();
    for paused in [false, true] {
        for gate in [false, true] {
            let mut before = switchboard();
            before.paused = paused;
            before.require_agent_approval = gate;
            for toggle in [BrokerToggleKind::Pause, BrokerToggleKind::RequireAgentApproval] {
                for value in [false, true] {
                    let standalone = broker_toggle_is_tightening(value);
                    check_switch(&mut v, &before, &Mutation::BrokerToggle { toggle, value }, standalone);
                }
            }
        }
    }
    v.finish("broker_toggle_is_tightening");
}

// ── The oracle against the engine ───────────────────────────────────────────────────────────────

/// The moments the oracle is held to the engine at: now, a nanosecond before, at and after every later expiry, and a
/// spread of others. Wider than the oracle's own reading of a grant would pick, so an engine that read the clock some
/// other way would part from it.
fn dense_instants(w: &World) -> Vec<OffsetDateTime> {
    let now = OffsetDateTime::now_utc();
    let tick = Duration::nanoseconds(1);
    let mut at: Vec<OffsetDateTime> = w
        .grants
        .iter()
        .filter_map(|g| g.expires_at)
        .filter(|e| *e > now)
        .flat_map(|e| [e - tick, e, e + tick])
        .chain([30, 90, 150, 24 * 60, 3650 * 24 * 60].map(|m| now + Duration::minutes(m)))
        .collect();
    at.push(now);
    at.sort();
    at.dedup();
    at
}

/// The oracle is only worth testing against if it reads the estate as the engine does, so it must agree with
/// `PolicyEngine::resolve` on the worlds the tests build, before and after their changes, budget ceilings of zero
/// included, at every one of [`dense_instants`].
#[test]
fn the_oracle_agrees_with_the_engine() {
    let mut worlds: Vec<World> = Vec::new();
    let proposals = estate_grants();
    for (i, (w, _)) in estates().into_iter().enumerate() {
        for (_, g) in proposals.iter().enumerate().filter(|(k, _)| (i + k) % 64 == 0) {
            worlds.push(apply(&w, &Mutation::GrantUpsert { grant: g.clone() }));
        }
        if i < 64 {
            let mut zero = w.clone();
            zero.grants[0].overall_limit = Some(0);
            worlds.push(zero);
        }
        worlds.push(w);
    }
    for (_, (w, m)) in policy_edit_cases().into_iter().enumerate().filter(|(i, _)| i % 64 == 0) {
        worlds.push(apply(&w, &m));
        worlds.push(w);
    }
    for (_, (w, m)) in delete_cases().into_iter().enumerate().filter(|(i, _)| i % 16 == 0) {
        worlds.push(apply(&w, &m));
    }
    let shapes = shapes(&["x"], &EVERY_RUNG);
    for others in others(&shapes, 1) {
        for s in &shapes {
            let current: Vec<Policy> = others.iter().cloned().chain(Some(policy("p", CONN, s, &["Token"]))).collect();
            worlds.extend(bindings(&others).into_iter().map(|grants| world(current.clone(), grants)));
        }
    }
    for (w, moves) in two_step_cases() {
        worlds.push(w.clone());
        for first in &moves {
            let after = apply(&w, first);
            worlds.push(after.clone());
            for second in &moves { worlds.push(apply(&after, second)); }
        }
    }
    let mut compared = 0;
    for w in &worlds {
        let mut expected_marks = BTreeMap::new();
        for at in dense_instants(w) {
            for agent in ["a", "b", "u"] {
                for conn in CONNS {
                    for action in ACTIONS {
                        if let Access::Permitted { rung: Rung::DeviceSigned, quorum, .. } = access(w, agent, conn, action, at) {
                            if quorum > 1 { let q = expected_marks.entry((conn.to_string(), action.to_string())).or_insert(quorum); *q = (*q).max(quorum); }
                        }
                    }
                }
            }
        }
        let actual_marks = crate::policy_guard::quorums_in_force(&w.policies, &w.grants);
        let actual_marks: BTreeMap<_, _> = actual_marks.into_iter().filter(|((c, a), _)| CONNS.contains(&c.as_str()) && ACTIONS.contains(&a.as_str())).collect();
        assert_eq!(actual_marks, expected_marks, "the in-force map must equal the independent oracle");
        let engine = permaura_policy::PolicyEngine::with(w.grants.clone(), w.policies.clone());
        for at in dense_instants(w) {
            for agent in ["a", "b", "u"] {
                for conn in CONNS {
                    for action in ACTIONS {
                        let input = DecisionInput {
                            capability_id: action.into(),
                            action: permaura_core::Action::Read,
                            connection_id: conn.into(),
                            risk: RiskTier::Low,
                            capability_requires_approval: false,
                            agent_id: agent.into(),
                            context: RequestContext::new(String::new(), at),
                        };
                        let r = engine.resolve(&input, &Unmetered);
                        let engine_says = (r.decision.kind != DecisionKind::Deny).then(|| {
                            let redact: BTreeSet<String> =
                                r.redact_fields.iter().map(|f| f.trim().to_ascii_lowercase()).collect();
                            (r.rung, r.quorum, redact)
                        });
                        let oracle_says = match access(w, agent, conn, action, at) {
                            Access::Denied => None,
                            Access::Permitted { rung, quorum, redact, .. } => Some((rung, quorum, redact)),
                        };
                        assert_eq!(oracle_says, engine_says, "{agent} on {conn}.{action} at {at} in {:?} {:?}", w.policies, w.grants);
                        compared += 1;
                    }
                }
            }
        }
    }
    assert!(compared > 100_000, "only {compared} decisions compared");
}
