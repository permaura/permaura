//! Telling the control plane that an approval is waiting, and that it is no longer waiting.
//!
//! WHY THE GATEWAY HAS TO BE THE ONE TO SPEAK. No gateway can see another's queue, and permaura.com
//! is deliberately out of the agent path, so an operator with gateways in several workspaces has no
//! way to see one queue: there is nowhere that knows. The obvious alternative, having a client poll
//! every gateway, is not a tuning problem: hosted workers are scale-to-zero, and polling at any
//! interval below the idle timeout keeps the whole fleet permanently warm. Announcing costs nothing,
//! because by definition this process is already awake: an agent has just called it.
//!
//! WHAT IT IS ALLOWED TO SAY. Metadata, and nothing else: for a hold, the capability, the connection, the risk tier, the rung, the approval's id, its deadline, the name the agent enrolled under and, for a held change, an opaque requester handle; for a waiting agent, its id and that name; for fair use, the month's counts and state.
//! **Never the approval message, never the parameters, never a result.** Those describe what an agent actually asked for, and they stay on this side of the
//! custody seam. The phone fetches the real card from here when a human opens it. The type in this
//! module is what enforces that: there is no field to put them in.
//!
//! IT IS ALLOWED TO FAIL, AND MUST NEVER BE LOAD-BEARING. Every call is detached, timed out and
//! swallowed. A hold is real because it is in this gateway's store; the announcement is a courtesy
//! that lets a phone find out quickly. If it is lost the decision is still enforced here, the queue
//! is still correct here, and the control plane's row simply ages out on its own expiry.
//!
//! The credential is a per-gateway announce secret (`PERMAURA_ANNOUNCE_SECRET`), which authorizes statements about exactly this gateway and nothing else: that it holds an approval or a waiting agent, that a hold was decided, its fair-use state, and its check-in.
//! The check-in's answer is more than a courtesy: permaura.com can name a new owner there, which this gateway adopts as its owner pin, and can ask for a fresh console bearer. It is deliberately NOT the
//! machine install secret: that one speaks for every gateway link on an install, across accounts,
//! and is documented as a kill switch for whoever owns the hardware. Widening it to cover routine
//! chatter would be the wrong direction for the broadest credential in the system, and it does not
//! exist at all on a hosted worker.
//!
//! A hosted worker is handed its secret in the environment at provisioning. A self-run gateway is
//! handed one when it is linked to a workspace, through `PUT /v1/announce`, which keeps it in
//! `config.toml` beside the gateway id so it survives a restart.

use std::time::Duration;

/// How long an announcement may take before it is abandoned. Detached, but an unbounded hang would
/// leak a task per held approval.
const POST_TIMEOUT: Duration = Duration::from_secs(8);

/// The control plane a gateway announces to when nothing says otherwise.
const DEFAULT_CONTROL_PLANE: &str = "https://permaura.com";

/// What this gateway may say about a held approval.
///
/// Every field here is metadata about the SHAPE of a request, never its content. There is
/// deliberately no `message`, no `params` and no `result` field: the compiler is a better guarantee
/// than a rule a future call site has to remember, and this is the boundary where the custody seam
/// would otherwise leak by omission.
#[derive(Debug, Clone)]
pub struct AnnouncedHold {
    /// The approval's id in this gateway's store, the handle the phone re-fetches the real card by.
    pub approval_id: String,
    /// The capability held, e.g. `stripe.refunds.create`. Names the action; carries none of its input.
    pub capability: String,
    /// The connection it targeted, e.g. `stripe`.
    pub resource: String,
    /// The gateway's grade for this hold, as it graded it AT HOLD TIME: `low` | `medium` | `high` |
    /// `critical`, or `unknown` for a hold with no capability behind it.
    ///
    /// Read off the row via `PendingApproval::risk_label`, never looked up in the capability
    /// catalogue here. A capability's risk is editable, so classifying at announce time would let an
    /// edit rewrite what a queue says about a request held an hour ago, and would let the notice and
    /// the gateway's own card disagree about the same approval. `unknown` is a real answer and the
    /// honest one for a vault export; it is not a tier and clients must not colour it as one.
    pub risk: String,
    /// Which rung of the ladder held it.
    pub required_tier: String,
    /// The agent that asked, by its human name, when the session behind the approval resolves to one.
    /// `None` rather than a guess: a card naming the wrong agent is worse than one naming none.
    pub agent: Option<String>,
    /// When this hold stops being decidable, in unix milliseconds. `None` when it never does.
    ///
    /// The CAPTURED `PendingApproval::expires_at`, read off the row: the same field the `202` body
    /// publishes and the same one `PendingApproval::is_expired` enforces against, so display,
    /// announcement and enforcement cannot drift. Recomputing it here from the TTL constant would let
    /// a later change to that constant move a deadline under a human already looking at it.
    ///
    /// Absolute rather than a window because a window is only meaningful against the clock of
    /// whoever computed it, and this one crosses a process boundary and a queue.
    ///
    /// `None` is a real answer and travels as an explicit `null`, never as an omitted key. Held agent
    /// calls do not expire today, so `None` is what they send, and a control plane that turned that
    /// into a short display window would stop showing a decision that was still waiting, on
    /// the one list a phone away from its workspace has. A held control-plane change sends the day it lapses after.
    pub expires_at: Option<i64>,
    /// Who asked for a held change or export, as [`crate::store::HoldRequester::served`] shows it: an opaque person handle, never the account id. `None` on a held agent call, and the key is then omitted.
    pub requested_by: Option<crate::store::HoldRequester>,
}

/// What kind of thing a notice is about, so a client can tell a decision it can take from one it
/// cannot. Sent explicitly on every announcement; the control plane defaults an absent key to
/// `approval`, which is what every gateway sent before agent notices existed.
/// A call this gateway is holding. Resolvable, and the one every client already knew about.
pub const KIND_APPROVAL: &str = "approval";
/// An agent waiting to be let in. Decided on the Agents screen, never on an approval card.
pub const KIND_AGENT_PENDING: &str = "agent_pending";

/// What this gateway may say about an agent that has enrolled and is waiting to be let in.
///
/// The same seam as [`AnnouncedHold`], and for the same reason: an id to fetch the real record by,
/// and the label the agent enrolled under. There is deliberately no field for anything the agent
/// supplied beyond that label, and no field for the code it redeemed.
///
/// Why it exists at all. An agent that enrols lands Pending and can do nothing until a human
/// approves it, which is the one gate every connection passes through, and until now it was the only
/// gate that rang nobody: the agent sat in a table the operator had to already be looking at. On a
/// hosted worker, where the whole point is that nobody is watching a terminal, that is a queue with
/// no doorbell.
#[derive(Debug, Clone)]
pub struct AnnouncedAgent {
    /// The agent's id in this gateway's store, the handle a client re-fetches the real row by.
    pub agent_id: String,
    /// The name it enrolled under. A label the agent chose, never an identity this gateway verified,
    /// and the control plane stores it in the column that already says exactly that.
    pub agent_name: String,
}

/// Where to announce, and what to prove we are. `None` from [`Config::from_env`] means announcing is
/// switched off, which is the default and the whole feature is then a no-op.
#[derive(Debug, Clone)]
pub struct Config {
    base_url: String,
    gateway_id: String,
    secret: String,
    /// Where an answer asking for this link's console bearer again is recorded: the announcer's, on every link it hands out.
    reseal: Option<std::sync::Arc<ResealRequests>>,
}

/// permaura.com's word, on an answer to this gateway, that a link holds no sealed console bearer and wants one again: a `needs_reseal: true` on any `/api/notify/*` answer, a check-in or a re-seal.
///
/// Only recorded here. The re-seal task alone acts on it, and a gateway with a public URL never starts that task, so there nothing is ever re-sealed whatever permaura.com says.
#[derive(Debug, Default)]
pub struct ResealRequests {
    asked: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl ResealRequests {
    /// Record that `gateway_id`'s link asked for a re-seal.
    pub fn ask(&self, gateway_id: &str) {
        if let Ok(mut asked) = self.asked.lock() {
            asked.insert(gateway_id.to_string());
        }
    }

    /// The links that asked since the last take, emptied.
    pub fn take(&self) -> std::collections::BTreeSet<String> {
        self.asked.lock().map(|mut asked| std::mem::take(&mut *asked)).unwrap_or_default()
    }
}

/// The most of an answer's body read for `needs_reseal`. An answer is a few dozen bytes; a longer one is not read further and asks for nothing.
const ANSWER_CAP: usize = 16 * 1024;

/// What an answer from permaura.com can tell this gateway. Every other field is ignored, and a body that is not JSON, longer than [`ANSWER_CAP`], or carries another type in any of these fields says none of them.
#[derive(Debug, Default, PartialEq, Eq, serde::Deserialize)]
pub(crate) struct Answer {
    /// `needs_reseal: true`: the link holds no sealed console bearer and wants one again.
    #[serde(default)]
    pub(crate) needs_reseal: bool,
    /// `owner_sub`: the account the organization's owner is now, on a check-in answer, so a gateway pinned to a previous owner can move.
    #[serde(default)]
    pub(crate) owner_sub: Option<String>,
    /// `publicUrl: true`: the link's row is the one holding this gateway's public URL, on the 409 a check-in for it is given. Only that row's `owner_sub` is the owner remote access was set up for.
    #[serde(default, rename = "publicUrl")]
    pub(crate) public_url: bool,
    /// `publicUrlValue`: on that same 409, the address the row holds, so a gateway paired into a second organization whose row holds an address of its own can tell that row from its own.
    #[serde(default, rename = "publicUrlValue")]
    pub(crate) row_public_url: RowAddress,
}

/// What a public-URL 409 says of the address its row holds. An explicit `null` and an absent field mean different things, so neither is read as the other.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) enum RowAddress {
    /// No `publicUrlValue` at all: a permaura.com older than the field, whose row is taken at its word.
    #[default]
    Unsent,
    /// `publicUrlValue: null`: the row holds no address that is an origin, which is what permaura.com answers for a stored public URL it cannot read as one, so it holds none of this gateway's.
    NoAddress,
    /// The origin the row holds.
    Address(String),
}

impl<'de> serde::Deserialize<'de> for RowAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Option::<String>::deserialize(deserializer)?.map_or(RowAddress::NoAddress, RowAddress::Address))
    }
}

/// Read what an answer says, under the cap.
pub(crate) async fn read_answer(mut resp: reqwest::Response) -> Answer {
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= ANSWER_CAP => body.extend_from_slice(&chunk),
            Ok(None) => break,
            _ => return Answer::default(),
        }
    }
    serde_json::from_slice::<Answer>(&body).unwrap_or_default()
}

/// Whether an answer from permaura.com carries `needs_reseal: true`.
pub(crate) async fn answer_needs_reseal(resp: reqwest::Response) -> bool {
    read_answer(resp).await.needs_reseal
}

#[cfg(test)]
thread_local! {
    /// The control plane the links a test makes on its own thread name, in place of the environment's, which a test run pins to an address nothing answers on.
    pub(crate) static TEST_CONTROL_PLANE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

impl Config {
    /// Read the environment. Returns `None` unless BOTH a gateway id and an announce secret are set.
    ///
    /// Both, because either alone is meaningless: an id with no secret cannot authenticate, and a
    /// secret with no id does not say which gateway it speaks for. A gateway that has been given
    /// neither is a self-run install that was never paired for this, and it should stay silent
    /// rather than post to a control plane it has no relationship with.
    pub fn from_env() -> Option<Self> {
        let gateway_id = std::env::var("PERMAURA_GATEWAY_ID").unwrap_or_default();
        let secret = std::env::var("PERMAURA_ANNOUNCE_SECRET").unwrap_or_default();
        Self::new(&gateway_id, &secret)
    }

    /// Credentials handed over at runtime (`PUT /v1/announce`), announcing to the same control plane
    /// [`Config::from_env`] would. The control plane itself is never settable this way: that would
    /// turn an operator call into an outbound request aimed wherever the caller liked.
    pub fn new(gateway_id: &str, secret: &str) -> Option<Self> {
        let (gateway_id, secret) = (gateway_id.trim(), secret.trim());
        if gateway_id.is_empty() || secret.is_empty() {
            return None;
        }
        #[cfg(test)]
        if let Some(base_url) = TEST_CONTROL_PLANE.with(|named| named.borrow().clone()) {
            return Some(Config::at(&base_url, gateway_id, secret));
        }
        let base_url = control_plane_base(crate::release::trust_root_override_unless(
            "PERMAURA_CONTROL_PLANE_URL",
            RELEASE_CONTROL_PLANE_TRUST,
            crate::release::is_loopback_http_url,
        ));
        // An announcement carries a bearer-equivalent secret in its body. Over http that is on the
        // wire in clear, so refuse rather than downgrade, and say so once, loudly, instead of
        // failing quietly on every hold for the life of the process.
        if !base_url.starts_with("https://") && !is_loopback(&base_url) {
            tracing::error!(
                "PERMAURA_CONTROL_PLANE_URL must be https:// (or loopback for tests); announcements disabled"
            );
            return None;
        }
        Some(Config { base_url, gateway_id: gateway_id.to_string(), secret: secret.to_string(), reseal: None })
    }

    /// A link to `base_url` as given, for a test that must neither depend on the control plane the environment names nor reach a real one.
    #[cfg(test)]
    pub(crate) fn at(base_url: &str, gateway_id: &str, secret: &str) -> Self {
        Config { base_url: base_url.to_string(), gateway_id: gateway_id.to_string(), secret: secret.to_string(), reseal: None }
    }

    /// The control plane's id for this gateway.
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    /// The control plane this link speaks to, with no trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// See [`fingerprint`].
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.secret)
    }

    /// This link as the config file states it, for persisting the whole list after a change.
    pub(crate) fn to_link(&self) -> crate::config::AnnounceLink {
        crate::config::AnnounceLink {
            gateway_id: self.gateway_id.clone(),
            announce_secret: self.secret.clone(),
        }
    }
}

/// The first 8 hex characters of `sha256(secret)`, which are also the first 8 of the hash
/// permaura.com stores. Lets the console tell "announcing" from "holding a secret this gateway does
/// not have" without either side revealing the secret.
pub fn fingerprint(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(secret.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A control-plane gateway id: `gw_` and a nanoid in practice, checked here only for a shape that is
/// safe to store and send.
pub fn is_gateway_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The shape permaura.com mints, `gwa_` then base64url. A band rather than an exact length, matching
/// the control plane's own check, so a change of encoding there does not strand a gateway here.
pub fn is_announce_secret(value: &str) -> bool {
    value.len() <= 200
        && value.strip_prefix("gwa_").is_some_and(|rest| {
            rest.len() >= 32 && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// The links this process announces to, replaceable while it runs.
///
/// A list, because one machine can be linked into several workspaces and every one of them can
/// already drive this gateway: announcing to only the newest would take the doorbell away from the
/// others, silently, at the moment a second link was made. Read from the environment or the config
/// file at construction, and from then on changed by `PUT`/`DELETE /v1/announce`, which is what lets
/// a gateway that was just linked start announcing without a restart.
#[derive(Debug)]
pub struct Announcer {
    live: std::sync::RwLock<Vec<Config>>,
    reseal: std::sync::Arc<ResealRequests>,
    pairings: std::sync::Arc<Pairings>,
}

/// How many times a caller on this machine has handed this gateway a link (`PUT /v1/announce` from loopback), the last step of every pairing `permaura pair`, `start --pair` or the desktop runs, and so of every pairing that may have handed permaura.com `operator.token`. The re-seal task rotates that token once per count, whatever permaura.com answered. A remote caller (the console) never counts, so permaura.com cannot make the gateway rotate on demand.
#[derive(Debug, Default)]
pub struct Pairings(std::sync::atomic::AtomicU64);

impl Pairings {
    /// Record that a pairing on this machine just ended.
    pub fn note(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many pairings have ended since boot.
    pub fn count(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The most links one gateway will announce to. A machine with more than a handful of workspace
/// links is a mistake somewhere, and an unbounded list is an unbounded fan-out per hold.
pub const MAX_LINKS: usize = 8;

impl Announcer {
    /// The environment's link, or failing that the ones the config file was read with at boot.
    ///
    /// The environment still wins, as it does for every other setting: a supervisor or a hosted
    /// worker that injects one link means that link and no other.
    pub fn from_env() -> Self {
        match Config::from_env() {
            Some(config) => Announcer::with(vec![config]),
            None => Announcer::with(crate::config::announce_links_at_boot()),
        }
    }

    /// An announcer over exactly these links.
    pub fn with(links: Vec<Config>) -> Self {
        Announcer { live: std::sync::RwLock::new(links), reseal: Default::default(), pairings: Default::default() }
    }

    /// Every link to announce to right now, each recording a request to re-seal it in [`Self::reseal_requests`].
    pub fn links(&self) -> Vec<Config> {
        let links = self.live.read().expect("announcer lock not poisoned").clone();
        links.into_iter().map(|link| Config { reseal: Some(self.reseal.clone()), ..link }).collect()
    }

    /// Where answers asking for a link's console bearer again are recorded, for the re-seal task.
    pub fn reseal_requests(&self) -> std::sync::Arc<ResealRequests> {
        self.reseal.clone()
    }

    /// The pairings this machine has completed since boot, for the re-seal task.
    pub fn pairings(&self) -> std::sync::Arc<Pairings> {
        self.pairings.clone()
    }

    /// Replace the links. An empty list switches announcing off.
    pub fn set(&self, links: Vec<Config>) {
        *self.live.write().expect("announcer lock not poisoned") = links;
    }

    /// Whether this gateway announces to a control plane at all.
    ///
    /// The one question the rest of the gateway asks of this module, and it decides more than whether
    /// a POST goes out: a gateway that announces is a gateway whose notifications are sent by the
    /// control plane, so it has no reason to hold a device push token and [`crate::push`] refuses to
    /// keep one. Announcing off means this gateway is the sender and keeps that job. See
    /// [`crate::service::EnforcementService`].
    pub fn is_configured(&self) -> bool {
        !self.live.read().expect("announcer lock not poisoned").is_empty()
    }
}

/// The body for `POST /api/notify/hold`. Pure, so what does and does not travel is testable without
/// a network, which is the only property of this module worth asserting.
pub fn hold_payload(cfg: &Config, hold: &AnnouncedHold) -> serde_json::Value {
    let mut body = serde_json::json!({
        "gatewayId": cfg.gateway_id,
        "announceSecret": cfg.secret,
        "kind": KIND_APPROVAL,
        "approvalId": hold.approval_id,
        "capability": hold.capability,
        "resource": hold.resource,
        "requiredTier": hold.required_tier,
        // Always present: the gateway always has an answer now, `unknown` included, and it is the
        // one already on the row.
        "risk": hold.risk,
        // Always present, null included. Unlike the fields below, the difference between "no
        // deadline" and "this gateway did not say" changes how long the notice lives, so it is the
        // one key that must never be inferred from an absence.
        "expiresAt": match hold.expires_at {
            Some(at) => serde_json::json!(at),
            None => serde_json::Value::Null,
        },
    });
    // Absent rather than null: the control plane's columns are nullable and an omitted key reads the
    // same, but a body that only carries what is actually known is easier to trust at a glance.
    if let Some(agent) = &hold.agent {
        body["agent"] = serde_json::Value::from(agent.clone());
    }
    if let Some(requester) = &hold.requested_by {
        body["requestedBy"] = requester.served();
    }
    body
}

/// The body for `POST /api/notify/hold` when the thing waiting is an agent rather than a call.
///
/// The same endpoint, because it is the same statement: this gateway is holding something a human
/// has to decide. `approvalId` carries the agent's id, which is the handle the control plane keys
/// the row on and a client re-fetches by; agent ids and approval ids cannot collide (`appr_…` versus
/// `<slug>-<hex>`) and the `kind` says which it is either way.
///
/// No `expiresAt`: an agent waits until somebody decides. Sent as an explicit null so the control
/// plane reads it as "no deadline" rather than "this gateway did not say".
pub fn agent_payload(cfg: &Config, agent: &AnnouncedAgent) -> serde_json::Value {
    serde_json::json!({
        "gatewayId": cfg.gateway_id,
        "announceSecret": cfg.secret,
        "kind": KIND_AGENT_PENDING,
        "approvalId": agent.agent_id,
        "agent": agent.agent_name,
        "expiresAt": serde_json::Value::Null,
    })
}

/// The body for `POST /api/notify/resolve`. The outcome is deliberately absent: what was decided
/// belongs to this gateway's signed audit chain, and a softer copy of it in a database this gateway
/// does not trust would be a record people could mistake for one.
pub fn resolve_payload(cfg: &Config, approval_id: &str) -> serde_json::Value {
    serde_json::json!({
        "gatewayId": cfg.gateway_id,
        "announceSecret": cfg.secret,
        "approvalId": approval_id,
    })
}

/// The body for `POST /api/gateways/:id/checkin`, the re-seal task's periodic question: the same two credential fields every `/api/notify/*` body opens with, and nothing else. Never the console bearer.
pub fn checkin_payload(cfg: &Config) -> serde_json::Value {
    serde_json::json!({
        "gatewayId": cfg.gateway_id,
        "announceSecret": cfg.secret,
    })
}

/// The body for `POST /api/notify/fair-use`: this worker's month against its fair-use thresholds.
/// Counts and a state, nothing about what any call was.
pub fn fair_use_payload(cfg: &Config, report: &crate::fair_use::Report) -> serde_json::Value {
    serde_json::json!({
        "gatewayId": cfg.gateway_id,
        "announceSecret": cfg.secret,
        "month": report.month.to_string(),
        "mutatingCalls": report.mutating_calls,
        "soft": report.soft,
        "hard": report.hard,
        "state": report.state.as_str(),
        "throttledRatePerMin": report.throttled_rate_per_min,
    })
}

/// Loopback is exempt from the https rule so a developer can point a gateway at a local console.
///
/// Judged on the parsed host, exactly: `localhost`, a `.localhost` name, `127.0.0.0/8`, `::1` or an IPv4-mapped loopback. A prefix test passed `http://127.0.0.1.example`, a public name, and the announce secret went to it in clear.
fn is_loopback(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else { return false };
    if parsed.scheme() != "http" {
        return false;
    }
    let Some(host) = parsed.host_str() else { return false };
    let host = host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.');
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        Err(_) => host == "localhost" || host.ends_with(".localhost"),
    }
}

/// What a release build trusts as the control plane, in its message when it ignores `PERMAURA_CONTROL_PLANE_URL`.
const RELEASE_CONTROL_PLANE_TRUST: &str = "https://permaura.com or a loopback http(s) address";

/// The control plane every link talks to, from the `PERMAURA_CONTROL_PLANE_URL` value a build honors: a debug build any, a release build only a loopback one, since a re-seal hands the control plane the install secret and a console session and its check-in answer can re-pin the owner.
fn control_plane_base(value: Option<String>) -> String {
    let base_url = value.filter(|v| !v.trim().is_empty()).unwrap_or_else(|| DEFAULT_CONTROL_PLANE.to_string());
    base_url.trim().trim_end_matches('/').to_string()
}

/// [`control_plane_base`] for a `PERMAURA_CONTROL_PLANE_URL` value in a build that is (`debug_build`) or is not a debug build.
#[cfg(test)]
fn control_plane_for(value: Option<String>, debug_build: bool) -> String {
    control_plane_base(crate::release::trust_root_override_in(value, debug_build, crate::release::is_loopback_http_url))
}

/// Announce a hold to every link. Detached, best-effort, and silent when there are none.
///
/// One task per link: they carry different credentials to the same control plane, and a slow or
/// refusing link must not hold up the others or the queue behind them.
pub async fn announce_hold(links: Vec<Config>, hold: AnnouncedHold) {
    for cfg in links {
        let hold = hold.clone();
        tokio::spawn(async move {
            post(&cfg, "/api/notify/hold", hold_payload(&cfg, &hold), &hold.approval_id).await;
        });
    }
}

/// Announce that an agent has enrolled and is waiting. Detached and best-effort, like every other
/// call here: the agent is Pending because this gateway's store says so, never because this arrived.
pub async fn announce_agent_pending(links: Vec<Config>, agent: AnnouncedAgent) {
    for cfg in links {
        let agent = agent.clone();
        tokio::spawn(async move {
            post(&cfg, "/api/notify/hold", agent_payload(&cfg, &agent), &agent.agent_id).await;
        });
    }
}

/// Announce that a hold has been decided, to everyone that was told about it. Carries no outcome;
/// see [`resolve_payload`].
pub async fn announce_resolved(links: Vec<Config>, approval_id: String) {
    for cfg in links {
        let approval_id = approval_id.clone();
        tokio::spawn(async move {
            post(&cfg, "/api/notify/resolve", resolve_payload(&cfg, &approval_id), &approval_id).await;
        });
    }
}

/// Announce a change in this worker's fair-use state, so the control plane can tell the owner. The
/// worker never emails anyone itself, and the ceiling holds here whether or not this arrives.
pub async fn announce_fair_use(links: Vec<Config>, report: crate::fair_use::Report) {
    for cfg in links {
        let report = report.clone();
        tokio::spawn(async move {
            let label = format!("fair-use {}", report.state.as_str());
            post(&cfg, "/api/notify/fair-use", fair_use_payload(&cfg, &report), &label).await;
        });
    }
}

/// How many times a single announcement is attempted, including the first.
///
/// Two, not more. A lost hold announcement costs one notification and the row ages out on its own
/// expiry; a lost RESOLVE announcement leaves a decided approval standing on somebody's dashboard
/// until then, which is the failure worth one cheap second try. Anything longer starts to look like
/// a delivery guarantee, and this is deliberately not one.
const ATTEMPTS: u32 = 2;

/// Pause before the second attempt. Short enough that the task is gone long before the hold is.
const RETRY_DELAY: Duration = Duration::from_millis(750);

/// Whether a refusal is worth trying again.
///
/// A 5xx or a transport error is the control plane having a moment. A 4xx is this gateway being
/// wrong about something (a bad secret, a retired row, a malformed body), and repeating it just
/// spends somebody's rate limit to be told the same thing twice.
fn worth_retrying(status: Option<u16>) -> bool {
    match status {
        None => true,
        Some(s) => s >= 500,
    }
}

async fn post(cfg: &Config, path: &str, body: serde_json::Value, approval_id: &str) {
    // No redirects: a 307 or 308 would resend the body, announce secret included, to wherever it pointed.
    let client = match reqwest::Client::builder().timeout(POST_TIMEOUT).redirect(reqwest::redirect::Policy::none()).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("announce: failed to build http client: {e}");
            return;
        }
    };
    let url = format!("{}{}", cfg.base_url, path);
    for attempt in 1..=ATTEMPTS {
        let status = match client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(approval = approval_id, "announce: delivered");
                if let Some(reseal) = &cfg.reseal {
                    if answer_needs_reseal(resp).await {
                        reseal.ask(&cfg.gateway_id);
                    }
                }
                return;
            }
            Ok(resp) => {
                // 403 here means this gateway's announce secret is not the one the control plane
                // holds, which a human has to fix. Logged at warn with the status and nothing else:
                // the body may echo the request, and the request carries the secret.
                let status = resp.status().as_u16();
                tracing::warn!(
                    status,
                    approval = approval_id,
                    "announce: control plane refused the announcement"
                );
                Some(status)
            }
            Err(e) => {
                tracing::warn!(approval = approval_id, "announce: send failed (best-effort): {e}");
                None
            }
        };
        if attempt == ATTEMPTS || !worth_retrying(status) {
            return;
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A release build announces only to permaura.com or a loopback stub: the control plane receives the install secret, the announce secret and a console session at every re-seal, and its check-in answer can re-pin the owner, so it is a trust root like the account API.
    #[test]
    fn a_release_build_ignores_a_foreign_control_plane_from_the_environment() {
        let foreign = Some("https://cp.attacker.example".to_string());
        assert_eq!(control_plane_for(foreign.clone(), false), DEFAULT_CONTROL_PLANE);
        assert_eq!(control_plane_for(Some("https://cp.attacker.example@127.0.0.1/".into()), false), DEFAULT_CONTROL_PLANE);
        assert_eq!(control_plane_for(Some("http://127.0.0.1:9/".into()), false), "http://127.0.0.1:9", "the loopback stub the tests use");
        assert_eq!(control_plane_for(Some("https://localhost:9".into()), false), "https://localhost:9");
        assert_eq!(control_plane_for(None, false), DEFAULT_CONTROL_PLANE);
        assert_eq!(control_plane_for(foreign, true), "https://cp.attacker.example", "a debug build takes any value");
    }

    fn cfg() -> Config {
        Config {
            base_url: "https://permaura.com".into(),
            gateway_id: "gw_1".into(),
            secret: "gwa_secret".into(),
            reseal: None,
        }
    }

    /// The check-in proves itself as every notification does and carries nothing else, the console bearer least of all.
    #[test]
    fn a_check_in_carries_the_link_credential_and_nothing_else() {
        let body = checkin_payload(&cfg());
        assert_eq!(body, serde_json::json!({ "gatewayId": "gw_1", "announceSecret": "gwa_secret" }));
    }

    /// The contract with permaura.com's check-in route: its public-URL 409, field for field, is read under the keys it sends, and a `public_url` key, which no permaura.com sends, is no `publicUrlValue`.
    #[test]
    fn the_public_url_409_is_read_under_the_keys_permaura_com_sends() {
        let sent = serde_json::json!({
            "error": "This gateway has a public URL, so permaura.com signs a short-lived token for each request and holds no bearer for it.",
            "publicUrl": true,
            "publicUrlValue": "https://g-abc.permaura.com",
            "needs_reseal": false,
            "owner_sub": "user_new",
        });
        assert_eq!(
            serde_json::from_value::<Answer>(sent).unwrap(),
            Answer {
                needs_reseal: false,
                owner_sub: Some("user_new".into()),
                public_url: true,
                row_public_url: RowAddress::Address("https://g-abc.permaura.com".into())
            }
        );
        let unsent = serde_json::json!({ "publicUrl": true, "public_url": "https://g-abc.permaura.com", "owner_sub": "user_new" });
        assert_eq!(serde_json::from_value::<Answer>(unsent).unwrap().row_public_url, RowAddress::Unsent);
    }

    /// The same contract, the address permaura.com cannot read as an origin: it answers `publicUrlValue: null`, which is a row naming no address, never the absent field of a permaura.com older than it. Read from the bytes, as a check-in reads them.
    #[test]
    fn an_explicit_null_address_is_not_an_absent_one() {
        for (what, sent, row) in [
            ("an older permaura.com", r#"{"publicUrl":true,"owner_sub":"user_new"}"#, RowAddress::Unsent),
            ("an address that is no origin", r#"{"publicUrl":true,"publicUrlValue":null,"owner_sub":"user_new"}"#, RowAddress::NoAddress),
            ("an origin", r#"{"publicUrl":true,"publicUrlValue":"https://g-abc.permaura.com","owner_sub":"user_new"}"#, RowAddress::Address("https://g-abc.permaura.com".into())),
        ] {
            let answer = serde_json::from_slice::<Answer>(sent.as_bytes()).unwrap_or_default();
            assert_eq!(answer.row_public_url, row, "{what}");
            assert_eq!((answer.public_url, answer.owner_sub.as_deref()), (true, Some("user_new")), "{what}: the rest of the answer still reads");
        }
        let mistyped = serde_json::from_slice::<Answer>(br#"{"publicUrl":true,"publicUrlValue":443,"owner_sub":"user_new"}"#).unwrap_or_default();
        assert_eq!(mistyped, Answer::default(), "another type in the field says nothing at all");
    }

    /// Every link an announcer hands out records a request to re-seal it in that announcer's registry, and a taken request is gone.
    #[test]
    fn a_reseal_request_is_recorded_once_per_link_and_taken_once() {
        let announcer = Announcer::with(vec![cfg()]);
        let link = announcer.links().pop().unwrap();
        let requests = link.reseal.as_ref().expect("an announcer's link records requests");
        requests.ask("gw_1");
        requests.ask("gw_1");
        assert_eq!(announcer.reseal_requests().take().into_iter().collect::<Vec<_>>(), vec!["gw_1".to_string()]);
        assert!(announcer.reseal_requests().take().is_empty());
    }

    fn hold() -> AnnouncedHold {
        AnnouncedHold {
            approval_id: "appr_1".into(),
            capability: "stripe.refunds.create".into(),
            resource: "stripe".into(),
            risk: "critical".into(),
            required_tier: "approve".into(),
            agent: Some("Claude Code".into()),
            expires_at: Some(1_700_000_000_000),
            requested_by: None,
        }
    }

    /// A held change says who asked as the approver-key list names people, by handle and never by account id; a held agent call says nothing about it.
    #[test]
    fn a_held_change_names_who_asked_by_handle_only() {
        let requester = crate::store::HoldRequester {
            person: Some("user_priya".into()),
            device_id: Some("phone-priya".into()),
            required_independence: Some(crate::relay::approver::Independence::Independent),
        };
        let body = hold_payload(&cfg(), &AnnouncedHold { requested_by: Some(requester), ..hold() });
        assert_eq!(
            body["requestedBy"],
            serde_json::json!({
                "person_handle": crate::service::person_handle("user_priya"),
                "device_id": "phone-priya",
                "required_independence": "independent",
            })
        );
        assert!(!body.to_string().contains("user_priya"), "{body}");
        assert!(hold_payload(&cfg(), &hold()).get("requestedBy").is_none());
    }

    /// The one property of this module that matters. A held approval's message, parameters and
    /// result describe what an agent actually asked for; the control plane is not entitled to them,
    /// and the struct has nowhere to put them, so this asserts the boundary end to end.
    #[test]
    fn an_announcement_carries_no_content_of_the_request() {
        let body = hold_payload(&cfg(), &hold()).to_string();
        for leaked in [
            "Refund GBP 42.00 for customer 12345",
            "ch_3PY9xK2eZvKYlo2C",
            "\"params\"",
            "\"message\"",
            "\"result\"",
            // Captured on the row since the metadata contract, and deliberately NOT announced: it is
            // one human sentence about what would run, which is the request's content.
            "action_description",
        ] {
            assert!(!body.contains(leaked), "leaked {leaked}");
        }
        // What it SHOULD carry: enough to list the decision and fetch the real one.
        assert!(body.contains("appr_1"));
        assert!(body.contains("stripe.refunds.create"));
    }

    #[test]
    fn a_resolution_carries_no_outcome() {
        // Approved or denied belongs to the signed audit chain, not to a row in our database.
        let body = resolve_payload(&cfg(), "appr_1").to_string();
        assert!(body.contains("appr_1"));
        for absent in ["approved", "denied", "outcome", "status"] {
            assert!(!body.contains(absent), "leaked {absent}");
        }
    }

    #[test]
    fn unknown_fields_are_omitted_rather_than_guessed() {
        let bare = AnnouncedHold { agent: None, ..hold() };
        let body = hold_payload(&cfg(), &bare);
        // A card naming the wrong agent is worse than one naming none.
        assert!(body.get("agent").is_none());
    }

    /// The one field that must NOT follow the rule above.
    ///
    /// "This hold has no deadline" and "this gateway did not tell me" are different facts with
    /// different consequences: the first means the notice stays open until somebody resolves it, the
    /// second means the control plane is guessing. An omitted key reads as the second, so `None`
    /// travels as an explicit null and the key is always there.
    #[test]
    fn an_absent_expiry_is_stated_rather_than_left_out() {
        let forever = AnnouncedHold { expires_at: None, ..hold() };
        let body = hold_payload(&cfg(), &forever);
        assert_eq!(body.get("expiresAt"), Some(&serde_json::Value::Null));

        let dated = hold_payload(&cfg(), &hold());
        assert_eq!(dated["expiresAt"], serde_json::json!(1_700_000_000_000i64));

        // A window would be meaningless by the time it crossed a queue, and the name matches the
        // field every other gateway surface uses for the same fact.
        assert!(dated.get("ttlSeconds").is_none());
        assert!(dated.get("ttl_secs").is_none());
    }

    /// The announcement's expiry is the one the gateway's own clients are given, not a second
    /// opinion. Two places computing it independently is how one of them ends up claiming a deadline
    /// the enforcement loop does not honour.
    #[test]
    fn the_announced_expiry_is_the_one_the_gateway_itself_publishes() {
        let created_at = 1_700_000_000_000i64;
        assert_eq!(crate::relay::hold_expiry(created_at), None);
        assert!(!crate::relay::approvals_expire(), "holds do not expire; see relay::APPROVAL_TTL_MS");
    }

    /// An agent notice is the same seam as a hold notice: a handle and a label, nothing the agent
    /// itself said. The enrolment code in particular must never travel: it is a live bearer until it
    /// is redeemed, and this body goes to a service that does not need it.
    #[test]
    fn an_agent_announcement_carries_only_a_handle_and_a_label() {
        let body = agent_payload(
            &cfg(),
            &AnnouncedAgent {
                agent_id: "claude-9f3a21bc".into(),
                agent_name: "Claude Code".into(),
            },
        );
        assert_eq!(body["kind"], serde_json::json!(KIND_AGENT_PENDING));
        assert_eq!(body["approvalId"], serde_json::json!("claude-9f3a21bc"));
        assert_eq!(body["agent"], serde_json::json!("Claude Code"));
        // An agent waits until a human decides, so the row must not be aged out from under it.
        assert_eq!(body.get("expiresAt"), Some(&serde_json::Value::Null));
        let raw = body.to_string();
        for absent in ["ENRL-", "token", "capability", "params"] {
            assert!(!raw.contains(absent), "leaked {absent}");
        }
    }

    /// The control plane stores these keys and mails on `state`, so they are a wire format.
    #[test]
    fn a_fair_use_announcement_carries_the_month_and_nothing_else() {
        let report = crate::fair_use::Report {
            month: crate::fair_use::Month::parse("2026-09").unwrap(),
            mutating_calls: 512_345,
            soft: 500_000,
            hard: 1_000_000,
            state: crate::fair_use::FairUseState::Warned,
            throttled_rate_per_min: 60,
        };
        let body = fair_use_payload(&cfg(), &report);
        let mut keys: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["announceSecret", "gatewayId", "hard", "month", "mutatingCalls", "soft", "state", "throttledRatePerMin"]
        );
        assert_eq!(body["month"], "2026-09");
        assert_eq!(body["mutatingCalls"], 512_345);
        assert_eq!(body["state"], "warned");
        assert_eq!(body["throttledRatePerMin"], 60);
    }

    /// A hold says what it is, so nothing downstream has to infer the kind from which keys are set.
    #[test]
    fn a_hold_announcement_names_its_kind() {
        assert_eq!(hold_payload(&cfg(), &hold())["kind"], serde_json::json!(KIND_APPROVAL));
    }

    #[test]
    fn announcing_is_off_unless_both_halves_are_set() {
        // An id with no secret cannot authenticate; a secret with no id does not say who it speaks
        // for. Either alone must leave the gateway silent rather than posting something useless.
        let vars = |id: &str, secret: &str| {
            std::env::set_var("PERMAURA_GATEWAY_ID", id);
            std::env::set_var("PERMAURA_ANNOUNCE_SECRET", secret);
            let out = Config::from_env().is_some();
            std::env::remove_var("PERMAURA_GATEWAY_ID");
            std::env::remove_var("PERMAURA_ANNOUNCE_SECRET");
            out
        };
        assert!(!vars("", ""));
        assert!(!vars("gw_1", ""));
        assert!(!vars("", "gwa_s"));
        assert!(!vars("  ", "  "));
        assert!(vars("gw_1", "gwa_s"));
    }

    #[test]
    fn only_a_control_plane_having_a_moment_is_tried_again() {
        // A transport error or a 5xx is worth one more go. A 4xx is this gateway being wrong (a
        // secret the control plane does not hold, a retired row), and repeating it spends a rate
        // limit to be told the same thing twice.
        assert!(worth_retrying(None));
        assert!(worth_retrying(Some(500)));
        assert!(worth_retrying(Some(503)));
        assert!(!worth_retrying(Some(400)));
        assert!(!worth_retrying(Some(403)));
        assert!(!worth_retrying(Some(429)));
    }

    /// The console compares this with the prefix of the hash permaura.com stores, so it has to be
    /// exactly `sha256` hex, not a different digest or encoding that merely looks like one.
    #[test]
    fn the_fingerprint_is_the_prefix_of_the_hash_the_control_plane_stores() {
        assert_eq!(fingerprint("gwa_secret"), "394b291c");
        assert_eq!(cfg().fingerprint(), "394b291c");
    }

    #[test]
    fn only_the_shapes_the_control_plane_mints_are_accepted() {
        let minted = format!("gwa_{}", "A1b2_-".repeat(8));
        assert!(is_announce_secret(&minted));
        assert!(!is_announce_secret("gwa_short"));
        assert!(!is_announce_secret(&format!("gwb_{}", "a".repeat(40))));
        // A value that would break out of a TOML string or a log line is refused, not escaped.
        assert!(!is_announce_secret(&format!("gwa_{}\"\n", "a".repeat(40))));
        assert!(!is_announce_secret(&format!("gwa_{}", "a".repeat(300))));

        assert!(is_gateway_id("gw_V1StGXR8_Z5jdHi6B-myT"));
        assert!(!is_gateway_id(""));
        assert!(!is_gateway_id("gw_1 OR 1=1"));
        assert!(!is_gateway_id(&"g".repeat(65)));
    }

    /// Linking a running gateway switches announcing on without a restart, and unlinking switches it
    /// off, so the answer every hold site reads has to follow the swap.
    #[test]
    fn links_handed_over_at_runtime_take_effect_and_can_be_withdrawn() {
        let announcer = Announcer::with(Vec::new());
        assert!(!announcer.is_configured());
        announcer.set(vec![Config::new("gw_1", "gwa_secret").unwrap()]);
        assert!(announcer.is_configured());
        assert_eq!(announcer.links()[0].gateway_id(), "gw_1");
        announcer.set(Vec::new());
        assert!(announcer.links().is_empty());
        // Half a credential is no credential, the same rule as the environment.
        assert!(Config::new("gw_1", "  ").is_none());
        assert!(Config::new("", "gwa_secret").is_none());
    }

    /// A machine linked into two workspaces announces the same hold to both, each under its own
    /// credential. Announcing to one and not the other is the failure this list exists to prevent.
    #[test]
    fn every_link_is_told_under_its_own_credential() {
        let a = Config::new("gw_a", "gwa_secret_a").unwrap();
        let b = Config::new("gw_b", "gwa_secret_b").unwrap();
        let first = hold_payload(&a, &hold());
        let second = hold_payload(&b, &hold());

        assert_eq!(first["gatewayId"], serde_json::json!("gw_a"));
        assert_eq!(second["gatewayId"], serde_json::json!("gw_b"));
        assert_eq!(first["announceSecret"], serde_json::json!("gwa_secret_a"));
        assert_eq!(second["announceSecret"], serde_json::json!("gwa_secret_b"));
        // The approval is the same one on both, which is how a phone in either workspace opens it.
        assert_eq!(first["approvalId"], second["approvalId"]);
        // One link's secret never travels to the other's row.
        assert!(!first.to_string().contains("gwa_secret_b"));
    }

    #[test]
    fn a_plaintext_control_plane_is_refused_but_loopback_is_not() {
        assert!(is_loopback("http://127.0.0.1:3102"));
        assert!(is_loopback("http://localhost:3102"));
        assert!(!is_loopback("http://permaura.com"));
        assert!(!is_loopback("http://evil.example"));
        assert!(!is_loopback("http://127.0.0.1.example"));
        assert!(!is_loopback("http://localhost.evil.example"));
        assert!(!is_loopback("http://localhost@evil.example"));
        assert!(!is_loopback("https://127.0.0.1"), "the exemption is for plain http; https needs none");
        assert!(is_loopback("http://[::1]:3102"));
        assert!(is_loopback("http://127.8.9.10"));
        assert!(is_loopback("http://console.localhost:3102"));
    }
}
