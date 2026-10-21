//! The worker's budget for the JSON trees its calls hold, and the pieces that keep every tree built from untrusted bytes inside it.
//!
//! What an upstream returns and what a command prints never become trees, except a Vercel response the projection reads and a result the relay frames (both below): the agent's view of them is a streaming pass ([`permaura_core::json_stream`]) and they travel as [`JsonText`]. What still needs a tree is charged here first:
//!
//! - an agent's params on `/v1/invoke` and `/mcp` ([`read_json`]), reserved with room for the request body written from them ([`params_room`]) and kept with their charge and the call's execution slot in one [`AgentParams`], which the detached execution task holds a clone of, so the room and the slot are given back when the call is done and not when its caller hangs up;
//! - a held call's params when a human approves it ([`MemoryBudget::parse_held`]), before the claim, with an execution slot's share of byte buffers beside them, as on 1.3.52, or with the execution slot the approved call runs under when that share and the params could never fit the pool together;
//! - the aliases of redacted fields an agent's GraphQL documents name, which its response is redacted under, while that response is read ([`crate::connectors::response_redact_keys`]), past a fixed allowance and only when the pool has room at once: the call already holds its params' room, so taking this room never waits, and with none the whole response is redacted;
//! - a Vercel response the projection reads, charged while the projection holds it, and a result the relay frames, charged only while it is parsed (the frame and the job ledger keep it uncharged). The projection waits for that room while its call holds its params' room, so it can queue behind a larger reservation that needs the room the call holds, as it could in gateway 1.3.52 (`EnforcementService::projected`);
//! - a document the gateway fetches for itself (an OAuth token response, a WordPress listing), but only when the pool has room at once: its request has been sent, so it never waits for room and is never refused for it ([`crate::limits::DEFAULT_INTERNAL_TREE_BYTES`]).
//!
//! Every agent call's params also meet one ceiling on their unpacked size, the estimate of their tree, whether or not the call needs approval: the pool less 64 MiB, 128 MiB hosted and 448 MiB self-run ([`crate::limits::LimitsConfig::unpacked_limit`]). [`read_json`] checks it before a body is parsed, and the service checks it again before the policy decides whether to hold the call, so a call is admitted or refused alike held and unheld; it is the only size test a call meets there. It replaced the 1.3.52 hold ceiling. Text this gateway writes longer than it was sent is held at its stored length and charged when the call is approved ([`MemoryBudget::parse_held`]), never refused when it is held. Approving a call reserves in the pool its tree, room for its text and, as on 1.3.52, a slot's share for its execution's buffers; when those could never fit the pool together the call runs under an execution slot instead, as an unheld one does, so a call sent in a body that runs unheld can be approved when it is held ([`held_room`]).

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use permaura_core::json_stream::{self, Viewed};
use permaura_core::{CredentialScrub, JsonText};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::connectors::json_budget::{self, ChargedParseError, MemoryCharge, MemoryPool, PoolRefusal};
use crate::error::GatewayError;
use crate::limits::{ExecutionSlot, LimitsConfig, HOLD_ROW_OVERHEAD_BYTES, OUTGOING_BODY_TENTHS, VIEW_FREE_TENTHS};

/// The worker's JSON memory budget and the hold budgets, resolved from [`LimitsConfig`].
#[derive(Debug, Clone)]
pub struct MemoryBudget {
    pool: Arc<MemoryPool>,
    wait: Duration,
    unpacked_limit: u64,
    held_total_bytes: u64,
    control_plane_held_total_bytes: u64,
    internal_tree_bytes: u64,
    /// Taken from an agent hold's budget check until its row is written, so two holds cannot both pass a check the other's row would fail. Async, so a hold waiting for it never blocks a runtime worker while another's write uploads the store.
    hold_admission: Arc<tokio::sync::Mutex<()>>,
    /// An execution slot's byte buffers, at most half the pool, which an approved held call reserves in the pool beside its params unless it runs under a slot ([`MemoryBudget::parse_held`]).
    resolution_bytes: u64,
    /// Where an agent's view of a response keeps the part past what its execution's slot holds.
    view_growth: Arc<MemoryPool>,
    /// How long a view may be within its slot's share: [`VIEW_FREE_TENTHS`] of the response cap.
    view_free_bytes: u64,
    /// The ceiling on what the capability rows take ([`LimitsConfig::capability_bytes`]).
    capability_bytes: u64,
}

impl MemoryBudget {
    /// The budget `config` describes.
    pub fn from_config(config: &LimitsConfig) -> Self {
        MemoryBudget {
            pool: Arc::new(MemoryPool::new(config.json_pool_bytes)),
            wait: config.json_pool_wait,
            unpacked_limit: config.unpacked_limit(),
            held_total_bytes: held_total_bytes(config),
            control_plane_held_total_bytes: control_plane_held_total_bytes(config),
            internal_tree_bytes: config.internal_tree_bytes,
            hold_admission: Arc::new(tokio::sync::Mutex::new(())),
            resolution_bytes: resolution_bytes(config),
            view_growth: Arc::new(MemoryPool::new(config.view_growth_bytes)),
            view_free_bytes: view_free_bytes(),
            capability_bytes: config.capability_bytes,
        }
    }

    /// The budget the environment describes, for this process's posture.
    pub fn from_env() -> Self {
        Self::from_config(&LimitsConfig::from_env())
    }

    /// The ceiling on what the capability rows take, for a writer that runs with the service and not the request's limits: a held change applied on its approval.
    pub fn capability_bytes(&self) -> u64 {
        self.capability_bytes
    }

    /// The worker-wide pool every tree is charged to.
    pub fn pool(&self) -> &Arc<MemoryPool> {
        &self.pool
    }

    /// How long a reservation waits for room.
    pub fn wait(&self) -> Duration {
        self.wait
    }

    /// The one ceiling on an agent call's unpacked size, held or not ([`LimitsConfig::unpacked_limit`]).
    pub fn unpacked_limit(&self) -> u64 {
        self.unpacked_limit
    }

    /// Refuse an agent call whose params' unpacked size, `estimate`, is over [`Self::unpacked_limit`], with one log line naming the size, the limit and `route` ([`log_unpacked_refusal`]). Every agent call is checked against it before the policy decides whether to hold it, so a call is admitted or refused alike whether or not it needs approval. Nothing is written.
    pub fn admit_unpacked(&self, estimate: u64, route: &str) -> Result<(), GatewayError> {
        if estimate > self.unpacked_limit {
            log_unpacked_refusal(estimate, self.unpacked_limit, route);
            return Err(over_unpacked_limit(estimate, self.unpacked_limit));
        }
        Ok(())
    }

    /// The budget for the stored rows of every pending agent hold, which a hold alone in the queue may pass ([`held_total_bytes`]).
    pub fn held_total_bytes(&self) -> u64 {
        self.held_total_bytes
    }

    /// The budget for the stored rows of every pending control-plane hold, which a change alone in the queue may pass ([`control_plane_held_total_bytes`]).
    pub fn control_plane_held_total_bytes(&self) -> u64 {
        self.control_plane_held_total_bytes
    }

    /// Admit one agent hold at a time, from its budget check until its row is written.
    pub async fn admit_one_hold(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.hold_admission.lock().await
    }

    /// The budget for the part of agents' views past what an execution's slot holds.
    pub fn view_growth(&self) -> &Arc<MemoryPool> {
        &self.view_growth
    }

    /// How long a view may be within an execution's slot.
    pub fn view_free_bytes(&self) -> u64 {
        self.view_free_bytes
    }

    /// An upstream body as its agent sees it ([`json_stream::agent_view`]), with the room the view takes past what an execution's slot holds for one, reserved in the view-growth budget before the view is written. Keep the charge for as long as the view's bytes are held: on an execution route, until its response has been sent.
    /// The call has been sent by then, so a budget with no room within the pool wait is [`ViewRefusal::NoRoom`], which the caller reports as a call that ran; the body is never handed on unredacted.
    pub async fn agent_view(&self, body: &[u8], scrub: &CredentialScrub, redact_keys: &[String]) -> Result<(JsonText, MemoryCharge), ViewRefusal> {
        let free = usize::try_from(self.view_free_bytes).unwrap_or(usize::MAX);
        let len = match json_stream::agent_view_within(body, scrub, redact_keys, free) {
            Ok(Viewed::Written(view)) => return Ok((view, MemoryCharge::none())),
            Ok(Viewed::Longer(len)) => len,
            Err(_) => return Err(ViewRefusal::NotJson),
        };
        // Longer than the whole budget, it takes all of it and runs alone rather than never.
        let past = ((len - free) as u64).min(self.view_growth.max_bytes());
        let charge = match self.view_growth.reserve(past, self.wait).await {
            Ok(charge) => charge,
            Err(_) => return Err(ViewRefusal::NoRoom { len, free: self.view_free_bytes, waited: self.wait }),
        };
        let view = json_stream::agent_view_at(body, scrub, redact_keys, len).map_err(|_| ViewRefusal::NotJson)?;
        Ok((view, charge))
    }

    /// An execution slot's byte buffers, which an approved held call reserves in the pool when it runs under no slot ([`Self::parse_held`]).
    pub fn resolution_bytes(&self) -> u64 {
        self.resolution_bytes
    }

    /// Whether approving a held call whose params are `text` with a slot's share of byte buffers beside them, as 1.3.52 reserved it ([`held_room`], [`Self::resolution_bytes`]), could ever fit the pool. When it could not, the approved call runs under an execution slot instead ([`Self::parse_held`]).
    pub fn held_fits_beside_buffers(&self, text: &[u8]) -> bool {
        held_room(text).saturating_add(self.resolution_bytes) <= self.pool.max_bytes()
    }

    /// The most one document the gateway fetches for itself may take as a tree.
    pub fn internal_tree_bytes(&self) -> u64 {
        self.internal_tree_bytes
    }

    /// Parse `bytes` into a tree charged `copies` times its estimate, waiting for room.
    pub async fn parse(&self, bytes: &[u8], copies: u64) -> Result<(Value, MemoryCharge), GatewayError> {
        json_budget::parse_charged(&self.pool, bytes, copies, self.wait).await.map_err(charged_parse_error)
    }

    /// A held call's params as the tree its execution needs, charged with [`held_room`], and `slot`, the execution slot the approved call runs under, if any, which goes with the params into the execution's task.
    /// With no slot the charge also reserves a slot's share of byte buffers ([`Self::resolution_bytes`]): as on 1.3.52 an approved call runs outside the slots, so agent calls filling the slots never refuse an approve and an approve never takes a slot from them, and the pool bounds how many run at once. Approving a call at the one ceiling sent within the 2 MiB body that way reserves at most 128 + 4.5 x 2 + 20 = 157 MiB at hosted defaults, which leaves 35 MiB of the 192 for agent calls while it runs. A call whose params and that share could never fit the pool together ([`Self::held_fits_beside_buffers`]: a raised body limit or response cap, a small pool) is handed the slot its caller took for it ([`crate::limits::Limits::admit_approved`]), and the charge holds only its params. A pool with no room within `wait` is a 429 the approver can retry; nothing has been claimed yet when this runs.
    /// A held call's text is charged at its stored length, never refused when it is held, so a call under the one ceiling whose tree and text pass the whole pool can never be approved on this gateway. That is a 413 telling the approver to deny it, and the approval stays pending until someone does. A call sent in a body whose unheld run fits the pool never reaches it, under any body limit, response cap or pool ([`held_room`]); params no body bounded, which the relay and in-process callers send, can.
    pub async fn parse_held(&self, params: &JsonText, slot: Option<ExecutionSlot>, wait: Duration) -> Result<AgentParams, GatewayError> {
        let text = params.get().as_bytes();
        let mut beside = held_text_room(text, json_budget::estimate(text));
        if slot.is_none() {
            beside = beside.saturating_add(self.resolution_bytes);
        }
        let (value, charge) = json_budget::parse_charged_beside(&self.pool, text, beside, wait).await.map_err(|error| match error {
            ChargedParseError::Pool(PoolRefusal::TooLarge { needed_bytes, pool_bytes }) => GatewayError::TooLarge(format!(
                "approving this call would take about {needed_bytes} bytes of memory, its parameters about {} bytes once unpacked and {beside} bytes beside them for their {} bytes of text and the request written from it, more than this gateway's {pool_bytes}-byte budget, so it can never run here; deny it, and have the agent split it into smaller calls",
                json_budget::estimate(text),
                text.len()
            )),
            other => charged_parse_error(other),
        })?;
        Ok(AgentParams::charged(value, charge).holding(slot))
    }
}

impl Default for MemoryBudget {
    fn default() -> Self {
        Self::from_config(&LimitsConfig::default())
    }
}

/// Why [`MemoryBudget::agent_view`] gave no view.
#[derive(Debug)]
pub enum ViewRefusal {
    /// The body is not one JSON document: the agent gets `null`, as it always has.
    NotJson,
    /// The view is longer than an execution's slot holds, and the view-growth budget had no room for the rest within the wait.
    NoRoom {
        /// The view's length.
        len: usize,
        /// What the slot holds of it.
        free: u64,
        /// How long it waited.
        waited: Duration,
    },
}

impl std::fmt::Display for ViewRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViewRefusal::NotJson => write!(f, "the response is not one JSON document"),
            ViewRefusal::NoRoom { len, free, waited } => write!(
                f,
                "its redacted answer is {len} bytes, and this gateway had no room within {} ms for the part past the {free} bytes an execution holds for one; other calls with answers this long are running",
                waited.as_millis()
            ),
        }
    }
}

/// How a refused reservation or parse reads to a caller.
pub fn charged_parse_error(error: ChargedParseError) -> GatewayError {
    match error {
        ChargedParseError::Pool(refusal) => pool_refusal(refusal),
        ChargedParseError::OverLimit(_) => GatewayError::TooLarge(error.to_string()),
        ChargedParseError::Json(e) => GatewayError::BadRequest(format!("the JSON document could not be read: {e}")),
    }
}

/// A [`PoolRefusal`] as a gateway error: 413 for what never fits, a 429 with `reason: "memory"` for a pool with no room, which is raised before anything about the call is recorded.
pub fn pool_refusal(refusal: PoolRefusal) -> GatewayError {
    match refusal {
        PoolRefusal::TooLarge { .. } => GatewayError::TooLarge(refusal.to_string()),
        PoolRefusal::Busy { .. } => GatewayError::TooManyRequests {
            reason: "memory".to_string(),
            message: refusal.to_string(),
            retry_after_secs: MEMORY_RETRY_AFTER_SECS,
            scope: None,
        },
    }
}

/// The refusal of an agent call whose params would unpack to `estimate` bytes, over `limit`: a 413 on REST, a tool error on `/mcp`. It names both and tells the agent what to do, since sending the same call again fails the same way.
pub fn over_unpacked_limit(estimate: u64, limit: u64) -> GatewayError {
    GatewayError::TooLarge(format!(
        "this call's parameters would take about {estimate} bytes ({}) once unpacked, over this gateway's limit of {limit} bytes ({}) for one call; split it into smaller calls",
        mib(estimate),
        mib(limit)
    ))
}

/// The message of the line [`log_unpacked_refusal`] writes, for a log query to match on.
pub const UNPACKED_REFUSAL_LOG_MESSAGE: &str = "an agent call was refused for its parameters' unpacked size";

/// One line for each agent call the one ceiling refuses, so the ceiling can be checked against the traffic it turns away: the call's estimated unpacked size, the limit and where it was refused, `/v1/invoke` or `/mcp` before the body was parsed and `service` when the service's own check refused it (a relayed or in-process call, or an agent URL the gateway wrote longer). Nothing of the params is logged. Every such call passed admission first, so the lines come no faster than calls are admitted.
pub fn log_unpacked_refusal(estimate: u64, limit: u64, route: &str) {
    tracing::warn!(unpacked_bytes = estimate, limit, route = %route, "{UNPACKED_REFUSAL_LOG_MESSAGE}");
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

/// What a caller shed for want of room in the pool is told to wait: about as long as a large call takes to finish and give its room back.
pub const MEMORY_RETRY_AFTER_SECS: u64 = 2;

/// An agent's params, held with the room they take in the [`MemoryBudget`] and the execution slot their call was admitted under: both are given back when the last clone is dropped, wherever that is.
#[derive(Clone, Debug)]
pub struct AgentParams(Arc<Held>);

#[derive(Clone, Debug)]
struct Held {
    value: Value,
    charge: MemoryCharge,
    slot: Option<ExecutionSlot>,
    unpacked: Option<u64>,
}

impl AgentParams {
    /// Params already in memory that nothing charged for (a test, a relayed frame).
    pub fn uncharged(value: Value) -> Self {
        Self::charged(value, MemoryCharge::none())
    }

    /// Params and the charge that paid for them.
    pub fn charged(value: Value, charge: MemoryCharge) -> Self {
        AgentParams(Arc::new(Held { value, charge, slot: None, unpacked: None }))
    }

    /// These params, also keeping `slot` until the last clone is dropped, so an execution that outlives its caller still counts against the slots.
    pub fn holding(mut self, slot: Option<ExecutionSlot>) -> Self {
        Arc::make_mut(&mut self.0).slot = slot;
        self
    }

    /// These params, with `estimate` as their unpacked size: the estimate [`read_json`] made of the body they were sent in.
    pub fn measured(mut self, estimate: u64) -> Self {
        Arc::make_mut(&mut self.0).unpacked = Some(estimate);
        self
    }

    /// The unpacked size [`Self::measured`] recorded, or `None` for params that did not come through [`read_json`].
    pub fn unpacked_bytes(&self) -> Option<u64> {
        self.0.unpacked
    }

    /// The params.
    pub fn value(&self) -> &Value {
        &self.0.value
    }

    /// The params to change in place. They are not shared yet when a call is being prepared, so this copies nothing then.
    pub fn make_mut(&mut self) -> &mut Value {
        &mut Arc::make_mut(&mut self.0).value
    }

    /// The bytes these params hold in the pool.
    pub fn charged_bytes(&self) -> u64 {
        self.0.charge.bytes()
    }

    /// Free the tree while keeping its charge and slot, when nothing else holds these params: an approved call's execution is done with it before its result is stored.
    pub fn drop_tree(&mut self) {
        if let Some(held) = Arc::get_mut(&mut self.0) {
            drop(std::mem::take(&mut held.value));
        }
    }
}

impl std::ops::Deref for AgentParams {
    type Target = Value;

    fn deref(&self) -> &Value {
        self.value()
    }
}

/// How long a view may be within an execution's slot: [`VIEW_FREE_TENTHS`] of the response cap.
fn view_free_bytes() -> u64 {
    crate::connectors::http_max_response_bytes().saturating_mul(VIEW_FREE_TENTHS) / 10
}

/// An execution slot's byte buffers, B + R + 2.6 R ([`crate::limits::DEFAULT_HOSTED_JSON_POOL_BYTES`]), at most half the pool: what an approved held call reserves in the pool beside its params, as on 1.3.52, unless the two could never fit the pool together and it runs under a slot instead ([`MemoryBudget::parse_held`]).
pub fn resolution_bytes(config: &LimitsConfig) -> u64 {
    let share = (config.body_exec_bytes as u64).saturating_add(crate::connectors::http_max_response_bytes()).saturating_add(view_free_bytes());
    share.min(config.json_pool_bytes / 2)
}

/// What an agent's params sent as `bytes` reserve before they are parsed, and the estimate their tree is built under: the tree, and room for the JSON or form body a connector writes from it while the tree is held, at most [`OUTGOING_BODY_TENTHS`] tenths of the text sent.
/// The builders write that body from the tree they borrow, so it is the only copy of the params an execution makes; the text sent is dropped once it is parsed.
pub fn params_room(bytes: &[u8]) -> (u64, u64) {
    let estimate = json_budget::estimate(bytes);
    (estimate, estimate.saturating_add(bytes.len() as u64 * OUTGOING_BODY_TENTHS / 10))
}

/// What approving a held call whose params are `text` reserves in the pool for them, the most its execution holds of them at once; its execution's buffers are a slot's share beside this, or in its slot ([`MemoryBudget::parse_held`]). While the call runs: the tree, and the request body written from it, no longer than the text as JSON and, as a form body, the text with each string percent-encoded to at most three times its length. Then the text written back from the tree into the approval's row, and once the tree is dropped two copies of it as the result is stored (the row and its text, then the text and SQLite's copy, then the row read back). The row's own copy of the text is not held while the call runs.
/// That is no more than the same params reserved when they ran unheld, the tree and 4.5 times the text sent ([`params_room`]), with one exception: strings serde_json writes are never longer than they were sent and other text at most 4.5 times, so the text and twice its strings is at most 4.5 times the text sent, but an agent URL the gateway canonicalizes is held at up to three times the bytes sent, and its growth is charged in the tree, in the text and twice as a string. That is four times the growth less 1.5 times the text sent, at most about 1.5 MiB since a canonical URL over a third of 2 MiB is refused before the policy decides ([`crate::connectors::MAX_ENCODED_PARAMS_BYTES`]), and only params sent in under about 1.25 MB have any; their tree, within the one ceiling, and their text with it still fit the pool. So a call sent in a body that runs unheld can be approved when it is held; params no body bounded can pass the pool here ([`MemoryBudget::parse_held`]).
pub fn held_room(text: &[u8]) -> u64 {
    let tree = json_budget::estimate(text);
    tree.saturating_add(held_text_room(text, tree))
}

/// The part of [`held_room`] beside a tree of `tree` bytes.
fn held_text_room(text: &[u8], tree: u64) -> u64 {
    let len = text.len() as u64;
    len.saturating_add(2 * string_bytes(text)).max((2 * len).saturating_sub(tree))
}

/// The bytes of `text` inside its JSON strings, keys and values, as written there.
pub fn string_bytes(text: &[u8]) -> u64 {
    let (mut inside, mut escaped, mut count) = (false, false, 0u64);
    for &b in text {
        if !inside {
            inside = b == b'"';
            continue;
        }
        if escaped {
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            inside = false;
            continue;
        }
        count += 1;
    }
    count
}

/// The budget for the stored rows of every pending agent hold: [`LimitsConfig::held_total_bytes`], and never less than a body's length of params ([`LimitsConfig::body_exec_bytes`]) and [`HOLD_ROW_OVERHEAD_BYTES`] for the rest of its row.
/// A hold alone in the queue is admitted whatever its row takes, so one whose row is longer than this takes the rows past it: its params as this gateway writes them may be longer than the body they were sent in (numbers serde_json reads as floats, and an agent URL the gateway canonicalizes), and its other fields may take more than the overhead.
pub fn held_total_bytes(config: &LimitsConfig) -> u64 {
    config.held_total_bytes.max((config.body_exec_bytes as u64).saturating_add(HOLD_ROW_OVERHEAD_BYTES))
}

/// The same for gateway-made control-plane holds, never less than the largest body a change arrives in, a management or a bulk one, and [`HOLD_ROW_OVERHEAD_BYTES`].
/// That floor does not fit every change from such a body: a change's row is its mutation as serde_json writes it, every default field included, about four times its body (a 34,999,832-byte row for one 8,323,223-byte connector install of minimal capability lines). Changes alone in the queue are admitted whatever their rows take, so the rows may pass this by that much.
pub fn control_plane_held_total_bytes(config: &LimitsConfig) -> u64 {
    let body = config.body_default_bytes.max(config.body_bulk_bytes) as u64;
    config.held_total_bytes.max(body.saturating_add(HOLD_ROW_OVERHEAD_BYTES))
}

/// The body of `request` read as a `T`, under the worker's JSON memory budget, with the charge that pays for it and its unpacked size, the estimate of its tree.
///
/// `Json<T>`'s own content-type check runs on the headers first, so its 415 is the one it gives, and the route's `DefaultBodyLimit` still bounds the bytes.
/// Then the body's tree is estimated and checked against the one ceiling on an agent call's unpacked size ([`MemoryBudget::admit_unpacked`]), and [`params_room`] reserved, waiting for room; only then is it parsed, and only `MeteredValue` fields of `T` can build a tree of any size, under that estimate.
/// A body over the ceiling or that can never fit is a 413 and one the pool has no room for a 429, raised before anything about the call exists; every other rejection is `Json<T>`'s, in the gateway's shape ([`crate::request_body::json_rejection`]).
/// A refusal by the ceiling is logged under `route` ([`log_unpacked_refusal`]).
pub async fn read_json<T, S>(budget: &MemoryBudget, request: Request, state: &S, route: &str) -> Result<(T, MemoryCharge, u64), Response>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    read_json_or(budget, request, state, route, |_, over| Some(over.into_response())).await
}

/// [`read_json`], answering a body over the one ceiling with `over_limit`, which is handed the body's bytes, unparsed, and the refusal: how `/mcp` answers it as a tool error carrying the request's id. `None` reads the body as though it were under the ceiling, for a body that carries no agent call, and logs nothing.
pub async fn read_json_or<T, S>(
    budget: &MemoryBudget,
    request: Request,
    state: &S,
    route: &str,
    over_limit: impl FnOnce(&[u8], GatewayError) -> Option<Response>,
) -> Result<(T, MemoryCharge, u64), Response>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    let mut probe = Request::new(Body::empty());
    *probe.headers_mut() = request.headers().clone();
    if let Err(missing @ JsonRejection::MissingJsonContentType(_)) = Json::<serde::de::IgnoredAny>::from_request(probe, state).await {
        return Err(crate::request_body::json_rejection(missing));
    }
    let bytes = Bytes::from_request(request, state)
        .await
        .map_err(|e| crate::request_body::json_rejection(JsonRejection::from(e)))?;
    let (estimate, room) = params_room(&bytes);
    if estimate > budget.unpacked_limit {
        if let Err(rejection) = Json::<serde::de::IgnoredAny>::from_bytes(&bytes) {
            return Err(crate::request_body::json_rejection(rejection));
        }
        if let Some(refusal) = over_limit(&bytes, over_unpacked_limit(estimate, budget.unpacked_limit)) {
            log_unpacked_refusal(estimate, budget.unpacked_limit, route);
            return Err(refusal);
        }
    }
    let charge = match budget.pool.reserve(room, budget.wait).await {
        Ok(charge) => charge,
        Err(refusal) => {
            if let Err(rejection) = Json::<serde::de::IgnoredAny>::from_bytes(&bytes) {
                return Err(crate::request_body::json_rejection(rejection));
            }
            return Err(pool_refusal(refusal).into_response());
        }
    };
    let (parsed, over) = json_budget::with_limit(estimate, || Json::<T>::from_bytes(&bytes));
    let trailing = if parsed.is_ok() { crate::request_body::nothing_after(&bytes).err() } else { None };
    drop(bytes);
    if over {
        return Err(GatewayError::TooLarge(format!(
            "the JSON body would take more than the {estimate} bytes reserved for it once parsed"
        ))
        .into_response());
    }
    if let Some(refusal) = trailing {
        return Err(refusal);
    }
    match parsed {
        Ok(Json(value)) => Ok((value, charge, estimate)),
        Err(rejection) => Err(crate::request_body::json_rejection(rejection)),
    }
}

/// A JSON response made of a small head and tail around one document's text, sent without copying the document: the body is the head, the document's own bytes and the tail.
pub fn document_response(status: StatusCode, assembled: Assembled) -> Response {
    let len = assembled.len();
    streamed_response(status, len, assembled.into_pieces())
}

/// A JSON response of exactly `len` bytes written from `pieces` as they are produced. The length is declared, as a `Json` body declares it, so a client sees the same headers it always has.
pub fn streamed_response(status: StatusCode, len: usize, pieces: impl Iterator<Item = Bytes> + Send + 'static) -> Response {
    let body = Body::from_stream(futures_util::stream::iter(pieces.map(Ok::<Bytes, std::convert::Infallible>)));
    (status, [(header::CONTENT_TYPE, "application/json".to_string()), (header::CONTENT_LENGTH, len.to_string())], body).into_response()
}

/// A JSON document assembled from small pieces around one large document, kept in pieces so it can be written, or escaped into a string, without a second copy of the large part.
pub struct Assembled {
    head: Bytes,
    doc: Bytes,
    tail: Bytes,
}

impl Assembled {
    /// `head` (an object's members, as written by serde_json), then `"key":`, then `doc`.
    pub fn object(head: serde_json::Map<String, Value>, key: &str, doc: JsonText) -> Self {
        Self::object_bytes(head, key, Bytes::from(doc.into_string()))
    }

    /// [`Self::object`] around `doc`'s bytes, which are one JSON document.
    pub fn object_bytes(head: serde_json::Map<String, Value>, key: &str, doc: Bytes) -> Self {
        let mut text = serde_json::to_string(&Value::Object(head)).unwrap_or_else(|_| "{}".to_string());
        text.pop();
        if text.len() > 1 {
            text.push(',');
        }
        text.push_str(&serde_json::to_string(key).unwrap_or_default());
        text.push(':');
        Assembled { head: Bytes::from(text), doc, tail: Bytes::from_static(b"}") }
    }

    /// The whole document's length in bytes.
    pub fn len(&self) -> usize {
        self.head.len() + self.doc.len() + self.tail.len()
    }

    /// Never true; here so a length check reads naturally.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn pieces(&self) -> impl Iterator<Item = Bytes> {
        [self.head.clone(), self.doc.clone(), self.tail.clone()].into_iter()
    }

    /// The document's bytes, piece by piece.
    pub fn into_pieces(self) -> impl Iterator<Item = Bytes> {
        [self.head, self.doc, self.tail].into_iter()
    }

    /// The document as one [`JsonText`] (one copy), for a caller that needs it whole.
    pub fn to_text(&self) -> JsonText {
        let mut text = String::with_capacity(self.len());
        for piece in self.pieces() {
            text.push_str(std::str::from_utf8(&piece).unwrap_or_default());
        }
        JsonText::from_string(text).unwrap_or_default()
    }

    /// The document's text as the contents of a JSON string (escaped, without the quotes), produced a chunk at a time.
    pub fn escaped(&self) -> impl Iterator<Item = Bytes> {
        self.pieces().flat_map(escaped_chunks)
    }

    /// The length of [`Self::escaped`], counted without producing it.
    pub fn escaped_len(&self) -> usize {
        [&self.head, &self.doc, &self.tail].iter().map(|piece| escaped_len(piece)).sum()
    }
}

/// How long `text` is once escaped as the inside of a JSON string, as serde_json escapes it: a quote and a backslash take two bytes, a control character two (`\n` and its kind) or six (`\u00XX`).
pub fn escaped_len(text: &[u8]) -> usize {
    text.iter()
        .map(|&b| match b {
            b'"' | b'\\' | 0x08 | 0x0c | b'\n' | b'\r' | b'\t' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        })
        .sum()
}

/// How much of a document is escaped into one chunk of a response body.
const ESCAPE_CHUNK_BYTES: usize = 64 * 1024;

/// `text`'s bytes escaped as the inside of a JSON string, `ESCAPE_CHUNK_BYTES` of input at a time. JSON escaping is per character, so escaping each piece and joining them is escaping the whole.
fn escaped_chunks(text: Bytes) -> impl Iterator<Item = Bytes> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        if at >= text.len() {
            return None;
        }
        let mut end = (at + ESCAPE_CHUNK_BYTES).min(text.len());
        // Back off a UTF-8 continuation byte so the chunk ends on a character boundary.
        while end < text.len() && end > at && text[end] & 0xC0 == 0x80 {
            end -= 1;
        }
        let chunk = std::str::from_utf8(&text[at..end]).unwrap_or_default();
        let quoted = serde_json::to_string(chunk).unwrap_or_default();
        at = end;
        Some(Bytes::from(quoted[1..quoted.len() - 1].to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_assembled_object_reads_back_as_one_document_and_escapes_as_one_string() {
        let mut head = serde_json::Map::new();
        head.insert("decision".into(), json!({ "kind": "allow" }));
        head.insert("upstream_status".into(), json!(200));
        let doc = JsonText::from_value(&json!({ "q": "a \"quoted\" é\n", "n": [1, 2] }));
        let assembled = Assembled::object(head, "result", doc);
        let whole = assembled.to_text().to_value_unbounded();
        assert_eq!(whole, json!({ "decision": { "kind": "allow" }, "upstream_status": 200, "result": { "q": "a \"quoted\" é\n", "n": [1, 2] } }));
        let escaped: Vec<u8> = assembled.escaped().flat_map(|b| b.to_vec()).collect();
        let as_string: String = serde_json::from_str(&format!("\"{}\"", String::from_utf8(escaped).unwrap())).unwrap();
        assert_eq!(as_string, assembled.to_text().get());
        let empty = Assembled::object(serde_json::Map::new(), "result", JsonText::null());
        assert_eq!(empty.to_text().get(), r#"{"result":null}"#);
    }

    #[test]
    fn the_escaped_length_is_what_serde_json_writes() {
        let text: String = (0u8..=127).map(char::from).chain("é\u{1F600}".chars()).collect::<String>().repeat(3);
        let quoted = serde_json::to_string(&text).unwrap();
        assert_eq!(escaped_len(text.as_bytes()), quoted.len() - 2);
    }

    #[test]
    fn escaping_in_chunks_keeps_every_character_whole() {
        let text: String = "é\"\\\u{1}x".repeat(ESCAPE_CHUNK_BYTES / 3);
        let chunks: Vec<Bytes> = escaped_chunks(Bytes::from(text.clone())).collect();
        assert!(chunks.len() > 1);
        let joined: String = chunks.iter().map(|c| std::str::from_utf8(c).unwrap()).collect();
        assert_eq!(format!("\"{joined}\""), serde_json::to_string(&text).unwrap());
    }

    /// `[1e15,...]` as large as fits under `cap`: its view is 3.8 times its size.
    fn exponent_numbers(cap: usize) -> Vec<u8> {
        let mut body = b"[".to_vec();
        while body.len() + 6 < cap {
            body.extend_from_slice(b"1e15,");
        }
        body.pop();
        body.push(b']');
        body
    }

    /// A view no longer than its slot's share takes nothing from the view-growth budget; a longer one holds the rest there for as long as its charge lives, so the budget bounds how many such views exist at once, and one that finds no room is refused rather than written.
    #[tokio::test]
    async fn a_view_past_its_slots_share_holds_the_rest_in_the_growth_budget() {
        let mib = 1024 * 1024;
        let config = LimitsConfig { view_growth_bytes: 8 * mib, json_pool_wait: Duration::ZERO, ..LimitsConfig::defaults_for(true) };
        let budget = MemoryBudget::from_config(&config);
        let scrub = CredentialScrub::default();
        let response = crate::connectors::http_max_response_bytes() as usize;
        assert_eq!(budget.view_free_bytes(), response as u64 * VIEW_FREE_TENTHS / 10);

        let short = br#"{"items":[{"id":1,"name":"a"}]}"#;
        let (view, room) = budget.agent_view(short, &scrub, &[]).await.unwrap();
        assert_eq!(view.get(), std::str::from_utf8(short).unwrap());
        assert_eq!(room.bytes(), 0, "a view within the slot's share is not charged");

        let body = exponent_numbers(response);
        let (view, room) = budget.agent_view(&body, &scrub, &[]).await.unwrap();
        let past = view.len() as u64 - budget.view_free_bytes();
        assert!(view.len() * 10 > body.len() * 37, "the whole 3.8x view is written: {} bytes", view.len());
        assert!(room.bytes() >= past && room.bytes() < past + 1024, "the part past the slot's share is charged: {} of {past}", room.bytes());
        assert_eq!(budget.view_growth().available_bytes(), 8 * mib - room.bytes());

        match budget.agent_view(&body, &scrub, &[]).await {
            Err(refusal @ ViewRefusal::NoRoom { .. }) => assert!(refusal.to_string().contains("no room"), "{refusal}"),
            other => panic!("a second long view while the first holds the budget is refused, got {:?}", other.map(|(v, r)| (v.len(), r))),
        }
        drop(view);
        drop(room);
        assert_eq!(budget.view_growth().available_bytes(), 8 * mib, "given back with the charge");
        assert!(budget.agent_view(&body, &scrub, &[]).await.is_ok(), "and the next long view fits");
        assert!(matches!(budget.agent_view(b"not json", &scrub, &[]).await, Err(ViewRefusal::NotJson)));
    }

    #[tokio::test]
    async fn params_keep_their_charge_until_the_last_holder_drops_them() {
        let budget = MemoryBudget::from_config(&LimitsConfig { json_pool_bytes: 16 * 1024 * 1024, ..LimitsConfig::default() });
        let held = budget.parse_held(&JsonText::from_value(&json!({ "rows": [{ "id": 1 }, { "id": 2 }] })), None, budget.wait()).await.unwrap();
        assert!(held.charged_bytes() > 0);
        let mut in_task = held.clone();
        in_task.drop_tree();
        assert_eq!(in_task.value(), &json!({ "rows": [{ "id": 1 }, { "id": 2 }] }), "a tree another holder still has stays");
        drop(held);
        assert!(budget.pool().available_bytes() < budget.pool().max_bytes(), "the task's clone still holds the room");
        drop(in_task);
        assert_eq!(budget.pool().available_bytes(), budget.pool().max_bytes());
    }

    /// The tree goes and its charge stays, so an approved call's result is stored within the room its approval reserved.
    #[tokio::test]
    async fn dropping_the_tree_keeps_the_charge() {
        let budget = MemoryBudget::from_config(&LimitsConfig { json_pool_bytes: 16 * 1024 * 1024, ..LimitsConfig::default() });
        let mut held = budget.parse_held(&JsonText::from_value(&json!({ "rows": [1, 2, 3] })), None, budget.wait()).await.unwrap();
        let charged = held.charged_bytes();
        held.drop_tree();
        assert_eq!(held.value(), &Value::Null);
        assert_eq!(held.charged_bytes(), charged);
        assert!(budget.pool().available_bytes() < budget.pool().max_bytes(), "the charge stays with the params");
        drop(held);
        assert_eq!(budget.pool().available_bytes(), budget.pool().max_bytes());
    }

    #[test]
    fn string_bytes_counts_what_is_inside_the_quotes_as_written() {
        assert_eq!(string_bytes(br#"{"a":1,"bc":[true,null,1e15]}"#), 3);
        assert_eq!(string_bytes(br#"["x\"y","\u00e9\\",""]"#), 4 + 8);
        assert_eq!(string_bytes("{\"é\":\"ü\"}".as_bytes()), 4);
        assert_eq!(string_bytes(b"12345"), 0);
    }

    /// The claim [`held_room`] makes: approving params sent in a body reserves no more in the pool than the same params reserved when they ran unheld (but for an agent URL the gateway canonicalizes, pinned in the next test), for the shapes that grow the most when serde_json writes them (exponent numbers), strings a form body percent-encodes, short rows and escapes; so a call that runs unheld can be approved when it is held.
    #[test]
    fn approving_reserves_no_more_than_the_unheld_call_did() {
        let shapes: [(&str, String); 7] = [
            ("1e15 numbers", format!("[{}]", vec!["1e15"; 50_000].join(","))),
            ("1e15 numbers, padded", format!("[ {} ]", vec!["1e15"; 50_000].join(" , "))),
            ("a long string", format!(r#"{{"content":"{}"}}"#, "QUJD+/09".repeat(40_000))),
            ("escaped strings", format!("[{}]", vec![r#""a\"\\\n\u0001é""#; 20_000].join(","))),
            ("point rows", format!("[{}]", vec![r#"{"x":1,"y":2}"#; 20_000].join(","))),
            ("one-key rows", format!("[{}]", vec![r#"{"a":1}"#; 20_000].join(","))),
            ("mixed", format!(r#"{{"n":[{}],"s":"{}"}}"#, vec!["-1.5e-300"; 10_000].join(","), "x".repeat(100_000))),
        ];
        for (shape, sent) in shapes {
            let value: Value = serde_json::from_str(&sent).unwrap();
            let stored = JsonText::from_value(&value);
            let (_, unheld) = params_room(sent.as_bytes());
            let approving = held_room(stored.get().as_bytes());
            assert!(approving <= unheld, "{shape}: approving reserves {approving} bytes, the unheld call {unheld}");
            assert_eq!(JsonText::from_value(&serde_json::from_str::<Value>(stored.get()).unwrap()).get(), stored.get(), "{shape}: written back from its tree as it was stored");
        }
    }

    /// The exception [`held_room`] states: an agent URL the gateway canonicalizes is held at up to three times the bytes sent, so approving it can reserve more than the call reserved unheld. At the longest canonical URL the request builder takes, a third of 2 MiB, that is about 1.5 MiB, and none once the params sent reach about 1.25 MB, here with a string beside the URL, which narrows it least.
    #[test]
    fn an_agent_url_the_gateway_canonicalizes_can_reserve_up_to_about_one_and_a_half_mib_more() {
        use crate::connectors::{canonical_agent_params, Connector, GenericHttpConnector, MAX_ENCODED_PARAMS_BYTES};
        let cap = GenericHttpConnector::new("generic_http", "sec_synthetic").capabilities().into_iter().find(|c| c.id == "http.request").expect("the generic HTTP capability");
        let excess = |path: &str, pad: usize| {
            let url = format!("https://api.example.com/{path}");
            let sent = format!(r#"{{"method":"GET","url":{},"pad":"{}"}}"#, serde_json::to_string(&url).unwrap(), "x".repeat(pad));
            let held = canonical_agent_params("generic_http", &cap, &serde_json::from_str(&sent).unwrap()).expect("the URL is written longer");
            let canonical = held["url"].as_str().unwrap().len();
            assert!(canonical * 3 <= MAX_ENCODED_PARAMS_BYTES, "{canonical}: within what the request builder takes");
            let stored = JsonText::from_value(&held);
            (held_room(stored.get().as_bytes()) as i64 - params_room(sent.as_bytes()).1 as i64, sent.len())
        };
        let spaces = (MAX_ENCODED_PARAMS_BYTES / 3 - 25) / 3;
        let accented = (MAX_ENCODED_PARAMS_BYTES / 3 - 25) / 6;
        for (shape, path) in [("spaces", format!("{}x", " ".repeat(spaces))), ("accented letters", format!("{}x", "\u{e9}".repeat(accented)))] {
            let (more, sent) = excess(&path, 0);
            eprintln!("{shape}: approving reserves {more} bytes more than unheld for {sent} bytes sent");
            assert!(more > 0 && more <= 3 * 1024 * 1024 / 2, "{shape}: {more} bytes more than unheld, {sent} sent");
            let (more, sent) = excess(&path, 1_050_000);
            assert!(more <= 0 && sent < 1_300_000, "{shape}: {more} bytes more than unheld, {sent} sent");
        }
    }
}
