//! Resource limits at the gateway's own service boundary.
//!
//! A hosted worker is reachable directly by an agent (Cloud Run ingress `all`, invoker `allUsers`),
//! so a limit that lives at permaura.com or at the Cloudflare edge cannot bind the traffic that
//! matters. Everything here therefore binds in-process, where a direct agent has to pass through it.
//!
//! What this module holds:
//!
//! - [`LimitsConfig`], every number in one place, each one env-overridable and clamped.
//! - the per-route-group request body limits, the inbound request timeout and the execution ceiling,
//! - a token bucket per caller and a global in-flight execution semaphore with a bounded wait queue,
//! - one more token bucket for the worker as a whole, which the monthly fair-use ceiling
//!   ([`crate::fair_use`]) lowers once a hosted worker has crossed it,
//! - the one structured log line every rejection emits, throttled so a flood of rejections cannot
//!   become a flood of log lines.
//!
//! **All of it is in-memory and per-instance.** Nothing here survives a cold start, and Cloud Run
//! cold-starts a scale-to-zero worker constantly. Two overlapping revisions during a rollout each run
//! their own counters, so each admits a full quota. That is accepted because these are capacity
//! guards rather than anything billed.
//!
//! **Nothing here writes to the store.** That is not an efficiency note, it is the design constraint:
//! on a hosted worker every store mutation is a full snapshot upload, so a rejection that touched the
//! store would make refusing a request more expensive than serving one.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::connectors;
use crate::error::GatewayError;
use crate::AppState;

// ── Defaults ────────────────────────────────────────────────────────────────────
//
// Sized for the shape the hosted fleet actually runs: one Cloud Run instance, 1 vCPU (so one tokio
// worker thread), 512 MiB, a SQLite store whose every mutation is a whole-database PUT to one GCS
// object name. Each one carries the measurement that would replace the guess.

/// Body limit for the execution routes (2 MiB). Deliberately the same number axum 0.7 applies by
/// default, chosen rather than inherited: agent params are small, but an SFTP put sends its payload
/// as base64 in the body and needs the headroom.
/// *Measure:* the p99 body size of real agent invocations, and the base64 size of the largest
/// legitimate SFTP put.
pub const DEFAULT_BODY_EXEC_BYTES: usize = 2 * 1024 * 1024;

/// This number and the SFTP put cap are one decision, not two.
///
/// A put's content arrives base64-encoded in the `/v1/invoke` body, so a put cap larger than this
/// limit can deliver is not a cap at all: it hands the caller a 413 that names no cap instead of the
/// connector's message. `permaura-connectors` derives [`connectors::SFTP_PUT_MAX_BYTES`] from its
/// own copy of this budget; this assertion is what stops the copy drifting, and it fails the build
/// rather than a test.
const _: () = assert!(
    connectors::SFTP_PUT_BODY_BUDGET_BYTES == DEFAULT_BODY_EXEC_BYTES as u64,
    "the SFTP put cap is derived from the execution body limit: change both or neither"
);

/// The smallest execution body limit an operator may configure: enough for an SFTP put at the
/// shipped cap, plus the envelope reserve.
///
/// The floor exists because the env knob is the other way the two numbers can disagree. A limit set
/// below this would resurrect exactly the bug the derivation above closes, silently, on a gateway
/// whose SFTP capabilities were created when the limit was wider.
pub const MIN_BODY_EXEC_BYTES: usize = (connectors::base64_len(connectors::SFTP_PUT_MAX_BYTES)
    + connectors::SFTP_PUT_ENVELOPE_RESERVE_BYTES)
    as usize;

/// Body limit for the bulk routes (8 MiB): vault bundles, an imported OpenAPI document, a connector
/// manifest. These are legitimately larger than anything else the gateway accepts, and 8 MiB matches
/// the response cap the web tier already applies to its own fetches.
/// *Measure:* the size of a vault export for a real estate, and of the largest tier-1 OpenAPI spec.
pub const DEFAULT_BODY_BULK_BYTES: usize = 8 * 1024 * 1024;

/// Body limit for everything else (256 KiB). No management payload is large: a grant, a policy, a
/// session, a device registration are all kilobytes, and the biggest realistic one is a secret
/// holding a PEM or a service-account JSON.
/// *Measure:* the p99 body size across the management routes.
pub const DEFAULT_BODY_DEFAULT_BYTES: usize = 256 * 1024;

/// Stored bytes of the staged rows one requester may have behind pending holds (4 MiB), counted as each whole row is stored (its sealed envelope and its metadata), so a payload moved from the value into the labels is counted too. A sealed byte is stored as about 3.6, so this is four values at the management body limit, or dozens of PEMs and service-account files; a hosted upload holds about three copies of the database, and the 1,024-hold ceiling alone let one member park about 915 MiB on a 512 MiB worker.
/// *Measure:* the stored row of the largest real credential (a service-account JSON or a PEM chain), times the changes one person plausibly leaves waiting.
pub const DEFAULT_STAGED_BYTES_PER_REQUESTER: usize = 4 * 1024 * 1024;

/// Stored bytes of the staged rows behind pending holds across the whole gateway (16 MiB), counted as for one requester: about 48 MiB inside a hosted upload.
/// *Measure:* resident memory of a hosted upload with this many staged bytes, against the worker's 512 MiB.
pub const DEFAULT_STAGED_BYTES_PER_GATEWAY: usize = 16 * 1024 * 1024;

/// Stored bytes of one secret's metadata, its labels above all, as JSON (4 KiB). Labels are short tags a person types or a console shows as chips ("production", "billing", a display name); the seed's longest set is under 100 bytes and ten labels of 64 characters are under 1 KiB, so 4 KiB refuses only a payload, never a real use. Without it the labels rode a 256 KiB body into a staged row the staged-bytes bound never saw.
/// *Measure:* the largest metadata among real estates' secrets, from a vault export.
pub const DEFAULT_SECRET_METADATA_BYTES: usize = 4 * 1024;

/// Inbound request timeout (120s). Above [`DEFAULT_EXECUTION_MS`] so the execution ceiling fires
/// first and the caller gets the specific error, and below Cloud Run's 300 second default so the
/// gateway decides its own deadline rather than the edge.
/// *Measure:* p99 end-to-end latency for the slowest legitimate route (a vault export at a realistic
/// estate size).
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 120_000;

/// The floor of the deadline an execution route's response has to be sent in, holding its execution slot (30s); the deadline grows with the response at [`crate::delivery::DELIVERY_MIN_RATE`] (128 KiB/s) up to 120 s, or to this floor when that is longer, so a stalled reader gives the slot back while the Cloud Run frontend, a Cloudflare tunnel or a local or remote MCP client reading at that rate gets all of a response up to 15 MiB (more under a floor past 120 s). Past that, which the longest views reach at the defaults, the deadline stops growing and a reader needs the response's length over the cap.
/// *Measure:* p99 time from response to last byte written for the largest legitimate view, through the Cloud Run frontend and through a Cloudflare tunnel to a remote MCP client.
pub const DEFAULT_DELIVERY_TIMEOUT_MS: u64 = 30_000;

/// Execution-duration ceiling for one upstream call or command (90s). A backstop, not a replacement:
/// the HTTP connector already stops at 30s, SSH at 30s and a command at 60s. It exists for the paths
/// with no budget of their own (dynamic secret resolution, a vault unwrap, a connector added later
/// that forgets one) and sits above the largest connector budget so it can never pre-empt a
/// connector's own, better-worded, timeout.
/// *Measure:* p99 `execute_allowed` duration per capability kind against real upstreams.
pub const DEFAULT_EXECUTION_MS: u64 = 90_000;

/// Sustained execution rate per caller on a gateway its owner runs (120 a minute). Two a second:
/// above a hosted store's write ceiling on purpose, because a self-run store uploads nothing and the
/// bucket is the cost guard there (each allowed invocation is an upstream call the tenant pays their
/// provider for) while the semaphore below is the capacity guard. A hosted worker takes
/// [`DEFAULT_HOSTED_RATE_PER_MIN`] instead.
/// *Measure:* requests per minute per session for one active agent at a realistic history size.
pub const DEFAULT_RATE_PER_MIN: u32 = 120;

/// Burst allowance per caller on a gateway its owner runs (30). Absorbs an agent's opening handshake
/// and first batch without shaping normal work; a burst this size drains in 15 seconds at the
/// sustained rate.
/// *Measure:* the request count in an agent's first 10 seconds after connecting.
pub const DEFAULT_RATE_BURST: u32 = 30;

/// Sustained execution rate per caller on a hosted worker (30 a minute): the worker's own rate, so a
/// single agent can use the whole of what the store can carry and no more.
///
/// *Measure (7 October 2026, gateway 1.3.32, 512 MiB and 1 vCPU, one agent driving an SSH
/// command that fails at its lookup):* 0.5 executions a second sustained ran clean, every call
/// executed with p95 1.2 s; from 0.75 a second Cloud Storage answered 429 on the single `store.db`
/// object (about one write a second per object, and each execution writes twice), the gateway
/// refused writes until an upload carried, and p95 rose to 4 s. The limits this replaced (120 a
/// minute per caller, 300 per worker) first refused anything at 3 a second.
pub const DEFAULT_HOSTED_RATE_PER_MIN: u32 = 30;

/// Burst allowance per caller on a hosted worker (10): an MCP handshake (`initialize`, the
/// `initialized` notification, `tools/list`, each charged like a call) and a short batch of calls.
/// *Measure:* the request count in an agent's first 10 seconds after connecting, against the 429s
/// Cloud Storage returns for a burst of uploads to one object.
pub const DEFAULT_HOSTED_RATE_BURST: u32 = 10;

/// Sustained execution rate across every caller on a hosted worker (30 a minute), the measured
/// ceiling of one worker's store: half an execution a second, which is one snapshot write a second
/// to the one object Cloud Storage rate-limits at about that. The per-caller bucket stops one agent
/// monopolizing the worker; this stops many agents together from driving the store past what it
/// can carry, which is where a worker used to fail rather than refuse.
/// *Measure:* see [`DEFAULT_HOSTED_RATE_PER_MIN`] for the run that set it. After any change to how
/// many uploads an execution makes, re-measure the sustained execution rate at which Cloud Storage
/// starts answering 429 on the store object, and set this at or below it.
pub const DEFAULT_WORKER_RATE_PER_MIN: u32 = 30;

/// Burst allowance across every caller on a hosted worker (10), the same as one caller's, so a burst
/// the worker admits is one the store has been seen to absorb.
pub const DEFAULT_WORKER_RATE_BURST: u32 = 10;

/// The worker-wide burst a gateway its owner runs gets when it sets a worker rate and no burst (100),
/// which is what every gateway got before the hosted numbers were measured.
pub const DEFAULT_SELF_RUN_WORKER_RATE_BURST: u32 = 100;

/// Concurrent in-flight executions (8). One vCPU means one tokio worker, and every mutating request
/// donates its worker through `block_in_place` and then queues on one store mutex held across a GCS
/// round trip, so admitting far more than a small multiple of the store's service rate only builds a
/// queue nobody bounded. Cloud Run's own default admits 80 into this same instance.
/// *Measure:* p95/p99 `persist()` latency at a realistic history, and the memory high-water mark at
/// N concurrent in-flight invocations. The 7 October run saw memory climb to the 512 MiB limit at 1.5 executions
/// a second with these 8 slots full, but the slots were not what held it: every execution ran the
/// vault KDF (a 19 MiB working set) and glibc kept each freed one. With the derived key cached
/// and the mmap threshold pinned, `tests/hosted_soak.rs` holds a 512 MiB container under 30 MiB
/// resident with all 8 slots and the queue full.
pub const DEFAULT_MAX_INFLIGHT: usize = 8;

/// Bounded wait queue (16), two deep per execution slot: enough to ride out one slow snapshot upload
/// without shedding, short enough that a queued request is answered well inside its wait budget.
/// *Measure:* the queue occupancy distribution under sustained load at 100k audit events. The 7 October run saw the
/// queue and busy limits refuse only at 3 executions a second, after Cloud Storage and memory had
/// already given way; the hosted rates above now refuse first.
pub const DEFAULT_QUEUE_DEPTH: usize = 16;

/// How long a queued request waits for a permit before it is shed (5s). A 429 the caller can retry
/// beats a request that eventually succeeds after a wait nobody wanted.
/// *Measure:* p99 `persist()` latency; the wait should cover two of those and no more. The 7 October run measured
/// end-to-end p95 at 1.2 s at 0.5 executions a second and 4 to 4.5 s at 0.75 to 1 a second, once
/// Cloud Storage was answering 429 and each retry held the store's lock.
pub const DEFAULT_QUEUE_WAIT_MS: u64 = 5_000;

/// The worker's budget for the JSON trees its calls hold at once, on a hosted worker (192 MiB).
///
/// A `serde_json::Value` costs per node, not per byte (about 85 bytes per byte for a body of one-key objects), so the byte caps alone let one call hold more than the worker.
/// Every tree built from untrusted bytes (an agent's params, a Vercel response, a held call's params when it is approved or rendered for an approver, a relayed result) reserves its estimated cost here first; every other upstream body an agent receives, and command output, is streamed into its redacted view and never built into a tree.
/// An agent's params reserve their tree and room for the JSON body a connector writes from it ([`OUTGOING_BODY_TENTHS`]), the one copy of them an execution makes: the builders write that body from the tree they borrow rather than from a second tree.
/// A document the gateway fetches for itself is charged here only when there is room at once, and otherwise built beside the pool under [`DEFAULT_INTERNAL_TREE_BYTES`]; see there.
/// Reading an agent's GraphQL documents builds no tree. In proportion to a document it holds only the brackets open at once, at most three bytes a bracket ([`crate::connectors::graphql::read_bytes`]), and only while nothing written from the params is held: at the gate and in the request builder before the body is written, and on the response path after the request is sent. So it fits in the room the params reserve for that body, 4.5 bytes for every byte of the document; past that it holds a fixed hundred bytes or so, an error's text or the stack's first buffer, which the pool counts for no call. A document in a URL's `query` parameter is read only on the response path, from the URL's parse and one decoded parameter at a time, each about the URL's length at most, so with the stack it fits in that room and the execution's request buffer B, both idle by then. The aliases of redacted fields a response is redacted under are charged here while it is read, past a fixed allowance ([`crate::connectors::UNCHARGED_ALIAS_ROOM`]) and only when there is room at once; with none the whole response is redacted ([`crate::connectors::response_redact_keys`]).
///
/// The arithmetic for 512 MiB, every class at its worst at once:
/// - about 96 MiB for the process and the in-memory copy of the store each snapshot upload reads, for an estate apart from the rows requests add. Those have budgets of their own, 56 MiB on a hosted worker: 16 MiB of staged credential rows ([`DEFAULT_STAGED_BYTES_PER_GATEWAY`]), 16 MiB of agent holds and 16 of control-plane holds ([`DEFAULT_HOSTED_HELD_TOTAL_BYTES`] each, which a hold alone in its queue may pass: one connector install in a body just under the 8 MiB bulk limit is held as a 33.4 MiB row) and 8 MiB of capability rows ([`DEFAULT_HOSTED_CAPABILITY_BYTES`]). An upload holds about three copies of the database (the database, its `VACUUM INTO` copy read into memory, the request body built from that), so with all four at their ceilings an upload needs about 168 MiB beyond this line, and about 220 MiB with that one change in place of the control-plane 16 MiB, which the 512 MiB does not cover; not measured;
/// - 8 execution slots, which bound every execution in flight, a caller who hung up included, and an approved held call whose params and a slot's share could never fit this pool together ([`ExecutionSlot`], [`Limits::admit_approved`]), and each execution route's response until it has been sent or its delivery deadline passes ([`crate::delivery::hold_until_sent`]), of at most 20 MiB of byte buffers each: B + R + [`VIEW_FREE_TENTHS`] / 10 x R, for the 2 MiB request body B (the agent's text until it is parsed, then the URL and headers written from the params and the keys a form body writes beside its values, which the connector builders hold to [`crate::connectors::MAX_ENCODED_PARAMS_BYTES`] together; a form body's values, like a JSON body, are in the params' charge), the 5 MiB response R and the first 2.6 R of its redacted view, written once at its length. A slot's other paths fit the same 20 MiB: an agent reading its approval's stored result holds the row's text once, the result served from it without its params being built ([`crate::store::ApprovalOutcome`]), at most 8 MiB of result ([`crate::store::MAX_STORED_RESULT_BYTES`]) and 4.5 B of params as this gateway wrote them, 17 MiB, and a slot held for a delivery keeps the view and hyper's copies of at most [`crate::delivery::STALLED_COPY_BYTES`] of it, B and R having been given back; 160 MiB;
/// - the rest of every view longer than 2.6 R, held in its own budget until its response has been sent (a relayed invoke's until its result has been framed), or an approved held call's until its result is stored and the row read back to answer the approver ([`DEFAULT_HOSTED_VIEW_GROWTH_BYTES`]): a view is at most [`VIEW_GROWTH_TENTHS`] / 10 x R, so at most 1.2 R past what its slot holds, and two such views fit at once; 12 MiB;
/// - two 8 MiB operator bulk bodies, 16 MiB;
/// - outside every budget, what hyper keeps of a response whose delivery deadline passed while its client read nothing: the deadline gives back the slot, the view-growth room and the unsent view, but the copies hyper has queued, up to about 472 KiB ([`crate::delivery::STALLED_COPY_BYTES`]), stay until the connection closes. Cloud Run closes it at a hosted worker's 130 s request timeout, so at its concurrency of 32 that is at most about 15 MiB; on a self-run gateway nothing closes a connection whose client keeps it open without reading, since neither `axum::serve` nor hyper's HTTP/1 has a write timeout, so there each call whose client does that adds up to 472 KiB for as long as it does;
/// - and this pool, 192 MiB. An approved held call runs outside the slots, as on 1.3.52, so it reserves a slot's 20 MiB here beside its params ([`crate::memory::resolution_bytes`]) and the pool bounds how many run at once; only one whose params and that 20 MiB could never fit the pool together runs under an execution slot instead ([`Limits::admit_approved`]). That 20 MiB, here or in its slot, covers its execution's buffers, then storing its result, which holds the row (the result moved into it) and the row's text, then the text and SQLite's copy, then the row read back to answer the approver, 2 x (8 MiB + B) each time, the params' text in those copies being charged here. For its params approving reserves here their tree and room for their text ([`crate::memory::held_room`]): the tree and the body written from it while it runs, at most the text and twice its strings, then two copies of the text once the tree is dropped. That is no more than the same params reserved unheld, the tree and 4.5 times the text sent, but for an agent URL the gateway canonicalizes, which can add about 1.5 MiB to params sent in under 1.25 MB. So approving a call at the one ceiling on an agent call's unpacked size, 128 MiB ([`LimitsConfig::unpacked_limit`]), whose params were sent within the 2 MiB body reserves at most 128 + 4.5 x 2 + 20 = 157 MiB, which leaves 35 MiB of the pool for other calls. Params this gateway writes longer than they were sent (numbers serde_json reads as floats, and an agent URL it canonicalizes) are held at their stored length, at most 4.5 times the body, and charged at it. Params no body bounded (the relay's, an in-process caller's) are held at whatever length they are written, and an approval that cannot fit the pool is refused ([`crate::memory::MemoryBudget::parse_held`]). The tree an approval's rendering walks (a listing, a read, the check of what a device was shown), at most that ceiling for an agent call and 164 MiB for a control-plane change, as on 1.3.52 ([`LimitsConfig::render_limit`]), is charged here too while it is rendered ([`crate::service::EnforcementService::display_room`]); a row whose approval is running is rendered only within room already held or room the pool has at once, for a listing, a read or the check of a device's approve, and another approve of it waits for no room or slot, so none of them queues behind that approval's reservation. In all, 476 MiB, and 644 MiB with the request-made rows at every ceiling during an upload (about 696 MiB with that lone change); about 15 MiB more for each with 32 deliveries stalled past their deadlines. Not counted: an operator's read of one approval (`GET /v1/approvals/:id`), which serves its params' rendering and their hash and so reads the row whole, its text and the row, up to 2 x (8 MiB + 4.5 B), 34 MiB, on a route outside the slots; and the answer to an approve, or to a repeated approve of a settled approval, which sends the row read back, up to 8 MiB of result and 4.5 B of params, on the approve routes, which are not execution routes.
///
/// An agent call's params are admitted only within the one ceiling on their unpacked size, this pool less [`UNPACKED_HEADROOM_BYTES`], 128 MiB, held or not. 2 MiB of params of realistic rows with two or more fields estimates at up to about 113 MiB (`{"x":1,"y":2}` points; empty-key two-field rows such as `{"":0,"a":0}` at about 120 MiB) and reserves that and 9 MiB for the body written from it, so it is admitted, as are one-key `{"id":i}` rows whose ids have four digits or more (124 MiB at four, 113 MiB counting up from 0). One-key rows over shorter values are not: near 2 MiB of `{"a":1}` estimates at about 180 MiB, `{"id":n}` at 161 MiB for one-digit ids, 148 MiB for two and 135 MiB for three, `{"qty":5}` at 146 MiB and `{"tag":"a"}` at 129 MiB, and each is refused before it is parsed, as are denser bodies, such as objects nested inside objects or empty-key objects `{"":0}`.
pub const DEFAULT_HOSTED_JSON_POOL_BYTES: u64 = 192 * 1024 * 1024;

/// The same budget on a gateway its owner runs (512 MiB): the same structure over a machine with more memory than a hosted worker (96 + 160 + 64 + 16 + 512 = 848 MiB at the defaults' worst, approved held calls inside the pool, and the copies of deliveries stalled past their deadlines beside it, which nothing bounds there), so the densest 2 MiB bodies are admitted there and the rest of the calls run around them.
/// A gateway on a small machine lowers it with `PERMAURA_LIMIT_JSON_POOL_BYTES`.
pub const DEFAULT_JSON_POOL_BYTES: u64 = 512 * 1024 * 1024;

/// How long a call waits for room in the JSON tree budget before it is shed with a 429 (10s).
/// Longer than the admission queue's wait, because what it waits for is another call finishing, and a realistic large call is worth more waiting than a refusal; shorter than every request timeout.
pub const DEFAULT_JSON_POOL_WAIT_MS: u64 = 10_000;

/// What the one ceiling on an agent call's unpacked size keeps free of the JSON pool beside the largest call it admits (64 MiB): 128 MiB of the hosted 192 MiB pool is the ceiling, 448 MiB of the self-run 512. Approving a call at the ceiling sent in a 2 MiB body reserves at most 29 MiB of that beside its tree, 9 MiB for its text and a slot's 20 MiB for its execution's buffers, which leaves 35 MiB for other calls. On a pool under 128 MiB half the pool is kept instead, so the ceiling is never under half the pool (8 MiB on the 16 MiB floor). A call within the ceiling passes it, and is then admitted only if the pool also holds its tree and the room for the body written from it ([`crate::memory::params_room`]), held or not, as on 1.3.52: on a 16 MiB pool, or under a raised body limit, a call under the ceiling can be refused by the pool. A held call that ran unheld can be approved: its params alone fit the pool, and when they and a slot's share could not, it runs under an execution slot ([`crate::memory::held_room`]). See [`LimitsConfig::unpacked_limit`].
pub const UNPACKED_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;

/// The budget for the stored rows of every pending agent hold, on a hosted worker (16 MiB): what a listing or the boot settlement reads at once, and what the hold queue adds to every snapshot upload.
/// Gateway-made control-plane holds are not counted in it, so an agent cannot use it to stop an operator's held change; they have a budget of their own the same size.
/// Each budget is floored at a body's length of params, the execution body limit for an agent call's or the largest body a change arrives in, plus [`HOLD_ROW_OVERHEAD_BYTES`] for the rest of its row ([`crate::memory::held_total_bytes`], [`crate::memory::control_plane_held_total_bytes`]), and holds alone in their queue (one call, one change or a vault import's set of them) are admitted whatever their rows take, so none is refused for the queue's total where no retry could clear it.
/// So a hold alone in its queue may pass the budget, and the rows of each kind are at most their budget or the hold or set alone in their queue, whichever is larger, not twice this together. An agent hold passes the floor by what its params, as this gateway writes them, take past the body (numbers it writes as floats and an agent URL it canonicalizes grow, to at most 4.5 times a body they were sent in, and params from the relay or an in-process caller were sent in none) and what its other fields take past 64 KiB, and a change by what it writes past its body: a change's row is its mutation as serde_json writes it, every default field included, about four times its body. At hosted defaults one connector install of minimal capability lines in an 8,323,223-byte body is held alone as a 34,999,832-byte row (33.4 MiB), 2.1 times this budget, and the agent queue may hold its own 16 MiB beside it.
pub const DEFAULT_HOSTED_HELD_TOTAL_BYTES: u64 = 16 * 1024 * 1024;

/// [`DEFAULT_HOSTED_HELD_TOTAL_BYTES`] on a gateway its owner runs (128 MiB).
pub const DEFAULT_HELD_TOTAL_BYTES: u64 = 128 * 1024 * 1024;

/// The room one hold's row is given for its fields besides its params (64 KiB): its ids, message and description, and an agent's intent, which [`crate::approval_display::MAX_STORED_INTENT_BYTES`] keeps to 4 KiB before JSON escapes it.
pub const HOLD_ROW_OVERHEAD_BYTES: u64 = 64 * 1024;

/// The most one document the gateway fetches for itself may take as a tree (64 MiB, hosted and self-run): an OAuth token response on a refresh or a code exchange, a WordPress site's index or Abilities listing during a re-sync.
/// Its request has been sent by the time it is read, and refusing the answer then loses what the upstream committed (a rotated refresh token, a single-use code), so it never waits for room in the JSON pool and is never refused for it: it is charged to the pool when the pool has room at once, and otherwise built beside it under this ceiling.
/// These documents come from endpoints the operator configured, never from a host an agent names; of an agent's upstream bodies only a Vercel response the projection reads and a result the relay frames are built into trees, and each waits for room in the pool (the relay's is charged only while it is parsed).
pub const DEFAULT_INTERNAL_TREE_BYTES: u64 = 64 * 1024 * 1024;

/// The most an agent's view of a document grows over the document, in tenths (3.8 times): serde_json writes `1e15` as `1000000000000000.0`, so an array of them comes out 19 bytes for every 5. A redaction marker or the credential placeholder in place of a short value grows less (at most about 2.8 times).
/// A property of serde_json's number formatting, not a setting; the arithmetic in [`DEFAULT_HOSTED_JSON_POOL_BYTES`] counts it.
pub const VIEW_GROWTH_TENTHS: u64 = 38;

/// How long an agent's view of a response may be, in tenths of the response cap, within what its execution's slot holds (2.6 times). A longer view reserves the rest in the view-growth budget ([`DEFAULT_HOSTED_VIEW_GROWTH_BYTES`]) before it is written, so only as many views as that budget holds grow past it at once.
/// Every realistic response's view is shorter than the response; only a body of exponent-written numbers, or of short values a redaction marker replaces, comes near this.
pub const VIEW_FREE_TENTHS: u64 = 26;

/// The budget for the part of agents' views past [`VIEW_FREE_TENTHS`] of the response cap, on a hosted worker (12 MiB): two of the longest views at once, each at most (3.8 - 2.6) x 5 MiB past it.
/// A view that finds no room within the pool wait is an error that says the call was sent; a view longer than the whole budget takes all of it and runs alone.
pub const DEFAULT_HOSTED_VIEW_GROWTH_BYTES: u64 = 12 * 1024 * 1024;

/// [`DEFAULT_HOSTED_VIEW_GROWTH_BYTES`] on a gateway its owner runs (64 MiB).
pub const DEFAULT_VIEW_GROWTH_BYTES: u64 = 64 * 1024 * 1024;

/// How many enrolment codes may wait to be redeemed at once on a hosted worker (20). Each is a row in the store until it expires 15 minutes after it was minted, and a member mints one per agent being connected, so a longer queue is someone minting faster than agents redeem.
pub const DEFAULT_HOSTED_LIVE_ENROLMENT_CODES: usize = 20;

/// [`DEFAULT_HOSTED_LIVE_ENROLMENT_CODES`] on a gateway its owner runs (100).
pub const DEFAULT_LIVE_ENROLMENT_CODES: usize = 100;

/// The most operations one OpenAPI import turns into capabilities (2,000), more than the largest public API descriptions have (GitHub's REST description has about 1,100). Each is a capability row the store keeps, every snapshot upload carries and `tools/list` reads.
pub const DEFAULT_OPENAPI_OPERATIONS: usize = 2_000;

/// The most the gateway's capability rows may take together on a hosted worker (8 MiB): what an import may add to, refused before anything is written. A large API's capabilities take about a kilobyte each.
pub const DEFAULT_HOSTED_CAPABILITY_BYTES: u64 = 8 * 1024 * 1024;

/// [`DEFAULT_HOSTED_CAPABILITY_BYTES`] on a gateway its owner runs (64 MiB).
pub const DEFAULT_CAPABILITY_BYTES: u64 = 64 * 1024 * 1024;

/// How long the body of a request built from an agent's params may be, in tenths of the text the agent sent (4.5 times), the room [`crate::memory::read_json`] reserves for it beside the params' tree.
/// The connector builders write that body from the tree they borrow, not from a copy of it. In a JSON body only a number serde_json reads as a float can come out longer than it was sent, at most 4.5 times (`1e15` as `1000000000000000.0`, 18 bytes for 4); strings, and integers that fit 64 bits, never do. A form body writes those numbers the same way and percent-encodes a string to at most three times its length; the keys it repeats beside each value count against [`crate::connectors::MAX_ENCODED_PARAMS_BYTES`] instead.
/// A property of serde_json's number formatting and of percent-encoding, not a setting.
pub const OUTGOING_BODY_TENTHS: u64 = 45;

/// The URL, headers and form keys a connector writes from an agent's params take the place of the agent's own text, which is dropped once it is parsed.
const _: () = assert!(
    connectors::MAX_ENCODED_PARAMS_BYTES <= DEFAULT_BODY_EXEC_BYTES,
    "a slot's B holds the request body until it is parsed and the URL, headers and form keys written from it after"
);

/// Minimum gap between two rejection log lines for the same limit and key class (1s). A rejection
/// flood is the exact condition under which logging every rejection turns a capacity problem into a
/// logging bill, and the log sink is billed per line; the suppressed count on the next line keeps
/// the information that the swallowed lines carried.
/// *Measure:* the rejection rate under sustained load, against the log ingestion budget.
pub const DEFAULT_LOG_INTERVAL_MS: u64 = 1_000;

/// The stable log message every limit rejection emits. A log-based metric is built on
/// this exact string, so it is a wire format: do not reword it, and do not fold another condition
/// into it.
///
/// The full line is a `WARN` from `permaura_gateway::limits` carrying:
///
/// ```text
/// gateway_id=<id> limit=<rate|queue|busy> key_class=<session|peer|anonymous|worker>
///   retry_after_secs=<n> suppressed=<n>
///   gateway resource limit rejected a request
/// ```
///
/// `suppressed` is how many rejections of this same `(limit, key_class)` were swallowed by the
/// throttle since the previous line, so a counter built on this message must add `suppressed + 1`
/// per line rather than counting lines.
///
/// The key itself is never in the line. It is a hash of a bearer token or a peer address, and both
/// are stable identifiers for a live caller that must not land in a log a support engineer reads.
pub const REJECTION_LOG_MESSAGE: &str = "gateway resource limit rejected a request";

/// Cap on the number of distinct keys the limiter tracks (4096). A limiter keyed on caller identity
/// is itself a memory target if its table is unbounded, which is the shape the held-approval cap in
/// the memory store already exists to prevent.
/// *Measure:* the distinct-session count for a real workspace over an hour.
pub const DEFAULT_MAX_KEYS: usize = 4096;

/// An idle bucket is dropped after this long. Ten minutes is far longer than any burst it could
/// still be holding state for, so eviction never forgives a caller that is actively being limited.
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(600);

/// Reserved capacity: the routes that must keep answering while execution is saturated or throttled.
///
/// Not a list the router consults. The reservation is structural, because admission control is a
/// layer on the execution group alone and these paths are in a different group. The list is here so
/// the contract is written down somewhere a reader will find it, and so a test can drive every entry
/// under saturation and fail if one of them ever moves into the limited group.
///
/// The judgement behind each class:
///
/// - **Management and revocation.** The moment execution is saturated is exactly when an operator
///   needs to revoke a session, delete an agent or pause the broker. A limiter that also shed these
///   would take the remedy away along with the problem.
/// - **Approval resolution by a human.** It does execute the held call upstream, so it is not free.
///   It is reserved anyway because it is operator-authenticated and human-paced, and because a held
///   approval that cannot be resolved is an agent blocked indefinitely. An approve runs the held call
///   outside the execution slots, with a slot's share of byte buffers reserved in the JSON pool, so
///   agent calls filling the slots never refuse it and it never takes a slot from them. Only a call
///   whose params and that share could never fit the pool together runs under a slot
///   ([`Limits::admit_approved`]), and when every slot is busy that is a 429 the approver can retry,
///   with nothing claimed; a denial runs nothing and never waits for one. The connector output caps
///   still bound what one resolution can consume.
/// - **Health.** A probe that fails under load turns shedding into a restart loop.
/// - **Recovery and restore.** The paths that exist for the worst day must not be gated on the
///   instance being healthy.
pub const RESERVED_ROUTES: &[&str] = &[
    "/health",
    "/v1/sessions/:id/revoke",
    "/v1/agents/:id",
    "/v1/broker/pause",
    "/v1/broker/require-approval",
    "/v1/devices/:id",
    "/v1/approver-keys/:approver_id",
    "/v1/approval-floor",
    "/v1/approvals",
    "/v1/recovery",
    "/v1/recovery-codes",
    "/v1/shutdown",
];

// ── Configuration ───────────────────────────────────────────────────────────────

/// Every limit this gateway enforces, resolved once at startup.
///
/// The provisioning payload carries no plan today, so nothing here is per-plan. The knobs are
/// environment variables precisely so the provisioner can set per-plan values later without another
/// code change; until it does, every tenant runs the same numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsConfig {
    /// Request body limit for `/v1/invoke` and `/mcp`.
    pub body_exec_bytes: usize,
    /// Request body limit for the vault, OpenAPI-import and connector-install routes.
    pub body_bulk_bytes: usize,
    /// Request body limit for every other route.
    pub body_default_bytes: usize,
    /// Inbound request timeout, `None` when disabled.
    pub request_timeout: Option<Duration>,
    /// The floor of the deadline an execution route's response has to be sent in, holding its slot, `None` when disabled. It applies with admission control disabled too, holding an empty permit.
    pub delivery_timeout: Option<Duration>,
    /// Ceiling on one upstream call or command, `None` when disabled.
    pub execution: Option<Duration>,
    /// Sustained executions a minute per caller.
    pub rate_per_min: u32,
    /// Burst allowance per caller.
    pub rate_burst: u32,
    /// Sustained executions a minute across every caller, `None` when there is no worker-wide bucket.
    pub worker_rate_per_min: Option<u32>,
    /// Burst allowance across every caller.
    pub worker_rate_burst: u32,
    /// Concurrent in-flight executions across the whole instance.
    pub max_inflight: usize,
    /// How many requests may wait for an execution permit.
    pub queue_depth: usize,
    /// How long a request waits for a permit before being shed.
    pub queue_wait: Duration,
    /// Cap on the limiter's own key table.
    pub max_keys: usize,
    /// Minimum gap between rejection log lines of the same limit and key class.
    pub log_interval: Duration,
    /// When true the token bucket and the semaphore are inert. Body limits and timeouts are
    /// structural and stay on: the switch is an operator escape hatch for admission control, not a
    /// way to run a gateway with no bounds at all.
    pub admission_disabled: bool,
    /// Stored bytes of the staged rows one requester may have behind pending holds.
    pub staged_bytes_per_requester: usize,
    /// Stored bytes of the staged rows behind pending holds across the gateway.
    pub staged_bytes_per_gateway: usize,
    /// Stored bytes of one secret's metadata, refused past this at every route that takes it from a caller.
    pub secret_metadata_bytes: usize,
    /// The worker's budget for the JSON trees its calls hold at once, and the largest one tree it admits. See [`DEFAULT_HOSTED_JSON_POOL_BYTES`].
    pub json_pool_bytes: u64,
    /// How long a call waits for room in that budget before it is shed.
    pub json_pool_wait: Duration,
    /// The budget for the stored rows of every pending agent hold, and the same again for every pending control-plane hold, each floored at one hold's longest text and the rest of its row ([`crate::memory::held_total_bytes`], [`crate::memory::control_plane_held_total_bytes`]); a hold alone in its queue may pass it. See [`DEFAULT_HOSTED_HELD_TOTAL_BYTES`].
    pub held_total_bytes: u64,
    /// The most one document the gateway fetches for itself may take as a tree. See [`DEFAULT_INTERNAL_TREE_BYTES`].
    pub internal_tree_bytes: u64,
    /// The budget for the part of agents' views past what an execution's slot holds. See [`VIEW_FREE_TENTHS`].
    pub view_growth_bytes: u64,
    /// How many enrolment codes may wait to be redeemed at once. See [`DEFAULT_HOSTED_LIVE_ENROLMENT_CODES`].
    pub live_enrolment_codes: usize,
    /// The most operations one OpenAPI import turns into capabilities. See [`DEFAULT_OPENAPI_OPERATIONS`].
    pub openapi_operations: usize,
    /// The most the gateway's capability rows may take together. See [`DEFAULT_HOSTED_CAPABILITY_BYTES`].
    pub capability_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            body_exec_bytes: DEFAULT_BODY_EXEC_BYTES,
            body_bulk_bytes: DEFAULT_BODY_BULK_BYTES,
            body_default_bytes: DEFAULT_BODY_DEFAULT_BYTES,
            request_timeout: Some(Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS)),
            delivery_timeout: Some(Duration::from_millis(DEFAULT_DELIVERY_TIMEOUT_MS)),
            execution: Some(Duration::from_millis(DEFAULT_EXECUTION_MS)),
            rate_per_min: DEFAULT_RATE_PER_MIN,
            rate_burst: DEFAULT_RATE_BURST,
            worker_rate_per_min: None,
            worker_rate_burst: DEFAULT_SELF_RUN_WORKER_RATE_BURST,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            queue_depth: DEFAULT_QUEUE_DEPTH,
            queue_wait: Duration::from_millis(DEFAULT_QUEUE_WAIT_MS),
            max_keys: DEFAULT_MAX_KEYS,
            log_interval: Duration::from_millis(DEFAULT_LOG_INTERVAL_MS),
            admission_disabled: false,
            staged_bytes_per_requester: DEFAULT_STAGED_BYTES_PER_REQUESTER,
            staged_bytes_per_gateway: DEFAULT_STAGED_BYTES_PER_GATEWAY,
            secret_metadata_bytes: DEFAULT_SECRET_METADATA_BYTES,
            json_pool_bytes: DEFAULT_JSON_POOL_BYTES,
            json_pool_wait: Duration::from_millis(DEFAULT_JSON_POOL_WAIT_MS),
            held_total_bytes: DEFAULT_HELD_TOTAL_BYTES,
            internal_tree_bytes: DEFAULT_INTERNAL_TREE_BYTES,
            view_growth_bytes: DEFAULT_VIEW_GROWTH_BYTES,
            live_enrolment_codes: DEFAULT_LIVE_ENROLMENT_CODES,
            openapi_operations: DEFAULT_OPENAPI_OPERATIONS,
            capability_bytes: DEFAULT_CAPABILITY_BYTES,
        }
    }
}

impl LimitsConfig {
    /// The defaults for a hosted worker (`hosted`) or for a gateway its owner runs.
    ///
    /// Only the rates differ. A hosted worker uploads its whole store to one Cloud Storage object
    /// twice per execution, so its rates are that object's measured ceiling; a self-run gateway
    /// uploads nothing and keeps the numbers it has always had, with no worker-wide bucket at all.
    pub fn defaults_for(hosted: bool) -> Self {
        let d = LimitsConfig::default();
        if !hosted {
            return d;
        }
        LimitsConfig {
            rate_per_min: DEFAULT_HOSTED_RATE_PER_MIN,
            rate_burst: DEFAULT_HOSTED_RATE_BURST,
            worker_rate_per_min: Some(DEFAULT_WORKER_RATE_PER_MIN),
            worker_rate_burst: DEFAULT_WORKER_RATE_BURST,
            json_pool_bytes: DEFAULT_HOSTED_JSON_POOL_BYTES,
            held_total_bytes: DEFAULT_HOSTED_HELD_TOTAL_BYTES,
            view_growth_bytes: DEFAULT_HOSTED_VIEW_GROWTH_BYTES,
            live_enrolment_codes: DEFAULT_HOSTED_LIVE_ENROLMENT_CODES,
            capability_bytes: DEFAULT_HOSTED_CAPABILITY_BYTES,
            ..d
        }
    }

    /// Resolve the configuration from the environment, clamping every value.
    ///
    /// An unparseable value falls back to the default rather than refusing to boot: a typo in one
    /// env var must not be the reason a gateway will not start. A value outside its clamp is pulled
    /// into range, so no setting can turn a bound off by making it absurd. `0` in particular means
    /// "the smallest supported value", never "unlimited", for everything except the timeouts, where
    /// `0` is the documented way to disable a timeout that has no safe minimum.
    pub fn from_env() -> Self {
        Self::from_env_for(crate::hosted_from_env())
    }

    /// [`Self::from_env`] for a gateway whose posture the caller already knows.
    ///
    /// On a hosted worker the per-caller defaults never exceed the worker rate in force, so a plan
    /// that sets only `PERMAURA_WORKER_RATE_PER_MIN` lower does not leave one caller able to spend more
    /// than the whole worker may. An explicit `PERMAURA_LIMIT_RATE_*` still wins.
    pub fn from_env_for(hosted: bool) -> Self {
        let d = LimitsConfig::defaults_for(hosted);
        let worker_rate_per_min = worker_rate_from_env(hosted);
        let worker_rate_burst = u32_env(
            "PERMAURA_WORKER_RATE_BURST",
            if hosted { DEFAULT_WORKER_RATE_BURST } else { DEFAULT_SELF_RUN_WORKER_RATE_BURST },
        )
        .clamp(1, 60_000);
        let json_pool_bytes =
            u64_env("PERMAURA_LIMIT_JSON_POOL_BYTES", d.json_pool_bytes).clamp(16 * 1024 * 1024, 8 * 1024 * 1024 * 1024);
        let (rate_default, burst_default) = match (hosted, worker_rate_per_min) {
            (true, Some(worker)) => (d.rate_per_min.min(worker), d.rate_burst.min(worker_rate_burst)),
            _ => (d.rate_per_min, d.rate_burst),
        };
        let mut config = LimitsConfig {
            body_exec_bytes: usize_env("PERMAURA_LIMIT_BODY_EXEC_BYTES", d.body_exec_bytes)
                .clamp(MIN_BODY_EXEC_BYTES, 64 * 1024 * 1024),
            body_bulk_bytes: usize_env("PERMAURA_LIMIT_BODY_BULK_BYTES", d.body_bulk_bytes)
                .clamp(16 * 1024, 64 * 1024 * 1024),
            body_default_bytes: usize_env(
                "PERMAURA_LIMIT_BODY_DEFAULT_BYTES",
                d.body_default_bytes,
            )
            .clamp(4 * 1024, 64 * 1024 * 1024),
            request_timeout: optional_duration_env(
                "PERMAURA_LIMIT_REQUEST_TIMEOUT_MS",
                DEFAULT_REQUEST_TIMEOUT_MS,
                1_000,
                600_000,
            ),
            delivery_timeout: optional_duration_env(
                "PERMAURA_LIMIT_DELIVERY_TIMEOUT_MS",
                DEFAULT_DELIVERY_TIMEOUT_MS,
                1_000,
                600_000,
            ),
            execution: optional_duration_env(
                "PERMAURA_LIMIT_EXECUTION_MS",
                DEFAULT_EXECUTION_MS,
                1_000,
                600_000,
            ),
            rate_per_min: u32_env("PERMAURA_LIMIT_RATE_PER_MIN", rate_default).clamp(1, 60_000),
            rate_burst: u32_env("PERMAURA_LIMIT_RATE_BURST", burst_default).clamp(1, 60_000),
            worker_rate_per_min,
            worker_rate_burst,
            max_inflight: usize_env("PERMAURA_LIMIT_MAX_INFLIGHT", d.max_inflight).clamp(1, 1_024),
            queue_depth: usize_env("PERMAURA_LIMIT_QUEUE_DEPTH", d.queue_depth).clamp(0, 16_384),
            queue_wait: Duration::from_millis(
                u64_env("PERMAURA_LIMIT_QUEUE_WAIT_MS", DEFAULT_QUEUE_WAIT_MS).clamp(0, 120_000),
            ),
            max_keys: usize_env("PERMAURA_LIMIT_MAX_KEYS", d.max_keys).clamp(64, 1_048_576),
            log_interval: Duration::from_millis(
                u64_env("PERMAURA_LIMIT_LOG_INTERVAL_MS", DEFAULT_LOG_INTERVAL_MS)
                    .clamp(0, 3_600_000),
            ),
            admission_disabled: flag_env("PERMAURA_LIMIT_ADMISSION_DISABLED"),
            staged_bytes_per_requester: usize_env(
                "PERMAURA_LIMIT_STAGED_BYTES_PER_REQUESTER",
                d.staged_bytes_per_requester,
            )
            .clamp(16 * 1024, 256 * 1024 * 1024),
            staged_bytes_per_gateway: usize_env("PERMAURA_LIMIT_STAGED_BYTES_PER_GATEWAY", d.staged_bytes_per_gateway)
                .clamp(16 * 1024, 256 * 1024 * 1024),
            secret_metadata_bytes: usize_env("PERMAURA_LIMIT_SECRET_METADATA_BYTES", d.secret_metadata_bytes)
                .clamp(1024, 64 * 1024),
            json_pool_bytes,
            json_pool_wait: Duration::from_millis(
                u64_env("PERMAURA_LIMIT_JSON_POOL_WAIT_MS", DEFAULT_JSON_POOL_WAIT_MS).clamp(0, 60_000),
            ),
            held_total_bytes: u64_env("PERMAURA_LIMIT_HELD_TOTAL_BYTES", d.held_total_bytes)
                .clamp(1024 * 1024, 4 * 1024 * 1024 * 1024),
            internal_tree_bytes: u64_env("PERMAURA_LIMIT_INTERNAL_TREE_BYTES", d.internal_tree_bytes)
                .clamp(1024 * 1024, 1024 * 1024 * 1024),
            view_growth_bytes: u64_env("PERMAURA_LIMIT_VIEW_GROWTH_BYTES", d.view_growth_bytes)
                .clamp(1024 * 1024, 1024 * 1024 * 1024),
            live_enrolment_codes: usize_env("PERMAURA_LIMIT_LIVE_ENROLMENT_CODES", d.live_enrolment_codes).clamp(1, 10_000),
            openapi_operations: usize_env("PERMAURA_LIMIT_OPENAPI_OPERATIONS", d.openapi_operations).clamp(1, 100_000),
            capability_bytes: u64_env("PERMAURA_LIMIT_CAPABILITY_BYTES", d.capability_bytes)
                .clamp(1024 * 1024, 1024 * 1024 * 1024),
        };
        config.held_total_bytes = crate::memory::held_total_bytes(&config);
        config
    }

    /// The one ceiling on an agent call's unpacked size, the estimate of the tree its params make, whether or not the call needs approval: the pool less [`UNPACKED_HEADROOM_BYTES`], 128 MiB of the hosted 192 and 448 of the self-run 512, whatever the body limit and response cap. On a pool under 128 MiB, where the pool less 64 MiB would be 64 MiB or less and nothing at all on the 16 MiB floor, half the pool is kept instead, so the ceiling is never under half the pool and is always more than the pool less 64 MiB there.
    /// It moves only with the pool. A call under it sent in a body that runs unheld can be approved when it is held, under any body limit, response cap or pool: approving reserves in the pool its params, no more than the call reserved unheld but for up to about 1.5 MiB of agent URL the gateway canonicalizes, which still fits ([`crate::memory::held_room`]), and a slot's share of byte buffers beside them, or runs it under an execution slot when that share could never fit beside them ([`crate::memory::MemoryBudget::parse_held`]).
    pub fn unpacked_limit(&self) -> u64 {
        self.json_pool_bytes - UNPACKED_HEADROOM_BYTES.min(self.json_pool_bytes / 2)
    }

    /// The 1.3.52 hold ceiling: the pool less four bodies of text and an execution's buffers ([`crate::memory::resolution_bytes`]), what 1.3.52 reserved beside a tree when it approved a call, 164 MiB of the hosted 192 and 484 of the self-run 512. It bounds nothing now; [`Self::render_limit`] keeps it so every control-plane change 1.3.52 rendered still renders.
    pub fn hold_ceiling_1_3_52(&self) -> u64 {
        let beside = 4 * self.body_exec_bytes as u64 + crate::memory::resolution_bytes(self);
        self.json_pool_bytes.saturating_sub(beside)
    }

    /// The largest tree an approval's rendering builds (a listing, a read, the check of what a device was shown): the larger of the one ceiling, so every agent call this gateway holds renders, and [`Self::hold_ceiling_1_3_52`], so a control-plane change, which gets no tree check, renders wherever 1.3.52 rendered it (164 MiB hosted, 484 self-run). A row over it renders as too large to show, which no device can sign an approve for.
    pub fn render_limit(&self) -> u64 {
        self.unpacked_limit().max(self.hold_ceiling_1_3_52())
    }
}

/// The worker-wide rate: on by default on a hosted worker, and only when set explicitly anywhere else,
/// because a self-run gateway's defaults are not this ceiling's business.
fn worker_rate_from_env(hosted: bool) -> Option<u32> {
    let set = std::env::var("PERMAURA_WORKER_RATE_PER_MIN")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok());
    match (set, hosted) {
        (Some(rate), _) => Some(rate.clamp(1, 60_000)),
        (None, true) => Some(DEFAULT_WORKER_RATE_PER_MIN),
        (None, false) => None,
    }
}

fn usize_env(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn u32_env(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn u64_env(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn flag_env(var: &str) -> bool {
    std::env::var(var)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// A timeout knob where `0` means "off". Anything else is clamped into `[min, max]` so a timeout
/// cannot be set so short that it cancels every request nor so long that it stops bounding anything.
fn optional_duration_env(var: &str, default_ms: u64, min: u64, max: u64) -> Option<Duration> {
    let ms = u64_env(var, default_ms);
    (ms != 0).then(|| Duration::from_millis(ms.clamp(min, max)))
}

// ── Caller identity ─────────────────────────────────────────────────────────────

/// What a limiter key was derived from. Reported on every rejection so an operator reading the log
/// can tell a limited agent from a limited stranger without the key itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// The caller presented a bearer token. The key is a hash of it, which is stable per session.
    Session,
    /// No bearer, but the TCP peer address is known.
    Peer,
    /// No bearer and no peer address: one shared bucket, deliberately the most restrictive place to
    /// land. Only reachable on a local gateway with open discovery, or from an in-process test.
    Anonymous,
    /// The worker as a whole: the bucket every request is charged to before its own.
    Worker,
    /// A held call a human approved that needs an execution slot ([`Limits::admit_approved`]). It is charged to no bucket, since the agent's call was charged when it was made.
    Approval,
}

impl KeyClass {
    /// The stable label used in the rejection log line.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyClass::Session => "session",
            KeyClass::Peer => "peer",
            KeyClass::Anonymous => "anonymous",
            KeyClass::Worker => "worker",
            KeyClass::Approval => "approval",
        }
    }
}

/// The identity a limit is charged against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LimitKey {
    class_label: &'static str,
    value: String,
}

impl LimitKey {
    /// Which class this key came from.
    pub fn class(&self) -> KeyClass {
        match self.class_label {
            "session" => KeyClass::Session,
            "peer" => KeyClass::Peer,
            "worker" => KeyClass::Worker,
            "approval" => KeyClass::Approval,
            _ => KeyClass::Anonymous,
        }
    }

    /// A key for tests and for callers that already know the identity.
    pub fn session(id: impl AsRef<str>) -> Self {
        LimitKey {
            class_label: "session",
            value: format!("s:{}", hash16(id.as_ref())),
        }
    }

    /// The one bucket every caller whose bearer resolves to nothing shares. Rotating the invented token
    /// string buys such a caller nothing, and it never reaches the worker-wide bucket.
    pub fn unauthenticated() -> Self {
        LimitKey {
            class_label: "anonymous",
            value: "u:".into(),
        }
    }

    /// The one key the worker-wide bucket is charged against.
    pub fn worker() -> Self {
        LimitKey {
            class_label: "worker",
            value: "w:".into(),
        }
    }

    /// The key an approved held call's slot refusals are reported under ([`Limits::admit_approved`]).
    pub fn approval() -> Self {
        LimitKey {
            class_label: "approval",
            value: "a:".into(),
        }
    }

    /// Derive the key for a request.
    ///
    /// The bearer token is hashed rather than resolved through the store. Resolving it would be a
    /// store read on the hot path of the very thing being protected, and the read would have to
    /// happen again inside the handler a moment later. The hash is stable for the life of a session,
    /// which is all a bucket needs.
    ///
    /// The cost of not resolving it is that a caller who rotates the token string gets a fresh
    /// bucket each time. That buys evasion of the rate limit only: an unresolvable token is refused
    /// by the handler at 401 without executing anything, and the in-flight semaphore below is global
    /// rather than per-key, so concurrency stays bounded whatever the caller does with its key.
    ///
    /// The peer address is the TCP peer and never a forwarding header, matching the gateway's
    /// existing stance that the guard is the peer address and never something the caller can set.
    /// Behind Cloud Run's frontend every peer is the same address, so the peer class collapses to
    /// one bucket there; that is acceptable because every execution route on a hosted worker
    /// requires a bearer, so a hosted request never lands in the peer class.
    pub fn from_request(req: &Request) -> Self {
        if let Some(token) = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            let token = token.strip_prefix("Bearer ").unwrap_or(token).trim();
            if !token.is_empty() {
                return LimitKey::session(token);
            }
        }
        match req.extensions().get::<ConnectInfo<SocketAddr>>() {
            Some(ConnectInfo(addr)) => LimitKey {
                class_label: "peer",
                value: format!("p:{}", addr.ip()),
            },
            None => LimitKey {
                class_label: "anonymous",
                value: "a:".into(),
            },
        }
    }
}

/// A short, stable, non-reversible digest. Only ever used as a map key, never logged or persisted:
/// a bearer token must not reach a log line even hashed, because a hash of a token is still a stable
/// identifier for it.
fn hash16(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

// ── Token bucket ────────────────────────────────────────────────────────────────

/// A classic token bucket: `burst` tokens, refilled at `per_min / 60` a second.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: u32) -> Self {
        Bucket {
            tokens: burst as f64,
            last: Instant::now(),
        }
    }

    /// Take one token. Returns `Ok(())` when there was one, or the wait until the next one.
    fn take(&mut self, burst: u32, per_min: u32, now: Instant) -> Result<(), Duration> {
        let per_sec = per_min as f64 / 60.0;
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * per_sec).min(burst as f64);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }
        let deficit = 1.0 - self.tokens;
        Err(Duration::from_secs_f64(deficit / per_sec))
    }

    fn idle_since(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last)
    }
}

// ── Rejections ──────────────────────────────────────────────────────────────────

/// Which limit refused a request. The label is stable and appears both in the log line and in the
/// 429 body's `reason` field, so an operator matching a metric to a caller's error sees one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The caller's token bucket was empty.
    Rate,
    /// Every execution slot was busy and the wait queue was full.
    Queue,
    /// The request waited for a slot and did not get one inside the wait budget.
    Busy,
    /// The worker-wide bucket was empty. Labelled `rate` like the per-caller one, since it is the same
    /// kind of limit; the key class and the body's `scope` say whose rate it was.
    WorkerRate,
}

impl Rejection {
    /// The stable label. Shared with the audit-backlog ceiling, which refuses through
    /// the same [`GatewayError::TooManyRequests`] variant, which is why the
    /// variant carries a reason at all: the two 429s must be distinguishable in the body.
    pub fn as_str(&self) -> &'static str {
        match self {
            Rejection::Rate | Rejection::WorkerRate => "rate",
            Rejection::Queue => "queue",
            Rejection::Busy => "busy",
        }
    }

    /// Whose rate a rate limit was, for the 429 body; `None` for the capacity limits.
    pub fn scope(&self) -> Option<&'static str> {
        match self {
            Rejection::Rate => Some("session"),
            Rejection::WorkerRate => Some("worker"),
            Rejection::Queue | Rejection::Busy => None,
        }
    }

    fn message(&self) -> &'static str {
        match self {
            Rejection::Rate => "execution rate limit exceeded for this caller",
            Rejection::Queue => "the gateway's execution queue is full",
            Rejection::Busy => "the gateway is at its execution concurrency limit",
            Rejection::WorkerRate => {
                "this hosted gateway is at its call rate limit across all callers; it is slowed, never cut off or billed"
            }
        }
    }
}

// ── The limiter ─────────────────────────────────────────────────────────────────

/// A permit for one in-flight execution. Held for the life of the request and released on drop, so
/// a panicking or cancelled handler cannot leak a slot.
///
/// It carries two permits, not one: the execution slot, and the admission slot that bounds how many
/// requests the instance has accepted at all. Holding the admission slot for the whole request
/// rather than only while queueing is what makes `max_inflight + queue_depth` a ceiling on accepted
/// work; released at the moment the execution slot arrives, it would bound nothing.
#[derive(Debug)]
pub struct ExecutionPermit {
    _slot: Option<tokio::sync::OwnedSemaphorePermit>,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// The execution slot a request on an execution route was admitted under, shared with the execution it starts.
/// The execution runs in a task of its own that outlives a caller who hangs up or whose request times out, and it keeps this clone until it has finished, so the slots bound every execution in flight and not only those whose callers are still connected.
#[derive(Clone, Debug)]
pub struct ExecutionSlot {
    _permit: Arc<ExecutionPermit>,
}

/// The instance-wide limiter. Cheap to clone through the `Arc` in [`AppState`].
#[derive(Debug)]
pub struct Limits {
    config: LimitsConfig,
    /// Stamped into every rejection line so a fleet-wide log query can group by tenant. Empty on a
    /// gateway that was never told its id, which a self-run one has not been; the line is still
    /// emitted, because "which gateway" is answerable from the log stream's own labels.
    gateway_id: String,
    buckets: Mutex<HashMap<LimitKey, Bucket>>,
    /// The worker-wide bucket, charged before the caller's own. Inert when the configuration has no
    /// worker rate.
    worker_bucket: Mutex<Bucket>,
    /// The monthly ceiling, consulted on every admission for whether the worker is throttled. Set once
    /// the state that owns it is assembled; replaceable so a test can hand in its own.
    fair_use: std::sync::RwLock<Option<Arc<crate::fair_use::FairUse>>>,
    execution: Arc<tokio::sync::Semaphore>,
    /// One permit per accepted request, running or waiting, so `max_inflight + queue_depth` bounds
    /// everything the instance has taken on at once.
    queue: Arc<tokio::sync::Semaphore>,
    log_state: Mutex<HashMap<(&'static str, &'static str), LogThrottle>>,
    /// Total rejections since this instance started, by reason. Reported by `/health` so an operator
    /// can see shedding without reading logs.
    rejected_rate: AtomicU64,
    rejected_queue: AtomicU64,
    rejected_busy: AtomicU64,
    rejected_worker: AtomicU64,
    /// Permits for the routes that walk the whole audit chain (full verification, export, the usage
    /// rebuild). They are operator routes outside execution admission, and each one holds a blocking
    /// thread and the archive for as long as it runs, so they get a ceiling of their own.
    chain_walks: Arc<tokio::sync::Semaphore>,
}

/// How many whole-chain walks one instance runs at once.
pub const CHAIN_WALKS_AT_ONCE: usize = 2;

/// Knobs a gateway may still be given that it no longer reads, each with what took its place. An operator who set one would otherwise lose the bound it gave without a word.
pub const REMOVED_KNOBS: &[(&str, &str)] = &[(
    "PERMAURA_LIMIT_HOLD_TREE_BYTES",
    "a held call and an unheld one meet one ceiling on an agent call's unpacked size, the JSON pool less 64 MiB, which only PERMAURA_LIMIT_JSON_POOL_BYTES moves",
)];

impl Limits {
    /// Build the limiter for a configuration.
    pub fn new(config: LimitsConfig) -> Self {
        let execution = Arc::new(tokio::sync::Semaphore::new(config.max_inflight));
        let queue = Arc::new(tokio::sync::Semaphore::new(
            config.max_inflight + config.queue_depth,
        ));
        let worker_bucket = Mutex::new(Bucket::new(config.worker_rate_burst));
        Limits {
            config,
            gateway_id: String::new(),
            buckets: Mutex::new(HashMap::new()),
            worker_bucket,
            fair_use: std::sync::RwLock::new(None),
            execution,
            queue,
            log_state: Mutex::new(HashMap::new()),
            rejected_rate: AtomicU64::new(0),
            rejected_queue: AtomicU64::new(0),
            rejected_busy: AtomicU64::new(0),
            rejected_worker: AtomicU64::new(0),
            chain_walks: Arc::new(tokio::sync::Semaphore::new(CHAIN_WALKS_AT_ONCE)),
        }
    }

    /// A permit to walk the whole audit chain, or a 429 while [`CHAIN_WALKS_AT_ONCE`] walks are
    /// already running. Refused rather than queued: a walk can take minutes, and a request waiting
    /// behind one holds a request slot the whole time.
    pub fn try_chain_walk(&self) -> Result<tokio::sync::OwnedSemaphorePermit, GatewayError> {
        self.chain_walks.clone().try_acquire_owned().map_err(|_| GatewayError::TooManyRequests {
            reason: "chain_walk".into(),
            message: "the audit chain is already being walked by another request (a full verification, an export or a usage rebuild); try again when it finishes".into(),
            retry_after_secs: 10,
            scope: None,
        })
    }

    /// Consult this fair-use ceiling from now on.
    pub fn attach_fair_use(&self, fair_use: Arc<crate::fair_use::FairUse>) {
        *self.fair_use.write().unwrap_or_else(|e| e.into_inner()) = Some(fair_use);
    }

    /// The worker-wide `(per_min, burst)` in force right now, or `None` when there is none.
    ///
    /// Throttled, both drop to the fair-use rate: a lower rate with the full burst would still hand out
    /// a hundred calls at a time. The lower of the two wins, so a contract rate set below the throttled
    /// one is never raised by being throttled.
    fn worker_rate(&self) -> Option<(u32, u32)> {
        let throttled = self
            .fair_use
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|f| f.throttled())
            .map(|f| f.config().throttled_rate_per_min);
        match (self.config.worker_rate_per_min, throttled) {
            (None, None) => None,
            (Some(rate), None) => Some((rate, self.config.worker_rate_burst)),
            (rate, Some(cap)) => {
                let rate = rate.map_or(cap, |r| r.min(cap));
                Some((rate, self.config.worker_rate_burst.min(rate)))
            }
        }
    }

    /// Worker-wide rejections since this instance started.
    pub fn worker_rejections(&self) -> u64 {
        self.rejected_worker.load(Ordering::Relaxed)
    }

    /// Name the gateway this limiter belongs to, for the rejection log line.
    pub fn with_gateway_id(mut self, gateway_id: impl Into<String>) -> Self {
        self.gateway_id = gateway_id.into();
        self
    }

    /// The limiter a gateway assembled from the environment gets. The first in a process warns about each knob it sets that this gateway no longer reads ([`REMOVED_KNOBS`]).
    pub fn from_env() -> Self {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            for (knob, instead) in REMOVED_KNOBS {
                if std::env::var_os(knob).is_some() {
                    tracing::warn!(knob = %knob, "{knob} is set, and this gateway no longer reads it: {instead}");
                }
            }
        });
        Limits::new(LimitsConfig::from_env())
            .with_gateway_id(std::env::var("PERMAURA_GATEWAY_ID").unwrap_or_default())
    }

    /// The resolved configuration, for `/health` and for tests.
    pub fn config(&self) -> &LimitsConfig {
        &self.config
    }

    /// Rejection counts since this instance started, as `(rate, queue, busy)`. In-memory, so they
    /// reset on a cold start like everything else here.
    pub fn rejection_counts(&self) -> (u64, u64, u64) {
        (
            self.rejected_rate.load(Ordering::Relaxed),
            self.rejected_queue.load(Ordering::Relaxed),
            self.rejected_busy.load(Ordering::Relaxed),
        )
    }

    /// Execution slots not currently held.
    pub fn available_execution_slots(&self) -> usize {
        self.execution.available_permits()
    }

    /// What `/health` reports about admission control.
    ///
    /// Assembled here rather than in the health handler so the handler's edit is one line: the
    /// shape of this document belongs to the limiter, not to the route.
    pub fn health_snapshot(&self) -> serde_json::Value {
        let (rate, queue, busy) = self.rejection_counts();
        serde_json::json!({
            // Every figure below resets on a cold start and describes this instance only. A
            // scale-to-zero worker cold-starts constantly, so a zero here means "since this
            // container started", never "since this gateway was provisioned".
            "in_flight": self.config.max_inflight - self.available_execution_slots(),
            "max_inflight": self.config.max_inflight,
            "queue_depth": self.config.queue_depth,
            "rate_per_min": self.config.rate_per_min,
            "rate_burst": self.config.rate_burst,
            "worker": {
                "enabled": self.config.worker_rate_per_min.is_some(),
                "rate_per_min": self.config.worker_rate_per_min,
                "rate_burst": self.config.worker_rate_burst,
                // What is actually enforced: lower than `rate_per_min` while the fair-use ceiling
                // throttles this worker.
                "effective_rate_per_min": self.worker_rate().map(|(rate, _)| rate),
            },
            "admission_disabled": self.config.admission_disabled,
            "rejected": { "rate": rate, "queue": queue, "busy": busy, "worker": self.worker_rejections() },
        })
    }

    /// Charge one execution against `key` and acquire an in-flight permit, or say why not.
    ///
    /// Order matters. The rate check is first because it is the cheapest and needs no permit; the
    /// admission slot is next, so a caller beyond what the instance can hold is shed before it can
    /// park anywhere; the execution permit is last, and waiting for it is the only step that blocks.
    ///
    /// Nothing on any path here reads or writes the store.
    pub async fn admit(&self, key: &LimitKey) -> Result<ExecutionPermit, Rejection> {
        self.admit_as(key, true).await
    }

    /// [`Self::admit`], charging the worker-wide bucket only when `charge_worker` is set: for a caller
    /// whose bearer resolved. An unauthenticated request cannot execute anything, so it must not be
    /// able to spend the worker's execution budget either.
    pub async fn admit_as(&self, key: &LimitKey, charge_worker: bool) -> Result<ExecutionPermit, Rejection> {
        if self.config.admission_disabled {
            return Ok(ExecutionPermit {
                _slot: None,
                _permit: None,
            });
        }
        // The worker's bucket first, then the caller's. A request any later check sheds is handed its
        // worker token back, so one caller hammering past its own limit spends only its own budget and
        // not everyone else's share of the worker's.
        let charged_worker = charge_worker && self.check_worker_rate()?;
        let refund = |reason: Rejection| {
            if charged_worker {
                self.refund_worker();
            }
            reason
        };
        self.check_rate(key).map_err(refund)?;

        // Shed immediately when the instance has already accepted all it can hold. A caller told to
        // come back is better served than one parked in a queue nobody bounded, which is the shape
        // the gateway has today.
        let slot = self
            .queue
            .clone()
            .try_acquire_owned()
            .map_err(|_| refund(self.reject(Rejection::Queue, key)))?;

        let permit = tokio::time::timeout(
            self.config.queue_wait,
            self.execution.clone().acquire_owned(),
        )
        .await
        .map_err(|_| refund(self.reject(Rejection::Busy, key)))?
        .map_err(|_| {
            // Only reachable if the semaphore was closed, which nothing does. Shed rather than
            // panic: an unexplained closed semaphore must not take execution down silently.
            refund(self.reject(Rejection::Busy, key))
        })?;
        Ok(ExecutionPermit {
            _slot: Some(slot),
            _permit: Some(permit),
        })
    }

    /// An execution slot for a held call a human approved whose params and a slot's share of byte buffers could never fit the JSON pool together, so its execution's buffers are in the slot, as an unheld call's are ([`crate::memory::MemoryBudget::held_fits_beside_buffers`]): the admission slot and the execution permit, waiting as long as a queued call does, or not at all when `at_once`. No rate bucket is charged, since the agent's call was charged when it was made.
    ///
    /// Nothing on any path here reads or writes the store.
    pub async fn admit_approved(&self, at_once: bool) -> Result<ExecutionSlot, Rejection> {
        if self.config.admission_disabled {
            return Ok(ExecutionSlot { _permit: Arc::new(ExecutionPermit { _slot: None, _permit: None }) });
        }
        let key = LimitKey::approval();
        let slot = self.queue.clone().try_acquire_owned().map_err(|_| self.reject(Rejection::Queue, &key))?;
        let wait = if at_once { Duration::ZERO } else { self.config.queue_wait };
        let permit = tokio::time::timeout(wait, self.execution.clone().acquire_owned())
            .await
            .map_err(|_| self.reject(Rejection::Busy, &key))?
            .map_err(|_| self.reject(Rejection::Busy, &key))?;
        Ok(ExecutionSlot { _permit: Arc::new(ExecutionPermit { _slot: Some(slot), _permit: Some(permit) }) })
    }

    /// Charge the worker-wide bucket. `Ok(true)` when a token was taken, `Ok(false)` when there is no
    /// worker-wide limit to charge.
    fn check_worker_rate(&self) -> Result<bool, Rejection> {
        let Some((per_min, burst)) = self.worker_rate() else {
            return Ok(false);
        };
        let taken = self
            .worker_bucket
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(burst, per_min, Instant::now());
        match taken {
            Ok(()) => Ok(true),
            Err(_) => Err(self.reject(Rejection::WorkerRate, &LimitKey::worker())),
        }
    }

    /// Give back a worker token taken by a request that was then shed. The next take caps the bucket
    /// at its burst again, so a refund can never lift it above that.
    fn refund_worker(&self) {
        self.worker_bucket.lock().unwrap_or_else(|e| e.into_inner()).tokens += 1.0;
    }

    fn check_rate(&self, key: &LimitKey) -> Result<(), Rejection> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if !buckets.contains_key(key) && buckets.len() >= self.config.max_keys {
            self.evict(&mut buckets, now);
        }
        let bucket = buckets
            .entry(key.clone())
            .or_insert_with(|| Bucket::new(self.config.rate_burst));
        match bucket.take(self.config.rate_burst, self.config.rate_per_min, now) {
            Ok(()) => Ok(()),
            Err(_) => {
                drop(buckets);
                Err(self.reject(Rejection::Rate, key))
            }
        }
    }

    /// Make room in the key table. Idle buckets go first; if none are idle the table is cleared,
    /// which briefly forgives everyone. That is the right trade at this boundary: a limiter that
    /// grows without bound is a memory DoS, and forgiving a burst is recoverable where an OOM is
    /// not. The table only reaches this size under an attack that is already rotating keys, and
    /// such a caller was never being held by its bucket anyway.
    fn evict(&self, buckets: &mut HashMap<LimitKey, Bucket>, now: Instant) {
        buckets.retain(|_, b| b.idle_since(now) < BUCKET_IDLE_TTL);
        if buckets.len() >= self.config.max_keys {
            tracing::warn!(
                keys = buckets.len(),
                max_keys = self.config.max_keys,
                "the rate limiter's key table is full of live keys and is being cleared; every caller is briefly forgiven"
            );
            buckets.clear();
        }
    }

    /// What a shed caller is told to wait, in seconds.
    ///
    /// One function for all three reasons, and the only source for both the `Retry-After` header and
    /// the `retry_after_secs` on the log line. Two computations would drift, and an operator
    /// correlating a log line with a client's backoff would be reading two different numbers.
    ///
    /// Never zero: `Retry-After: 0` means "retry now", which is the one thing a shed caller must not
    /// do.
    pub fn retry_after_secs(&self, reason: Rejection) -> u64 {
        match reason {
            // The steady-state refill time for one token, which is what the caller is waiting on.
            Rejection::Rate => (60_f64 / self.config.rate_per_min.max(1) as f64).ceil() as u64,
            Rejection::WorkerRate => {
                let per_min = self.worker_rate().map_or(1, |(rate, _)| rate).max(1);
                (60_f64 / per_min as f64).ceil() as u64
            }
            // Roughly how long a slot takes to come free, which is what a shed or timed-out caller
            // is waiting on either way.
            Rejection::Queue | Rejection::Busy => self.config.queue_wait.as_secs().max(1),
        }
    }

    /// Count the rejection, emit the throttled operator signal, and return the reason.
    fn reject(&self, reason: Rejection, key: &LimitKey) -> Rejection {
        let counter = match reason {
            Rejection::Rate => &self.rejected_rate,
            Rejection::Queue => &self.rejected_queue,
            Rejection::Busy => &self.rejected_busy,
            Rejection::WorkerRate => &self.rejected_worker,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.log_rejection(reason, key.class(), self.retry_after_secs(reason));
        reason
    }

    /// One stable line per rejection class per interval. Returns the suppressed count it carried
    /// when it emitted, and `None` when the throttle swallowed it, so the throttle is testable
    /// without capturing a tracing subscriber.
    ///
    /// Every path that reaches here is a path an attacker can drive, so whatever it does happens at
    /// their rate. That is the whole reason for the throttle: an unthrottled line per rejection
    /// turns a capacity problem into a logging bill, and the line the operator needs is buried in
    /// the flood it caused.
    fn log_rejection(
        &self,
        reason: Rejection,
        class: KeyClass,
        retry_after_secs: u64,
    ) -> Option<u64> {
        let now = Instant::now();
        let suppressed = {
            let mut state = self.log_state.lock().unwrap_or_else(|e| e.into_inner());
            match state.get_mut(&(reason.as_str(), class.as_str())) {
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
                    state.insert(
                        (reason.as_str(), class.as_str()),
                        LogThrottle {
                            last: now,
                            suppressed: 0,
                        },
                    );
                    0
                }
            }
        };
        tracing::warn!(
            gateway_id = %self.gateway_id,
            // Display, not the default Debug: a `&str` field renders quoted (`limit="rate"`), and the log-based metric's label extractor matches the documented `limit=rate`.
            limit = %reason.as_str(),
            key_class = %class.as_str(),
            retry_after_secs,
            suppressed,
            "{REJECTION_LOG_MESSAGE}"
        );
        Some(suppressed)
    }
}

#[derive(Debug)]
struct LogThrottle {
    last: Instant,
    suppressed: u64,
}

impl Rejection {
    /// Render as the gateway's 429.
    pub fn into_error(self, retry_after_secs: u64) -> GatewayError {
        GatewayError::TooManyRequests {
            reason: self.as_str().into(),
            message: self.message().into(),
            retry_after_secs,
            scope: self.scope(),
        }
    }
}

/// The largest tree an approval's rendering builds ([`LimitsConfig::render_limit`]), read once per process, for the paths that render a held call and have no service to ask. Every agent hold this gateway makes fits it; a control-plane change gets no tree check, so its row may not.
pub fn render_limit_bytes() -> u64 {
    static LIMIT: OnceLock<u64> = OnceLock::new();
    *LIMIT.get_or_init(|| LimitsConfig::from_env().render_limit())
}

/// The execution ceiling, read once per process.
///
/// A process-level read rather than a field on the service, because `EnforcementService` is
/// constructed without the router's state and the embedded daemon builds one with no `AppState` at
/// all. `None` disables the ceiling.
pub fn execution_budget() -> Option<Duration> {
    static BUDGET: OnceLock<Option<Duration>> = OnceLock::new();
    *BUDGET.get_or_init(|| LimitsConfig::from_env().execution)
}

// ── Middleware ──────────────────────────────────────────────────────────────────

/// Admission control for the execution routes.
///
/// Placement is the load-bearing part. This runs before the handler, so a rejection happens before
/// `EnforcementService::invoke` reaches the pre-execution `"attempt"` audit append that fences every
/// execution. Nothing has been appended, nothing has been written, and on a hosted worker no
/// snapshot has been uploaded: a refused request costs a hash and a semaphore poll.
pub async fn admit_execution(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let bearer = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v).trim())
        .filter(|t| !t.is_empty());
    // A caller that will be refused at 401 is refused at 401 here, ahead of every bucket, when the refusal is the thing it needs: an agent whose fifteen-minute token has lapsed refreshes on the 401, and a client with no token yet learns where to sign in from it. Both used to share the one unauthenticated bucket with every stranger's junk, so a stranger at one request a second turned every such refusal into a 429 that no client refreshes on. Answering costs no more than limiting: a signature check and no store read. Everything else that fails to verify stays in the shared bucket, where it belongs.
    let (key, authenticated) = match bearer {
        Some(token) if state.service.bearer_is_live(token) => (LimitKey::from_request(&req), true),
        Some(token) if state.service.bearer_lapsed(token) => {
            return match state.service.oauth() {
                Some(oauth) => crate::mcp::sign_in_challenge(oauth, "unauthorized: invalid token: token expired"),
                None => GatewayError::Unauthorized("invalid token: token expired".into()).into_response(),
            };
        }
        Some(_) => (LimitKey::unauthenticated(), false),
        // Every execution route on a gateway with a resource server needs a bearer, and the peer bucket a tokenless request would land in is one address for every caller behind a hosted frontend or a tunnel.
        None if state.service.oauth().is_some() => {
            return crate::mcp::sign_in_challenge(state.service.oauth().expect("checked above"), "authorization required");
        }
        None => (LimitKey::from_request(&req), false),
    };
    let permit = match state.limits.admit_as(&key, authenticated).await {
        Ok(permit) => permit,
        Err(reason) => {
            let retry = state.limits.retry_after_secs(reason);
            return reason.into_error(retry).into_response();
        }
    };
    let slot = ExecutionSlot { _permit: Arc::new(permit) };
    req.extensions_mut().insert(slot.clone());
    let mut response = next.run(req).await;
    let held = response.extensions_mut().remove::<crate::delivery::HoldWhileSending>();
    // The slot is held until the response has been sent, not merely built: the body is the redacted view, often several times the upstream document, and hyper keeps it until the client reads it. An execution the handler started holds its own clone.
    crate::delivery::hold_until_sent(response, (slot, held), state.limits.config().delivery_timeout)
}

/// Bound how long any single request may occupy the instance.
///
/// A request that outlives this is cancelled at its next await point. The default sits above the
/// execution ceiling so this can only fire on something that is not a normal upstream call, which
/// matters because cancelling mid-execution loses the terminal audit append that would otherwise
/// follow the `"attempt"` fence.
pub async fn request_timeout(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(budget) = state.limits.config().request_timeout else {
        return next.run(req).await;
    };
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    match tokio::time::timeout(budget, next.run(req)).await {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(
                %method,
                %path,
                timeout_ms = budget.as_millis() as u64,
                "a request exceeded the gateway's inbound timeout and was cancelled"
            );
            (
                StatusCode::GATEWAY_TIMEOUT,
                axum::Json(serde_json::json!({
                    "error": format!(
                        "the gateway cancelled this request after {}ms",
                        budget.as_millis()
                    ),
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole-chain walks get a ceiling of their own, refused rather than queued,
    /// and a finished walk gives its place back.
    #[test]
    fn whole_chain_walks_are_capped_and_refused_past_the_cap() {
        let limits = Limits::new(LimitsConfig::defaults_for(true));
        let held: Vec<_> = (0..CHAIN_WALKS_AT_ONCE).map(|_| limits.try_chain_walk().expect("a free walk")).collect();
        let refused = limits.try_chain_walk().expect_err("a walk past the cap is refused");
        assert!(matches!(refused, GatewayError::TooManyRequests { ref reason, .. } if reason == "chain_walk"), "{refused}");
        drop(held);
        assert!(limits.try_chain_walk().is_ok(), "and a finished walk gives its place back");
    }

    fn cfg() -> LimitsConfig {
        LimitsConfig {
            rate_per_min: 60,
            rate_burst: 2,
            max_inflight: 2,
            queue_depth: 1,
            queue_wait: Duration::from_millis(50),
            // No throttle, so a test that drives several rejections is not also testing the clock.
            log_interval: Duration::ZERO,
            ..LimitsConfig::default()
        }
    }

    #[tokio::test]
    async fn a_bucket_admits_its_burst_then_refuses() {
        let limits = Limits::new(cfg());
        let key = LimitKey::session("agent-a");
        let first = limits.admit(&key).await.expect("burst token 1");
        let second = limits.admit(&key).await.expect("burst token 2");
        assert_eq!(limits.admit(&key).await.unwrap_err(), Rejection::Rate);
        drop((first, second));
    }

    #[tokio::test]
    async fn buckets_are_per_caller() {
        let limits = Limits::new(cfg());
        let a = LimitKey::session("agent-a");
        let b = LimitKey::session("agent-b");
        let _ = limits.admit(&a).await.expect("a burst 1");
        let _ = limits.admit(&a).await.expect("a burst 2");
        assert_eq!(limits.admit(&a).await.unwrap_err(), Rejection::Rate);
        // b has its own bucket and is untouched by a's spending.
        limits.admit(&b).await.expect("b is not charged for a");
    }

    #[tokio::test]
    async fn a_refilled_bucket_admits_again() {
        let limits = Limits::new(
            LimitsConfig {
                rate_per_min: 6_000, // 100/s, so a token refills in 10ms
                rate_burst: 1,
                ..cfg()
            },
        );
        let key = LimitKey::session("agent-a");
        let _ = limits.admit(&key).await.expect("the one burst token");
        assert_eq!(limits.admit(&key).await.unwrap_err(), Rejection::Rate);
        tokio::time::sleep(Duration::from_millis(40)).await;
        limits.admit(&key).await.expect("the bucket refilled");
    }

    /// The semaphore is global, not per-key: that is what makes it a capacity guard rather than a
    /// second, coarser fairness control.
    #[tokio::test]
    async fn the_execution_semaphore_is_global_across_callers() {
        let limits = Limits::new(
            LimitsConfig {
                rate_burst: 100,
                rate_per_min: 60_000,
                max_inflight: 2,
                queue_depth: 0,
                queue_wait: Duration::from_millis(20),
                ..cfg()
            },
        );
        let held: Vec<_> = vec![
            limits.admit(&LimitKey::session("a")).await.expect("slot 1"),
            limits.admit(&LimitKey::session("b")).await.expect("slot 2"),
        ];
        // A third caller, with a full bucket of its own, is still shed.
        assert_eq!(
            limits.admit(&LimitKey::session("c")).await.unwrap_err(),
            Rejection::Queue
        );
        drop(held);
        limits
            .admit(&LimitKey::session("c"))
            .await
            .expect("a released slot is reusable");
    }

    #[tokio::test]
    async fn a_full_queue_sheds_rather_than_waiting() {
        let limits = Arc::new(Limits::new(
            LimitsConfig {
                rate_burst: 100,
                rate_per_min: 60_000,
                max_inflight: 1,
                queue_depth: 1,
                queue_wait: Duration::from_millis(500),
                ..cfg()
            },
        ));
        let _held = limits.admit(&LimitKey::session("a")).await.expect("slot 1");
        // One waiter fits in the queue and will time out; a second has nowhere to wait.
        let waiter = {
            let limits = limits.clone();
            tokio::spawn(async move { limits.admit(&LimitKey::session("b")).await.map(|_| ()) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            limits.admit(&LimitKey::session("c")).await.unwrap_err(),
            Rejection::Queue,
            "the queue was full, so the third caller is shed immediately"
        );
        assert_eq!(
            waiter.await.unwrap().unwrap_err(),
            Rejection::Busy,
            "the queued caller waited its budget and was then shed"
        );
    }

    #[tokio::test]
    async fn the_disable_switch_makes_admission_inert() {
        let limits = Limits::new(
            LimitsConfig {
                rate_burst: 1,
                max_inflight: 1,
                queue_depth: 0,
                admission_disabled: true,
                ..cfg()
            },
        );
        let key = LimitKey::session("agent-a");
        let mut held = Vec::new();
        for _ in 0..10 {
            held.push(limits.admit(&key).await.expect("admission is off"));
        }
        assert_eq!(limits.rejection_counts(), (0, 0, 0));
    }

    #[tokio::test]
    async fn the_key_table_never_grows_past_its_cap() {
        let limits = Limits::new(
            LimitsConfig {
                max_keys: 64,
                rate_burst: 1,
                ..cfg()
            },
        );
        for i in 0..1_000 {
            let _ = limits.admit(&LimitKey::session(format!("agent-{i}"))).await;
        }
        let keys = limits.buckets.lock().unwrap().len();
        assert!(keys <= 64, "the limiter tracked {keys} keys, over its own cap");
    }

    /// One rejection line as the operator's log renders it, with `between` run on this thread once the capture is installed and before the line is emitted.
    fn rendered_rejection_line(between: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Captured(std::sync::Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Captured::default();
        let sink = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        // While only one dispatcher is registered, tracing-core caches a callsite's interest from the default of whichever thread reaches it first, so a parallel test reaching this line before us would cache it as never; with a second registered, every thread asks them all.
        let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        tracing::subscriber::with_default(subscriber, || {
            between();
            let limits = Limits::new(cfg());
            assert_eq!(limits.log_rejection(Rejection::Rate, KeyClass::Session, 3), Some(0));
        });
        let line = captured.0.lock().unwrap().clone();
        String::from_utf8(line).unwrap()
    }

    #[test]
    fn the_rejection_line_is_captured_when_another_thread_reaches_it_first() {
        let line = rendered_rejection_line(|| {
            std::thread::spawn(|| Limits::new(cfg()).log_rejection(Rejection::Rate, KeyClass::Session, 3))
                .join()
                .unwrap();
        });
        assert!(line.contains(REJECTION_LOG_MESSAGE), "{line}");
    }

    /// The operator signal is one line per `(limit, key class)` per interval, and the line that does
    /// emit carries how many it stood in for. A counter built on the message has to add
    /// `suppressed + 1`, which only works if the count is accurate.
    #[test]
    fn the_rejection_line_renders_its_fields_the_way_the_metric_reads_them() {
        let line = rendered_rejection_line(|| {});
        assert!(line.contains(REJECTION_LOG_MESSAGE), "{line}");
        assert!(line.contains("limit=rate"), "{line}");
        assert!(line.contains("key_class=session"), "{line}");
        assert!(line.contains("suppressed=0"), "{line}");
        assert!(line.contains("retry_after_secs=3"), "{line}");
    }

    #[test]
    fn a_flood_of_rejections_emits_one_line_and_counts_the_rest() {
        let limits = Limits::new(LimitsConfig {
            log_interval: Duration::from_secs(3600),
            ..cfg()
        });
        assert_eq!(
            limits.log_rejection(Rejection::Rate, KeyClass::Session, 1),
            Some(0),
            "the first rejection of a class always emits"
        );
        for _ in 0..99 {
            assert_eq!(
                limits.log_rejection(Rejection::Rate, KeyClass::Session, 1),
                None,
                "the throttle swallows the rest of the flood"
            );
        }
        // A different class is its own throttle: shedding agents and shedding strangers are
        // different conditions and an operator needs to see both.
        assert_eq!(
            limits.log_rejection(Rejection::Rate, KeyClass::Peer, 1),
            Some(0)
        );
        assert_eq!(
            limits.log_rejection(Rejection::Queue, KeyClass::Session, 1),
            Some(0)
        );
    }

    #[tokio::test]
    async fn the_next_line_after_a_throttled_window_carries_the_suppressed_count() {
        let limits = Limits::new(LimitsConfig {
            log_interval: Duration::from_millis(30),
            ..cfg()
        });
        assert_eq!(
            limits.log_rejection(Rejection::Busy, KeyClass::Session, 1),
            Some(0)
        );
        for _ in 0..7 {
            assert_eq!(limits.log_rejection(Rejection::Busy, KeyClass::Session, 1), None);
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            limits.log_rejection(Rejection::Busy, KeyClass::Session, 1),
            Some(7),
            "the seven swallowed rejections are accounted for on the next line"
        );
    }

    #[test]
    fn rejection_counts_track_each_reason_separately() {
        let limits = Limits::new(cfg());
        let key = LimitKey::session("agent-a");
        limits.reject(Rejection::Rate, &key);
        limits.reject(Rejection::Rate, &key);
        limits.reject(Rejection::Busy, &key);
        assert_eq!(limits.rejection_counts(), (2, 0, 1));
    }

    #[test]
    fn a_bearer_and_a_peer_land_in_different_key_classes() {
        let with_token = Request::builder()
            .uri("/v1/invoke")
            .header("authorization", "Bearer tok_abc")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            LimitKey::from_request(&with_token).class(),
            KeyClass::Session
        );

        let mut bare = Request::builder()
            .uri("/v1/invoke")
            .body(axum::body::Body::empty())
            .unwrap();
        bare.extensions_mut()
            .insert(ConnectInfo("203.0.113.7:51000".parse::<SocketAddr>().unwrap()));
        assert_eq!(LimitKey::from_request(&bare).class(), KeyClass::Peer);

        let nothing = Request::builder()
            .uri("/v1/invoke")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(LimitKey::from_request(&nothing).class(), KeyClass::Anonymous);
    }

    /// The token itself must never be recoverable from the key, because the key is compared,
    /// counted and (in a debug dump) printed.
    #[test]
    fn a_key_never_carries_the_token_it_was_derived_from() {
        let key = LimitKey::session("tok_super_secret_value");
        assert!(!format!("{key:?}").contains("super_secret"));
        assert!(!key.value.contains("super_secret"));
    }

    #[test]
    fn two_different_tokens_do_not_share_a_bucket() {
        assert_ne!(LimitKey::session("tok_a"), LimitKey::session("tok_b"));
        assert_eq!(LimitKey::session("tok_a"), LimitKey::session("tok_a"));
    }

    #[test]
    fn env_values_are_clamped_rather_than_trusted() {
        // Parsed through the same helpers the config uses, without touching the process environment,
        // which every other test in this binary shares.
        assert_eq!(optional_duration_env("PERMAURA_LIMIT_UNSET_TEST", 0, 1_000, 600_000), None);
        assert_eq!(
            optional_duration_env("PERMAURA_LIMIT_UNSET_TEST", 5_000_000, 1_000, 600_000),
            Some(Duration::from_millis(600_000))
        );
        assert_eq!(
            optional_duration_env("PERMAURA_LIMIT_UNSET_TEST", 1, 1_000, 600_000),
            Some(Duration::from_millis(1_000))
        );
    }

    #[test]
    fn the_shipped_defaults_are_internally_consistent() {
        let d = LimitsConfig::default();
        assert!(
            d.execution.unwrap() < d.request_timeout.unwrap(),
            "the execution ceiling must fire before the inbound timeout, or the caller gets the vaguer error"
        );
        assert!(
            d.request_timeout.unwrap() < Duration::from_secs(300),
            "the inbound timeout must fire before Cloud Run's 300s edge default, or the edge decides"
        );
        assert!(
            d.delivery_timeout.is_some_and(|t| t < Duration::from_secs(130)),
            "a stalled reader must give its slot back before a hosted worker's 130s frontend timeout would close the connection anyway"
        );
        assert!(
            d.rate_burst <= d.rate_per_min,
            "a burst larger than the sustained minute rate takes over a minute to refill"
        );
        assert!(DEFAULT_WORKER_RATE_BURST <= DEFAULT_WORKER_RATE_PER_MIN);
        let hosted = LimitsConfig::defaults_for(true);
        let worker = hosted.worker_rate_per_min.expect("a hosted worker has a worker-wide rate");
        assert!(
            hosted.rate_per_min <= worker && hosted.rate_burst <= hosted.worker_rate_burst,
            "one caller may never be allowed more than the whole worker"
        );
        assert!(hosted.rate_burst <= hosted.rate_per_min);
    }

    /// The execution ceiling is a backstop. If it ever dropped below a connector's own budget it
    /// would start pre-empting the better-worded timeouts and every upstream failure would read the
    /// same.
    #[test]
    fn the_execution_ceiling_sits_above_every_connector_budget() {
        let ceiling = LimitsConfig::default().execution.unwrap();
        assert!(ceiling > permaura_connectors::command::DEFAULT_COMMAND_TIMEOUT);
        assert!(ceiling > permaura_connectors::ssh::DEFAULT_SSH_TIMEOUT);
        // The HTTP connector's 30s request timeout is inside reqwest's builder and has no constant
        // to compare against; it is the smallest of the three.
    }

    /// The header a caller reads and the number on the log line must be the same, which they are
    /// only because both come from here.
    #[test]
    fn the_retry_hint_is_never_zero() {
        let hint = |per_min| {
            Limits::new(LimitsConfig {
                rate_per_min: per_min,
                ..cfg()
            })
            .retry_after_secs(Rejection::Rate)
        };
        assert_eq!(hint(120), 1);
        assert_eq!(hint(60), 1);
        assert_eq!(hint(6), 10);
        assert_eq!(hint(1), 60);

        let limits = Limits::new(LimitsConfig {
            queue_wait: Duration::from_millis(200),
            ..cfg()
        });
        assert_eq!(limits.retry_after_secs(Rejection::Queue), 1);
        assert_eq!(limits.retry_after_secs(Rejection::Busy), 1);
    }

    // ── the worker-wide bucket and the fair-use throttle ─────────────────────────

    fn worker_cfg(per_min: u32, burst: u32) -> LimitsConfig {
        LimitsConfig {
            rate_per_min: 60_000,
            rate_burst: 1_000,
            worker_rate_per_min: Some(per_min),
            worker_rate_burst: burst,
            max_inflight: 64,
            queue_depth: 64,
            ..cfg()
        }
    }

    fn fair_use(hard: u64, throttled: u32, disabled: bool) -> Arc<crate::fair_use::FairUse> {
        Arc::new(crate::fair_use::FairUse::new(crate::fair_use::FairUseConfig {
            active: true,
            disabled,
            soft_calls: hard,
            hard_calls: hard,
            throttled_rate_per_min: throttled,
        }))
    }

    fn spend(fair_use: &crate::fair_use::FairUse, calls: u64) {
        use crate::store::SnapshotMeter;
        for _ in 0..calls {
            crate::fair_use::in_request(|| fair_use.note_mutation());
        }
    }

    /// The whole point of the worker bucket: many callers each well inside their own rate still add
    /// up to one worker's worth, however many sessions they spread across.
    #[tokio::test]
    async fn the_worker_bucket_is_shared_by_every_session() {
        let limits = Limits::new(worker_cfg(60, 3));
        let mut held = Vec::new();
        for caller in ["a", "b", "c"] {
            held.push(limits.admit(&LimitKey::session(caller)).await.expect("inside the worker burst"));
        }
        assert_eq!(
            limits.admit(&LimitKey::session("d")).await.unwrap_err(),
            Rejection::WorkerRate,
            "a fresh session with a full bucket of its own is still over the worker's"
        );
        assert_eq!(limits.worker_rejections(), 1);
        assert_eq!(limits.rejection_counts(), (0, 0, 0), "the per-caller counters are untouched");
    }

    #[tokio::test]
    async fn the_worker_bucket_refills_at_its_sustained_rate() {
        let limits = Limits::new(worker_cfg(6_000, 1)); // 100/s, a token every 10ms
        let _first = limits.admit(&LimitKey::session("a")).await.expect("the one burst token");
        assert_eq!(limits.admit(&LimitKey::session("b")).await.unwrap_err(), Rejection::WorkerRate);
        tokio::time::sleep(Duration::from_millis(40)).await;
        limits.admit(&LimitKey::session("b")).await.expect("the worker bucket refilled");
    }

    /// A caller shed by its own bucket hands the worker token back, so one agent hammering past its
    /// limit spends its own budget and not everyone else's share of the worker.
    #[tokio::test]
    async fn a_caller_over_its_own_rate_does_not_drain_the_worker() {
        let limits = Limits::new(LimitsConfig { rate_per_min: 1, rate_burst: 1, ..worker_cfg(60, 2) });
        let _a = limits.admit(&LimitKey::session("a")).await.expect("a's one token");
        for _ in 0..5 {
            assert_eq!(limits.admit(&LimitKey::session("a")).await.unwrap_err(), Rejection::Rate);
        }
        limits
            .admit(&LimitKey::session("b"))
            .await
            .expect("b still has the worker token a's refusals gave back");
    }

    #[tokio::test]
    async fn a_throttled_worker_runs_at_the_throttled_rate() {
        let limits = Limits::new(worker_cfg(6_000, 100));
        let fu = fair_use(2, 1, false);
        limits.attach_fair_use(fu.clone());
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(limits.admit(&LimitKey::session("a")).await.expect("not yet throttled"));
        }
        spend(&fu, 2);
        assert!(fu.throttled());
        let _one = limits.admit(&LimitKey::session("a")).await.expect("the throttled burst is one call");
        assert_eq!(limits.admit(&LimitKey::session("b")).await.unwrap_err(), Rejection::WorkerRate);
        assert_eq!(limits.retry_after_secs(Rejection::WorkerRate), 60, "one call a minute");
        assert_eq!(limits.health_snapshot()["worker"]["effective_rate_per_min"], 1);
    }

    /// Enterprise: no ceiling, but the worker-wide limiter is still there, at the contract's rate.
    #[tokio::test]
    async fn a_disabled_ceiling_never_throttles_but_the_worker_limit_stays() {
        let limits = Limits::new(worker_cfg(60, 3));
        let fu = fair_use(1, 1, true);
        limits.attach_fair_use(fu.clone());
        spend(&fu, 50);
        assert!(!fu.throttled());
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(limits.admit(&LimitKey::session("a")).await.expect("the contract burst, not the throttled one"));
        }
        assert_eq!(limits.admit(&LimitKey::session("a")).await.unwrap_err(), Rejection::WorkerRate);
    }

    /// A contract rate below the throttled one is not raised by being throttled.
    #[test]
    fn the_throttle_only_ever_lowers_the_rate() {
        let limits = Limits::new(worker_cfg(30, 100));
        let fu = fair_use(1, 60, false);
        limits.attach_fair_use(fu.clone());
        spend(&fu, 1);
        assert_eq!(limits.worker_rate(), Some((30, 30)));
    }

    /// The hosted JSON pool admits the realistic worst documents at their byte caps with the room their execution reserves beside them, refuses a costlier shape at once, and the hosted memory arithmetic in [`DEFAULT_HOSTED_JSON_POOL_BYTES`] adds up under 512 MiB.
    #[test]
    fn the_hosted_json_pool_admits_realistic_documents_at_their_caps() {
        use crate::connectors::json_budget::estimate;
        const MIB: u64 = 1024 * 1024;
        let rows = |cap: usize, row: &dyn Fn(usize) -> String| {
            let mut out = String::from("[");
            let mut i = 0;
            loop {
                let next = row(i);
                if out.len() + next.len() + 2 > cap {
                    break;
                }
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&next);
                i += 1;
            }
            out.push(']');
            out
        };
        let hosted = LimitsConfig::defaults_for(true);
        let pool = hosted.json_pool_bytes;
        let body = DEFAULT_BODY_EXEC_BYTES - 256;
        // Realistic rows and pairs at the 2 MiB body limit, each reserving its tree and the body written from it, are admitted; the 136 MiB pool refused five of them, and reserving the tree twice refused the short rows at the end.
        let family: [(&str, &dyn Fn(usize) -> String); 16] = [
            ("{id, ok: true}", &|i| format!(r#"{{"id":{i},"ok":true}}"#)),
            ("{id, ok: 1}", &|i| format!(r#"{{"id":{i},"ok":1}}"#)),
            ("{id, v: \"a\"}", &|i| format!(r#"{{"id":{i},"v":"a"}}"#)),
            ("bulk insert {id, qty}", &|i| format!(r#"{{"id":{i},"qty":{}}}"#, i % 100)),
            ("Airtable {fields: {Name, Count}}", &|i| format!(r#"{{"fields":{{"Name":"n{i}","Count":{}}}}}"#, i % 1000)),
            ("pairs [i, j]", &|i| format!("[{},{}]", i % 1000, i % 100)),
            ("pairs of digits [d, d]", &|i| format!("[{},{}]", i % 10, i / 10 % 10)),
            ("{id, done: false}", &|i| format!(r#"{{"id":{i},"done":false}}"#)),
            ("{sku, qty}", &|i| format!(r#"{{"sku":"A{i}","qty":{}}}"#, i % 10)),
            ("{key, value}", &|i| format!(r#"{{"key":"k{i}","value":"v"}}"#)),
            ("pairs [i, \"x\"]", &|i| format!(r#"[{i},"x"]"#)),
            ("{x: d, y: d}", &|i| format!(r#"{{"x":{},"y":{}}}"#, i % 10, i / 10 % 10)),
            ("chart points {x: 0-99, y: 0-99}", &|i| format!(r#"{{"x":{},"y":{}}}"#, i % 100, i / 100 % 100)),
            ("{k: \"a\", v: d}", &|i| format!(r#"{{"k":"a","v":{}}}"#, i % 10)),
            ("one key {id}", &|i| format!(r#"{{"id":{i}}}"#)),
            ("one letter, one key {a: 1}", &|_| r#"{"a":1}"#.to_string()),
        ];
        for (shape, row) in family {
            let (tree, room) = crate::memory::params_room(rows(body, row).as_bytes());
            eprintln!("2 MiB of {shape}: {} MiB, reserved {} of {} MiB", tree / MIB, room / MIB, pool / MIB);
            assert!(room <= pool, "2 MiB of {shape} as params reserves {} MiB, more than the {} MiB pool", room / MIB, pool / MIB);
            // Every row shape is under the one 128 MiB ceiling, held or not, but the one-letter one-key objects.
            let one_letter = shape.starts_with("one letter");
            assert_eq!(tree <= hosted.unpacked_limit(), !one_letter, "2 MiB of {shape} is {} MiB as a tree, against the {} MiB ceiling", tree / MIB, hosted.unpacked_limit() / MIB);
        }
        let two_field = estimate(rows(body, &|i| format!(r#"{{"id":{i},"ok":true}}"#)).as_bytes());
        let five_field = estimate(
            rows(body, &|i| format!(r#"{{"id":{i},"name":"item-{i}","status":"active","created_at":"2026-10-16T01:02:03Z","owner":"o{i}"}}"#)).as_bytes(),
        );
        let one_key = estimate(rows(body, &|_| r#"{"a":1}"#.to_string()).as_bytes());
        let (nested, nested_room) = crate::memory::params_room(rows(body, &|_| r#"{"a":{"a":1}}"#.to_string()).as_bytes());
        let response = crate::connectors::DEFAULT_HTTP_MAX_RESPONSE_BYTES as usize;
        let vercel_env = estimate(
            rows(response, &|i| format!(
                r#"{{"id":"env_{i:016}","key":"KEY_{i}","type":"encrypted","target":["production","preview"],"gitBranch":null,"createdAt":1760000000000,"updatedAt":1760000000000,"value":"v{i}"}}"#
            ))
            .as_bytes(),
        );
        eprintln!(
            "estimates: 2 MiB two-field rows {} KiB, five-field rows {} MiB, one-key objects {} MiB, objects in objects {} MiB; 5 MiB Vercel env listing {} MiB; pool {} MiB",
            two_field / 1024,
            five_field / MIB,
            one_key / MIB,
            nested / MIB,
            vercel_env / MIB,
            pool / MIB
        );
        assert!(five_field <= two_field, "five-field rows cost less than two-field rows");
        assert!(vercel_env * 2 <= pool, "a 5 MiB Vercel env listing through the projection");
        assert!(nested_room > pool, "2 MiB of objects nested in objects is refused before it is parsed");

        // Every execution in flight holds a slot, a slot's byte buffers are B + R + 2.6 R, and the rest of a view up to 3.8 R is held in the view-growth budget, which fits two of the longest at once.
        let slot = DEFAULT_BODY_EXEC_BYTES as u64 + response as u64 + VIEW_FREE_TENTHS * response as u64 / 10;
        assert_eq!(slot, 20 * MIB);
        assert!(2 * (crate::store::MAX_STORED_RESULT_BYTES as u64 + DEFAULT_BODY_EXEC_BYTES as u64) <= slot, "storing a result and reading it back fits a slot's share");
        assert!(crate::store::MAX_STORED_RESULT_BYTES as u64 + OUTGOING_BODY_TENTHS * DEFAULT_BODY_EXEC_BYTES as u64 / 10 <= slot, "an agent reading its approval's outcome, one copy of the row with params written up to 4.5 times the body, fits a slot's share");
        let longest_past_slot = (VIEW_GROWTH_TENTHS - VIEW_FREE_TENTHS) * response as u64 / 10;
        assert!(2 * longest_past_slot <= hosted.view_growth_bytes, "two of the longest views fit the view-growth budget at once");
        assert_eq!(crate::memory::resolution_bytes(&hosted), slot, "an approved held call with no slot to run under reserves a slot's share in the pool");
        let total = 96 * MIB + hosted.max_inflight as u64 * slot + hosted.view_growth_bytes + 2 * DEFAULT_BODY_BULK_BYTES as u64 + pool;
        assert_eq!(total, 476 * MIB, "the sum the doc on DEFAULT_HOSTED_JSON_POOL_BYTES states");
        assert!(total <= 512 * MIB, "the hosted budget adds to {} MiB", total / MIB);
        let request_rows = hosted.staged_bytes_per_gateway as u64 + 2 * hosted.held_total_bytes + hosted.capability_bytes;
        assert_eq!(request_rows, 56 * MIB, "the request-made rows the doc on DEFAULT_HOSTED_JSON_POOL_BYTES names");
        assert_eq!(total + 3 * request_rows, 644 * MIB, "and three copies of them in an upload, as it states");
        // The row one connector install of minimal capability lines in an 8,323,223-byte body is held as, alone in its queue, measured at hosted defaults.
        let lone_change = 34_999_832;
        assert!(lone_change > hosted.held_total_bytes, "a change alone in its queue passes its budget");
        let with_lone_change = request_rows - hosted.held_total_bytes + lone_change;
        assert_eq!((total + 3 * with_lone_change) / MIB, 696, "about 696 MiB with that change in place of the control-plane budget, as it states");
        // The copies hyper keeps for a delivery stalled past its deadline, at a hosted worker's Cloud Run concurrency (32), each until Cloud Run's 130 s request timeout closes its connection.
        let stalled = crate::delivery::STALLED_COPY_BYTES as u64;
        assert_eq!(stalled.div_ceil(1024), 472, "about 472 KiB a stalled connection, as it states");
        assert_eq!((32 * stalled + MIB / 2) / MIB, 15, "about 15 MiB at a concurrency of 32, as it states");
        assert!(total + 32 * stalled <= 512 * MIB, "and the hosted sum still fits with them: {} MiB", (total + 32 * stalled) / MIB);
    }

    /// Which near-2 MiB documents of short rows the hosted ceiling refuses, as the doc on [`DEFAULT_HOSTED_JSON_POOL_BYTES`] states them: not only one-letter-key objects but one-key objects over a one-digit number or a one-letter string, and one-key id rows whose ids are under four digits; ids of four digits or more are under it.
    #[test]
    fn near_two_mib_documents_of_one_key_rows_over_short_values_pass_the_hosted_ceiling() {
        use crate::connectors::json_budget::estimate;
        const MIB: f64 = 1024.0 * 1024.0;
        let ceiling = LimitsConfig::defaults_for(true).unpacked_limit();
        let body = |row: &dyn Fn(usize) -> String| {
            let mut out = String::from(r#"{"capability":"github.pull_requests.list","params":{"owner":"o","repo":"r","extra":["#);
            let mut i = 0;
            loop {
                let next = row(i);
                if out.len() + next.len() + 4 > DEFAULT_BODY_EXEC_BYTES {
                    break;
                }
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&next);
                i += 1;
            }
            out.push_str("]}}");
            out
        };
        let over: [(&str, &dyn Fn(usize) -> String); 6] = [
            ("{a: 1}", &|_| r#"{"a":1}"#.into()),
            ("{qty: 5}", &|_| r#"{"qty":5}"#.into()),
            ("{tag: \"a\"}", &|_| r#"{"tag":"a"}"#.into()),
            ("{id: n}, n < 10", &|i| format!(r#"{{"id":{}}}"#, i % 10)),
            ("{id: n}, n < 100", &|i| format!(r#"{{"id":{}}}"#, i % 100)),
            ("{id: n}, n < 1000", &|i| format!(r#"{{"id":{}}}"#, i % 1000)),
        ];
        let under: [(&str, &dyn Fn(usize) -> String); 2] =
            [("{id: n}, four digits", &|i| format!(r#"{{"id":{}}}"#, 1000 + i % 9000)), ("{id: i} counting from 0", &|i| format!(r#"{{"id":{i}}}"#))];
        for (shapes, is_over) in [(&over[..], true), (&under[..], false)] {
            for (shape, row) in shapes {
                let text = body(row);
                assert!(text.len() <= DEFAULT_BODY_EXEC_BYTES);
                let tree = estimate(text.as_bytes());
                eprintln!("2 MiB of {shape}: {:.1} MiB as a tree", tree as f64 / MIB);
                assert_eq!(tree > ceiling, is_over, "2 MiB of {shape} is {:.1} MiB as a tree, against the {:.0} MiB ceiling", tree as f64 / MIB, ceiling as f64 / MIB);
            }
        }
    }

    /// One ceiling on an agent call's unpacked size, the pool less 64 MiB, which only the pool moves: a raised body limit, which 1.3.52's hold ceiling and the clamp this replaced both followed down (to nothing past a 35 MiB body on a hosted worker), leaves it where it is. On a pool under 128 MiB half the pool is kept instead, so it is never under half the pool, and never nothing on the 16 MiB floor. Approving a call at it sent within the body reserves at most its tree, 4.5 times the body and an execution's buffers in the pool, which fits the pool at both postures' defaults.
    #[test]
    fn the_one_ceiling_is_the_pool_less_64_mib_and_only_the_pool_moves_it() {
        const MIB: u64 = 1024 * 1024;
        let approving = |c: &LimitsConfig, sent: u64| c.unpacked_limit() + OUTGOING_BODY_TENTHS * sent / 10 + crate::memory::resolution_bytes(c);
        let (hosted, self_run) = (LimitsConfig::defaults_for(true), LimitsConfig::defaults_for(false));
        assert_eq!(hosted.unpacked_limit(), 128 * MIB);
        assert_eq!(self_run.unpacked_limit(), 448 * MIB);
        assert_eq!(hosted.hold_ceiling_1_3_52(), 164 * MIB, "192 - 4 x 2 - 20");
        assert_eq!(self_run.hold_ceiling_1_3_52(), 484 * MIB);
        assert_eq!(approving(&hosted, 2 * MIB), 157 * MIB, "128 + 4.5 x 2 + 20, leaving 35 MiB of the 192 MiB pool");
        assert_eq!(approving(&self_run, 2 * MIB), 477 * MIB);
        for config in [&hosted, &self_run] {
            assert!(approving(config, config.body_exec_bytes as u64) <= config.json_pool_bytes, "params sent within the body can be approved at the defaults");
        }
        for body in [MIN_BODY_EXEC_BYTES, 8 * MIB as usize, 16 * MIB as usize, 32 * MIB as usize, 35 * MIB as usize, 40 * MIB as usize, 64 * MIB as usize] {
            let config = LimitsConfig { body_exec_bytes: body, ..hosted.clone() };
            assert_eq!(config.unpacked_limit(), 128 * MIB, "a {body}-byte body limit leaves the hosted ceiling at 128 MiB");
        }
        assert_eq!(LimitsConfig { body_exec_bytes: 40 * MIB as usize, ..hosted.clone() }.hold_ceiling_1_3_52(), 0, "where the clamp put the ceiling");
        for (pool, ceiling) in [(16, 8), (32, 16), (64, 32), (96, 48), (128, 64), (129, 65), (192, 128), (300, 236), (512, 448), (8192, 8128)] {
            let config = LimitsConfig { json_pool_bytes: pool * MIB, ..hosted.clone() };
            assert_eq!(config.unpacked_limit(), ceiling * MIB, "a {pool} MiB pool");
            assert_eq!(config.unpacked_limit(), (pool * MIB).saturating_sub(UNPACKED_HEADROOM_BYTES).max(pool * MIB / 2));
        }
    }

    /// The largest tree an approval's rendering builds is never under the 1.3.52 hold ceiling, so a control-plane change, which gets no tree check, renders wherever 1.3.52 rendered it (164 MiB hosted rather than the 128 MiB agent ceiling, and half the pool rather than nothing on a 16 MiB one), and never under the one ceiling, so every agent call held renders. It never passes the pool.
    #[test]
    fn a_rendering_builds_what_the_ceiling_or_the_1_3_52_hold_ceiling_admits() {
        const MIB: u64 = 1024 * 1024;
        let hosted = LimitsConfig::defaults_for(true);
        assert_eq!(hosted.render_limit(), 164 * MIB);
        assert_eq!(LimitsConfig::defaults_for(false).render_limit(), 484 * MIB);
        assert_eq!(LimitsConfig { json_pool_bytes: 16 * MIB, ..hosted.clone() }.render_limit(), 8 * MIB);
        assert_eq!(LimitsConfig { body_exec_bytes: 32 * MIB as usize, ..hosted.clone() }.render_limit(), 128 * MIB);
        for pool in [16 * MIB, 32 * MIB, 64 * MIB, 192 * MIB, 512 * MIB, 8192 * MIB] {
            for body in [MIN_BODY_EXEC_BYTES, DEFAULT_BODY_EXEC_BYTES, 32 * MIB as usize, 64 * MIB as usize] {
                let config = LimitsConfig { json_pool_bytes: pool, body_exec_bytes: body, ..hosted.clone() };
                let hold_ceiling_1_3_52 = config.hold_ceiling_1_3_52().max(64 * 1024);
                assert!(config.render_limit() >= hold_ceiling_1_3_52, "a {pool}-byte pool, a {body}-byte body");
                assert!(config.render_limit() >= config.unpacked_limit());
                assert!(config.render_limit() <= pool);
            }
        }
    }

    /// The growth the arithmetic counts is what the agent's view writes. Exponent-written numbers grow it 3.8 times and short values under a redacted key less, both within [`VIEW_GROWTH_TENTHS`], and the part of the longest view past what a slot holds fits the hosted view-growth budget twice.
    #[test]
    fn the_view_growth_the_arithmetic_counts_is_what_the_view_writes() {
        let response = crate::connectors::DEFAULT_HTTP_MAX_RESPONSE_BYTES as usize;
        let filled = |row: &str| {
            let mut body = String::from("[");
            while body.len() + row.len() + 2 < response {
                body.push_str(row);
                body.push(',');
            }
            body.pop();
            body.push(']');
            body.into_bytes()
        };
        let scrub = permaura_core::CredentialScrub::default();
        let mut longest = 0;
        for (shape, body, keys) in [
            ("1e15", filled("1e15"), vec![]),
            ("{\"pw\":1} under a redacted key", filled(r#"{"pw":1}"#), vec!["pw".to_string()]),
            ("[1e15] nested", filled("[1e15]"), vec![]),
        ] {
            let view = permaura_core::json_stream::agent_view(&body, &scrub, &keys).unwrap();
            let tenths = view.len() * 10 / body.len();
            eprintln!("{shape}: the view is {}.{} times the body", tenths / 10, tenths % 10);
            assert!(tenths as u64 <= VIEW_GROWTH_TENTHS, "{shape}: {tenths} tenths");
            longest = longest.max(view.len());
        }
        assert!(longest * 10 >= response * 37, "the worst shape measured is the one the constant names");
        let past_slot = (longest - response * VIEW_FREE_TENTHS as usize / 10) as u64;
        assert!(2 * past_slot <= LimitsConfig::defaults_for(true).view_growth_bytes, "two of the longest views fit the hosted view-growth budget");
    }

    /// A hosted worker's rates are its store's measured ceiling, and a gateway its owner runs
    /// keeps every number it had before that ceiling was measured.
    #[test]
    fn hosted_defaults_sit_at_the_measured_store_ceiling_and_self_run_ones_do_not_move() {
        let hosted = LimitsConfig::defaults_for(true);
        assert_eq!((hosted.rate_per_min, hosted.rate_burst), (30, 10));
        assert_eq!((hosted.worker_rate_per_min, hosted.worker_rate_burst), (Some(30), 10));
        let own = LimitsConfig::defaults_for(false);
        assert_eq!(own, LimitsConfig::default());
        assert_eq!((own.rate_per_min, own.rate_burst), (120, 30));
        assert_eq!(own.worker_rate_per_min, None);
        assert_eq!(own.worker_rate_burst, DEFAULT_SELF_RUN_WORKER_RATE_BURST);
    }

    /// Arrivals simulated against the hosted buckets on a synthetic clock: half an execution a second,
    /// the clean rate the 7 October run measured, is never refused, and one a second, where Cloud Storage began
    /// answering 429, is refused about half the time once the burst is spent.
    #[test]
    fn the_hosted_buckets_admit_the_clean_rate_and_refuse_above_it() {
        let hosted = LimitsConfig::defaults_for(true);
        let worker = hosted.worker_rate_per_min.unwrap();
        let admitted = |every: Duration, secs: u64| {
            let start = Instant::now();
            let (mut caller, mut whole) = (Bucket::new(hosted.rate_burst), Bucket::new(hosted.worker_rate_burst));
            caller.last = start;
            whole.last = start;
            let (mut yes, mut no) = (0u32, 0u32);
            let mut t = Duration::ZERO;
            while t < Duration::from_secs(secs) {
                let now = start + t;
                let ok = whole.take(hosted.worker_rate_burst, worker, now).is_ok()
                    && caller.take(hosted.rate_burst, hosted.rate_per_min, now).is_ok();
                if ok { yes += 1 } else { no += 1 }
                t += every;
            }
            (yes, no)
        };
        assert_eq!(admitted(Duration::from_millis(2000), 600), (300, 0), "0.5/s for ten minutes");
        let (yes, no) = admitted(Duration::from_millis(1000), 600);
        assert!((305..=312).contains(&yes), "1/s: the burst plus half a second's worth, got {yes}");
        assert_eq!(yes + no, 600);
    }

    #[test]
    fn a_self_run_gateway_has_no_worker_bucket_by_default() {
        let limits = Limits::new(LimitsConfig::default());
        assert_eq!(limits.worker_rate(), None);
        assert_eq!(worker_rate_from_env(false), None);
        assert_eq!(worker_rate_from_env(true), Some(DEFAULT_WORKER_RATE_PER_MIN));
    }

    #[test]
    fn a_worker_rejection_names_its_scope_and_the_fair_use_page() {
        let limits = Limits::new(worker_cfg(300, 100));
        let err = Rejection::WorkerRate.into_error(limits.retry_after_secs(Rejection::WorkerRate));
        match err {
            GatewayError::TooManyRequests { reason, scope, retry_after_secs, .. } => {
                assert_eq!(reason, "rate");
                assert_eq!(scope, Some("worker"));
                assert_eq!(retry_after_secs, 1);
            }
            other => panic!("expected a 429, got {other:?}"),
        }
        assert_eq!(Rejection::Rate.scope(), Some("session"));
        assert_eq!(Rejection::Queue.scope(), None);
    }

    #[test]
    fn a_worker_rejection_logs_its_own_key_class() {
        let limits = Limits::new(cfg());
        assert_eq!(LimitKey::worker().class(), KeyClass::Worker);
        assert_eq!(limits.log_rejection(Rejection::WorkerRate, KeyClass::Worker, 1), Some(0));
        assert_eq!(
            limits.log_rejection(Rejection::Rate, KeyClass::Session, 1),
            Some(0),
            "the worker's line does not swallow a session's"
        );
    }
}
