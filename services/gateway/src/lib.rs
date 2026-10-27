//! # permaura-gateway
//!
//! The Permaura **enforcement runtime**: an `axum` service that *is* the gate every
//! agent action passes through. It is usable both as a library ([`build_router`] over
//! an [`AppState`], which the demo daemon `permad` and the tests use) and as the `permaura`
//! binary (`src/main.rs`), whose `permaura start` is both the self-run and the hosted gateway.
//!
//! ## The enforcement loop (`POST /v1/invoke`, `permaura_invoke`)
//!
//! 1. identify the agent/session from the bearer token,
//! 2. load the grants for the capability's resource,
//! 3. run [`permaura_policy::PolicyEngine`] to a `Decision`,
//! 4. **Deny** → `403` with the reason; **RequiresApproval** → `202` with a pending
//!    approval id; **Allow** → resolve the sealed secret, run the connector (real transports,
//!    or deterministic mocks under `--mock` and `--demo`), redact the result, and append
//!    hash-chained, signed audit events (a pre-execution `attempt` and a terminal event),
//! 5. the raw secret is never returned to the agent.
//!
//! ## REST v1 surface
//!
//! `POST /v1/sessions`, `GET /v1/capabilities`, `POST /v1/grants`, `POST /v1/invoke`,
//! `POST /v1/approvals`, `GET /v1/audit-events`, `POST /v1/secrets`,
//! `POST /v1/secrets/:id/rotate`, `POST /v1/devices/enroll`, `POST /v1/agents/register`,
//! plus the read endpoints `GET /v1/agents`, `GET /v1/sessions`, `GET /v1/grants`,
//! `GET /v1/secrets` (metadata only), `GET /v1/connections`, and `GET /health` and the
//! MCP `POST /mcp` JSON-RPC endpoint.
//!
//! Vault portability is `POST /v1/vault/export`, `POST /v1/vault/import/preview` and
//! `POST /v1/vault/import`: all three POST, deliberately, since the console proxy treats
//! any GET as a read open to every workspace member.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod allowances;
pub mod announce;
pub mod approval_display;
pub mod archive;
pub mod audit_bound;
pub mod audit_ceiling;
pub mod audit_key;
pub mod reconcile;
pub mod backend;
pub mod client_name;
pub mod config;
pub mod connectors;
pub mod custody;
pub mod delivery;
pub mod drain;
pub mod error;
pub mod fair_use;
pub mod landing;
pub mod limits;
pub mod manifest;
pub mod mcp;
pub mod memory;
pub mod notify;
pub mod objectstore;
pub mod oauth;
pub mod oauth_connect;
pub mod oauth_credential;
pub mod openapi;
pub mod policy_guard;
pub mod posture_floor;
pub mod presets;
pub mod push;
pub mod recovery;
pub mod relay;
pub mod release;
pub mod request_body;
pub mod reseal;
pub mod restore;
pub mod rest;
pub mod secret_inventory;
pub mod seed;
pub mod service;
pub mod store;
pub mod tunnel;
pub mod vault_bundle;
pub mod wordpress;

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use crate::connectors::{
    CommandRunner, HttpClient, MockHttpClient, MockSshRunner, RealCommandRunner, ReqwestClient,
    SshRunner,
};
use crate::service::EnforcementService;
use crate::store::memory::MemoryStore;
use crate::store::Store;

/// What a running gateway actually **is**, as opposed to what it looks like over the wire. A
/// `--demo` gateway answers every endpoint exactly like a real one, so support triage, and any
/// probe, otherwise cannot tell a customer's install from a seeded toy holding a published
/// operator bearer.
///
/// Set by the constructor that built the state, never from the environment: posture is a property of
/// how this process was started, and an env var would let a real install claim to be a demo or the
/// reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posture {
    /// Real transports over a real (persistent, unseeded) store: a shipped install.
    Real,
    /// Mock transports: HTTP, command execution and SSH return canned results. Nothing it reports
    /// about an upstream happened.
    Mock,
    /// Mock transports over the in-memory seeded demo estate, whose operator bearer is public.
    Demo,
}

impl Posture {
    /// The wire spelling used by `/health`.
    pub fn as_str(self) -> &'static str {
        match self {
            Posture::Real => "real",
            Posture::Mock => "mock",
            Posture::Demo => "demo",
        }
    }
}

/// The shared application state every handler receives. Cheap to clone (it is just an
/// `Arc` around the enforcement service).
#[derive(Clone)]
pub struct AppState {
    /// The transport-independent enforcement service (store + http client + policy).
    pub service: Arc<EnforcementService>,
    /// True on a hosted (Mode C) worker: it is directly internet-exposed with no trusted loopback
    /// client, so the credential-free operator plane (session-open, approver-key pairing) is closed.
    /// Set by `PERMAURA_HOSTED`. See `rest::reject_if_remote`.
    pub hosted: bool,
    /// This gateway's id as the control plane knows it (`PERMAURA_GATEWAY_ID`), or empty when the
    /// process was never told one; a self-run gateway typically has not been. Descriptive only: it
    /// is stamped into a vault bundle's provenance header and never drives a decision anywhere.
    pub gateway_id: String,
    /// The root-signed connector-manifest revocation state, loaded once at boot from
    /// `PERMAURA_PMCONN_REVOCATION`. Consulted by `POST /v1/connectors/install`, and through the service by every call on a connection made from an installed manifest. Replace it with [`AppState::with_revocation`], which keeps the two the same.
    pub pmconn_revocation: Arc<crate::manifest::Revocation>,
    /// When set, an authenticated loopback `POST /v1/shutdown` fires this to trigger the binary's
    /// graceful shutdown (the portable stop path the desktop supervisor and npm CLI call before a
    /// hard kill; console/`ctrl_close` events don't reach a windowless GUI child on Windows). `None`
    /// in the embedded daemon and tests, where the host process must not self-terminate; the endpoint
    /// then reports the shutdown path is unavailable rather than silently no-op.
    pub shutdown: Option<Arc<tokio::sync::Notify>>,
    /// In-flight connector OAuth authorizations, keyed by `state`. In memory only; see
    /// [`crate::oauth_connect::PendingAuths`] for why.
    pub oauth_pending: Arc<crate::oauth_connect::PendingAuths>,
    /// Real / mock / demo; see [`Posture`]. Reported by `/health`.
    pub posture: Posture,
    /// The instance's resource limits: request rate, in-flight executions, the wait queue and the
    /// numbers the router's body and timeout layers are built from. Entirely in memory, so it starts
    /// fresh on every cold start. See [`crate::limits`].
    pub limits: Arc<crate::limits::Limits>,
    /// The monthly fair-use ceiling: counting on a hosted worker, inert everywhere else. Shared with
    /// the store, which counts, and with `limits`, which throttles. See [`crate::fair_use`].
    pub fair_use: Arc<crate::fair_use::FairUse>,
    /// Where `PUT /v1/announce` keeps the credentials it is handed. `None` in the embedded daemon and
    /// tests, where the credentials apply to the running process only and the answer says so.
    pub config_path: Option<std::path::PathBuf>,
    /// The operator token this gateway has published to `$PERMAURA_HOME/operator.token`, which is what
    /// keys its answer to a `/health` challenge. See [`PublishedToken`].
    pub published_token: Arc<PublishedToken>,
    /// The console sessions permaura.com may hold for this gateway, which `/health` proves for the browser-direct console. Written by the re-seal task; see [`crate::reseal::HeldConsoleSessions`].
    pub held_console_sessions: Arc<crate::reseal::HeldConsoleSessions>,
    /// The tunnel connector `permaura start` runs, which `POST /v1/remote/disable` stops. `None` in the embedded daemon and tests, which run none.
    pub tunnel: Option<crate::tunnel::ConnectorSlot>,
    /// Set for a demo (`permaura start --demo`, `permad`): a request that carries a tunnel or proxy's forwarding header, or comes from another address, is refused; a raw forwarder that adds no header and connects from loopback is not detected. See [`AppState::local_only`].
    pub local_only: bool,
}

/// The operator token this gateway published for local clients, which `/health` proves it holds ([`permaura_core::health_proof`]). Empty when nothing was published (a hosted worker, a store outside the home).
///
/// Held in memory rather than re-read from the file so that a gateway left running on a store since recreated answers with the token it published, a proof that does not match, which a client can tell apart from a gateway too old to answer at all.
#[derive(Default)]
pub struct PublishedToken(std::sync::RwLock<Option<String>>);

impl PublishedToken {
    /// The token, when this gateway has published one.
    pub fn get(&self) -> Option<String> {
        self.0.read().ok().and_then(|t| t.clone())
    }

    /// Record the token now published, or that there is none.
    pub fn set(&self, token: Option<String>) {
        if let Ok(mut slot) = self.0.write() {
            *slot = token;
        }
    }
}

/// The size from which glibc serves an allocation with its own mapping, pinned by `permaura start`
/// on a glibc build so a large buffer goes back to the kernel the moment it is freed.
///
/// Left to itself glibc raises its threshold to the size of the largest mapped block freed so far,
/// and from then on carves every block up to that size from an arena that keeps it once freed. A
/// hosted worker's large buffers are snapshot copies that grow with the store, so each one lands where
/// no earlier hole fits and the arenas only grow; with a KDF working set among them, a 512 MiB worker
/// ran out of memory at 1.5 executions a second. Pinned, each such buffer is its own mapping,
/// and the footprint follows what the process holds rather than the most it ever held. Here rather
/// than beside the call because the library forbids `unsafe`, and the soak test pins the same number.
pub const MMAP_THRESHOLD_BYTES: usize = 128 * 1024;

/// How often a store holding a commit its last upload failed to carry tries again on its own.
pub const STORE_CARRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Keep carrying a local commit whose snapshot upload failed, rather than leaving it until the next
/// write happens to arrive.
///
/// What such a commit holds is mostly the terminal audit events of executions that ran while uploads
/// were being refused: recorded on this instance, durable only once an upload carries them. An
/// instance that went quiet after a burst of 429s used to keep them in memory until its next write or
/// its shutdown, whichever came first. Inert on a store that uploads nothing.
///
/// This tick only runs inside requests on a hosted worker deployed with request-based CPU, which is how
/// they are deployed: Cloud Run gives the container CPU while a request is in flight, at startup and at
/// SIGTERM, and next to none between. [`carry_owed_commit`] is what carries an owed commit there, on
/// the next request's path, a read included; this tick covers a worker with CPU always allocated.
pub fn spawn_store_carrier(store: Arc<dyn Store>, every: std::time::Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match store.carry_pending() {
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "a pending store commit is still not carried; retrying"),
            }
        }
    })
}

/// How long a request waits, once its handler has answered, for the carry [`carry_owed_commit`] started.
const REQUEST_CARRY_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The store a request may carry an owed commit for, and whether a carry is already running.
#[derive(Clone)]
struct RequestCarry {
    store: Arc<dyn Store>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// Carry a commit an upload failure left local on the path of the next request, whatever the request.
///
/// On request-based CPU a hosted worker's background tick ([`spawn_store_carrier`]) gets no CPU between
/// requests, so a commit left local after a burst of refused uploads waited for a write to arrive, or
/// for the SIGTERM drain. The carry runs beside the handler and, except on `/health`, the response waits for it up to
/// [`REQUEST_CARRY_WAIT`], so it has CPU for at least that long (a liveness probe starts the carry but is answered at once); one still uploading then carries on
/// whenever the instance next has CPU. One at a time, and nothing at all on a store that owes nothing.
async fn carry_owed_commit(
    axum::extract::State(carry): axum::extract::State<RequestCarry>,
    req: Request,
    next: Next,
) -> axum::response::Response {
    use std::sync::atomic::Ordering;
    let running = carry.store.owes_upload()
        && carry.running.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok();
    // A liveness probe is answered at once: its own store bound and a carry wait together would reach the probe's timeout.
    let wait = req.uri().path() != "/health";
    let task = running.then(|| {
        struct Done(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let carry = carry.clone();
        tokio::spawn(async move {
            let _done = Done(carry.running.clone());
            if let Err(e) = carry.store.carry_pending() {
                tracing::debug!(error = %e, "a pending store commit is still not carried; the next request tries again");
            }
        })
    });
    let response = next.run(req).await;
    if let Some(task) = task.filter(|_| wait) {
        let _ = tokio::time::timeout(REQUEST_CARRY_WAIT, task).await;
    }
    response
}

/// Whether this process is a hosted (Mode C) worker. A hosted worker on Cloud Run has no loopback
/// client (every request arrives from the internet) so the loopback-trust operator plane must be
/// closed. Truthy `PERMAURA_HOSTED` (`1`/`true`).
pub(crate) fn hosted_from_env() -> bool {
    std::env::var("PERMAURA_HOSTED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

impl AppState {
    /// Build state from an already-constructed service.
    pub fn new(service: EnforcementService) -> Self {
        let hosted = hosted_from_env();
        let fair_use = Arc::new(crate::fair_use::FairUse::from_env(hosted));
        fair_use.attach(service.store().as_ref());
        let limits = Arc::new(crate::limits::Limits::from_env());
        limits.attach_fair_use(fair_use.clone());
        service.attach_execution_slots(limits.clone());
        let pmconn_revocation = Arc::new(crate::manifest::load_revocation());
        service.attach_revocation(pmconn_revocation.clone());
        crate::manifest::log_revoked_installed(service.store().as_ref(), &pmconn_revocation);
        crate::posture_floor::at_start(service.store().as_ref());
        AppState {
            service: Arc::new(service),
            hosted,
            gateway_id: std::env::var("PERMAURA_GATEWAY_ID").unwrap_or_default(),
            pmconn_revocation,
            shutdown: None,
            oauth_pending: Arc::new(crate::oauth_connect::PendingAuths::default()),
            // The honest default for a caller that assembled its own service: real transports over
            // whatever store it handed us. The mock and demo paths below say so explicitly.
            posture: Posture::Real,
            limits,
            fair_use,
            config_path: None,
            published_token: Arc::new(PublishedToken::default()),
            held_console_sessions: Arc::new(crate::reseal::HeldConsoleSessions::default()),
            tunnel: None,
            local_only: false,
        }
    }

    /// Replace the resource limits, for a test that needs to reach a bound without generating the
    /// traffic that would normally reach it.
    pub fn with_limits(mut self, limits: Arc<crate::limits::Limits>) -> Self {
        limits.attach_fair_use(self.fair_use.clone());
        self.service.attach_execution_slots(limits.clone());
        self.limits = limits;
        self
    }

    /// Replace the connector revocation state, for the install check and for every call alike.
    pub fn with_revocation(mut self, revocation: crate::manifest::Revocation) -> Self {
        let revocation = Arc::new(revocation);
        self.service.attach_revocation(revocation.clone());
        crate::manifest::log_revoked_installed(self.service.store().as_ref(), &revocation);
        self.pmconn_revocation = revocation;
        self
    }

    /// Replace the fair-use ceiling, for a test that needs a throttled worker without making a
    /// million calls. The store keeps counting into the one it was attached to at construction.
    pub fn with_fair_use(mut self, fair_use: Arc<crate::fair_use::FairUse>) -> Self {
        self.limits.attach_fair_use(fair_use.clone());
        self.fair_use = fair_use;
        self
    }

    /// Attach the graceful-shutdown trigger so `POST /v1/shutdown` can stop the process. The binary
    /// wires this to an `axum::serve(...).with_graceful_shutdown(...)` future; the daemon and tests
    /// leave it unset so an embedded gateway can never be told to terminate its host.
    pub fn with_shutdown(mut self, signal: Arc<tokio::sync::Notify>) -> Self {
        self.shutdown = Some(signal);
        self
    }

    /// Refuse a request that carries a tunnel or proxy's forwarding header, and anything from another address. For a gateway whose operator bearer is published, a demo, which a forwarder left pointing at its port would otherwise hand to anyone; a raw forwarder on loopback adds no header and is not caught, which is why a demo also takes a port of its own.
    pub fn local_only(mut self) -> Self {
        self.local_only = true;
        self
    }

    /// Hand over the slot the binary keeps its tunnel connector in, so `POST /v1/remote/disable` can stop it.
    pub fn with_tunnel(mut self, slot: crate::tunnel::ConnectorSlot) -> Self {
        self.tunnel = Some(slot);
        self
    }

    /// Name the config file runtime settings are written to. The binary passes the default
    /// location; anything that leaves it unset keeps those settings in memory.
    pub fn with_config_path(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.config_path = path;
        self
    }

    /// Record what this gateway is. Crate-private on purpose: posture is decided by the constructor
    /// that wired the transports and the store, so nothing outside can relabel a demo as real.
    fn with_posture(mut self, posture: Posture) -> Self {
        self.posture = posture;
        self
    }

    /// Build state over a store and HTTP client.
    pub fn from_parts(store: Arc<dyn Store>, http: Arc<dyn HttpClient>) -> Self {
        AppState::new(EnforcementService::new(store, http))
    }

    /// The offline dev/test/demo configuration: an in-memory store seeded with demo data and
    /// **mock** transports (no network, no shelling out, no SSH), so the gateway runs end-to-end
    /// with zero setup. This is what the demo daemon, `permaura start --demo` and the tests use.
    /// The shipped gateway uses [`AppState::from_env`] instead, which is real and never seeded.
    ///
    /// The demo estate includes an operator session under the published [`seed::DEMO_TOKEN`], so
    /// **this constructor must never back a network-reachable gateway**: `permaura start --demo` refuses a non-loopback `--addr`, and the demo daemon binds loopback only.
    /// The store is in-memory and the transports are mocks, so nothing it holds is a real credential and no connector call leaves the process,
    /// but sealing the demo secrets resolves this install's vault KEK, and mints and stores one when the machine has none.
    pub fn in_memory_seeded() -> Self {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        // An in-memory store always starts empty, so it is always seeded; no env consulted.
        seed_demo_store(store.as_ref());
        let state = Self::assemble(store, /* mock */ true).with_posture(Posture::Demo);
        // The demo estate's operator bearer is the published constant, so that is what this gateway
        // proves it holds: a client driving a demo gateway names it with `--token`.
        state.published_token.set(Some(seed::DEMO_TOKEN.to_string()));
        state
    }

    /// Like [`AppState::in_memory_seeded`] but with a caller-supplied HTTP client, so a test can queue
    /// upstream responses (the OAuth token endpoint, an upstream API) on its own mock.
    pub fn in_memory_seeded_with_http(http: Arc<dyn HttpClient>) -> Self {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        seed_demo_store(store.as_ref());
        let command: Arc<dyn CommandRunner> = Arc::new(connectors::MockCommandRunner::new());
        let backend = crate::backend::build_backend(store.clone());
        let service = EnforcementService::from_components(store, http, command, backend, None);
        let state = AppState::new(service).with_posture(Posture::Demo);
        state.published_token.set(Some(seed::DEMO_TOKEN.to_string()));
        state
    }

    /// The binary/daemon entry point: select a **persistent** store from the environment and
    /// bootstrap it only when it is empty, so agents/grants/secrets/audit survive restarts.
    /// Store selection (`PERMAURA_STORE_PATH`):
    /// - unset → the default persistent SQLite DB (`~/.permaura/gateway.db`),
    /// - a path → SQLite at that path,
    /// - `:memory:` → ephemeral in-memory (the old behaviour, for throwaway runs).
    /// A non-empty store is loaded as-is.
    ///
    /// **Never seeded, under any environment.** A gateway built here is a real one: it can hold real
    /// credentials and be reachable from the network, and the demo estate contains a public operator
    /// bearer. Demo data comes from [`AppState::in_memory_seeded`] and nowhere else.
    ///
    /// Unless `mock` is set, this wires the **real** transports (real HTTP, real command execution,
    /// real SSH); real is the default so a shipped install works with no flags. The binary passes
    /// `mock=true` for its `--mock` flag.
    pub fn from_env(mock: bool) -> Self {
        let store = build_store_from_env();
        if store.kind() == "sqlite+gcs" {
            spawn_store_carrier(store.clone(), STORE_CARRY_INTERVAL);
        }
        let listed = store.list_agents();
        let posture = store_posture(&listed);
        if posture == StorePosture::Unreadable {
            tracing::error!(
                error = %listed.err().map(|e| e.to_string()).unwrap_or_default(),
                "could not read the gateway store to decide whether this install is new: refusing to start rather than bootstrapping over an identity that may already be there"
            );
            std::process::exit(1);
        }
        let fresh = posture == StorePosture::Bootstrap;
        let published = prepare_operator_credentials(store.as_ref(), fresh);
        if !fresh {
            let agents = store.list_agents().map(|a| a.len()).unwrap_or(0);
            let connections = store.list_connections().map(|c| c.len()).unwrap_or(0);
            // A clean bootstrap creates one agent (the `operator` identity holding the root token)
            // so "agents = 1, connections = 0" is a store that has only ever been bootstrapped, not
            // one carrying a user's work. Saying "data survived restart" there tells someone on the
            // second boot of a brand-new install that they have data they do not have. The old line
            // also advertised "skipping seed", and there has been no seed to skip since demo seeding
            // was removed from the shipped gateway.
            if connections == 0 && agents <= 1 {
                tracing::info!("opened the gateway store: no connections configured yet");
            } else {
                tracing::info!(agents, connections, "opened the gateway store");
            }
        }
        let state = Self::assemble(store, mock);
        state.published_token.set(published);
        state
    }

    /// Assemble the service over a ready (already-bootstrapped) store: wire the transports, the
    /// secret backend, and the OAuth RS. Posture is the caller's explicit `mock` argument, NOT an
    /// env var: `mock=false` (the shipped default via [`AppState::from_env`]) wires the REAL
    /// transports (real HTTP, real command execution, real SSH) so an end user's install works
    /// out of the box; `mock=true` (tests and the binary's `--mock` and `--demo` flags) wires the
    /// deterministic mocks. Real is the default precisely so a
    /// feature is never silently canned: you opt *out* of real, you don't opt in.
    fn assemble(store: Arc<dyn Store>, mock: bool) -> Self {
        // The client charges a document it parses to the service's pool when there is room at once, and never waits for room or refuses for it.
        let memory = crate::memory::MemoryBudget::from_env();
        let http: Arc<dyn HttpClient> = if mock {
            Arc::new(MockHttpClient::new())
        } else {
            Arc::new(
                ReqwestClient::new()
                    .expect("reqwest client builds with default config")
                    .with_memory(memory.pool().clone())
                    .with_max_tree_bytes(memory.internal_tree_bytes()),
            )
        };
        let command: Arc<dyn CommandRunner> = if mock {
            Arc::new(connectors::MockCommandRunner::new())
        } else {
            Arc::new(RealCommandRunner::new())
        };
        // The secret backend: the worker's local sealed vault, optionally fronted by Infisical
        // or KMS for the secret_ids configured via PERMAURA_INFISICAL_*/PERMAURA_KMS_*.
        // Custody stays worker-local.
        let backend = crate::backend::build_backend(store.clone());
        // OAuth Resource Server: enabled once the gateway has a public URL (PERMAURA_PUBLIC_URL).
        // It validates permaura.com-issued access-token JWTs so a remote MCP client can connect
        // directly. Off for a pure-local gateway (opaque tokens only). The JWKS is refreshed in
        // the background.
        let oauth = crate::oauth::RsConfig::from_env().map(|cfg| {
            if cfg.owner_sub.is_none() {
                // A public RS with no operator binding fails closed (rejects every remote token). Make
                // the misconfiguration loud: the web tunnel-provisioning path always sets this.
                tracing::error!(public_url = %cfg.public_url, "OAuth RS has no PERMAURA_OWNER_SUB: failing closed (all remote tokens rejected); set it to this gateway's operator account id");
            }
            let rs = std::sync::Arc::new(crate::oauth::OAuthRs::new(cfg.clone()));
            rs.spawn_refresh(std::time::Duration::from_secs(300));
            tracing::info!(public_url = %cfg.public_url, issuer = %cfg.issuer, owner_bound = cfg.owner_sub.is_some(), "OAuth Resource Server enabled");
            rs
        });
        let mut service = EnforcementService::from_components(store, http, command, backend, oauth)
            .with_ssh_runner(build_ssh_runner(mock))
            .with_memory_budget(memory);
        // The execution hold, read once here. A configured hold bucket this worker cannot reach
        // ends the process inside `restore::from_env`, in the spirit of the store's own
        // `an_unreachable_bucket_never_starts_empty`: a worker that cannot tell whether it is held
        // must not decide that it is not.
        if let Some(hold) = crate::restore::from_env() {
            service = service.with_execution_hold(hold);
        }
        // The audit archive: a bucket when `PERMAURA_AUDIT_ARCHIVE=1`, otherwise on a gateway its owner
        // runs its own disk, and on a hosted worker nothing. Unlike the hold, a bucket this
        // worker cannot reach does NOT end the process: an archive that cannot publish costs a
        // growing hot store and eventually a 429 from the ceiling, which is a bounded, visible,
        // reversible failure, while refusing to start would turn a storage blip into an outage for
        // a tenant whose chain is perfectly intact.
        if let Some(archive) = build_audit_archive(service.store().as_ref()) {
            service = service.with_audit_archive(archive);
        }
        // Before anything serves a request, at the first start that has this and never again: a gateway
        // that already had a device enrolled keeps the blanket device-signed floor it has been running
        // with, written down explicitly now that enrolment no longer implies it. Only gateways pairing
        // their first device from here on get the new policy-decides default, which is the population
        // that is offered the choice.
        service.adopt_enrolment_floor();
        // Reconciliation, the first act on a restored database (the restore's invalidation). A no-op on
        // every ordinary cold start; on a restored one it deletes every session, denies every
        // pending approval, removes every unconsumed enrolment code, raises both floors and lists
        // every restored authority as needing the owner's confirmation. A failure is reported rather
        // than fatal, because the hold that triggered it is still held: nothing executes, and the
        // next cold start finds the same trigger and tries again.
        let reconciled = match crate::reconcile::run_at_boot(&service) {
            Ok(_) => true,
            Err(e) => {
                tracing::error!(error = %e, "this worker booted into a restore and could not reconcile it; execution stays held and it is retried in the background");
                false
            }
        };
        // PERMAURA_REQUIRE_AGENT_APPROVAL=1 makes a newly-seen OAuth agent land Pending (invokes
        // denied) until an operator approves it in the console, on top of the AS sign-in consent.
        // Without it the gate follows its default (on once a device is paired on a gateway reachable
        // from off the host) or the operator's stored choice; this one lasts only for the run.
        if std::env::var("PERMAURA_REQUIRE_AGENT_APPROVAL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            service.require_agent_approval_for_this_run();
        }
        if agents_paused_from_env(std::env::var(AGENTS_PAUSED_ENV).ok().as_deref()) {
            service.pause_agents_for_this_run();
            tracing::warn!("{AGENTS_PAUSED_ENV} is set: every agent and every execution is refused for this run; the console and the vault export still work");
        }
        match service.settle_agent_session_clock_at_start() {
            Ok(0) => {}
            Ok(moved) => tracing::info!(moved, "moved agent sessions' expiry forward by the time agents were paused"),
            Err(e) => tracing::error!(error = %e, "could not hold agent sessions' expiry still across the agent pause"),
        }
        if let Err(e) = service.note_hold_requesters_recorded_since() {
            tracing::error!(error = %e, "could not mark when this gateway began recording who asks for a held change");
        }
        if let Err(e) = service.record_agent_gate_default_at_start() {
            tracing::error!(error = %e, "could not record the new-agent gate's default at start");
        }
        // Device signatures that name no gateway and approves that do not bind what the
        // approver was shown are refused by default. Each variable is an explicit opt-out for an
        // approver app that predates them, and says so on every boot it is set.
        let (accept_v1, require_display_bound) = legacy_signature_posture(
            std::env::var("PERMAURA_ACCEPT_V1_DEVICE_SIGNATURES").ok().as_deref(),
            std::env::var("PERMAURA_REQUIRE_DISPLAY_BOUND_APPROVALS").ok().as_deref(),
        );
        if accept_v1 {
            service.set_accept_v1_device_signatures(true);
            tracing::warn!(
                "PERMAURA_ACCEPT_V1_DEVICE_SIGNATURES is set: device signatures that name no gateway are accepted, so one collected by any gateway that trusts the same device key can be replayed here"
            );
        }
        if !require_display_bound {
            service.set_require_display_bound_approvals(false);
            tracing::warn!(
                "PERMAURA_REQUIRE_DISPLAY_BOUND_APPROVALS=0: device-signed approvals that do not bind the parameters the approver was shown are accepted"
            );
        }
        // Minted before the first request so every instance of a hosted worker serves the stored value
        // rather than racing to create it on a read.
        if let Err(e) = service.approval_audience() {
            tracing::error!(error = %e, "could not mint this gateway's approval audience at boot; it is retried on first use");
        }
        let state = AppState::new(service).with_posture(if mock { Posture::Mock } else { Posture::Real });
        if !reconciled {
            crate::reconcile::retry_in_background(state.service.clone());
        }
        state
    }
}

/// The deployment's agent pause, which the hosted control plane sets through a lapse's grace and a decommission. See [`crate::service::EnforcementService::agents_paused`].
pub const AGENTS_PAUSED_ENV: &str = "PERMAURA_AGENTS_PAUSED";

/// Any value but an explicit `0`/`false`/`off`/`no` (or empty) pauses, so a misspelt value fails closed.
fn agents_paused_from_env(value: Option<&str>) -> bool {
    value.map(str::trim).is_some_and(|v| {
        !v.is_empty() && !["0", "false", "off", "no"].iter().any(|off| v.eq_ignore_ascii_case(off))
    })
}

/// `(accept_v1, require_display_bound)` from the two opt-out variables. Refusing legacy signatures is
/// the default, so only an explicit value turns either back on: `1`/`true` for the first, `0`/`false`
/// for the second. Anything else, including a typo, leaves the default in place.
fn legacy_signature_posture(accept_v1: Option<&str>, require_display_bound: Option<&str>) -> (bool, bool) {
    let truthy = |v: &str| v == "1" || v.eq_ignore_ascii_case("true");
    let falsy = |v: &str| v == "0" || v.eq_ignore_ascii_case("false");
    (accept_v1.is_some_and(truthy), !require_display_bound.is_some_and(falsy))
}

/// Select the SSH transport for [`crate::connectors::CapabilityKind::Ssh`] capabilities. Real by
/// default (the shipped binary has the `ssh-transport` feature in `default`), so an end user's SSH
/// connections actually reach hosts with no flag to set. `mock=true` (tests / `--mock` / demo) uses
/// the deterministic [`MockSshRunner`]. The only way to get mock SSH otherwise is a deliberate
/// `--no-default-features` build with no real transport compiled, which warns loudly.
fn build_ssh_runner(mock: bool) -> Arc<dyn SshRunner> {
    if mock {
        return Arc::new(MockSshRunner::new());
    }
    #[cfg(feature = "ssh-transport")]
    {
        return Arc::new(crate::connectors::RealSshRunner::new());
    }
    #[cfg(not(feature = "ssh-transport"))]
    {
        tracing::warn!(
            "gateway built with --no-default-features (no `ssh-transport`): SSH capabilities use the mock transport (canned results). Build with default features for real SSH."
        );
        Arc::new(MockSshRunner::new())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum StorePosture {
    /// Readable and empty: a new install, so mint its identity.
    Bootstrap,
    /// Readable and populated: adopt it exactly as it is.
    Adopt,
    /// Unreadable, so its contents are unknown: refuse to start. [`build_store_from_env`] already
    /// takes this line when the store fails to OPEN, for the same stated reason: an infrastructure
    /// failure must not change who this gateway is. Exiting is also the recoverable choice: a
    /// supervisor respawns on a generic failure, and a lock that was busy for one boot usually is not
    /// for the next, whereas a wrong bootstrap is unrecoverable.
    Unreadable,
}

/// Read the posture off an agent listing. Generic over the element type and taking the listing by
/// reference so the caller keeps the error for its own message, and so a test can pin all three
/// outcomes without a store: boot itself cannot be tested, because it ends in `process::exit`.
fn store_posture<T>(listed: &Result<Vec<T>, crate::error::GatewayError>) -> StorePosture {
    match listed {
        Err(_) => StorePosture::Unreadable,
        Ok(agents) if agents.is_empty() => StorePosture::Bootstrap,
        Ok(_) => StorePosture::Adopt,
    }
}

/// Where a freshly minted operator bearer should be published, or `None` when it must not be written
/// at all. Split out from [`publish_operator_token`] so the placement rule is one named decision a
/// test can ask about without a filesystem.
pub fn operator_token_path() -> Option<std::path::PathBuf> {
    if hosted_from_env() {
        tracing::debug!("hosted worker: not publishing an operator token to disk (no local installer reads it)");
        return None;
    }
    if !store_owns_home_token(
        std::env::var("PERMAURA_STORE_PATH").ok().as_deref(),
        default_store_path().as_deref(),
    ) {
        tracing::debug!("PERMAURA_STORE_PATH selects a store outside PERMAURA_HOME: not publishing this gateway's operator token there; read it from the log instead");
        return None;
    }
    let path = permaura_core::permaura_path("operator.token");
    if path.is_none() {
        tracing::warn!("no PERMAURA_HOME or home directory: cannot publish the operator token for the installer; pair with the token from the log");
    }
    path
}

/// Whether the store this gateway is running is the one `$PERMAURA_HOME` owns, and so the one whose
/// bearer belongs in that home's `operator.token`.
///
/// The hosted skip above is the same rule for one specific case; this is the general one, and it was
/// missing. `operator.token` is addressed by *home*, the store by `PERMAURA_STORE_PATH`, and nothing
/// tied the two together: any gateway run against another store (an E2E suite's temp DB, a
/// throwaway `:memory:` run, a second install under test) clean-bootstrapped that store and then
/// published ITS brand-new token over the real one. The file ends up naming a session that exists,
/// but in a store the local gateway cannot see, so every CLI call 401s and the desktop Pair button
/// reports the token as unavailable while the gateway it is supervising is perfectly healthy.
///
/// Pure, so the rule is testable without an environment or a filesystem. Paths are compared after
/// canonicalisation where both sides resolve, so the home store reached through a symlink or a
/// relative path still counts as itself; `:memory:` canonicalises to nothing and is correctly never
/// the home store.
fn store_owns_home_token(configured: Option<&str>, home_default: Option<&str>) -> bool {
    let Some(configured) = configured.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    let Some(home_default) = home_default else {
        return false;
    };
    let resolve = |p: &str| {
        let p = std::path::Path::new(p);
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    };
    resolve(configured) == resolve(home_default)
}

/// Hand an operator bearer to the local installer through `$PERMAURA_HOME/operator.token`
/// (owner-read/write only). The npm launcher reads this instead of falling back to a shared constant,
/// so the token a real install enrols with was never predictable.
///
/// It used to hold only a token the CURRENT boot had minted, which sounded conservative and was in
/// fact the bug in [`ensure_published_operator_token`]: the two paths that mint one fire on a clean
/// bootstrap and on a demo-session rotation, neither of which an established gateway re-enters, so
/// from the second boot onwards nothing maintained the file at all.
///
/// **Skipped entirely on a hosted (Mode C) worker.** The file exists for a local installer to read,
/// and a Cloud Run container has none: its filesystem is ephemeral, nothing on it ever reads the
/// token, and the CLI reaches a hosted worker over its public URL rather than through `~/.permaura`.
/// Writing it there is at best pointless. Where it is not pointless is a developer's Mac, where
/// starting a hosted-mode gateway for testing silently overwrote the token belonging to their real
/// local gateway and broke its CLI pairing; a hosted worker has no business writing to the home
/// directory of a machine it is only pretending to run on.
///
/// **Called only from [`AppState::from_env`]**, which is the one context where this process really is
/// the gateway that `$PERMAURA_HOME` belongs to. The minting paths used to call it themselves, so any
/// caller that bootstrapped a store (every unit test that builds a [`MemoryStore`] included) wrote
/// its throwaway bearer over the developer's real `operator.token`. The session backing it died with
/// the test process, leaving a file that named no session in the real store, which is exactly the
/// state that makes the CLI 401 and the desktop Pair button report the token as missing. Minting
/// returns the token now and publishing is the caller's decision, so a test cannot reach the disk.
fn publish_operator_token(token: &str) -> bool {
    let Some(path) = operator_token_path() else {
        return false;
    };
    publish_operator_token_at(&path, token)
}

/// [`publish_operator_token`] to `path`.
fn publish_operator_token_at(path: &std::path::Path, token: &str) -> bool {
    // Replace rather than truncate. `OpenOptions::mode` applies only at CREATION, so an
    // `operator.token` that any earlier build left at `0644` kept that mode through every republish
    // since, and a truncating write that died mid-way left the install with no bearer at all.
    let write = || -> std::io::Result<()> {
        permaura_core::replace_secret_file(path, token.as_bytes())?;
        permaura_credential_store::restrict_to_owner(path)
    };
    match write() {
        Ok(()) => {
            tracing::info!(path = %path.display(), "operator token published for the installer");
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not publish the operator token");
            false
        }
    }
}

/// Everything a boot does to this store's operator credentials, between opening the store and
/// starting the listener.
///
/// One function rather than a limb of [`AppState::from_env`] so the ORDER is testable without an
/// assembled gateway: retirement happens before anything can be published or reused, so a store that
/// arrives holding an immortal bearer is never served from in that state, and the replacement is on
/// disk by the time the listener accepts its first call.
///
/// `fresh` is the caller's already-computed "this store has never held an agent", so the decision is
/// not made twice against a store the first branch has since written to.
///
/// Returns the operator token now published in `$PERMAURA_HOME/operator.token`, or `None` when none
/// is (a hosted worker, a store outside the home, or a write that failed).
///
/// A boot with a public URL reuses a live token here like any other, and replaces it only once it holds its address: see [`republish_operator_token_once_bound`].
fn prepare_operator_credentials(store: &dyn Store, fresh: bool) -> Option<String> {
    revoke_immortal_operator_sessions(store);
    if fresh {
        let token = bootstrap_store(store)?;
        return publish_operator_token(&token).then_some(token);
    }
    // A store that survived a restart may predate the launcher fix, so it can still carry the
    // public demo operator bearer alongside real credentials.
    if let Some(token) = revoke_demo_operator_session(store) {
        publish_operator_token(&token);
    }
    // Runs AFTER the rotation, so a token that rotation has just published and logged is
    // seen as live and reused rather than immediately replaced by a second one.
    ensure_published_operator_token(store)
}

/// A boot with a public URL, once this process holds its address: publish a fresh operator token, end every operator token published before it with no grace, and have `/health` prove the fresh one. Nothing on a hosted worker or a store outside the home, which publish no token.
///
/// After the bind, never while the state is built: a second `permaura start` on the same home that loses the bind must exit having changed nothing. Retiring first ended the running gateway's token and left its `/health` proof naming a dead one, so every CLI command refused that listener until the refresher's next tick. `permaura start` serves nothing until this returns.
pub fn republish_operator_token_once_bound(store: &dyn Store, published: &PublishedToken) {
    let Some(path) = operator_token_path() else { return };
    published.set(republish_operator_token_for_a_public_url(store, &path));
}

/// Publish a fresh operator token to `path` and end every operator token published before it, and every session one of them opened, at once: [`republish_operator_token_once_bound`]'s step.
///
/// A desktop pairing that puts the token `operator.token` names in the enrolment body hands it to permaura.com (this machine's `permaura pair` no longer does), and the re-seal task retires it on its own clock within a poll. That task can be outrun or kept from running: a permaura.com that answers an enrolment with no link never starts it, and a pairing followed by `permaura remote enable` and a restart inside one poll never reaches it. A gateway that comes up with a public URL is the one remote access is meant to reach, so this boot retires the token whatever the task did. It is not the only process a tunnel can reach: the desktop starts its connector before it relaunches the gateway with the public URL, and for those seconds the loopback-only process still serves a token handed over with no link. That window is the desktop's to close (see [`crate::reseal`]). No grace: nothing has read the new file yet, and every local reader reads it afresh per call.
///
/// When the fresh token cannot be written the old ones are ended anyway, and the error says so: a home that cannot take the file leaves the CLI locked out until it can, which is the lesser harm than leaving permaura.com a local operator token on a gateway the internet can reach.
pub(crate) fn republish_operator_token_for_a_public_url(store: &dyn Store, path: &std::path::Path) -> Option<String> {
    let previous = std::fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let fresh = match mint_operator_session(store) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(error = %e, "could not mint an operator token for this install");
            return None;
        }
    };
    let published = publish_operator_token_at(path, &fresh);
    let retired = retire_operator_tokens_except(store, &fresh, previous.as_deref(), crate::service::now_ms());
    if !published {
        tracing::error!(retired, path = %path.display(), "this gateway has a public URL, so every earlier operator token was ended, but its replacement could not be written; the CLI cannot reach this gateway until operator.token can be written and the gateway restarts");
        return None;
    }
    tracing::info!(
        retired,
        operator_token = %redact_token(&fresh),
        "this gateway has a public URL, so the operator token a pairing may have handed permaura.com was replaced at boot, and every one published before it ended"
    );
    Some(fresh)
}

/// Retire every operator session that was minted before operator bearers had an expiry.
///
/// **Why revoke rather than stamp an expiry on them.** Stamping would leave every copy already taken
/// (the ones in a 0644 log, in a support bundle, in a backup, and on hosted in Cloud Logging and in
/// the `sessions.token` column) valid for another TTL after the upgrade that was meant to end them.
/// Revoking costs nothing a user can feel: every client reads `operator.token` per call and handles a
/// 401 by re-reading it, and [`ensure_published_operator_token`] publishes the replacement in the same
/// boot, before the listener starts.
///
/// Agent sessions that carry `None` are [`sweep_idle_agent_sessions`]'s, not this one's. They get a
/// 30-day idle grace rather than being retired on sight, because retiring one logs an agent out and
/// it returns under a NEW id: the always-present Default grant reapplies once it is approved, but
/// membership of any enumerated grant does not.
///
/// Best-effort per session rather than fail-closed on the first error, so one unreadable row cannot
/// leave the rest of a store's immortal bearers live.
fn revoke_immortal_operator_sessions(store: &dyn Store) -> usize {
    let sessions = match store.list_sessions() {
        Ok(sessions) => sessions,
        Err(e) => {
            tracing::error!(error = %e, "could not read the sessions to retire pre-expiry operator bearers; any that exist stay live");
            return 0;
        }
    };
    let mut ended = Vec::new();
    for session in sessions {
        if session.revoked
            || session.expires_at.is_some()
            || session.role != crate::store::SessionRole::Operator
        {
            continue;
        }
        match store.revoke_session(&session.id) {
            Ok(_) => ended.push(session.id),
            Err(e) => {
                tracing::error!(error = %e, session = %session.id, "could not retire an operator bearer that has no expiry")
            }
        }
    }
    record_retired_bearers(store, &ended, "no_expiry", None);
    let retired = ended.len();
    if retired > 0 {
        tracing::warn!(
            retired,
            "retired operator bearers that were minted with no expiry; any copy of one has stopped working, and this boot publishes a replacement"
        );
    }
    retired
}

/// Guarantee that a local install has a usable operator bearer BOTH on disk and in this boot's log,
/// reusing the published one whenever it still works.
///
/// **The gap this closes.** An operator token was only ever minted on a clean bootstrap or a demo
/// rotation. Every later boot of an established gateway published nothing and logged nothing, so the
/// two consumers of that credential (the CLI, which reads the file, and the desktop supervisor,
/// which scrapes `operator_token=…` out of the log) were left with whatever the last such boot
/// happened to leave behind. When that value stopped authenticating there was no path back: the CLI
/// answered every command with `session has expired`, and the desktop app could not reach the
/// gateway it was itself supervising, so pairing a Mac was impossible on any real install. The
/// reachability of the credential, not the credential itself, was the defect.
///
/// **Reuse is the default and the file is the only thing consulted.** A published token that still
/// resolves to a live operator session is re-logged for this boot's scrape and otherwise left
/// completely alone, so a token someone noted down keeps working across restarts and the store does
/// not accumulate a session per boot. Only when the file is missing, unreadable, or names a session
/// that is revoked, expired or simply gone is a replacement minted. Nothing here ever copies an
/// existing bearer OUT of the store to repair the file; a token that is not already on disk stays
/// where it is, and the install gets a fresh one instead.
///
/// The replacement carries [`OPERATOR_TOKEN_TTL_MS`], matching [`seed::clean_bootstrap`]'s root
/// credential. A cap alone used to be an outage, because the published bearer would die mid-run on a
/// gateway that outlives it with no restart to notice. That is what [`spawn_operator_token_refresher`]
/// exists to prevent, and what made the TTL safe to have.
fn ensure_published_operator_token(store: &dyn Store) -> Option<String> {
    let path = operator_token_path()?;
    if let Some(token) = std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if operator_token_is_live(store, &token) && !operator_token_needs_refresh(store, &token) {
            // Re-logged rather than skipped: the desktop supervisor reads this boot's log, so a
            // valid-but-unlogged token is invisible to the app that needs it most.
            tracing::info!(
                operator_token = %redact_token(&token),
                "operator token still valid: reusing the one already published"
            );
            return Some(token);
        }
        tracing::warn!(
            path = %path.display(),
            "the published operator token no longer authenticates: minting a replacement"
        );
    }
    match mint_operator_session(store) {
        Ok(token) => {
            let published = publish_operator_token(&token);
            tracing::info!(
                operator_token = %redact_token(&token),
                "per-gateway operator token minted and published"
            );
            published.then_some(token)
        }
        Err(e) => {
            tracing::error!(error = %e, "could not mint an operator token for this install");
            None
        }
    }
}

/// Whether `token` still names a usable operator bearer: the same three conditions
/// [`crate::service::EnforcementService::authenticate`] applies, checked against the store directly
/// because boot has no service assembled yet.
///
/// The role check is not ceremony: `sessions` also holds agent bearers, and publishing one of those
/// to `operator.token` would hand the CLI a credential that authenticates and then fails every
/// control-plane call with a role refusal, far harder to read than a plain 401.
fn operator_token_is_live(store: &dyn Store, token: &str) -> bool {
    match store.session_by_token(token) {
        Ok(Some(s)) => {
            !s.revoked
                && !s.is_expired(crate::service::now_ms())
                && s.role == crate::store::SessionRole::Operator
        }
        Ok(None) => false,
        Err(e) => {
            // Fail CLOSED onto the mint path. Treating an unreadable store as "still valid" would
            // leave the install with a token nothing has verified.
            tracing::warn!(error = %e, "could not check the published operator token; minting a replacement");
            false
        }
    }
}

/// Keep the published operator token from expiring under a gateway that never restarts.
///
/// **This is the half that makes a TTL safe, and without it the TTL is an outage.**
/// [`ensure_published_operator_token`] runs at startup only, so a gateway left up for weeks would
/// reach its token's expiry with nothing to notice, and every client reading the file would start
/// getting 401s at once. That is why the token was immortal before, and a test said so.
///
/// The old session is left to expire on its own rather than revoked, so a client still holding the
/// previous value keeps working through the overlap instead of being cut off the instant a new one
/// lands.
///
/// `published` follows every replacement, so `/health` proves the token the file now names. It never
/// leaves this machine: permaura.com's sealed copy is a console session [`reseal`] keeps current.
pub fn spawn_operator_token_refresher(service: Arc<EnforcementService>, published: Arc<PublishedToken>) {
    let store = service.store().clone();
    tokio::spawn(async move {
        // Well inside the refresh window, so a missed tick or a suspended laptop cannot walk past it.
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30 * 60));
        tick.tick().await; // the first tick is immediate; startup already published one
        loop {
            tick.tick().await;
            let current = operator_token_path()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            // Above the freshness guard below, which skips the rest of the tick: this sweep has
            // nothing to do with whether the operator token needs replacing.
            maintain_agent_sessions(&service);
            let stale = match current {
                Some(ref t) => !operator_token_is_live(store.as_ref(), t)
                    || operator_token_needs_refresh(store.as_ref(), t),
                None => true,
            };
            if !stale {
                // Still this store's live token, so it is the one a client reading the file holds.
                published.set(current);
                continue;
            }
            if let Some(path) = operator_token_path() {
                if publish_fresh_operator_token(store.as_ref(), &path, &published).is_some() {
                    tracing::info!("operator token refreshed before expiry");
                }
            }
        }
    });
}

/// Mint an operator token, write it to `path` and record it as the one `/health` proves: the refresher's step, shared with [`OperatorTokenRotation`]. `None`, with the reason logged, when either the mint or the write failed.
fn publish_fresh_operator_token(store: &dyn Store, path: &std::path::Path, published: &PublishedToken) -> Option<String> {
    let token = match mint_operator_session(store) {
        Ok(token) => token,
        Err(e) => {
            tracing::warn!(error = %e, "could not mint a replacement operator token");
            return None;
        }
    };
    if !publish_operator_token_at(path, &token) {
        return None;
    }
    published.set(Some(token.clone()));
    Some(token)
}

/// How long the operator token permaura.com was handed keeps working after [`OperatorTokenRotation`] replaces it, for a local reader that read the file just before. The CLI and the desktop supervisor read `operator.token` afresh for every request, so this only has to cover one in flight.
pub(crate) const HANDED_OVER_TOKEN_GRACE: std::time::Duration = std::time::Duration::from_secs(2 * 60);

/// Retiring the operator token permaura.com may hold, once this gateway has a console session to offer it instead.
///
/// A desktop pairing that puts the token `operator.token` names in the enrolment body hands it to permaura.com (`permaura pair` and `start --pair` no longer do), and an earlier build kept re-sealing it there. That token is local wherever it arrives from, so the re-seal task replaces the file at its first poll with a link and within a poll of every pairing on this machine, before that poll's offers, and the old token, with every other token minted for the file before it, stops working at the end of [`HANDED_OVER_TOKEN_GRACE`]. The rotation runs on this gateway's clock and never waits for permaura.com's acknowledgement or its answer to an offer, which a permaura.com holding the token would be the one to withhold; a boot with a public URL ends them all at once whatever ran here ([`republish_operator_token_once_bound`]). The console session is minted on its own and never read from the file, so a rotation cannot cause another seal.
///
/// The end of the grace is written into each retired row's expiry when the rotation runs, rather than left to a timer that revokes by class later: a second rotation inside the grace would have had the first one's sweep revoke the token the file then named, and a restart inside it would have left the handed-over token live for its whole twelve hours. A stored expiry is honored by every later boot, whatever it starts as.
pub(crate) struct OperatorTokenRotation {
    pub(crate) store: Arc<dyn Store>,
    pub(crate) path: std::path::PathBuf,
    pub(crate) published: Arc<PublishedToken>,
    pub(crate) grace: std::time::Duration,
}

impl OperatorTokenRotation {
    /// The rotation for the gateway that published `$PERMAURA_HOME/operator.token`, or `None` when this one published none (a hosted worker, a store outside the home).
    pub(crate) fn for_this_install(store: Arc<dyn Store>, published: Arc<PublishedToken>) -> Option<Self> {
        published.get()?;
        Some(OperatorTokenRotation { store, path: operator_token_path()?, published, grace: HANDED_OVER_TOKEN_GRACE })
    }

    /// Publish a fresh operator token now, and end every one it replaces at the end of the grace. Nothing is touched when the file no longer names the token this gateway published: another process owns it then (a `--demo` gateway beside a real install, a second gateway on the same home). Returns the fresh token.
    pub(crate) fn rotate(&self) -> Option<String> {
        let handed_over = std::fs::read_to_string(&self.path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if handed_over.is_none() || handed_over != self.published.get() {
            tracing::warn!(path = %self.path.display(), "operator.token is not the token this gateway published, so it is not rotated");
            return None;
        }
        let fresh = publish_fresh_operator_token(self.store.as_ref(), &self.path, &self.published)?;
        let grace = i64::try_from(self.grace.as_millis()).unwrap_or(i64::MAX);
        let until = crate::service::now_ms().saturating_add(grace);
        let retired = retire_operator_tokens_except(self.store.as_ref(), &fresh, handed_over.as_deref(), until);
        tracing::info!(retired, grace_secs = self.grace.as_secs(), "this gateway was paired, so the operator token permaura.com may have been handed was replaced, and it and every operator token published before it stop working once the grace has passed");
        Some(fresh)
    }
}

/// Bring the expiry of `handed_over`, when it names an operator session other than a console session, of every live session minted for `operator.token` except `keep`, and of every session `POST /v1/sessions` opened from any of those (and from what they opened), forward to `until`: the ids are taken now, so a token published after this rotation is never among them. Returns how many it retired.
fn retire_operator_tokens_except(store: &dyn Store, keep: &str, handed_over: Option<&str>, until: i64) -> usize {
    use crate::store::{SessionClass, SessionRole};
    let keep = store.session_by_token(keep).ok().flatten().map(|s| s.id);
    let mut ids: Vec<String> = handed_over
        .and_then(|token| store.session_by_token(token).ok().flatten())
        .filter(|s| s.role == SessionRole::Operator && s.class != SessionClass::Console)
        .map(|s| s.id)
        .into_iter()
        .collect();
    let sessions = store.list_sessions().unwrap_or_default();
    ids.extend(sessions.iter().filter(|s| s.class == SessionClass::OperatorToken).map(|s| s.id.clone()));
    ids.retain(|id| Some(id) != keep.as_ref());
    // What a retired token opened would otherwise outlive it by its own twelve hours.
    let mut next = 0;
    while next < ids.len() {
        let parent = ids[next].clone();
        for child in sessions.iter().filter(|s| s.opened_by.as_deref() == Some(parent.as_str())) {
            if !ids.contains(&child.id) && Some(&child.id) != keep.as_ref() {
                ids.push(child.id.clone());
            }
        }
        next += 1;
    }
    ids.sort();
    ids.dedup();
    let mut retired = Vec::new();
    for id in ids.into_iter().filter(|id| Some(id) != keep.as_ref()) {
        match store.expire_session_by(&id, until) {
            Ok(true) => retired.push(id),
            Ok(false) => {}
            Err(e) => tracing::warn!(session = %id, error = %e, "could not retire an operator token published before the rotation"),
        }
    }
    record_retired_bearers(store, &retired, "rotation", Some(until));
    retired.len()
}

/// The refresher's session upkeep: settles the agent pause's session clock when this run and the stored record of the pause disagree (a boot whose own settle failed), then retires and deletes what has gone unused, never while agents are paused.
pub(crate) fn maintain_agent_sessions(service: &EnforcementService) {
    let store = service.store().as_ref();
    let paused = service.agents_paused();
    if !matches!(crate::store::agents_paused_since(store), Ok(since) if since.is_some() == paused) {
        match service.settle_agent_session_clock_at_start() {
            Ok(0) => {}
            Ok(moved) => tracing::info!(moved, "moved agent sessions' expiry forward by the time agents were paused"),
            Err(e) => tracing::warn!(error = %e, "could not settle agent sessions' expiry across the agent pause; retried on the next pass"),
        }
    }
    sweep_idle_agent_sessions(store, paused);
    prune_dead_sessions(store, paused);
}

/// Delete session rows that stopped being usable more than [`DEAD_SESSION_GRACE_MS`] ago.
///
/// Nothing removed a session row before this. Every pairing, every sign-in and every re-pair added
/// one and it stayed for ever: a laptop that had been paired since September held 41 rows, 38 of them
/// already expired. That is not an authority leak (an expired row authenticates nothing, and a revoked
/// one is refused by name) but it is weight, and on a hosted worker it is weight in a place that
/// matters: the whole SQLite file is uploaded on every state-changing request and read back on every
/// restore, so dead rows ride along for ever.
///
/// Only rows nothing can present are touched, and only after the grace period, so a token that
/// stopped working this week is still there to be looked at. A live session, or one whose expiry is
/// merely close to passing, is never deleted.
fn prune_dead_sessions(store: &dyn Store, agents_paused: bool) {
    let now = crate::service::now_ms();
    let Ok(paused_since) = crate::store::agents_paused_since(store) else { return };
    // The run's own pause holds every agent row, whatever the record of when it began says or fails to.
    let paused_since = if agents_paused { Some(i64::MIN) } else { paused_since };
    let Ok(sessions) = store.list_sessions() else { return };
    let mut pruned = 0u64;
    for session in sessions {
        if !dead_long_enough(&session, now) || paused_since.is_some_and(|since| held_by_the_agent_pause(&session, since)) {
            continue;
        }
        // Judged again on the row as it is when the delete lands: the owner can revoke a relayed or
        // OAuth row after the snapshot above was read, and that row is then a tombstone to keep.
        match store.delete_session_if(&session.id, &|row| dead_long_enough(row, now)) {
            Ok(true) => pruned += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(session = %session.id, error = %e, "could not delete a dead session row");
                return;
            }
        }
    }
    if pruned > 0 {
        tracing::info!(pruned, "deleted session rows that expired or were revoked over a week ago");
    }
}

/// Whether an agent session was live when the deployment paused agents, so its expiry is held still and the resume moves it forward.
fn held_by_the_agent_pause(session: &crate::store::Session, since: i64) -> bool {
    session.role == crate::store::SessionRole::Agent && !session.revoked && session.expires_at.is_some_and(|expiry| expiry > since)
}

/// Whether this row has been unusable for longer than the grace period.
///
/// A revoked row is dated by when it was last used, or failing that when it was created: revocation
/// itself is not timestamped, and treating an undated revocation as "just now" keeps it for one more
/// grace period rather than deleting something recent.
fn dead_long_enough(session: &crate::store::Session, now: i64) -> bool {
    if session.is_revocation_tombstone() {
        return false;
    }
    let dead_since = match (session.expires_at, session.revoked) {
        (Some(expiry), _) if expiry <= now => expiry,
        (_, true) => session.last_used_at.unwrap_or(session.created_at),
        // Live, or immortal and left to `sweep_idle_agent_sessions`.
        _ => return false,
    };
    now - dead_since > crate::store::DEAD_SESSION_GRACE_MS
}

/// Revoke agent sessions that have gone unused for [`AGENT_SESSION_TTL_MS`].
///
/// The sliding expiry in `touch_session` already stops an idle bearer authenticating; this closes the
/// rows behind it, so a store read shows what is actually live rather than a pile of lapsed sessions.
/// Never touches Operator sessions.
///
/// An OAuth agent's row is deleted instead. Its client authenticates with a JWT, never with the row,
/// and a revoked `sess_oauth:` row is how an owner's revocation is recorded, so retiring one here would
/// lock out a client nobody decided to stop; the next call re-creates the row with an expiry.
pub(crate) fn sweep_idle_agent_sessions(store: &dyn Store, agents_paused: bool) {
    // Nobody can use a session while agents are paused, and the resume gives these rows their expiry.
    if agents_paused || !matches!(crate::store::agents_paused_since(store), Ok(None)) {
        return;
    }
    let now = crate::service::now_ms();
    let Ok(sessions) = store.list_sessions() else { return };
    for session in sessions {
        if !idle_without_expiry(&session, now) {
            continue;
        }
        if session.id.starts_with("sess_oauth:") {
            // Judged again on the current row, because an owner's revocation after the snapshot makes
            // it a tombstone, and deleting that would let the client back in.
            if matches!(store.delete_session_if(&session.id, &|row| idle_without_expiry(row, now)), Ok(true)) {
                tracing::info!(session = %session.id, "deleted an OAuth agent's session row that had no expiry; its next call re-creates it");
            }
            continue;
        }
        // In place: writing back the row read above would put back whatever changed in it since.
        if matches!(store.revoke_session(&session.id), Ok(true)) {
            tracing::info!(session = %session.id, "retired an agent session that had no expiry and had gone unused for 30 days");
        }
    }
}

/// Whether `session` is an unrevoked Agent row with no expiry, unused for [`AGENT_SESSION_TTL_MS`].
fn idle_without_expiry(session: &crate::store::Session, now: i64) -> bool {
    // A session that carries an expiry is already denied at `authenticate` by `Session::is_expired`, and
    // retiring one here would replace an accurate "session has expired" 401 with "session has been
    // revoked", pointing whoever debugs it at a deliberate act that never happened. Only rows minted
    // before the cap existed carry no expiry, and those are otherwise immortal.
    if session.revoked || session.expires_at.is_some() || session.role != crate::store::SessionRole::Agent {
        return false;
    }
    // Never used means measure from enrolment, or a session nobody ever presented would live for ever.
    now - session.last_used_at.unwrap_or(session.created_at) > crate::store::AGENT_SESSION_TTL_MS
}

/// Mint a replacement operator bearer. Only a session: unlike [`seed::clean_bootstrap`] this does
/// not touch agents or the default grant, because the store it runs against is already established.
/// A token rendered for a log: enough to correlate two lines, useless to anyone who reads it.
///
/// **The value used to go into the log in full, and that undid the care taken everywhere else.**
/// `operator.token` is written mode 0600, owner only. The log beside it is 0644 on every install
/// path, so the same credential sat in a file readable by every account on the machine, not just an
/// agent running as the owner, which is the threat this was all about, but anybody with a login.
///
/// The desktop reads the token from the file and only falls back to the log, so nothing depends on
/// the value being there. It keeps that fallback for older gateways; against this one it will find
/// nothing, which is correct.
fn redact_token(token: &str) -> String {
    // The `pgt_` prefix and four characters: enough to tell "still the same token" from "a new one"
    // when reading a log, which is the entire reason these lines exist.
    let shown: String = token.chars().take(8).collect();
    format!("{shown}...redacted")
}

/// How long a published operator bearer stays valid.
///
/// It used to be forever. The token is written to `$PERMAURA_HOME/operator.token` at mode 0600, which
/// on a machine that runs agents means every agent the owner runs can read it, and a copy taken once
/// worked for the life of the install. Nothing here stops the read (on the same OS user nothing can,
/// which is what `--service-user` is for) but it does put a clock on the copy.
///
/// Twelve hours rather than something dramatic. The value of a shorter window falls away quickly (an
/// attacker who can read the file once can read it again), while the cost of an expiry that lands
/// mid-task is paid every time. What this really removes is the durable artefact: a token in an old
/// backup, a log, a screenshot or a support bundle is inert by the time anyone finds it.
pub(crate) const OPERATOR_TOKEN_TTL_MS: i64 = 12 * 60 * 60 * 1000;

/// Re-publish when less than this is left, so a client reading the file always gets one with usable
/// life in it rather than one about to expire under them.
const OPERATOR_TOKEN_REFRESH_AT_MS: i64 = 4 * 60 * 60 * 1000;

/// Mint a replacement operator bearer. Only a session: unlike [`seed::clean_bootstrap`] this does
/// not touch agents or the default grant, because the store it runs against is already established.
fn mint_operator_session(store: &dyn Store) -> Result<String, crate::error::GatewayError> {
    mint_operator_bearer(store, "pgt_", crate::store::SessionClass::OperatorToken)
}

/// The prefix of a console session: the operator bearer permaura.com's sealed copy holds for the console's browser-direct path to a loopback-only gateway.
///
/// The request path classes every bearer with this prefix remote whatever transport delivered it, as it does a permaura.com JWT: permaura.com's Cloudflare account can push the managed tunnel's connector a configuration, or route private-network traffic through it, that delivers requests from loopback with no forwarder header for the second or so before the gateway stops it, so a copy it holds could otherwise arrive that way and be the owner at the keyboard. The console's own use of it is a cross-origin fetch, already remote by its `Origin`, so it loses nothing. An enrolment code a remote request mints carries it too, so the agent bearer the code becomes is as remote as the request that minted it. `operator.token` (the CLI, the desktop supervisor, the installer) and the sessions `POST /v1/sessions` opens never carry it.
pub const CONSOLE_TOKEN_PREFIX: &str = "pgc_";

/// Mint a console session: an operator bearer that is remote wherever it is presented. It is the only bearer this gateway hands permaura.com; see [`CONSOLE_TOKEN_PREFIX`].
pub fn mint_console_session(store: &dyn Store) -> Result<String, crate::error::GatewayError> {
    mint_operator_bearer(store, CONSOLE_TOKEN_PREFIX, crate::store::SessionClass::Console)
}

/// Whether `token` is a console session's bearer.
pub fn is_console_token(token: &str) -> bool {
    token.starts_with(CONSOLE_TOKEN_PREFIX)
}

/// Whether a console session is live with life left in it to hand permaura.com: the test the published operator token passes.
pub(crate) fn console_token_is_fresh(store: &dyn Store, token: &str) -> bool {
    is_console_token(token) && operator_token_is_live(store, token) && !operator_token_needs_refresh(store, token)
}

/// Revoke every live console session, for a gateway whose console reaches it with the owner's own short-lived token and so has no use for one. Returns how many it revoked.
///
/// Found by the class recorded at minting: a persistent store keeps only the bearer's digest, so its `pgc_` prefix cannot be read back.
pub(crate) fn revoke_console_sessions(store: &dyn Store) -> usize {
    let Ok(sessions) = store.list_sessions() else { return 0 };
    let mut revoked = Vec::new();
    for session in sessions {
        if session.revoked || session.class != crate::store::SessionClass::Console {
            continue;
        }
        match store.revoke_session(&session.id) {
            Ok(true) => revoked.push(session.id),
            Ok(false) => {}
            Err(e) => tracing::warn!(session = %session.id, error = %e, "could not revoke a console session"),
        }
    }
    record_retired_bearers(store, &revoked, "console_not_needed", None);
    revoked.len()
}

/// The audit action recorded when this gateway mints an operator token for `operator.token`, the resource its session id.
pub const OPERATOR_TOKEN_MINT_ACTION: &str = "permaura.operator_token.mint";

/// The audit action recorded when this gateway mints the console session permaura.com holds, the resource its session id.
pub const CONSOLE_SESSION_MINT_ACTION: &str = "permaura.console_session.mint";

/// The audit action recorded when this gateway retires or revokes operator tokens or console sessions on its own: a rotation, the boot that ends bearers with no expiry or the public demo one, or a console session it has no use for.
pub const OPERATOR_BEARERS_RETIRE_ACTION: &str = "permaura.operator_token.retire";

/// Record a change this gateway made on its own to who holds operator authority, by session id and never by bearer.
///
/// The gateway acts here rather than a caller, so the event names the `operator` agent and no session of its own.
fn audit_operator_bearers(
    store: &dyn Store,
    action: &str,
    resource: &str,
    summary: serde_json::Value,
) -> Result<(), crate::error::GatewayError> {
    let mut payload = permaura_core::AuditPayload::new(action, resource, "allow");
    payload.agent_id = Some("operator".into());
    payload.summary = summary;
    store.append_audit(payload).map(|_| ())
}

/// [`audit_operator_bearers`] for sessions this gateway has just ended, best effort: the sessions stay ended whether or not the record lands.
fn record_retired_bearers(store: &dyn Store, ids: &[String], reason: &str, until: Option<i64>) {
    if ids.is_empty() {
        return;
    }
    let summary = serde_json::json!({ "sessions": ids, "reason": reason, "until": until });
    if let Err(e) = audit_operator_bearers(store, OPERATOR_BEARERS_RETIRE_ACTION, "operator-bearers", summary) {
        tracing::error!(error = %e, retired = ids.len(), reason, "operator bearers were ended, but the audit chain could not record it");
    }
}

/// Record the operator session `token` names, which [`seed::clean_bootstrap`] just minted. It stands only once recorded, as every mint's does.
fn record_bootstrap_mint(store: &dyn Store, token: &str, reason: &str) -> Result<(), crate::error::GatewayError> {
    let Some(session) = store.session_by_token(token)? else { return Ok(()) };
    let summary = serde_json::json!({ "class": "operator_token", "expires_at": session.expires_at, "reason": reason });
    if let Err(e) = audit_operator_bearers(store, OPERATOR_TOKEN_MINT_ACTION, &session.id, summary) {
        let _ = store.revoke_session(&session.id);
        return Err(e);
    }
    Ok(())
}

fn mint_operator_bearer(
    store: &dyn Store,
    prefix: &str,
    class: crate::store::SessionClass,
) -> Result<String, crate::error::GatewayError> {
    let now = crate::service::now_ms();
    let token = format!("{prefix}{}", crate::service::short_id());
    let id = format!("sess_{}", crate::service::short_id());
    let expires_at = now + OPERATOR_TOKEN_TTL_MS;
    store.put_session(crate::store::Session {
        class,
        opened_by: None,
        id: id.clone(),
        agent_id: "operator".into(),
        user_id: None,
        device_id: None,
        token: token.clone(),
        role: crate::store::SessionRole::Operator,
        created_at: now,
        revoked: false,
        expires_at: Some(expires_at),
        last_used_at: None,
        actor: None,
    })?;
    let (action, class_name) = match class {
        crate::store::SessionClass::Console => (CONSOLE_SESSION_MINT_ACTION, "console"),
        _ => (OPERATOR_TOKEN_MINT_ACTION, "operator_token"),
    };
    // Operator authority whose issue is not in the chain does not stand.
    if let Err(e) = audit_operator_bearers(store, action, &id, serde_json::json!({ "class": class_name, "expires_at": expires_at })) {
        let _ = store.revoke_session(&id);
        return Err(e);
    }
    Ok(token)
}

/// Whether the published token has enough life left to hand to a client.
///
/// Deliberately NOT the same question as "does it authenticate". A token with four minutes left
/// authenticates and then fails in the middle of whatever read it. The old one is left alone rather
/// than revoked, so a client still holding it keeps working until it expires on its own; two valid
/// operator sessions overlapping for a few hours is a far smaller problem than every client being
/// logged out the moment a new one is written.
fn operator_token_needs_refresh(store: &dyn Store, token: &str) -> bool {
    match store.session_by_token(token) {
        Ok(Some(session)) => {
            if session.revoked {
                return true;
            }
            match session.expires_at {
                // A bearer from before operator sessions had a TTL. Unreachable now that
                // `revoke_immortal_operator_sessions` retires those at boot, but it fails toward
                // minting rather than toward keeping an immortal token if it is ever reached again.
                None => true,
                Some(exp) => exp - crate::service::now_ms() < OPERATOR_TOKEN_REFRESH_AT_MS,
            }
        }
        Ok(None) => true,
        // Fail closed onto the mint path, same reasoning as `operator_token_is_live`.
        Err(_) => true,
    }
}

/// Bootstrap a fresh store: a CLEAN gateway, always. No demo connections, policies, grants or
/// agents, and a real per-gateway operator token rather than the shared [`seed::DEMO_TOKEN`] (the
/// paired-install path: "connected" means a true clean slate). Called only when the store is
/// empty, so it never clobbers persisted data.
///
/// **There is no environment variable that turns demo seeding back on here, and that is deliberate.**
/// The seed installs an *operator* session under a token constant published in the README, and
/// `operator_authed` is a plain token lookup with no remote check, so a seeded gateway reachable
/// from the network is a public operator bearer. Expressing "I want demo data" as the *absence* of
/// `PERMAURA_SEED=0` meant every install path had to remember to opt out, and the one that forgot
/// (the hosted provisioner) put that bearer on an `--allow-unauthenticated` URL. Demo data is now
/// something a caller asks for explicitly, via [`AppState::in_memory_seeded`], which is what the
/// `--demo` flag, the daemon and the test suite use. Customer-facing demo data lives in the console,
/// not in the gateway.
fn bootstrap_store(store: &dyn Store) -> Option<String> {
    match seed::clean_bootstrap(store).and_then(|token| record_bootstrap_mint(store, &token, "bootstrap").map(|()| token)) {
        Ok(token) => {
            // Where no `operator.token` is published (a hosted worker, or a store outside this home)
            // nothing on the machine reads a `pgt_` bearer, so a line naming one has no audience.
            if operator_token_path().is_some() {
                tracing::info!(
                    operator_token = %redact_token(&token),
                    "clean gateway: no demo data; per-gateway operator token minted"
                );
            } else {
                tracing::info!("clean gateway with no demo data");
            }
            Some(token)
        }
        Err(e) => {
            tracing::error!(error = %e, "clean bootstrap failed");
            None
        }
    }
}

/// Seed the reproducible demo estate into an empty store. Only ever called through
/// [`AppState::in_memory_seeded`], so demo data cannot reach a persistent store, and `--demo` refuses a non-loopback address, so
/// it is never served to a network. See [`bootstrap_store`] for why that separation is load-bearing rather than tidiness.
fn seed_demo_store(store: &dyn Store) {
    seed::seed(store).expect("seeding the store cannot fail");
    tracing::info!(
        token = seed::DEMO_TOKEN,
        "seeded IN-MEMORY demo gateway (agent: codex-cli; connections: braintree_production, github_acme, vercel_acme, fal): its operator bearer is public by design; never expose this to a network"
    );
}

/// Remediate an install created by the pre-fix npm launcher, which started a *seeded* gateway and so
/// left the globally-known [`seed::DEMO_TOKEN`] valid as an operator bearer on a store the user then
/// added real credentials to. A gateway running without the demo seed must never accept it, so the
/// session is revoked on sight and a fresh bearer is minted to re-pair with: the operator is rotated,
/// not locked out.
///
/// This runs unconditionally on the [`AppState::from_env`] path now. It used to return early whenever
/// the seed was on, which disabled the remediation in precisely the case that needed it: a gateway
/// that had been seeded and left the public bearer live.
fn revoke_demo_operator_session(store: &dyn Store) -> Option<String> {
    let token = rotate_demo_operator_session(store)?;
    tracing::warn!(
        operator_token = %redact_token(&token),
        "minted a replacement per-gateway operator token: re-pair this gateway with it"
    );
    Some(token)
}

/// The rotation itself: revoke a live demo session and mint a replacement operator bearer, returning
/// it. `None` when there was nothing to rotate. Split from [`revoke_demo_operator_session`] so the
/// behaviour is testable without touching the environment or the real `~/.permaura`.
fn rotate_demo_operator_session(store: &dyn Store) -> Option<String> {
    let existing = match store.session_by_token(seed::DEMO_TOKEN) {
        Ok(Some(s)) if !s.revoked => s,
        Ok(_) => return None,
        Err(e) => {
            tracing::error!(error = %e, "could not check for a public demo operator session");
            return None;
        }
    };
    if let Err(e) = store.revoke_session(&existing.id) {
        tracing::error!(error = %e, session = %existing.id, "could not revoke the public demo operator session");
        return None;
    }
    tracing::warn!(
        session = %existing.id,
        "revoked the public demo operator session this gateway was created with: the shared demo bearer no longer authenticates here"
    );
    record_retired_bearers(store, std::slice::from_ref(&existing.id), "public_demo_bearer", None);
    match seed::clean_bootstrap(store).and_then(|token| record_bootstrap_mint(store, &token, "replaces_demo_bearer").map(|()| token)) {
        Ok(token) => Some(token),
        Err(e) => {
            tracing::error!(error = %e, "could not mint a replacement operator token after revoking the demo session");
            None
        }
    }
}

/// Select the store from `PERMAURA_STORE_PATH`. Defaults to a persistent SQLite DB; `:memory:`
/// keeps the old ephemeral behaviour; if the gateway was built without the `sqlite` feature it
/// always uses the in-memory store.
///
/// A file-backed SQLite store that fails to open or migrate ABORTS boot instead of falling back
/// to in-memory: the caller re-seeds an empty store, so the fallback would look like a healthy
/// gateway whose grants/secrets/audit had silently vanished, the exact failure the schema-version
/// gate exists to prevent.
fn build_store_from_env() -> Arc<dyn Store> {
    /// The exit code a store failure aborts with. Selected from the error TYPE, never from its text:
    /// a supervisor watching this process can then stop respawning on a schema refusal (which no
    /// restart can fix) without either side parsing the other's prose.
    #[cfg(feature = "sqlite")]
    fn exit_code(e: &crate::error::GatewayError) -> i32 {
        match e {
            crate::error::GatewayError::SchemaTooNew(_) => crate::store::migrations::EXIT_STORE_SCHEMA_TOO_NEW,
            crate::error::GatewayError::StoreHeld(_) => crate::store::migrations::EXIT_STORE_HELD,
            crate::error::GatewayError::AuditKeyMissing(_) => crate::store::migrations::EXIT_AUDIT_KEY_MISSING,
            _ => 1,
        }
    }

    let configured = std::env::var("PERMAURA_STORE_PATH").ok();
    if configured.as_deref() == Some(":memory:") {
        return Arc::new(MemoryStore::new());
    }
    // A leftover database URL must not fall through to the file-path arm below, which would create
    // a store named after the URL and come up as a brand-new gateway.
    if configured.as_deref().is_some_and(|u| u.starts_with("postgres://") || u.starts_with("postgresql://")) {
        // Not the value: a database URL carries its password in the userinfo.
        tracing::error!("PERMAURA_STORE_PATH is a postgres:// URL: the Postgres store was removed, so this gateway has no way to open it. Set PERMAURA_STORE_PATH to a file path, and PERMAURA_STORE_BUCKET as well on a hosted worker.");
        std::process::exit(1);
    }
    #[cfg(feature = "sqlite")]
    {
        let path = match configured.or_else(default_store_path) {
            Some(p) => p,
            None => {
                tracing::error!("no PERMAURA_HOME or home directory to place the gateway store: refusing to start (the sealed-secret DB must not fall back to a relative path); set PERMAURA_HOME");
                std::process::exit(1);
            }
        };
        // A bucket makes the store durable for a worker whose filesystem is not: the SQLite file
        // lives in the instance's memory and is snapshotted to object storage before any mutation is
        // acknowledged. Selected by the bucket alone, so a mis-set path cannot quietly land on the
        // plain file store and lose everything at the next restart.
        if let Some(bucket) = store_bucket_from_env() {
            let object = std::env::var("PERMAURA_STORE_OBJECT")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| crate::store::persisted::DEFAULT_OBJECT.to_string());
            let opened = crate::backend::shared_gcp_token_source()
                .ok_or_else(|| {
                    crate::error::GatewayError::Internal(
                        "PERMAURA_STORE_BUCKET is set but the HTTP client for Google's endpoints could not \
                         be built, so the workload token cannot be minted: refusing to start"
                            .into(),
                    )
                })
                .and_then(|token| crate::objectstore::GcsObjectStore::new(&bucket, token))
                .and_then(|objects| {
                    crate::store::persisted::PersistedSqliteStore::open(
                        &path,
                        std::sync::Arc::new(objects),
                        &object,
                        crate::backend::audit_key_wrap_from_env(),
                    )
                })
                .map(|store| match store_warn_bytes_from_env() {
                    Some(bytes) => store.with_warn_bytes(bytes),
                    None => store,
                });
            match opened {
                Ok(s) => {
                    let generation = s.generation();
                    tracing::info!(
                        path = %path,
                        generation,
                        "persistent SQLite store, snapshotted to gs://{bucket}/{object} (restored generation {generation})"
                    );
                    return Arc::new(s);
                }
                Err(e) => {
                    tracing::error!(error = %e, path = %path, bucket = %bucket, object = %object, "failed to open the snapshotted SQLite store: refusing to start over an empty in-memory store (existing grants/secrets/audit would silently vanish)");
                    std::process::exit(exit_code(&e));
                }
            }
        }
        // Waits out a predecessor still draining against the same file, so the two never write it together.
        match crate::store::sqlite::SqliteStore::open_waiting(&path, crate::store::lock::STORE_LOCK_WAIT) {
            Ok(s) => {
                tracing::info!(path = %path, "persistent SQLite store");
                // A writer that took no lock (a gateway from before it) wrote a seq this one holds in memory: a restart reloads the chain from the table rather than serving a log it can no longer append to.
                let s = s.with_on_collision(Box::new(|message| {
                    tracing::error!("{message}");
                    std::process::exit(crate::store::migrations::EXIT_STORE_HELD);
                }));
                return Arc::new(s);
            }
            Err(e @ crate::error::GatewayError::StoreHeld(_)) => {
                tracing::error!("{e} Stop the other one first (`permaura stop`), or give this gateway its own PERMAURA_HOME.");
                std::process::exit(exit_code(&e));
            }
            Err(e @ crate::error::GatewayError::AuditKeyMissing(_)) => {
                tracing::error!("{e}");
                std::process::exit(exit_code(&e));
            }
            Err(e) => {
                // No backup hint here any more: a schema refusal now carries the exact filename in
                // its own message, and two different pieces of backup advice on one line is what
                // made the original diagnosis hard to act on.
                tracing::error!(error = %e, path = %path, "failed to open the persistent SQLite store: refusing to start over an empty in-memory store (existing grants/secrets/audit would silently vanish)");
                std::process::exit(exit_code(&e));
            }
        }
    }
    #[cfg(not(feature = "sqlite"))]
    {
        if let Some(p) = configured {
            tracing::warn!(path = %p, "PERMAURA_STORE_PATH set but the gateway was built without the `sqlite` feature: using in-memory");
        }
        Arc::new(MemoryStore::new())
    }
}

/// Build the audit archive writer, or `None` when it is switched off or unconfigured.
///
/// Without the flag, a gateway its owner runs gets [`crate::archive::local`] and a hosted worker gets
/// none. With it, three things must all be true: the flag, a bucket, and a tenant slug. The slug is
/// [`crate::restore::TENANT_ENV`] and never the control-plane row id, for the reason that constant
/// gives: every hosted object, IAM condition and path is keyed by the slug, which is the only key
/// still knowable after a worker is deleted.
fn build_audit_archive(store: &dyn Store) -> Option<Arc<crate::archive::AuditArchive>> {
    if !crate::archive::is_enabled() {
        return crate::archive::local(hosted_from_env(), permaura_core::paths::permaura_home(), store);
    }
    let bucket = std::env::var(crate::archive::BUCKET_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let tenant = std::env::var(crate::restore::TENANT_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let (Some(bucket), Some(tenant)) = (bucket, tenant) else {
        tracing::error!(
            "{} is set but {} or {} is not, so nothing can be published: the audit archive stays off and the hot store keeps everything",
            crate::archive::ENABLED_ENV,
            crate::archive::BUCKET_ENV,
            crate::restore::TENANT_ENV
        );
        return None;
    };
    let objects = crate::backend::shared_gcp_token_source()
        .ok_or_else(|| {
            crate::error::GatewayError::Internal(
                "the HTTP client for Google's endpoints could not be built, so no workload token can be minted".into(),
            )
        })
        .and_then(|token| crate::objectstore::GcsObjectStore::new(&bucket, token));
    match objects {
        Ok(objects) => {
            tracing::info!(bucket = %bucket, tenant = %tenant, "audit archive enabled: segments publish to gs://{bucket}/audit/{tenant}/");
            Some(Arc::new(crate::archive::AuditArchive::new(Arc::new(objects), tenant)))
        }
        Err(e) => {
            tracing::error!(error = %e, bucket = %bucket, "the audit archive bucket could not be opened: the archive stays off and the hot store keeps everything");
            None
        }
    }
}

/// The Cloud Storage bucket the store is snapshotted to, or `None` for an ordinary local store.
/// Empty is treated as unset so an unfilled provisioning template does not select the mode.
#[cfg(feature = "sqlite")]
fn store_bucket_from_env() -> Option<String> {
    std::env::var("PERMAURA_STORE_BUCKET").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The snapshot size above which every upload warns, from `PERMAURA_STORE_WARN_BYTES`. `None` keeps
/// the shipped default. An unreadable value is ignored rather than fatal: the guard is advice, and a
/// typo in it must not stop a worker that would otherwise run.
#[cfg(feature = "sqlite")]
fn store_warn_bytes_from_env() -> Option<u64> {
    let raw = std::env::var("PERMAURA_STORE_WARN_BYTES").ok()?;
    match raw.trim().parse::<u64>() {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::warn!(error = %e, value = %raw, "PERMAURA_STORE_WARN_BYTES is not a byte count; keeping the default");
            None
        }
    }
}

/// The default persistent DB path: `$PERMAURA_HOME/gateway.db`, else `~/.permaura/gateway.db`
/// (the same `~/.permaura` directory the relay keystore lives under). `None` when no home resolves;
/// the caller then refuses to start rather than write the sealed-secret DB to a relative path.
#[cfg(feature = "sqlite")]
fn default_store_path() -> Option<String> {
    permaura_core::permaura_path("gateway.db").map(|p| p.display().to_string())
}

/// The store this gateway would open on start: `PERMAURA_STORE_PATH` when set, else `gateway.db`
/// under the Permaura home. For host-side commands that must reach the store while the gateway is stopped.
pub fn store_path_from_env() -> Option<String> {
    std::env::var("PERMAURA_STORE_PATH")
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .or_else(default_store_path)
}

/// Without `sqlite` there is no persistent store, so no path in `$PERMAURA_HOME` is the one this
/// gateway owns. `operator_token_path` is not feature-gated and calls this on every build.
#[cfg(not(feature = "sqlite"))]
fn default_store_path() -> Option<String> {
    None
}

/// Build the full axum [`Router`] for the gateway over the given [`AppState`], bound at `bind_addr`.
///
/// This is the single source of truth for the route table; the binary and the daemon
/// both call it, and the tests `oneshot` it directly. `bind_addr` is the actual resolved
/// listen address (from `--addr` OR `PERMAURA_ADDR`, whichever the caller used); the Host
/// allowlist is derived from its port so a custom bind port never rejects its own traffic.
pub fn build_router(state: AppState, bind_addr: std::net::SocketAddr) -> Router {
    let allowed_hosts = Arc::new(allowed_hosts_list(bind_addr.port()));
    // A dedicated clone for the remote-tagging middleware (the router's own state is moved into
    // `.with_state` below).
    let remote_state = state.clone();
    let local_only = state.local_only;
    let admission_state = state.clone();
    let timeout_state = state.clone();
    let fair_use_state = state.clone();
    let carry_state = RequestCarry {
        store: state.service.store().clone(),
        running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let limits = state.limits.config().clone();

    // ── The execution group ──────────────────────────────────────────────────────
    // The two routes an agent can reach that cost an upstream call, and the only two that carry
    // admission control. Their body limit is set here rather than inherited from axum's 2 MiB
    // default so the number is a decision: agent params are small, but an SFTP put sends its payload
    // base64-encoded in this body and needs the headroom.
    let execution = Router::new()
        .route("/v1/invoke", post(rest::invoke))
        .route("/mcp", post(mcp::handle))
        .layer(axum::middleware::from_fn_with_state(
            admission_state,
            crate::limits::admit_execution,
        ))
        .layer(DefaultBodyLimit::max(limits.body_exec_bytes));

    // ── The bulk group ───────────────────────────────────────────────────────────
    // Routes whose payload is legitimately a document rather than a record: a vault bundle, an
    // OpenAPI specification, a connector manifest. Every one is operator-authenticated, so a larger
    // body here is not a larger surface for an agent.
    let bulk_auth_state = state.clone();
    let bulk = Router::new()
        // All three vault routes are POST, including export. The permaura.com proxy classifies every
        // GET as an open "read" available to any workspace member, so a GET export would hand the
        // entire vault to a read-only viewer.
        .route("/v1/vault/export", post(rest::export_vault))
        .route("/v1/vault/import/preview", post(rest::preview_vault_import))
        .route("/v1/vault/import", post(rest::import_vault))
        .route(
            "/v1/connections/import-openapi",
            post(rest::import_openapi_connection),
        )
        .route("/v1/connectors/install", post(rest::install_connector))
        .layer(axum::middleware::from_fn_with_state(
            bulk_auth_state,
            rest::operator_before_body,
        ))
        .layer(DefaultBodyLimit::max(limits.body_bulk_bytes));

    // ── Everything else ──────────────────────────────────────────────────────────
    // Management, revocation, approval resolution, recovery and health. Deliberately NOT behind
    // admission control: these are the routes an operator needs most at the moment execution is
    // saturated, so they draw on neither the execution semaphore nor any caller's bucket.
    Router::new()
        // A browser that lands on the gateway itself gets a page saying what this host is and a way
        // to the console. It used to get an empty 404, which reads as a broken box, including on the
        // tunnel URL an operator pastes precisely to check that it is not.
        .route("/", get(rest::landing))
        // `/health`, not `/healthz`: Google's frontend answers `/healthz` itself on Cloud Run and the
        // container never sees the request, so on a hosted worker the older path returned an edge 404
        // and every liveness probe read a healthy gateway as dead. Provable from the response rather
        // than inferred: a 404 the gateway wrote carries `x-cloud-trace-context` and
        // `server: Google Frontend`, and the intercepted one carries neither. Only `/healthz` is taken;
        // `/health`, `/livez` and `/status` all reach the container.
        .route(
            "/health",
            get(rest::health).layer(axum::Extension(rest::HealthPort(bind_addr.port()))),
        )
        // ── REST v1 ────────────────────────────────────────────────────────────
        .route(
            "/v1/sessions",
            post(rest::create_session).get(rest::list_sessions),
        )
        .route("/v1/sessions/:id/revoke", post(rest::revoke_session))
        .route("/v1/capabilities", get(rest::list_capabilities))
        .route("/v1/agents", get(rest::list_agents))
        .route(
            "/v1/agents/:id",
            delete(rest::delete_agent).put(rest::update_agent),
        )
        .route(
            "/v1/grants",
            post(rest::create_grant).get(rest::list_grants),
        )
        .route(
            "/v1/grants/:id",
            put(rest::update_grant)
                .patch(rest::patch_grant)
                .delete(rest::delete_grant),
        )
        .route("/v1/grants/:id/usage", get(rest::grant_usage))
        // Operator only, and never automatic: recounting a budget from the chain is the way
        // back when the counter and the chain can have drifted, not a routine maintenance tick.
        .route("/v1/grants/rebuild-usage", post(rest::rebuild_grant_usage))
        .route("/v1/secrets", post(rest::create_secret).get(rest::list_secrets))
        .route("/v1/secrets/:id", delete(rest::delete_secret))
        // ── connections (first-class) ────────────────────────────────────────────
        .route(
            "/v1/connections",
            get(rest::list_connections).post(rest::create_connection),
        )
        // ── marketplace presets (data-driven catalog) ────────────────────────────
        .route("/v1/presets", get(rest::list_presets))
        .route(
            "/v1/connections/from-preset",
            post(rest::create_from_preset),
        )
        // ── discovered connections (a WordPress site's REST index and Abilities) ──
        .route("/v1/connections/discover", post(rest::discover_connection))
        .route(
            "/v1/connections/import-wordpress",
            post(rest::import_wordpress_connection),
        )
        .route("/v1/connections/:id/resync", post(rest::resync_connection))
        // ── runtime-installed connector manifests (marketplace push) ─────────────
        // ── connector OAuth (bring-your-own app) ────────────────────────────────
        .route(
            "/v1/connections/:id/oauth/start",
            post(rest::start_connector_oauth),
        )
        // The provider redirects a browser here. Unauthenticated by necessity: the unguessable,
        // single-use, expiring `state` minted by an operator-authed `start` is what authenticates it.
        .route("/oauth/callback", get(rest::connector_oauth_callback))
        .route("/v1/connectors/installed", get(rest::list_installed_connectors))
        .route("/v1/connectors/:id", axum::routing::delete(rest::delete_connector))
        .route(
            "/v1/connections/:id",
            get(rest::get_connection)
                .patch(rest::patch_connection)
                .delete(rest::delete_connection),
        )
        .route(
            "/v1/connections/:id/credential",
            post(rest::set_connection_credential),
        )
        .route(
            "/v1/connections/:id/capabilities",
            post(rest::toggle_capability),
        )
        .route(
            "/v1/connections/:id/capability-posture",
            post(rest::set_capability_posture),
        )
        // ── policies (connection-scoped templates) ───────────────────────────────
        .route(
            "/v1/policies",
            get(rest::list_policies).post(rest::create_policy),
        )
        .route(
            "/v1/policies/:id",
            put(rest::update_policy).delete(rest::delete_policy),
        )
        // ── broker kill switch (global pause) ─────────────────────────────────────
        .route("/v1/broker", get(rest::broker_status))
        .route("/v1/broker/pause", post(rest::set_broker_pause))
        .route("/v1/broker/require-approval", post(rest::set_require_approval))
        // Graceful stop: authenticated + loopback-only. The portable stop path the desktop supervisor
        // and npm CLI call before any hard kill (see `rest::shutdown_gateway`).
        .route("/v1/shutdown", post(rest::shutdown_gateway))
        // Remote access off in the running process: authenticated + loopback-only, like the stop above.
        .route("/v1/remote/disable", post(rest::disable_remote_access))
        .route(
            "/v1/approvals",
            post(rest::resolve_approval).get(rest::list_approvals),
        )
        .route("/v1/approvals/:id", get(rest::approval_status))
        .route("/v1/audit-events", get(rest::audit_events))
        .route("/v1/audit/diagnostics", delete(rest::purge_call_diagnostics))
        // The two cross-boundary surfaces. Both are operator-only and both are allowed to be
        // slow: one hashes every published segment, the other streams the whole chain.
        .route("/v1/audit/verify-full", get(rest::verify_audit_full))
        .route("/v1/audit/export", get(rest::export_audit))
        .route("/v1/secrets/:id/rotate", post(rest::rotate_secret))
        .route("/v1/devices/enroll", post(rest::enroll_device))
        .route("/v1/devices", get(rest::list_devices))
        .route("/v1/devices/:id", delete(rest::revoke_device))
        .route("/v1/devices/push-token", post(rest::register_push_token))
        // Approver signing-key trust: pairing WRITES trust and is loopback/LAN-only (never the
        // broker); revocation is fail-safe and may run through the console. The listing is the
        // keyring's own census: `/v1/devices` is the push registry and misses every key paired
        // without a push registration, which is exactly the key that then cannot be revoked.
        .route("/v1/approver-keys", get(rest::list_approver_keys))
        .route("/v1/approver-keys/pair", post(rest::pair_approver_key))
        .route("/v1/approver-keys/:approver_id", delete(rest::revoke_approver_key))
        .route("/v1/approval-floor", put(rest::set_approval_floor))
        // Announce credentials: where this gateway tells the control plane what it is holding.
        .route(
            "/v1/announce",
            get(rest::announce_status).put(rest::set_announce).delete(rest::clear_announce),
        )
        // The recovery authority behind lowering the floor and revoking the last key: code status,
        // the pending delayed recovery, and code regeneration (which itself needs a code).
        .route("/v1/recovery", get(rest::recovery_status))
        // Restore reconciliation. Control-plane mutations, permitted while held, authenticated by
        // the OAuth operator subject rather than by any session or device in the restored database,
        // and deliberately outside the execution group so neither admission control nor the hot-audit
        // ceiling can refuse the one thing a restored tenant needs to be able to do.
        .route(
            "/v1/recovery/reconciliation",
            get(rest::list_reconciliation),
        )
        .route(
            "/v1/recovery/reconciliation/confirm",
            post(rest::confirm_reconciliation_item),
        )
        .route(
            "/v1/recovery/reconciliation/remove",
            post(rest::remove_reconciliation_item),
        )
        .route(
            "/v1/recovery/reconciliation/confirm-all",
            post(rest::confirm_all_reconciliation),
        )
        .route(
            "/v1/recovery/reconciliation/close",
            post(rest::close_reconciliation),
        )
        .route("/v1/recovery-codes", post(rest::regenerate_recovery_codes))
        .route("/v1/agents/register", post(rest::register_agent))
        // ── agent MCP self-enrolment (connect → approve) ─────────────────────────
        .route("/v1/agents/enroll", post(rest::enroll_agent))
        .route("/v1/agents/:id/approve", post(rest::approve_agent))
        // ── OAuth Resource Server discovery (active only when PERMAURA_PUBLIC_URL is set) ──
        .route(
            "/.well-known/oauth-protected-resource",
            get(rest::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(rest::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(rest::as_metadata_redirect),
        )
        .route(
            "/.well-known/openid-configuration",
            get(rest::as_metadata_redirect),
        )
        .layer(DefaultBodyLimit::max(limits.body_default_bytes))
        .merge(bulk)
        .merge(execution)
        // Mounted here, ahead of the layers: axum applies a `.layer` only to what is already on the
        // router, so a fallback added after them would answer outside the Host allowlist and CORS.
        .fallback(rest::not_found)
        // Every route, because the fair-use ceiling counts what callers make the worker write, and a
        // console edit uploads a snapshot exactly as an agent's call does. Inside the edge layers so a
        // refused Host or preflight never reaches it.
        .layer(axum::middleware::from_fn_with_state(
            fair_use_state,
            crate::fair_use::scope_request,
        ))
        // Every route, a read included: on request-based CPU the next request is the only time a hosted
        // worker can carry a commit its last upload left local.
        .layer(axum::middleware::from_fn_with_state(carry_state, carry_owed_commit))
        // Strict CORS: only the known console origins may script this gateway from a browser, so a
        // random page the operator visits cannot read an operator session token out of a cross-origin
        // response; the old permissive `*` made that a drive-by takeover. `allow_private_network`
        // still satisfies Chrome's Private Network Access preflight for the HTTPS console origins.
        .layer(console_cors())
        // Compute each request's remote-ness ONCE (hosted flag + Cloudflare headers + TCP peer
        // address) and stamp it as a `RemoteFlag` extension, so every operator-plane guard reads a
        // single, consistently-derived value, including the peer address, which is only reachable
        // here as a connection extension (populated by `into_make_service_with_connect_info`), not
        // in a handler's `HeaderMap`.
        .layer(axum::middleware::from_fn_with_state(remote_state, rest::tag_remote))
        // A demo's operator bearer is published, so it answers only this machine: nothing a tunnel or proxy forwarded, nothing from another address. A raw forwarder that adds no header and connects from loopback cannot be told apart, which is why a demo also takes a port of its own.
        .layer(axum::middleware::from_fn(move |req: Request, next: Next| async move {
            if local_only && rest::forwarded_or_off_host(&req) {
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({ "error": "a demo gateway answers only this machine: this request came through a tunnel, a proxy or another address" })),
                )
                    .into_response();
            }
            next.run(req).await
        }))
        // Outside the per-request work but inside the Host check, so a misdirected request is refused
        // without starting a clock. Nothing in the process bounded a request's lifetime before this:
        // the only ceiling was Cloud Run's 300 second edge default, which does not exist on a
        // self-hosted gateway at all.
        .layer(axum::middleware::from_fn_with_state(
            timeout_state,
            crate::limits::request_timeout,
        ))
        // Reject any request whose Host is not a known gateway host. This neutralises DNS rebinding,
        // which an Origin allowlist alone cannot stop (a rebound page keeps its own Origin but targets
        // our loopback by IP). Added last so it is the OUTERMOST layer and a rebinding probe is
        // refused before it reaches CORS or any handler.
        .layer(axum::middleware::from_fn(move |req: Request, next: Next| {
            let allowed = allowed_hosts.clone();
            async move {
                // Liveness is exempt, and has to be: a platform probe dials the container directly, so
                // it carries that instance's own address as Host, which is not knowable when the
                // allowlist is built. Refusing it cost nothing visible and everything operationally.
                // Cloud Run read the 421 as a container that never came up, so the probes could not be
                // added, the reconcile that adds them failed, and the worker was marked failed and
                // skipped by every fleet rollout while it was in fact serving normally. Safe because
                // the handler already answers an unauthenticated caller with a fixed two-field body:
                // a rebound page learns only that something is listening, which a closed port tells it
                // too.
                if req.uri().path() != "/health" {
                    if let Some(host) = req
                        .headers()
                        .get(axum::http::header::HOST)
                        .and_then(|h| h.to_str().ok())
                    {
                        if !allowed.iter().any(|a| a.eq_ignore_ascii_case(host)) {
                            return (StatusCode::MISDIRECTED_REQUEST, "host not allowed")
                                .into_response();
                        }
                    }
                }
                next.run(req).await
            }
        }))
        .with_state(state)
}

/// Hosts a request's `Host` header may legitimately carry: the loopback bind in every spelling and,
/// when configured, the public tunnel hostname. Anything else is a misdirected / DNS-rebinding request.
/// `port` is the actual bind port (from the resolved `--addr`/`PERMAURA_ADDR`), so a gateway started
/// with the `--addr` flag alone still accepts its own traffic. `PERMAURA_PUBLIC_URL_ALIASES` adds the
/// hostnames this gateway was moved from, and `PERMAURA_ALLOWED_HOSTS` (comma-separated) appends extras
/// for deployments whose edge rewrites Host; a hosted worker behind its branded name is exactly that.
fn allowed_hosts_list(port: u16) -> Vec<String> {
    allowed_hosts_from(
        port,
        std::env::var("PERMAURA_PUBLIC_URL").ok().as_deref(),
        std::env::var("PERMAURA_PUBLIC_URL_ALIASES").ok().as_deref(),
        std::env::var("PERMAURA_ALLOWED_HOSTS").ok().as_deref(),
    )
}

/// The list itself, with the environment read out of it so it can be tested without racing every other
/// test in the process over the same three variables.
fn allowed_hosts_from(
    port: u16,
    public_url: Option<&str>,
    aliases: Option<&str>,
    extra: Option<&str>,
) -> Vec<String> {
    let mut hosts = vec![
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    if let Some(host) = public_url.and_then(host_of) {
        hosts.push(host);
    }
    // The hostnames this gateway was MOVED from answer here too, for the same reason their audiences
    // still verify: an agent holding a token for the old name would otherwise clear the audience check
    // and be refused by the Host check instead, which is the same outage arriving one layer later.
    for alias in aliases.unwrap_or_default().split([',', ' ', '\t', '\n', '\r']) {
        if let Some(host) = host_of(alias) {
            hosts.push(host);
        }
    }
    // Bare hostnames, not URLs: this is the escape hatch for an edge that rewrites Host to an origin
    // that has no public URL of its own.
    for host in extra.unwrap_or_default().split(',') {
        let host = host.trim();
        if !host.is_empty() {
            hosts.push(host.to_string());
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The host[:port] a client sends as `Host` for a URL, or None when it names none: the host as the URL
/// parser clients use reads it, with the port only when it is not the scheme's default. Anything that is
/// not an absolute http(s) URL, or that carries userinfo or an authority two parsers could read apart,
/// has no host to contribute and is dropped rather than guessed at.
fn host_of(url: &str) -> Option<String> {
    let (parsed, parts) = crate::connectors::egress::parse_checked(url.trim()).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = parsed.host_str()?;
    Some(match parts.port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// Browser origins permitted to call the gateway cross-origin: the hosted console and the desktop
/// webview, plus the local console in a debug build ([`default_console_origins`]), overridable via `PERMAURA_CONSOLE_ORIGINS`. Never `*`: a wildcard let any page
/// the operator visited read an operator session token out of the response body.
fn console_cors() -> CorsLayer {
    let raw = console_origins(std::env::var("PERMAURA_CONSOLE_ORIGINS").ok().as_deref(), cfg!(debug_assertions));
    let origins: Vec<HeaderValue> = raw
        .split(',')
        .filter_map(|s| s.trim().parse::<HeaderValue>().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers([
            HeaderName::from_static(permaura_core::health_proof::PROOF_HEADER),
            HeaderName::from_static(permaura_core::health_proof::CONSOLE_PROOF_HEADER),
        ])
        .allow_private_network(true)
}

/// The origins [`console_cors`] allows when `PERMAURA_CONSOLE_ORIGINS` is unset, in a build that is (`debug_build`) or is not a debug build: the hosted console and the desktop webview (`tauri://localhost` on macOS, `http://tauri.localhost` on Windows), and in a debug build also the development hostname and the local console's and the desktop's dev-server ports. A release build used with a local console adds its origin with `PERMAURA_CONSOLE_ORIGINS=+<origin>`.
fn default_console_origins(debug_build: bool) -> String {
    const RELEASE: &str = "https://permaura.com,https://www.permaura.com,tauri://localhost,http://tauri.localhost";
    const DEVELOPMENT: &str = "https://permaura.lan,http://localhost:3102,http://localhost:1420";
    if debug_build { format!("{RELEASE},{DEVELOPMENT}") } else { RELEASE.to_string() }
}

/// The origin list [`console_cors`] allows for a `PERMAURA_CONSOLE_ORIGINS` value: the defaults when it is unset, the defaults and the rest when it starts with `+`, and otherwise the value as the whole list.
fn console_origins(value: Option<&str>, debug_build: bool) -> String {
    match value.map(str::trim) {
        None | Some("") => default_console_origins(debug_build),
        Some(more) if more.starts_with('+') => format!("{},{}", default_console_origins(debug_build), &more[1..]),
        Some(list) => list.to_string(),
    }
}

#[cfg(test)]
mod console_origin_tests {
    /// A release build trusts the hosted console and the desktop webview only: a development hostname or a local dev-server port in its defaults would let whatever answers there read the gateway's unauthenticated answers cross-origin. A debug build adds them for local development.
    #[test]
    fn a_release_build_allows_no_development_origin_by_default() {
        let release = super::default_console_origins(false);
        let release: Vec<&str> = release.split(',').collect();
        assert_eq!(release, ["https://permaura.com", "https://www.permaura.com", "tauri://localhost", "http://tauri.localhost"]);
        let debug = super::default_console_origins(true);
        for dev in ["https://permaura.lan", "http://localhost:3102", "http://localhost:1420"] {
            assert!(debug.split(',').any(|o| o == dev), "{dev} in {debug}");
        }
        assert!(release.iter().all(|o| debug.split(',').any(|d| d == *o)), "a debug build keeps every release origin");
    }

    /// A developer adding one origin (a local console's dev server) keeps the hosted console and the desktop webview by prefixing the value with `+`; a value without it is the whole list, as before.
    #[test]
    fn a_plus_prefixed_value_adds_to_the_defaults_and_a_plain_one_replaces_them() {
        let added = super::console_origins(Some("+http://localhost:3102"), false);
        for origin in ["https://permaura.com", "tauri://localhost", "http://tauri.localhost", "http://localhost:3102"] {
            assert!(added.split(',').any(|o| o == origin), "{origin} in {added}");
        }
        assert_eq!(super::console_origins(Some("http://localhost:3102"), false), "http://localhost:3102");
        assert_eq!(super::console_origins(None, false), super::default_console_origins(false));
    }
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    use crate::store::{Session, SessionRole};

    fn service_over(store: Arc<dyn Store>) -> EnforcementService {
        EnforcementService::new(store, Arc::new(MockHttpClient::new()))
    }

    /// The property the whole change exists to guarantee: the bootstrap a real gateway runs cannot
    /// produce demo data, so no environment, flag or forgotten install script can put the published
    /// `DEMO_TOKEN` operator bearer on a gateway that holds real credentials.
    ///
    /// This replaces a pair of tests that asserted *when* `PERMAURA_SEED` seeded. That variable is
    /// gone: seeding is now something a caller requests by constructing an in-memory demo gateway,
    /// not something the environment leaves switched on.
    #[test]
    fn the_real_bootstrap_can_never_seed_demo_data() {
        let store = MemoryStore::new();
        bootstrap_store(&store);

        assert!(
            store.session_by_token(seed::DEMO_TOKEN).unwrap().is_none(),
            "the published demo bearer must not authenticate against a bootstrapped gateway"
        );
        assert!(
            store.list_connections().unwrap().is_empty(),
            "a bootstrapped gateway holds none of the demo connections"
        );
        // A clean bootstrap does create one agent, the `operator` identity holding the per-gateway
        // root token. What it must never create is the demo estate's `codex-cli`.
        let agents = store.list_agents().unwrap();
        assert_eq!(agents.len(), 1, "only the operator identity, got {agents:?}");
        assert_eq!(agents[0].id, "operator");
    }

    /// Build a session with the shape a caller cares about, defaults otherwise.
    fn session(token: &str, role: SessionRole, revoked: bool, expires_at: Option<i64>) -> Session {
        Session {
            class: Default::default(),
            opened_by: None,
            id: format!("sess_{token}"),
            agent_id: "operator".into(),
            user_id: None,
            device_id: None,
            token: token.into(),
            role,
            created_at: crate::service::now_ms(),
            revoked,
            expires_at,
            last_used_at: None,
            actor: None,
        }
    }

    /// An unreadable store must never be mistaken for an empty one. Collapsing the two is what let a
    /// transient store error bootstrap a live install, resetting its `operator` agent and minting a
    /// second root token, so the three outcomes stay distinct and this pins them.
    #[test]
    fn an_unreadable_store_is_not_an_empty_one() {
        let unreadable: Result<Vec<()>, crate::error::GatewayError> =
            Err(crate::error::GatewayError::Internal("database is locked".into()));
        let empty: Result<Vec<()>, crate::error::GatewayError> = Ok(vec![]);
        let populated: Result<Vec<()>, crate::error::GatewayError> = Ok(vec![()]);

        assert_eq!(store_posture(&unreadable), StorePosture::Unreadable, "a failed read");
        assert_eq!(store_posture(&empty), StorePosture::Bootstrap, "a genuinely new install");
        assert_eq!(store_posture(&populated), StorePosture::Adopt, "an established install");
    }

    /// Only the gateway whose store lives in `$PERMAURA_HOME` may publish into it. Running any other
    /// store against the same home (an E2E temp DB, a `:memory:` throwaway) used to overwrite the
    /// real install's `operator.token` with a bearer valid only in that other store, which reads from
    /// the real gateway as a token matching no session at all.
    #[test]
    fn only_the_home_store_publishes_the_home_token() {
        let home = "/Users/x/.permaura/gateway.db";

        assert!(store_owns_home_token(None, Some(home)), "unset selects the home store itself");
        assert!(store_owns_home_token(Some(home), Some(home)), "the home store named explicitly");
        assert!(store_owns_home_token(Some("  "), Some(home)), "blank is not a store selection");

        assert!(!store_owns_home_token(Some("/tmp/e2e.db"), Some(home)), "a test suite's temp store");
        assert!(!store_owns_home_token(Some(":memory:"), Some(home)), "an ephemeral store");
        assert!(!store_owns_home_token(Some("/tmp/e2e.db"), None), "no home to own the file");
    }

    /// The reuse half of the contract: a published token that still works is left alone, so a
    /// restart does not invalidate a bearer someone has already noted down or handed to the CLI.
    #[test]
    fn a_live_operator_token_is_reused_rather_than_replaced() {
        let store = MemoryStore::new();
        store.put_session(session("pgt_live", SessionRole::Operator, false, None)).unwrap();
        assert!(operator_token_is_live(&store, "pgt_live"));
    }

    /// The three ways a published token stops counting. Each one has to reach the mint path: the
    /// bug being fixed is precisely an install left holding a token that no longer authenticates
    /// and no boot that would notice.
    #[test]
    fn a_dead_operator_token_is_not_reused() {
        let store = MemoryStore::new();
        let past = crate::service::now_ms() - 1;
        store.put_session(session("pgt_revoked", SessionRole::Operator, true, None)).unwrap();
        store
            .put_session(session("pgt_expired", SessionRole::Operator, false, Some(past)))
            .unwrap();
        store.put_session(session("tok_agent", SessionRole::Agent, false, None)).unwrap();

        assert!(!operator_token_is_live(&store, "pgt_revoked"), "revoked");
        assert!(!operator_token_is_live(&store, "pgt_expired"), "expired");
        assert!(!operator_token_is_live(&store, "pgt_missing"), "absent from the store");
        // An agent bearer authenticates but cannot drive the control plane, so publishing one would
        // trade a legible 401 for a confusing role refusal on every command.
        assert!(!operator_token_is_live(&store, "tok_agent"), "agent role");
    }

    /// The log must not carry a usable operator token.
    ///
    /// `operator.token` is mode 0600, owner only. The log beside it is 0644 on every install path, so
    /// logging the value in full handed the same credential to every account on the machine, a wider
    /// audience than the agents-running-as-you problem this was all about. Found by reading a real
    /// gateway log, which had 48 copies of it.
    #[test]
    fn a_token_in_a_log_line_is_not_a_usable_token() {
        let store = MemoryStore::new();
        let token = mint_operator_session(&store).expect("minting cannot fail on a healthy store");

        let logged = redact_token(&token);
        assert!(!logged.contains(&token), "the whole token must never reach a log line");
        assert!(
            operator_token_is_live(&store, &logged).eq(&false),
            "and what does reach it must not authenticate"
        );
        // Still enough to tell one token from another while reading a log, which is why these lines
        // exist at all.
        assert!(logged.starts_with("pgt_"), "got {logged}");
        assert_ne!(logged, redact_token(&mint_operator_session(&store).unwrap()));
    }

    /// Idle agents lapse; busy ones do not. The cap measures idleness rather than age, or an agent in
    /// daily use would stop working thirty days after enrolment for no reason its owner could see.
    #[test]
    fn only_the_idle_agent_session_is_swept() {
        use crate::store::{Session, SessionRole, AGENT_SESSION_TTL_MS};
        let store = MemoryStore::new();
        let now = crate::service::now_ms();
        let put = |id: &str, role: SessionRole, last_used: Option<i64>| {
            store
                .put_session(Session {
                    class: Default::default(),
                    opened_by: None,
                    id: id.into(),
                    agent_id: "a".into(),
                    user_id: None,
                    device_id: None,
                    token: format!("tok_{id}"),
                    role,
                    created_at: now - AGENT_SESSION_TTL_MS - 1,
                    revoked: false,
                    expires_at: None,
                    last_used_at: last_used,
                    actor: None,
                })
                .unwrap();
        };
        put("idle", SessionRole::Agent, Some(now - AGENT_SESSION_TTL_MS - 1));
        put("busy", SessionRole::Agent, Some(now - 1_000));
        put("never_used", SessionRole::Agent, None);
        put("operator", SessionRole::Operator, Some(now - AGENT_SESSION_TTL_MS - 1));
        // Idle for just as long, but it carries an expiry, so `authenticate` already denies it with
        // the accurate reason and this sweep must not overwrite that with "revoked".
        store
            .put_session(Session {
                class: Default::default(),
                opened_by: None,
                id: "idle_but_expiring".into(),
                agent_id: "a".into(),
                user_id: None,
                device_id: None,
                token: "tok_idle_but_expiring".into(),
                role: SessionRole::Agent,
                created_at: now - AGENT_SESSION_TTL_MS - 1,
                revoked: false,
                expires_at: Some(now - 1),
                last_used_at: Some(now - AGENT_SESSION_TTL_MS - 1),
                actor: None,
            })
            .unwrap();

        sweep_idle_agent_sessions(&store, false);

        let revoked = |id: &str| store.get_session(id).unwrap().unwrap().revoked;
        assert!(revoked("idle"), "an agent unused for the whole window must be revoked");
        assert!(!revoked("busy"), "an agent used a second ago must not be");
        assert!(revoked("never_used"), "never presented measures from enrolment, or it lives for ever");
        assert!(!revoked("operator"), "operator sessions have their own lifetime, not this sweep's");
        assert!(
            !revoked("idle_but_expiring"),
            "an expiring session is already denied as expired; relabelling it as revoked misdirects whoever debugs the 401"
        );
    }

    /// A minted replacement must be usable by the CLI immediately, and now carries a TTL.
    ///
    /// It used to be deliberately immortal, and the reason was sound: `ensure_published_operator_token`
    /// runs at startup only, so an expiry on a gateway that outlives it would leave every client
    /// reading a dead token with nothing to notice. That outage is what
    /// [`spawn_operator_token_refresher`] exists to prevent, and the TTL only became safe once it did.
    ///
    /// The reason for the TTL is that the file is mode 0600 in the owner's home, so on a machine that
    /// runs agents every agent the owner runs can read it, and a copy taken once used to work for the
    /// life of the install. Nothing here stops the read; it puts a clock on the copy, which is what
    /// makes a token in an old backup, a log or a support bundle inert.
    #[test]
    fn a_minted_operator_token_is_live_and_expires_before_it_can_be_reused_forever() {
        let store = MemoryStore::new();
        let token = mint_operator_session(&store).expect("minting cannot fail on a healthy store");

        assert!(token.starts_with("pgt_"), "shape the desktop log scrape matches, got {token}");
        assert!(operator_token_is_live(&store, &token));
        let s = store.session_by_token(&token).unwrap().expect("the session was stored");
        assert_eq!(s.role, SessionRole::Operator);
        let expires = s.expires_at.expect("the published bearer must not be immortal any more");
        let life = expires - crate::service::now_ms();
        assert!(
            life > OPERATOR_TOKEN_REFRESH_AT_MS,
            "a fresh token must start with more life than the refresh window, or it is born stale"
        );
        assert!(life <= OPERATOR_TOKEN_TTL_MS, "and no more than the TTL");

        // The pair that makes the TTL safe: fresh is not due for refresh, and a token close to expiry
        // is. Getting this backwards is the outage the immortal token was avoiding.
        assert!(!operator_token_needs_refresh(&store, &token), "a fresh token must not be refreshed");
        let mut aging = store.session_by_token(&token).unwrap().unwrap();
        aging.expires_at = Some(crate::service::now_ms() + 60_000);
        store.put_session(aging).unwrap();
        assert!(
            operator_token_needs_refresh(&store, &token),
            "a token about to expire must be replaced BEFORE a client reads it"
        );
    }

    /// Minting does not disturb an established store: it is a session and nothing else. The old
    /// path reached for `clean_bootstrap`, which also writes an agent and the default grant.
    #[test]
    fn minting_touches_nothing_but_the_session() {
        let store = MemoryStore::new();
        bootstrap_store(&store);
        let before = store.list_agents().unwrap().len();

        mint_operator_session(&store).unwrap();

        assert_eq!(store.list_agents().unwrap().len(), before, "no agent was added");
    }

    /// The other half of the contract: asking for a demo gateway explicitly still gets one, so the
    /// daemon, `permaura start`, `--demo` and the test suite keep their reproducible scenario.
    #[test]
    fn an_explicitly_seeded_store_still_gets_the_demo_estate() {
        let store = MemoryStore::new();
        seed_demo_store(&store);

        assert!(
            store.session_by_token(seed::DEMO_TOKEN).unwrap().is_some(),
            "an explicitly seeded store keeps the demo session: that is what it is for"
        );
        assert!(!store.list_connections().unwrap().is_empty());
    }

    /// The state every real installer must produce: nothing demo-shaped, and a bearer that could not
    /// have been known in advance.
    #[test]
    fn a_clean_gateway_has_no_demo_footprint_and_an_unguessable_operator_bearer() {
        let store = MemoryStore::new();
        let token = seed::clean_bootstrap(&store).expect("clean bootstrap");

        assert!(token.starts_with("pgt_"), "operator bearer should be per-install, got {token}");
        assert_ne!(token, seed::DEMO_TOKEN);
        assert!(store.list_connections().unwrap().is_empty(), "no demo connections");
        assert!(store.get_secret("sec_braintree_prod").unwrap().is_none(), "no demo secrets");
        assert!(
            store.session_by_token(seed::DEMO_TOKEN).unwrap().is_none(),
            "the published demo bearer must not exist on a clean gateway"
        );

        let session = store.session_by_token(&token).unwrap().expect("minted session");
        assert_eq!(session.role, SessionRole::Operator);
    }

    /// The demo bearer is a published constant, so it must not authenticate against a clean gateway;
    /// this is the assertion that would have failed for every `npx`-created install.
    #[test]
    fn the_published_demo_bearer_does_not_authenticate_against_a_clean_gateway() {
        let store = Arc::new(MemoryStore::new());
        let token = seed::clean_bootstrap(store.as_ref()).expect("clean bootstrap");
        let service = service_over(store);

        assert!(
            service.authenticate(seed::DEMO_TOKEN).is_err(),
            "the demo token must never authenticate against a real gateway"
        );
        assert!(service.authenticate(&token).is_ok(), "the minted token is the operator bearer");
    }

    /// The upgrade path for gateways the old launcher created seeded: the public bearer is revoked on
    /// sight and rotated, so an existing install stops accepting it without locking the operator out.
    #[test]
    fn upgrading_a_seeded_install_rotates_the_public_demo_bearer_away() {
        let store = Arc::new(MemoryStore::new());
        seed::seed(store.as_ref()).expect("seed");
        assert!(
            store.session_by_token(seed::DEMO_TOKEN).unwrap().is_some(),
            "precondition: the old npm path left this session behind"
        );

        let rotated = rotate_demo_operator_session(store.as_ref()).expect("a demo session to rotate");
        assert!(rotated.starts_with("pgt_"));

        let demo = store.session_by_token(seed::DEMO_TOKEN).unwrap().expect("row retained for audit");
        assert!(demo.revoked, "the demo session must be revoked, not merely shadowed");

        let service = service_over(store);
        assert!(service.authenticate(seed::DEMO_TOKEN).is_err(), "demo bearer is dead after upgrade");
        assert!(service.authenticate(&rotated).is_ok(), "the operator can re-pair with the new bearer");
    }

    /// Rotation is driven by boot and must be safe to run repeatedly.
    #[test]
    fn rotation_is_a_no_op_once_there_is_no_live_demo_session() {
        let store = MemoryStore::new();
        seed::clean_bootstrap(&store).expect("clean bootstrap");
        assert!(rotate_demo_operator_session(&store).is_none());
    }

    /// A scratch Permaura home nothing else on the machine shares.
    fn scratch_home() -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("permaura-boot-{}-{}", std::process::id(), crate::service::short_id()));
        std::fs::create_dir_all(&dir).expect("scratch home");
        dir
    }

    /// Run `f` with the boot environment pointed at a scratch home, restoring it afterwards.
    /// Serialised, because the environment is process-wide and these assertions are about what a
    /// boot resolves out of it.
    fn with_boot_env<T>(home: &std::path::Path, hosted: bool, f: impl FnOnce() -> T) -> T {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev_home = std::env::var_os("PERMAURA_HOME");
        let prev_hosted = std::env::var_os("PERMAURA_HOSTED");
        let prev_store = std::env::var_os("PERMAURA_STORE_PATH");
        let prev_bucket = std::env::var_os("PERMAURA_STORE_BUCKET");
        std::env::set_var("PERMAURA_HOME", home);
        std::env::remove_var("PERMAURA_STORE_PATH");
        std::env::remove_var("PERMAURA_STORE_BUCKET");
        match hosted {
            true => std::env::set_var("PERMAURA_HOSTED", "1"),
            false => std::env::remove_var("PERMAURA_HOSTED"),
        }
        let out = f();
        let restore = |k: &str, v: Option<std::ffi::OsString>| match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        };
        restore("PERMAURA_HOME", prev_home);
        restore("PERMAURA_HOSTED", prev_hosted);
        restore("PERMAURA_STORE_PATH", prev_store);
        restore("PERMAURA_STORE_BUCKET", prev_bucket);
        out
    }

    /// An established store holding one immortal operator bearer, the shape every install
    /// bootstrapped on 1.3.3 or earlier arrives in.
    fn store_with_an_immortal_operator_bearer(token: &str) -> Arc<MemoryStore> {
        let store = Arc::new(MemoryStore::new());
        store
            .put_agent(crate::store::Agent::approved(
                "operator",
                "Operator",
                crate::service::now_ms(),
            ))
            .unwrap();
        store.put_session(session(token, SessionRole::Operator, false, None)).unwrap();
        store
    }

    /// The whole point: a bearer minted before operator sessions had an expiry does not survive
    /// the boot that upgrades past it, and the install is not locked out: the same boot publishes a
    /// replacement that does have a clock on it.
    ///
    /// Stamping an expiry instead would have left every copy already taken (in a 0644 log, a support
    /// bundle, a backup, or on hosted in Cloud Logging) good for another twelve hours.
    #[test]
    fn a_boot_retires_an_immortal_operator_bearer_and_republishes() {
        let home = scratch_home();
        let store = store_with_an_immortal_operator_bearer("pgt_immortal");

        let proven = with_boot_env(&home, false, || prepare_operator_credentials(store.as_ref(), false));

        assert!(
            service_over(store.clone()).authenticate("pgt_immortal").is_err(),
            "the bearer that never expired must stop authenticating at the first boot after the fix"
        );
        let published = std::fs::read_to_string(home.join("operator.token"))
            .expect("the same boot must publish a replacement, or the install is locked out");
        assert_eq!(
            proven.as_deref(),
            Some(published.trim()),
            "/health proves the token this boot published, so it must be handed back"
        );
        let session = store
            .session_by_token(published.trim())
            .unwrap()
            .expect("operator.token must name a session in this store");
        assert_eq!(session.role, SessionRole::Operator);
        assert!(
            session.expires_at.is_some(),
            "the replacement must carry an expiry, or the boot has re-created what it just retired"
        );
        assert!(service_over(store).authenticate(published.trim()).is_ok());

        std::fs::remove_dir_all(&home).ok();
    }

    /// A boot with a public URL does not keep the published token however much life it has left: it may be the one a pairing handed permaura.com. Up to the bind it reuses the live token like any other boot, so one that never gets its address changes nothing; once it holds the address the token is ended, with no grace, and a replacement published and proved.
    #[test]
    fn a_public_url_boot_replaces_the_published_operator_token_once_bound_and_ends_it() {
        let home = scratch_home();
        let store = store_with_an_immortal_operator_bearer("pgt_immortal_handover");
        let handed_over = mint_operator_session(store.as_ref()).unwrap();
        std::fs::write(home.join("operator.token"), &handed_over).unwrap();

        let reused = with_boot_env(&home, false, || prepare_operator_credentials(store.as_ref(), false));
        assert_eq!(reused.as_deref(), Some(handed_over.as_str()), "the boot up to the bind reuses a live token");
        assert!(service_over(store.clone()).authenticate(&handed_over).is_ok(), "and ends nothing");

        let proven = PublishedToken::default();
        proven.set(reused);
        with_boot_env(&home, false, || republish_operator_token_once_bound(store.as_ref(), &proven));
        let published = std::fs::read_to_string(home.join("operator.token")).unwrap();
        assert_eq!(proven.get().as_deref(), Some(published.trim()), "/health proves the replacement");
        assert_ne!(published.trim(), handed_over);
        assert!(service_over(store.clone()).authenticate(&handed_over).is_err(), "ended at boot");
        assert!(service_over(store.clone()).authenticate(published.trim()).is_ok());
        let now = crate::service::now_ms();
        let live: Vec<_> = store
            .list_sessions()
            .unwrap()
            .into_iter()
            .filter(|s| s.role == SessionRole::Operator && !s.revoked && !s.is_expired(now))
            .collect();
        assert_eq!(live.len(), 1, "only the file's token is live: {live:?}");

        std::fs::remove_dir_all(&home).ok();
    }

    /// On a hosted worker the same retirement runs, but nothing is minted to replace it: the web
    /// tier mints short-lived operator JWTs and no `pgt_` bearer has a reader there.
    #[test]
    fn a_hosted_boot_retires_the_bearer_and_mints_nothing() {
        let home = scratch_home();
        let store = store_with_an_immortal_operator_bearer("pgt_hosted_immortal");

        let proven = with_boot_env(&home, true, || prepare_operator_credentials(store.as_ref(), false));
        assert_eq!(proven, None, "a hosted worker publishes nothing, so it has nothing to prove");
        let bound = PublishedToken::default();
        with_boot_env(&home, true, || republish_operator_token_once_bound(store.as_ref(), &bound));
        assert_eq!(bound.get(), None, "nor once it holds its address");

        assert!(
            service_over(store.clone()).authenticate("pgt_hosted_immortal").is_err(),
            "the leaked hosted bearer must be dead"
        );
        assert_eq!(
            store.list_sessions().unwrap().len(),
            1,
            "a hosted boot must not mint a replacement, because nothing on a worker reads one"
        );
        assert!(
            !home.join("operator.token").exists(),
            "and nothing may be published to a hosted container's filesystem"
        );

        std::fs::remove_dir_all(&home).ok();
    }

    /// The snapshotted store does not change where a hosted worker publishes its operator bearer,
    /// which is nowhere. Worth pinning: the bucket mode is the first store whose path really is a
    /// file on a hosted worker, and the placement rule reads a path.
    #[test]
    fn a_hosted_boot_with_a_store_bucket_still_publishes_nothing() {
        let home = scratch_home();
        let published = with_boot_env(&home, true, || {
            std::env::set_var("PERMAURA_STORE_BUCKET", "pw-store-test");
            std::env::set_var("PERMAURA_STORE_PATH", "/var/lib/permaura/gateway.db");
            operator_token_path()
        });
        assert!(published.is_none(), "a hosted worker publishes no operator token, bucket or not");
        std::fs::remove_dir_all(&home).ok();
    }

    /// Retirement is by role. Agent bearers carry `None` too and are a separate policy: expiring one
    /// logs an agent out, which needs the agent-side re-enrol path checked first.
    #[test]
    fn retirement_leaves_agent_sessions_and_already_capped_operators_alone() {
        let store = MemoryStore::new();
        let live = crate::service::now_ms() + OPERATOR_TOKEN_TTL_MS;
        store.put_session(session("pgt_immortal", SessionRole::Operator, false, None)).unwrap();
        store.put_session(session("pgt_capped", SessionRole::Operator, false, Some(live))).unwrap();
        store.put_session(session("tok_agent", SessionRole::Agent, false, None)).unwrap();

        assert_eq!(revoke_immortal_operator_sessions(&store), 1);

        let revoked = |t: &str| store.session_by_token(t).unwrap().unwrap().revoked;
        assert!(revoked("pgt_immortal"), "the immortal operator bearer");
        assert!(!revoked("pgt_capped"), "an operator bearer that already has a clock");
        assert!(!revoked("tok_agent"), "an agent bearer, which the idle-agent sweep decides and this does not");

        // Boot runs it on every start, so a second pass must find nothing left to do.
        assert_eq!(revoke_immortal_operator_sessions(&store), 0, "idempotent across restarts");
    }

    /// The belt to the boot revocation's braces: if a `None`-expiry operator bearer is ever reached
    /// again, the refresh question must fail toward minting rather than toward keeping it.
    #[test]
    fn a_bearer_with_no_expiry_always_needs_refreshing() {
        let store = MemoryStore::new();
        store.put_session(session("pgt_immortal", SessionRole::Operator, false, None)).unwrap();

        assert!(operator_token_needs_refresh(&store, "pgt_immortal"));
    }
}

/// Bearer sessions must not authenticate forever.
#[cfg(test)]
mod session_expiry_tests {
    use super::*;
    use crate::store::{
        Session, SessionRole, AGENT_SESSION_TTL_MS, OPERATOR_SESSION_TTL_MS,
    };

    fn service_over(store: Arc<dyn Store>) -> EnforcementService {
        EnforcementService::new(store, Arc::new(MockHttpClient::new()))
    }

    fn now() -> i64 {
        crate::service::now_ms()
    }

    /// No bearer works forever: an opened control-plane session is capped.
    #[test]
    fn an_opened_operator_session_carries_an_absolute_expiry() {
        let store = Arc::new(MemoryStore::new());
        let service = service_over(store.clone());
        store
            .put_session(Session {
                class: Default::default(),
                opened_by: None,
                id: "sess_x".into(),
                agent_id: "operator".into(),
                user_id: None,
                device_id: None,
                token: "tok_x".into(),
                role: SessionRole::Operator,
                created_at: now(),
                revoked: false,
                expires_at: Some(now() + OPERATOR_SESSION_TTL_MS),
                last_used_at: None,
                actor: None,
            })
            .unwrap();
        assert!(service.authenticate("tok_x").is_ok(), "a fresh session authenticates");
    }

    /// The whole point: past the cap, the token stops working.
    /// Rows nothing can present any more are eventually deleted, and everything else is left alone.
    /// Before this, a session row was immortal: 41 rows on a laptop paired for two weeks, 38 of them
    /// expired, all of them carried by every hosted snapshot for ever.
    #[test]
    fn dead_session_rows_are_pruned_once_the_grace_period_has_passed() {
        use crate::store::{Session, SessionRole, DEAD_SESSION_GRACE_MS};
        let now = crate::service::now_ms();
        let long_ago = now - DEAD_SESSION_GRACE_MS - 60_000;
        let session = |id: &str, expires_at: Option<i64>, revoked: bool, last_used: Option<i64>| Session {
            class: Default::default(),
            opened_by: None,
            id: id.into(),
            agent_id: "operator".into(),
            user_id: None,
            device_id: None,
            token: format!("tok_{id}"),
            role: SessionRole::Operator,
            created_at: long_ago,
            revoked,
            expires_at,
            last_used_at: last_used,
            actor: None,
        };
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        // Gone: expired long ago, and revoked long ago.
        store.put_session(session("expired-long-ago", Some(long_ago), false, None)).unwrap();
        store.put_session(session("revoked-long-ago", Some(now + 60_000), true, Some(long_ago))).unwrap();
        // Kept: live, expired only just now (still worth looking at), and revoked only just now.
        store.put_session(session("live", Some(now + 3_600_000), false, None)).unwrap();
        store.put_session(session("expired-today", Some(now - 60_000), false, None)).unwrap();
        store.put_session(session("revoked-today", Some(now + 60_000), true, Some(now - 60_000))).unwrap();

        prune_dead_sessions(store.as_ref(), false);

        let left: Vec<String> = store.list_sessions().unwrap().into_iter().map(|s| s.id).collect();
        assert!(!left.contains(&"expired-long-ago".to_string()), "{left:?}");
        assert!(!left.contains(&"revoked-long-ago".to_string()), "{left:?}");
        for kept in ["live", "expired-today", "revoked-today"] {
            assert!(left.contains(&kept.to_string()), "{kept} must survive: {left:?}");
        }
    }

    #[test]
    fn legacy_device_signatures_are_refused_unless_explicitly_opted_back_in() {
        assert_eq!(legacy_signature_posture(None, None), (false, true));
        assert_eq!(legacy_signature_posture(Some("1"), Some("0")), (true, false));
        assert_eq!(legacy_signature_posture(Some("TRUE"), Some("false")), (true, false));
        // The values that used to turn the protection ON now leave it on, and a typo opts out of nothing.
        assert_eq!(legacy_signature_posture(Some("0"), Some("1")), (false, true));
        assert_eq!(legacy_signature_posture(Some("yes"), Some("off")), (false, true));
    }

    #[test]
    fn the_agent_pause_engages_on_any_value_but_an_explicit_off() {
        for on in ["1", "true", "TRUE", "yes", "lapse", " 1 "] {
            assert!(agents_paused_from_env(Some(on)), "{on:?} pauses");
        }
        for off in [None, Some(""), Some("  "), Some("0"), Some("false"), Some("Off"), Some("no")] {
            assert!(!agents_paused_from_env(off), "{off:?} leaves agents running");
        }
    }

    /// A revoked OAuth agent row is what keeps its client out, so no amount of age makes it prunable.
    #[test]
    fn a_revoked_oauth_agent_row_is_never_pruned() {
        let now = crate::service::now_ms();
        let long_ago = now - crate::store::DEAD_SESSION_GRACE_MS - 60_000;
        let tombstone = crate::store::Session {
            created_at: long_ago,
            expires_at: Some(long_ago),
            last_used_at: Some(long_ago),
            ..crate::service::oauth_tombstone("oauth:client-gone")
        };
        assert!(!dead_long_enough(&tombstone, now));
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        store.put_session(tombstone).unwrap();
        prune_dead_sessions(store.as_ref(), false);
        assert!(store.get_session("sess_oauth:client-gone").unwrap().is_some());
        // An expired row that was never revoked is ordinary weight and still goes.
        let lapsed = crate::store::Session {
            id: "sess_oauth:client-lapsed".into(),
            revoked: false,
            ..store.get_session("sess_oauth:client-gone").unwrap().unwrap()
        };
        assert!(dead_long_enough(&lapsed, now));
    }

    /// A revoked relayed identity's row is the same kind of tombstone: the control plane can relay that
    /// session again, and with the row gone the next relayed invoke would recreate it unrevoked.
    #[test]
    fn a_revoked_relayed_identity_row_is_never_pruned() {
        let now = crate::service::now_ms();
        let long_ago = now - crate::store::DEAD_SESSION_GRACE_MS - 60_000;
        let tombstone = crate::store::Session {
            class: Default::default(),
            opened_by: None,
            id: crate::relay::relayed_session_id("cp_revoked"),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: "tok_never_presented".into(),
            role: crate::store::SessionRole::Agent,
            created_at: long_ago,
            revoked: true,
            expires_at: Some(long_ago),
            last_used_at: None,
            actor: None,
        };
        assert!(!dead_long_enough(&tombstone, now));
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        store.put_session(tombstone.clone()).unwrap();
        prune_dead_sessions(store.as_ref(), false);
        assert!(store.get_session(&tombstone.id).unwrap().is_some());
        let lapsed = crate::store::Session { revoked: false, ..tombstone };
        assert!(dead_long_enough(&lapsed, now), "an expired relayed row nobody revoked is still weight");
    }

    /// The prune must never reach a session somebody is still using, whatever else is in the row.
    #[test]
    fn a_live_session_is_never_pruned_however_old_it_is() {
        use crate::store::{Session, SessionRole};
        let now = crate::service::now_ms();
        let ancient = crate::store::Session {
            class: Default::default(),
            opened_by: None,
            id: "ancient-but-live".into(),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: "tok_live".into(),
            role: SessionRole::Agent,
            created_at: now - 400 * 24 * 60 * 60 * 1000,
            revoked: false,
            expires_at: Some(now + 60_000),
            last_used_at: Some(now - 400 * 24 * 60 * 60 * 1000),
            actor: None,
        };
        assert!(!dead_long_enough(&ancient, now), "a session that still authenticates is not dead");
        // And one with no expiry at all belongs to the other sweep, which revokes rather than deletes.
        let immortal = Session { expires_at: None, ..ancient };
        assert!(!dead_long_enough(&immortal, now));
        let _ = SessionRole::Operator;
    }

    #[test]
    fn an_expired_session_is_rejected() {
        let store = Arc::new(MemoryStore::new());
        let service = service_over(store.clone());
        store
            .put_session(Session {
                class: Default::default(),
                opened_by: None,
                id: "sess_old".into(),
                agent_id: "codex".into(),
                user_id: None,
                device_id: None,
                token: "tok_old".into(),
                role: SessionRole::Agent,
                created_at: now() - AGENT_SESSION_TTL_MS - 2,
                revoked: false,
                expires_at: Some(now() - 1),
                last_used_at: None,
                actor: None,
            })
            .unwrap();
        let err = service.authenticate("tok_old").expect_err("an expired bearer must not authenticate");
        assert!(format!("{err:?}").contains("expired"), "got {err:?}");
    }

    /// The install's ROOT credential carries a clock like every other bearer. It used to be
    /// deliberately immortal, on the reasoning that it is published to `operator.token` and had no
    /// rotation path, so capping it would strand the install; [`spawn_operator_token_refresher`] is
    /// the rotation path that reasoning was missing.
    #[test]
    fn the_root_operator_credential_carries_an_expiry() {
        let store = Arc::new(MemoryStore::new());
        let token = seed::clean_bootstrap(store.as_ref()).expect("clean bootstrap");
        let session = store.session_by_token(&token).unwrap().expect("minted session");

        let expires = session.expires_at.expect("the root bearer must not be immortal any more");
        assert!(
            expires - crate::service::now_ms() > OPERATOR_TOKEN_REFRESH_AT_MS,
            "it must be born with more life than the refresh window, or the first refresh is instant"
        );
        assert!(!session.is_expired(crate::service::now_ms()), "and it is usable right now");
        assert!(service_over(store).authenticate(&token).is_ok());
    }

    /// Upgrading an existing install must not log everyone out: rows written before the field existed
    /// have no `expires_at` and deserialize to "no expiry".
    #[test]
    fn a_session_stored_before_this_field_existed_still_authenticates() {
        let legacy = r#"{"id":"sess_legacy","agent_id":"codex-cli","user_id":null,"device_id":null,
            "token":"tok_legacy","role":"operator","created_at":1,"revoked":false}"#;
        let session: Session = serde_json::from_str(legacy).expect("legacy session deserializes");
        assert_eq!(session.expires_at, None);
        assert_eq!(session.last_used_at, None);
        assert!(!session.is_expired(now()));

        let store = Arc::new(MemoryStore::new());
        store.put_session(session).unwrap();
        assert!(service_over(store).authenticate("tok_legacy").is_ok());
    }

    /// `last_used_at` is what makes an idle session visible; it must actually be recorded.
    #[test]
    fn authenticating_records_last_use() {
        let store = Arc::new(MemoryStore::new());
        let service = service_over(store.clone());
        store
            .put_session(Session {
                class: Default::default(),
                opened_by: None,
                id: "sess_t".into(),
                agent_id: "codex".into(),
                user_id: None,
                device_id: None,
                token: "tok_t".into(),
                role: SessionRole::Agent,
                created_at: now(),
                revoked: false,
                expires_at: Some(now() + AGENT_SESSION_TTL_MS),
                last_used_at: None,
                actor: None,
            })
            .unwrap();

        service.authenticate("tok_t").unwrap();
        let touched = store.session_by_token("tok_t").unwrap().unwrap();
        assert!(touched.last_used_at.is_some(), "first authentication should stamp last_used_at");

        // Throttled: a second call inside the interval must not write again: authenticate() is on the
        // invoke hot path, and a store write per request is a cost this field does not justify.
        let stamp = touched.last_used_at;
        service.authenticate("tok_t").unwrap();
        assert_eq!(
            store.session_by_token("tok_t").unwrap().unwrap().last_used_at,
            stamp,
            "a repeat authentication inside the touch interval should not rewrite the session"
        );
    }

    /// An expiry must not resurrect a revoked session, nor vice versa; both gates stand alone.
    #[test]
    fn revocation_still_wins_for_an_unexpired_session() {
        let store = Arc::new(MemoryStore::new());
        let service = service_over(store.clone());
        store
            .put_session(Session {
                class: Default::default(),
                opened_by: None,
                id: "sess_r".into(),
                agent_id: "codex".into(),
                user_id: None,
                device_id: None,
                token: "tok_r".into(),
                role: SessionRole::Agent,
                created_at: now(),
                revoked: true,
                expires_at: Some(now() + AGENT_SESSION_TTL_MS),
                last_used_at: None,
                actor: None,
            })
            .unwrap();
        assert!(service.authenticate("tok_r").is_err(), "a revoked session must stay dead");
    }
}

#[cfg(test)]
mod allowed_hosts_tests {
    use super::allowed_hosts_from;

    fn hosts(public: Option<&str>, aliases: Option<&str>, extra: Option<&str>) -> Vec<String> {
        allowed_hosts_from(7376, public, aliases, extra)
    }

    #[test]
    fn loopback_is_always_accepted_in_every_spelling() {
        let h = hosts(None, None, None);
        for want in ["127.0.0.1:7376", "localhost:7376", "[::1]:7376"] {
            assert!(h.contains(&want.to_string()), "missing {want} in {h:?}");
        }
    }

    #[test]
    fn the_public_url_contributes_its_host_and_nothing_else() {
        let h = hosts(Some("https://acme.permaura.app/"), None, None);
        assert!(h.contains(&"acme.permaura.app".to_string()));
        // Not the scheme, not a path, and emphatically not the whole zone.
        assert!(!h.iter().any(|x| x.contains("://") || x.contains('/')));
        assert!(!h.contains(&"permaura.app".to_string()));
    }

    #[test]
    fn a_hostname_this_gateway_moved_from_still_answers() {
        // The alias exists so a moved gateway keeps working. Accepting its audience while refusing its
        // Host would just relocate the outage, so both layers read the same list.
        let h = hosts(
            Some("https://acme.permaura.app"),
            Some("https://pw-acme.a.run.app, https://old.example.com"),
            None,
        );
        assert!(h.contains(&"pw-acme.a.run.app".to_string()));
        assert!(h.contains(&"old.example.com".to_string()));
        assert!(h.contains(&"acme.permaura.app".to_string()));
    }

    #[test]
    fn the_escape_hatch_takes_bare_hosts_for_an_edge_that_rewrites_host() {
        // What a hosted worker behind its branded name needs: the origin has no public URL of its own.
        let h = hosts(
            Some("https://acme.permaura.app"),
            None,
            Some("pw-acme-hash-nw.a.run.app, pw-acme-1234.europe-west2.run.app"),
        );
        assert!(h.contains(&"pw-acme-hash-nw.a.run.app".to_string()));
        assert!(h.contains(&"pw-acme-1234.europe-west2.run.app".to_string()));
    }

    /// The public URL contributes the `Host` a client sends for it, as the URL parser reads it: a default port is dropped, another kept, and no hand split can hand the list a different host.
    #[test]
    fn the_public_url_contributes_the_host_a_client_sends() {
        assert!(hosts(Some("https://acme.permaura.app:443/"), None, None).contains(&"acme.permaura.app".to_string()));
        assert!(hosts(Some("https://acme.permaura.app:8443/"), None, None).contains(&"acme.permaura.app:8443".to_string()));
        for odd in ["https://acme.permaura.app\\@evil.example/", "https://user@acme.permaura.app/", "https://acme.permaura.app@evil.example/"] {
            let h = hosts(Some(odd), None, None);
            assert_eq!(h.len(), 3, "{odd} contributes nothing: {h:?}");
        }
    }

    #[test]
    fn nothing_unparseable_or_empty_ever_lands_in_the_list() {
        // A blank or malformed entry must contribute NOTHING. An empty string in the list would match
        // a request that sent no Host at all, which is the rebinding case this check exists to refuse.
        let h = hosts(Some("not-a-url"), Some(",, ,"), Some(", ,"));
        assert!(!h.iter().any(|x| x.is_empty()));
        assert_eq!(h.len(), 3, "only the three loopback spellings should remain: {h:?}");
    }

    #[test]
    fn the_same_host_named_twice_appears_once() {
        let h = hosts(
            Some("https://acme.permaura.app"),
            Some("https://acme.permaura.app"),
            Some("acme.permaura.app"),
        );
        assert_eq!(h.iter().filter(|x| *x == "acme.permaura.app").count(), 1);
    }
}

#[cfg(all(test, feature = "sqlite"))]
#[path = "session_cleanup_race_tests.rs"]
mod session_cleanup_race_tests;

#[cfg(all(test, feature = "sqlite"))]
mod long_hold_tests;

#[cfg(test)]
mod operator_bearer_audit_tests;
