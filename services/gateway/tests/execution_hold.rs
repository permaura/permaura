//! The execution hold, driven through the real router with `tower`'s `oneshot`.
//!
//! Through `build_router` rather than against `ExecutionHold` directly, because what is worth
//! proving is where the hold sits in the stack: which routes it refuses, which keep answering, and
//! what has and has not happened to the store by the time a refusal is returned. The hold's own
//! parsing rules are unit-tested beside it in `src/restore.rs`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::restore::{hold_document, hold_metadata, hold_object, ExecutionHold};
use permaura_gateway::store::PendingApproval;
use common::build_router;
use permaura_gateway::{seed, AppState};
use tower::ServiceExt; // for `oneshot`

mod common;

/// The tenant every hold object in this file names.
const TENANT: &str = "acme";

/// Short enough that a test can cross an interval without sleeping for a minute, and above the
/// clamp's floor so it is the interval that is actually configured.
const INTERVAL: Duration = Duration::from_secs(1);

fn app(state: AppState) -> axum::Router {
    build_router(state, "127.0.0.1:7376".parse().unwrap())
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn request(method: &str, uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn invoke_body() -> serde_json::Value {
    serde_json::json!({
        "capability": "braintree.transactions.search",
        "params": { "status": "failed" },
        "reason": "a held tenant must not reach an upstream"
    })
}

/// A bucket holding one hold object for [`TENANT`].
fn bucket(state: &str, hold_id: &str) -> Arc<CountingHeads> {
    let objects = Arc::new(CountingHeads::new());
    objects.write(hold_document(TENANT, state, hold_id, "a synthetic restore"));
    objects
}

/// A bucket with no hold object in it at all.
fn empty_bucket() -> Arc<CountingHeads> {
    Arc::new(CountingHeads::new())
}

fn hold_over(objects: Arc<CountingHeads>, env: Option<&str>) -> Arc<ExecutionHold> {
    Arc::new(
        ExecutionHold::open(env.map(String::from), objects, TENANT, INTERVAL)
            .expect("the hold object reads"),
    )
}

/// A [`MemoryObjectStore`] that counts `head` calls, so a test can assert the recheck interval the
/// way `fresh_reads_confirm_the_generation_once_an_interval_and_only_inside_the_window` asserts the
/// fresh-read one: by how many metadata requests a run of traffic produced.
struct CountingHeads {
    inner: MemoryObjectStore,
    heads: AtomicU64,
}

impl CountingHeads {
    fn new() -> Self {
        CountingHeads { inner: MemoryObjectStore::new(), heads: AtomicU64::new(0) }
    }

    fn heads(&self) -> u64 {
        self.heads.load(Ordering::SeqCst)
    }

    /// Replace the hold object, the way the restoration authority does.
    fn write(&self, body: Vec<u8>) {
        let current = self.inner.head(&hold_object(TENANT)).unwrap().unwrap_or(0);
        self.inner
            .put_if_generation(&hold_object(TENANT), &body, current, &hold_metadata())
            .unwrap();
    }
}

impl ObjectStore for CountingHeads {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        self.heads.fetch_add(1, Ordering::SeqCst);
        self.inner.head(name)
    }
    fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        self.inner.head_full(name)
    }
    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        self.inner.has_history(name)
    }
    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        self.inner.get(name, generation)
    }
    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        self.inner.put_if_generation(name, bytes, expected, metadata)
    }
    fn describe(&self) -> String {
        "synthetic-hold-bucket".into()
    }
}

/// An object store whose every call fails from the moment it is armed, for the recheck-failure rule.
struct FailsOnDemand {
    inner: MemoryObjectStore,
    failing: std::sync::atomic::AtomicBool,
}

impl FailsOnDemand {
    fn new(body: Vec<u8>) -> Self {
        let inner = MemoryObjectStore::new();
        inner.put_if_generation(&hold_object(TENANT), &body, 0, &hold_metadata()).unwrap();
        FailsOnDemand { inner, failing: std::sync::atomic::AtomicBool::new(false) }
    }

    fn start_failing(&self) {
        self.failing.store(true, Ordering::SeqCst);
    }

    fn stop_failing(&self) {
        self.failing.store(false, Ordering::SeqCst);
    }

    fn refuse<T>(&self) -> Result<T, GatewayError> {
        Err(GatewayError::Internal("synthetic: the hold bucket is unreachable".into()))
    }
}

impl ObjectStore for FailsOnDemand {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        if self.failing.load(Ordering::SeqCst) {
            return self.refuse();
        }
        self.inner.head(name)
    }
    fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        if self.failing.load(Ordering::SeqCst) {
            return self.refuse();
        }
        self.inner.head_full(name)
    }
    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        self.inner.has_history(name)
    }
    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        if self.failing.load(Ordering::SeqCst) {
            return self.refuse();
        }
        self.inner.get(name, generation)
    }
    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        self.inner.put_if_generation(name, bytes, expected, metadata)
    }
    fn describe(&self) -> String {
        "synthetic-failing-hold-bucket".into()
    }
}

/// Park a pending approval in the store directly, the way `operator_token` parks a session: an
/// approval normally arrives through `invoke`, and on a held tenant `invoke` is the thing being
/// refused.
fn park_approval(state: &AppState, id: &str) {
    state
        .service
        .store()
        .put_approval(PendingApproval {
            id: id.into(),
            session_id: "sess_demo".into(),
            capability: "braintree.transactions.refund".into(),
            resource: "braintree_production".into(),
            message: "a synthetic held call".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({ "transaction_id": "tx_synthetic" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: 0,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        })
        .expect("the seeded store accepts an approval");
}

// ── What the hold refuses ───────────────────────────────────────────────────────

/// The three execution paths a hold stops, refused with 423, while the routes an owner needs
/// in order to reconcile keep answering.
#[tokio::test]
async fn a_held_tenant_refuses_invoke_resolve_approval_and_a_vault_export_with_423() {
    let state = common::seeded_with_hold(hold_over(bucket("held", "hold_1"), None));
    let token = common::operator_token(state.clone()).await;
    park_approval(&state, "appr_held");
    let app = app(state);

    let resp = app.clone().oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED, "invoke");
    let body = body_json(resp).await;
    assert_eq!(body["hold_id"], "hold_1", "the 423 names the hold");
    assert_eq!(body["state"], "held");
    assert!(body["reason"].as_str().is_some_and(|r| !r.is_empty()), "and says why");

    let resolve = serde_json::json!({ "approval_id": "appr_held", "approve": true });
    let resp = app.clone().oneshot(request("POST", "/v1/approvals", &token, resolve)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED, "resolve_approval");

    let export = serde_json::json!({ "passphrase": "a-synthetic-passphrase" });
    let resp = app.oneshot(request("POST", "/v1/vault/export", &token, export)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED, "vault export");
}

/// The same refusal reaches an MCP caller, because both transports enter the one service method.
/// That is the whole reason the check is at the service layer: a direct OAuth agent on `/mcp` and
/// the console on `/v1/invoke` are refused by the same line, and a route added later cannot miss it.
#[tokio::test]
async fn every_transport_into_invoke_is_refused_with_the_same_facts() {
    let state = common::seeded_with_hold(hold_over(bucket("reconciling", "hold_2"), None));
    let app = app(state);

    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "permaura_invoke", "arguments": invoke_body() }
    });
    let resp = app
        .oneshot(request("POST", "/mcp", seed::DEMO_TOKEN, call))
        .await
        .unwrap();
    // JSON-RPC carries its failures in a 200 body; the code and the data are its 423.
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["error"]["code"], -32005, "a held tenant is not an ordinary tool failure");
    assert_eq!(body["error"]["data"]["hold_id"], "hold_2");
    assert_eq!(body["error"]["data"]["state"], "reconciling");
    assert!(body["error"]["data"]["reason"].as_str().is_some_and(|r| !r.is_empty()));
}

/// Reads, control-plane mutations and health keep working, because reconciliation is a sequence of
/// control-plane mutations and an owner has to be able to inspect the restored state to do it.
#[tokio::test]
async fn a_held_tenant_still_serves_reads_control_plane_mutations_and_health() {
    let state = common::seeded_with_hold(hold_over(bucket("held", "hold_3"), None));
    let token = common::operator_token(state.clone()).await;
    let app = app(state);

    for (method, uri) in [("GET", "/v1/grants"), ("GET", "/v1/approvals"), ("GET", "/v1/agents")] {
        let resp = app
            .clone()
            .oneshot(request(method, uri, &token, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{method} {uri} is a read and must answer");
    }

    let resp = app
        .clone()
        .oneshot(request("POST", "/v1/sessions/sess_demo/revoke", &token, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "a revoke is a control-plane mutation");

    let resp = app
        .oneshot(request("GET", "/health", &token, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["execution_hold"]["state"], "held", "health says this tenant is held");
    assert_eq!(body["execution_hold"]["hold_id"], "hold_3");
    assert!(body["execution_hold"].get("reason").is_none(), "and no more than that");
}

/// A held refusal is free: nothing is appended to the audit chain and no row is written, which on a
/// hosted worker is the difference between a refusal and a whole-database upload.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_held_refusal_moves_neither_the_audit_chain_nor_the_store() {
    use permaura_gateway::connectors::{CommandRunner, HttpClient, MockCommandRunner, MockHttpClient};
    use permaura_gateway::service::EnforcementService;
    use permaura_gateway::store::sqlite::SqliteStore;
    use permaura_gateway::store::Store;

    common::isolate_from_the_real_install();
    let sqlite = Arc::new(SqliteStore::open_in_memory().expect("an in-memory store opens"));
    let store: Arc<dyn Store> = sqlite.clone();
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http: Arc<dyn HttpClient> = Arc::new(MockHttpClient::new());
    let command: Arc<dyn CommandRunner> = Arc::new(MockCommandRunner::new());
    let backend = permaura_gateway::backend::build_backend(store.clone());
    let service = EnforcementService::from_components(store.clone(), http, command, backend, None)
        .with_execution_hold(hold_over(bucket("held", "hold_4"), None));
    let state = AppState::new(service);
    let app = app(state);

    // One refusal first, then snapshot. Authentication runs before any handler and notes a
    // session's last use at most once a minute, so the very first request of any kind writes that
    // one row; taking the baseline after it measures what the refusal itself costs, which is the
    // number that matters on a worker where a row is a whole-database upload.
    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
            .await
            .unwrap()
            .status(),
        StatusCode::LOCKED
    );
    let events = store.audit_events(None).unwrap().len();
    let changes = sqlite.change_count().unwrap();

    for _ in 0..5 {
        let resp = app
            .clone()
            .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::LOCKED);
    }

    assert_eq!(store.audit_events(None).unwrap().len(), events, "a held refusal appends nothing");
    assert_eq!(sqlite.change_count().unwrap(), changes, "and writes no row");
}

// ── Which layers are consulted ──────────────────────────────────────────────────

/// Layer 2 is opt-in. A self-hosted gateway, and every hosted worker provisioned before the backup
/// project existed, has no hold bucket and therefore no hold object to be missing.
#[tokio::test]
async fn an_unset_hold_bucket_means_no_second_layer() {
    let state = common::seeded_with_hold(Arc::new(ExecutionHold::env_only(None)));
    let token = common::operator_token(state.clone()).await;
    let app = app(state);

    let resp = app
        .clone()
        .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "nothing configured is not a hold");

    let resp = app.oneshot(request("GET", "/health", &token, serde_json::json!({}))).await.unwrap();
    assert!(
        body_json(resp).await["execution_hold"].is_null(),
        "a gateway that was never told about holds reports null, never open"
    );
}

/// Once a bucket IS configured, an absent object refuses. Provisioning writes an explicit open
/// object, so nothing there means either that it never did or that somebody removed it, and neither
/// is a reason to execute on possibly-restored authority.
#[tokio::test]
async fn a_configured_bucket_with_no_hold_object_refuses_execution() {
    let state = common::seeded_with_hold(hold_over(empty_bucket(), None));
    let app = app(state);

    let resp = app.oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED);
    assert_eq!(body_json(resp).await["state"], "absent");
}

#[tokio::test]
async fn an_explicit_open_object_permits_execution() {
    let state = common::seeded_with_hold(hold_over(bucket("open", "hold_none"), None));
    let token = common::operator_token(state.clone()).await;
    let app = app(state);

    let resp = app
        .clone()
        .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app.oneshot(request("GET", "/health", &token, serde_json::json!({}))).await.unwrap();
    assert_eq!(body_json(resp).await["execution_hold"]["state"], "open");
}

/// The fail-closed rule. An environment that says open beside an object that says held is the
/// signature of a deploy that dropped the variable, so the object wins and the gateway logs the
/// disagreement at ERROR.
#[tokio::test]
async fn a_hold_object_that_says_held_wins_over_an_env_var_that_says_open() {
    let state = common::seeded_with_hold(hold_over(bucket("held", "hold_5"), None));
    let resp = app(state)
        .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED);
    assert_eq!(body_json(resp).await["hold_id"], "hold_5");
}

/// And the other way round: layer 1 holds on its own, whatever the object says, because a hold
/// lifted in one layer only is still a hold.
#[tokio::test]
async fn an_env_var_that_says_held_wins_over_an_object_that_says_open() {
    let state = common::seeded_with_hold(hold_over(bucket("open", "hold_none"), Some("hold_env")));
    let resp = app(state)
        .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED);
    assert_eq!(body_json(resp).await["hold_id"], "hold_env");
}

/// A hold object describing another workspace has said nothing about this one, so it is unreadable,
/// and an unreadable hold refuses.
#[tokio::test]
async fn a_hold_object_naming_another_tenant_is_treated_as_unreadable() {
    let objects = Arc::new(CountingHeads::new());
    objects.write(hold_document("someone-else", "open", "hold_6", "not this workspace"));
    let state = common::seeded_with_hold(hold_over(objects, None));

    let resp = app(state).oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED);
    assert_eq!(body_json(resp).await["state"], "unreadable");
}

// ── What it costs, and how fast it moves ────────────────────────────────────────

/// The scale-to-zero rule, measured in `head` calls the way the fresh-read window's own test
/// measures its confirmations: reads never touch the bucket, and traffic inside one interval never
/// touches it however much of it there is.
///
/// A ten-minute interval, so "no recheck happened" is a fact about the rule rather than about how
/// fast the machine ran the batch. The interval *elapsing* is the other test below.
#[tokio::test]
async fn nothing_but_an_elapsed_interval_on_the_execution_path_rechecks_the_hold() {
    let objects = bucket("open", "hold_none");
    let hold = Arc::new(
        ExecutionHold::open(None, objects.clone(), TENANT, Duration::from_secs(600))
            .expect("the hold object reads"),
    );
    let state = common::seeded_with_hold(hold);
    let token = common::operator_token(state.clone()).await;
    let app = app(state);
    // Boot cost: one `head` for the hold object, one for the retained record.
    let after_boot = objects.heads();

    for _ in 0..10 {
        let resp = app
            .clone()
            .oneshot(request("GET", "/v1/grants", &token, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(objects.heads(), after_boot, "nothing on a read path may wake the bucket");

    for _ in 0..20 {
        app.clone()
            .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
            .await
            .unwrap();
    }
    assert_eq!(
        objects.heads(),
        after_boot,
        "twenty executions inside one interval cost no metadata request at all"
    );
}

/// And once the interval has elapsed, the next execution rechecks exactly once and the one behind it
/// rides the answer. Two back-to-back requests, so the second cannot straddle the next interval.
#[tokio::test]
async fn an_elapsed_interval_costs_one_metadata_request_and_the_next_execution_rides_it() {
    let interval = Duration::from_secs(3);
    let objects = bucket("open", "hold_none");
    let hold = Arc::new(
        ExecutionHold::open(None, objects.clone(), TENANT, interval).expect("the hold object reads"),
    );
    let app = app(common::seeded_with_hold(hold));
    let after_boot = objects.heads();

    tokio::time::sleep(interval + Duration::from_millis(100)).await;
    app.clone()
        .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
        .await
        .unwrap();
    assert_eq!(objects.heads(), after_boot + 1, "the first execution after the interval rechecks");

    app.oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
        .await
        .unwrap();
    assert_eq!(objects.heads(), after_boot + 1, "and the one behind it rides that answer");
}

/// A hold set while the instance is running binds within one interval, without a restart.
#[tokio::test]
async fn a_hold_set_while_the_instance_is_running_takes_effect_within_one_interval() {
    let objects = bucket("open", "hold_none");
    let state = common::seeded_with_hold(hold_over(objects.clone(), None));
    let app = app(state);

    assert_eq!(
        app.clone().oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap().status(),
        StatusCode::OK
    );

    objects.write(hold_document(TENANT, "held", "hold_7", "a restore started"));
    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;

    let resp = app.oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED);
    assert_eq!(body_json(resp).await["hold_id"], "hold_7");
}

/// And a hold cleared binds within one interval too, so lifting it does not need a redeploy.
#[tokio::test]
async fn a_hold_cleared_while_the_instance_is_running_takes_effect_within_one_interval() {
    let objects = bucket("held", "hold_8");
    let state = common::seeded_with_hold(hold_over(objects.clone(), None));
    let app = app(state);

    assert_eq!(
        app.clone().oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap().status(),
        StatusCode::LOCKED
    );

    objects.write(hold_document(TENANT, "open", "hold_8", "reconciled"));
    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;

    assert_eq!(
        app.oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap().status(),
        StatusCode::OK
    );
}

/// The recheck-failure rule, both halves. One failed read is absorbed, because a single Cloud
/// Storage blip must not take a working tenant down; a failure still standing one interval later
/// refuses, because at that point nobody can say whether this tenant is held.
#[tokio::test]
async fn an_unreadable_hold_refuses_execution_only_after_a_further_interval() {
    let objects = Arc::new(FailsOnDemand::new(hold_document(TENANT, "open", "hold_9", "open")));
    let hold = Arc::new(
        ExecutionHold::open(None, objects.clone(), TENANT, INTERVAL).expect("the hold object reads"),
    );
    let state = common::seeded_with_hold(hold);
    let app = app(state);

    objects.start_failing();
    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
    assert_eq!(
        app.clone().oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap().status(),
        StatusCode::OK,
        "the first failed read is absorbed"
    );

    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
    let resp = app.oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED, "a failure that persists refuses");
    assert_eq!(body_json(resp).await["state"], "unreadable");
}

/// The refusal an outage puts in place is the gateway's own, not anything
/// the object said, so it lasts only as long as the outage. Once the bucket answers, the unchanged
/// generation is no reason to keep it, and execution resumes on the next check.
#[tokio::test]
async fn an_open_hold_that_went_unreadable_reopens_once_the_bucket_answers_again() {
    let objects = Arc::new(FailsOnDemand::new(hold_document(TENANT, "open", "hold_12", "open")));
    let hold = Arc::new(ExecutionHold::open(None, objects.clone(), TENANT, INTERVAL).expect("the hold object reads"));
    let app = app(common::seeded_with_hold(hold));
    objects.start_failing();
    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
    let _ = app.clone().oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
    let resp = app.clone().oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED, "precondition: a lasting failure refuses");
    assert_eq!(body_json(resp).await["state"], "unreadable");

    objects.stop_failing();
    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
    let first = app.clone().oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap().status();
    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
    let then = app.oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap().status();
    assert_eq!((first, then), (StatusCode::OK, StatusCode::OK), "after recovery: first={first} then={then}");
}

/// The other side: a hold the object actually states is not lifted by the bucket coming
/// back. The re-read finds it still held.
#[tokio::test]
async fn a_held_tenant_that_went_unreadable_is_still_held_when_the_bucket_answers_again() {
    let objects = Arc::new(FailsOnDemand::new(hold_document(TENANT, "held", "hold_13", "a restore")));
    let hold = Arc::new(ExecutionHold::open(None, objects.clone(), TENANT, INTERVAL).expect("the hold object reads"));
    let app = app(common::seeded_with_hold(hold));
    objects.start_failing();
    for _ in 0..2 {
        tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
        let _ = app.clone().oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    }
    objects.stop_failing();
    tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
    let resp = app.oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED);
    assert_eq!(body_json(resp).await["hold_id"], "hold_13");
}

/// A hold that was already held is never lifted by a failure to read it, however long the failure
/// lasts. The grace period exists for the open case and for that case only.
#[tokio::test]
async fn a_held_tenant_stays_held_when_the_hold_object_becomes_unreadable() {
    let objects = Arc::new(FailsOnDemand::new(hold_document(TENANT, "held", "hold_10", "a restore")));
    let hold = Arc::new(
        ExecutionHold::open(None, objects.clone(), TENANT, INTERVAL).expect("the hold object reads"),
    );
    let state = common::seeded_with_hold(hold);
    let app = app(state);

    objects.start_failing();
    for _ in 0..3 {
        tokio::time::sleep(INTERVAL + Duration::from_millis(50)).await;
        let resp = app
            .clone()
            .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::LOCKED);
        assert_eq!(body_json(resp).await["hold_id"], "hold_10", "still the hold it already had");
    }
}

/// The property the whole two-layer design exists for: the hold is not in the database, so a
/// database promoted from before the incident cannot clear it. Two gateways, two entirely separate
/// stores, one hold object, and both refuse.
#[tokio::test]
async fn a_restored_database_cannot_clear_its_own_hold() {
    let objects = bucket("held", "hold_11");

    for attempt in 0..2 {
        let state = common::seeded_with_hold(hold_over(objects.clone(), None));
        let resp = app(state)
            .oneshot(request("POST", "/v1/invoke", seed::DEMO_TOKEN, invoke_body()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::LOCKED,
            "a fresh store under the same hold object is still held (attempt {attempt})"
        );
    }
}

// ── What a client can see before it is refused ──────────────────────────────────────────────────

/// The gap: no client could tell a held tenant from a healthy one until an
/// action was refused.
///
/// The console's status pill reads `GET /v1/broker`, not `/health`, and `/v1/broker` carried only
/// `store_degraded`. So a worker answering 423 to every execution looked perfectly well until
/// somebody tried something, and the first anyone knew was a failure.
#[tokio::test]
async fn the_broker_status_shows_a_held_tenant_before_anything_is_refused() {
    let state = common::seeded_with_hold(hold_over(bucket("held", "hold_pill"), None));
    let token = common::operator_token(state.clone()).await;
    let app = app(state);

    let resp = app
        .clone()
        .oneshot(request("GET", "/v1/broker", &token, serde_json::Value::Null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "reads keep working while held");
    let body = body_json(resp).await;
    assert_eq!(body["execution_hold"]["state"], "held");
    assert_eq!(body["execution_hold"]["hold_id"], "hold_pill");
    assert!(
        body["execution_hold"].get("reason").is_none(),
        "the reason names the checkpoint a restore is promoting and belongs in the 423, not in a status document"
    );
    assert!(body.get("reconciliation").is_some(), "the block is present even when it is null");
    assert_eq!(body["reconciliation"], serde_json::Value::Null, "nothing has been restored here");
    // Still the field the console has always watched.
    assert!(body.get("store_degraded").is_some());
}

/// The two documents are fed from the same source, so they cannot come to different answers about
/// whether this tenant is held.
#[tokio::test]
async fn the_broker_status_and_health_agree_about_the_hold() {
    let state = common::seeded_with_hold(hold_over(bucket("open", "hold_none"), None));
    let token = common::operator_token(state.clone()).await;
    let app = app(state);

    let broker = body_json(
        app.clone()
            .oneshot(request("GET", "/v1/broker", &token, serde_json::Value::Null))
            .await
            .unwrap(),
    )
    .await;
    let health = body_json(
        app.oneshot(request("GET", "/health", &token, serde_json::Value::Null)).await.unwrap(),
    )
    .await;
    assert_eq!(broker["execution_hold"], health["execution_hold"]);
    assert_eq!(broker["reconciliation"], health["reconciliation"]);
    assert_eq!(broker["execution_hold"]["state"], "open");
}

/// A gateway with no hold configured answers `null`, which must not read as "open": one is a
/// gateway that was never told about holds and the other is one that checked.
#[tokio::test]
async fn a_gateway_with_no_hold_reports_null_on_the_broker_rather_than_open() {
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    let app = app(state);
    let body = body_json(
        app.oneshot(request("GET", "/v1/broker", &token, serde_json::Value::Null)).await.unwrap(),
    )
    .await;
    assert_eq!(body["execution_hold"], serde_json::Value::Null);
}
