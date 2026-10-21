//! Resource limits, driven through the real router with `tower`'s `oneshot`.
//!
//! These go through `build_router` rather than calling the limiter directly, because the thing worth
//! proving is where the limits sit in the stack: which route group a request lands in, and what has
//! and has not happened by the time a request is refused.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::limits::{Limits, LimitsConfig};
use common::build_router;
use permaura_gateway::{seed, AppState};
use tower::ServiceExt; // for `oneshot`

mod common;

/// Read a response body into a `serde_json::Value`.
async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn app() -> axum::Router {
    build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap())
}

/// A JSON body of roughly `bytes` bytes. Well-formed, so anything that rejects it rejected it on
/// size rather than on shape.
fn padded_json(bytes: usize) -> String {
    format!(r#"{{"capability":"x","params":{{"pad":"{}"}}}}"#, "p".repeat(bytes))
}

/// As the operator, because `/v1/invoke` and the bulk routes refuse a caller they do not know before reading the body, so their size limits show only to a bearer they accept.
async fn post(app: axum::Router, uri: &str, body: String) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

// ── Body limits, per route group ────────────────────────────────────────────────

#[tokio::test]
async fn the_execution_routes_refuse_a_body_over_their_limit() {
    let over = padded_json(3 * 1024 * 1024);
    assert_eq!(
        post(app(), "/v1/invoke", over.clone()).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(post(app(), "/mcp", over).await, StatusCode::PAYLOAD_TOO_LARGE);
}

/// The management routes take a much smaller body than the execution routes, which is the whole
/// point of setting them per group: before this they all silently shared axum's 2 MiB default.
#[tokio::test]
async fn the_management_routes_have_a_tighter_limit_than_the_execution_routes() {
    let between = padded_json(512 * 1024);
    assert_eq!(
        post(app(), "/v1/grants", between.clone()).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "512 KiB is over the management limit"
    );
    // The same body on an execution route is refused for a reason that is not its size.
    assert_ne!(
        post(app(), "/v1/invoke", between).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "512 KiB is under the execution limit"
    );
}

/// A vault bundle or an OpenAPI document is legitimately larger than any management record, so the
/// bulk group is the one place the limit goes up rather than down.
#[tokio::test]
async fn the_bulk_routes_accept_what_the_management_routes_refuse() {
    let body = padded_json(512 * 1024);
    for route in ["/v1/vault/import", "/v1/connections/import-openapi"] {
        assert_ne!(
            post(app(), route, body.clone()).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{route} should accept a body this size"
        );
    }
}

/// A body under every limit must still reach its handler; a limit that refuses ordinary traffic is
/// an outage, not a control.
#[tokio::test]
async fn an_ordinary_body_still_reaches_its_handler() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "capability": "braintree.transactions.search",
                        "params": { "status": "failed" },
                        "reason": "a body well under every limit"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Admission control: the 429 and where it happens ─────────────────────────────

/// A state whose limiter admits exactly one execution and refuses the next, so a test reaches the
/// rate limit in two requests instead of a hundred.
fn state_admitting_one() -> AppState {
    common::seeded().with_limits(Arc::new(Limits::new(
        LimitsConfig {
            rate_per_min: 1,
            rate_burst: 1,
            ..LimitsConfig::default()
        },
    )))
}

fn invoke_request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "capability": "braintree.transactions.search",
                "params": { "status": "failed" },
                "reason": "resource limit test"
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn an_over_rate_execution_is_refused_with_429_and_a_retry_after() {
    let state = state_admitting_one();
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(invoke_request()).await.unwrap().status(),
        StatusCode::OK,
        "the first call spends the only token"
    );

    let resp = app.oneshot(invoke_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = resp
        .headers()
        .get("retry-after")
        .expect("a 429 without Retry-After leaves the client no strategy but to retry at once")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry >= 1, "Retry-After of 0 means 'retry now'");
    let json = body_json(resp).await;
    // The reason is what separates this 429 from the audit-backlog ceiling that will share the
    // variant.
    assert_eq!(json["reason"], "rate");
    assert_eq!(json["retry_after"], retry);
}

/// The placement rule, stated as a test: a refusal happens before the
/// pre-execution `"attempt"` append that fences every execution. If it did not, a rejected request
/// would already have recorded an intent to execute.
#[tokio::test]
async fn a_rejection_appends_no_audit_event() {
    let state = state_admitting_one();
    let store = state.service.store().clone();
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    app.clone().oneshot(invoke_request()).await.unwrap();
    let before = store.audit_events(None).unwrap().len();

    for _ in 0..5 {
        let resp = app.clone().oneshot(invoke_request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    assert_eq!(
        store.audit_events(None).unwrap().len(),
        before,
        "a refused request must not have appended anything to the audit chain"
    );
}

/// The same rule measured where it costs money. On a hosted worker every store mutation is a full
/// snapshot upload, so a rejection that moved SQLite's change counter by even one row would mean a
/// refused request cost a whole-database PUT.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_rejection_writes_no_row_to_the_store() {
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
    let service = EnforcementService::from_components(store, http, command, backend, None);
    let state = AppState::new(service).with_limits(Arc::new(Limits::new(
        LimitsConfig {
            rate_per_min: 1,
            rate_burst: 1,
            ..LimitsConfig::default()
        },
    )));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    // Spend the token on a real execution first, so the counter is snapshotted after every write an
    // allowed call makes (both audit appends and the session touch).
    assert_eq!(
        app.clone().oneshot(invoke_request()).await.unwrap().status(),
        StatusCode::OK
    );
    let before = sqlite.change_count().unwrap();

    for _ in 0..5 {
        let resp = app.clone().oneshot(invoke_request()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    assert_eq!(
        sqlite.change_count().unwrap(),
        before,
        "a refused request wrote a row, which on a hosted worker is a full snapshot upload"
    );
}

/// Admission control is on the execution group only. A limiter that also shed management traffic
/// would take away the console at the exact moment an operator needs it.
#[tokio::test]
async fn the_management_routes_are_not_rate_limited() {
    let state = state_admitting_one();
    let token = common::operator_token(state.clone()).await;
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    // Spend the execution budget several times over.
    for _ in 0..4 {
        app.clone().oneshot(invoke_request()).await.unwrap();
    }

    for _ in 0..20 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/grants")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a management read must not draw on an agent's execution budget"
        );
    }
}

// ── Reserved capacity ───────────────────────────────────────────────────────────

/// A limiter with every execution slot already taken, and the permits keeping it that way.
///
/// Saturating through the limiter's own API rather than by generating traffic is deliberate: it is
/// the same call the middleware makes, so the test proves the real bound rather than a stand-in, and
/// it is deterministic.
async fn saturated() -> (AppState, Vec<permaura_gateway::limits::ExecutionPermit>) {
    let limits = Arc::new(Limits::new(LimitsConfig {
        max_inflight: 2,
        queue_depth: 0,
        queue_wait: Duration::from_millis(50),
        // Generous, so what the test observes is the semaphore and not the bucket.
        rate_per_min: 60_000,
        rate_burst: 1_000,
        ..LimitsConfig::default()
    }));
    let mut held = Vec::new();
    for i in 0..2 {
        held.push(
            limits
                .admit(&permaura_gateway::limits::LimitKey::session(format!("filler-{i}")))
                .await
                .expect("a fresh limiter admits up to its ceiling"),
        );
    }
    (common::seeded().with_limits(limits), held)
}

/// The whole point of reserved capacity: an operator can still revoke and a probe still answers at
/// the exact moment execution has nothing left to give.
#[tokio::test]
async fn a_revoke_and_a_health_check_answer_while_execution_is_saturated() {
    let (state, held) = saturated().await;
    let token = common::operator_token(state.clone()).await;
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    // Execution really is saturated.
    let shed = app.clone().oneshot(invoke_request()).await.unwrap();
    assert_eq!(shed.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(shed).await["reason"], "queue");

    // Promptly, not eventually: a reserved route that merely queues behind execution is not
    // reserved. The budget is far below the limiter's own 50ms wait, so anything that took a
    // permit would fail here.
    let revoke = tokio::time::timeout(
        Duration::from_millis(500),
        app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sessions/sess_test_operator/revoke")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("the revoke route answered within its budget")
    .unwrap();
    assert_eq!(revoke.status(), StatusCode::OK);

    let health = tokio::time::timeout(
        Duration::from_millis(500),
        app.oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap()),
    )
    .await
    .expect("the health route answered within its budget")
    .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    drop(held);
}

/// Every route the module reserves is driven under saturation. None may answer 429: a 404 or a 401
/// is fine, because what is under test is which route group the path landed in, not its handler.
#[tokio::test]
async fn no_reserved_route_is_shed_while_execution_is_saturated() {
    let (state, held) = saturated().await;
    let token = common::operator_token(state.clone()).await;
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    for route in permaura_gateway::limits::RESERVED_ROUTES {
        // The documented paths carry axum's parameter syntax; give each one a concrete id.
        let uri = route.replace(":id", "x").replace(":approver_id", "x");
        for method in ["GET", "POST", "DELETE", "PUT"] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(&uri)
                        .header("authorization", format!("Bearer {token}"))
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "{method} {uri} is reserved and must never be shed"
            );
        }
    }

    drop(held);
}

/// An operator has to be able to see shedding without reading logs, and the counters have to say
/// which limit fired.
#[tokio::test]
async fn health_reports_the_limiter_state_to_an_authenticated_caller() {
    let state = state_admitting_one();
    let token = common::operator_token(state.clone()).await;
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    app.clone().oneshot(invoke_request()).await.unwrap();
    app.clone().oneshot(invoke_request()).await.unwrap();

    let health = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(health).await;
    assert_eq!(json["limits"]["rejected"]["rate"], 1);
    assert_eq!(json["limits"]["rejected"]["queue"], 0);
    assert_eq!(json["limits"]["max_inflight"], 8);
}

/// The unauthenticated health document is liveness and nothing else; the limiter's state describes
/// the instance's capacity and belongs behind the same bearer as the seeded counts.
#[tokio::test]
async fn an_unauthenticated_health_check_sees_no_limiter_state() {
    let json = body_json(
        app()
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(json["status"], "ok");
    assert!(json["limits"].is_null());
}

// ── Configuration ───────────────────────────────────────────────────────────────

/// The numbers the router is built from are the ones the module documents, and they are distinct
/// per group. A regression that collapsed them back to one figure would otherwise be invisible.
#[test]
fn the_three_body_limits_are_distinct_and_ordered() {
    let cfg = permaura_gateway::limits::LimitsConfig::default();
    assert!(cfg.body_default_bytes < cfg.body_exec_bytes);
    assert!(cfg.body_exec_bytes < cfg.body_bulk_bytes);
}

/// An invented bearer is refused at 401 and executes nothing, so it must not spend the worker's
/// execution budget. A flood of them used to drain the worker-wide bucket and 429 every real agent.
#[tokio::test]
async fn invented_bearers_cannot_drain_the_worker_bucket() {
    let state = common::seeded().with_limits(Arc::new(Limits::new(LimitsConfig {
        rate_per_min: 60_000,
        rate_burst: 1_000,
        worker_rate_per_min: Some(60),
        worker_rate_burst: 2,
        ..LimitsConfig::default()
    })));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    for i in 0..10 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/invoke")
                    .header("authorization", format!("Bearer invented-{i}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"capability":"braintree.transactions.read","params":{}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "request {i}");
    }
    let resp = app.clone().oneshot(invoke_request()).await.unwrap();
    let status = resp.status();
    assert_eq!(status, StatusCode::OK, "a real agent still executes: {}", body_json(resp).await);
}

// ── A hosted worker refuses at its store's measured ceiling ────────────────────────

/// Twelve calls back to back against a hosted worker's default limits: the burst runs, then the
/// caller is refused with a 429 and a `Retry-After` of one token's refill, rather than the call
/// going on to the store's upload and, under sustained load, to memory the worker did not have. One
/// caller's rate equals the worker's, and the worker's bucket is charged first, so it is the
/// worker's that refuses.
#[tokio::test]
async fn a_hosted_worker_refuses_once_its_burst_is_spent() {
    let state = common::seeded().with_limits(Arc::new(Limits::new(LimitsConfig::defaults_for(true))));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    let mut statuses = Vec::new();
    // Only the status is kept, because an unread response holds its execution slot until it has been sent.
    for _ in 0..11 {
        statuses.push(app.clone().oneshot(invoke_request()).await.unwrap().status());
    }
    assert!(statuses[..10].iter().all(|s| *s == StatusCode::OK), "the hosted burst is 10");
    let resp = app.clone().oneshot(invoke_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "2", "30 a minute refills one token every 2 s");
    let json = body_json(resp).await;
    assert_eq!(json["reason"], "rate");
    assert_eq!(json["scope"], "worker");
}

/// And a caller's own bucket at the hosted default binds even on a worker that a plan lets run
/// faster: one agent is never allowed past the store's ceiling on its own.
#[tokio::test]
async fn a_hosted_caller_is_refused_at_its_own_rate_on_a_faster_worker() {
    let state = common::seeded().with_limits(Arc::new(Limits::new(LimitsConfig {
        worker_rate_per_min: Some(1_200),
        worker_rate_burst: 100,
        ..LimitsConfig::defaults_for(true)
    })));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    let mut statuses = Vec::new();
    // Only the status is kept, because an unread response holds its execution slot until it has been sent.
    for _ in 0..11 {
        statuses.push(app.clone().oneshot(invoke_request()).await.unwrap().status());
    }
    assert!(statuses[..10].iter().all(|s| *s == StatusCode::OK));
    let resp = app.clone().oneshot(invoke_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "2");
    let json = body_json(resp).await;
    assert_eq!(json["scope"], "session");
}
