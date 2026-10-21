//! The hosted fair-use limits, driven through the real router: the worker-wide 429, the throttle a
//! month over its ceiling brings, what `/health` reports, and what a request costs the counter.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::fair_use::{FairUse, FairUseConfig, Month, DOCS_URL, META_KEY};
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

mod common;

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn invoke() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "capability": "braintree.transactions.search",
                "params": { "status": "failed" },
                "reason": "fair use test"
            })
            .to_string(),
        ))
        .unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn this_month() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    Month::from_unix(now).to_string()
}

fn hosted(soft: u64, hard: u64, throttled_rate_per_min: u32) -> FairUseConfig {
    FairUseConfig { active: true, disabled: false, soft_calls: soft, hard_calls: hard, throttled_rate_per_min }
}

/// A ceiling that has already counted `calls` this month, loaded the way a cold start loads it.
fn ceiling_at(state: &AppState, config: FairUseConfig, calls: u64) -> Arc<FairUse> {
    let store = state.service.store();
    store
        .put_meta(META_KEY, &serde_json::json!({ "month": this_month(), "mutating_calls": calls }).to_string())
        .unwrap();
    let fair_use = Arc::new(FairUse::new(config));
    fair_use.attach(store.as_ref());
    fair_use
}

fn worker_limits(per_min: u32, burst: u32) -> Arc<Limits> {
    Arc::new(Limits::new(LimitsConfig {
        worker_rate_per_min: Some(per_min),
        worker_rate_burst: burst,
        ..LimitsConfig::default()
    }))
}

#[tokio::test]
async fn a_worker_over_its_rate_is_told_so_and_where_the_numbers_are() {
    let state = common::seeded().with_limits(worker_limits(1, 1));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    assert_eq!(app.clone().oneshot(invoke()).await.unwrap().status(), StatusCode::OK);

    let resp = app.oneshot(invoke()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = resp.headers()["retry-after"].to_str().unwrap().parse().unwrap();
    assert_eq!(retry, 60, "one call a minute means the next token is a minute away");
    let json = body_json(resp).await;
    assert_eq!(json["error"], "rate_limited");
    assert_eq!(json["scope"], "worker");
    assert_eq!(json["docs"], DOCS_URL);
    assert_eq!(json["reason"], "rate");
    assert_eq!(json["retry_after"], retry);
}

/// Throttled means slowed. The worker keeps executing at the throttled rate, and everything an
/// operator needs (management, health) answers as it always did.
#[tokio::test]
async fn a_throttled_worker_is_slowed_and_never_cut_off() {
    let state = common::seeded().with_limits(worker_limits(6_000, 100));
    let fair_use = ceiling_at(&state, hosted(1, 2, 1), 2);
    assert!(fair_use.throttled());
    let state = state.with_fair_use(fair_use);
    let operator = common::operator_token(state.clone()).await;
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    assert_eq!(app.clone().oneshot(invoke()).await.unwrap().status(), StatusCode::OK, "still executing");
    let refused = app.clone().oneshot(invoke()).await.unwrap();
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(refused).await["scope"], "worker");

    for route in ["/v1/agents", "/health"] {
        let resp = app.clone().oneshot(get(route, &operator)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{route} is not behind the throttle");
    }
}

#[tokio::test]
async fn health_reports_the_month_on_a_hosted_worker() {
    let state = common::seeded();
    let fair_use = ceiling_at(&state, hosted(10, 20, 60), 12);
    let state = state.with_fair_use(fair_use);
    let operator = common::operator_token(state.clone()).await;
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(get("/health", &operator))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(
        json["fair_use"],
        serde_json::json!({
            "month": this_month(),
            "mutating_calls": 12,
            "soft": 10,
            "hard": 20,
            "state": "warned",
            "throttled_rate_per_min": 60,
        })
    );
}

#[tokio::test]
async fn a_gateway_that_is_not_hosted_reports_no_fair_use_and_no_worker_limit() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(get("/health", &operator))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert!(json["fair_use"].is_null(), "{}", json["fair_use"]);
    assert_eq!(json["limits"]["worker"]["enabled"], false);
}

/// The whole path on the hosted store: the router opens the request scope, the persisted store sees a
/// changed row and counts the request once, and a read costs nothing.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_through_the_router_counts_once_and_a_read_does_not() {
    use permaura_gateway::connectors::MockHttpClient;
    use permaura_gateway::objectstore::MemoryObjectStore;
    use permaura_gateway::service::EnforcementService;
    use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
    use permaura_gateway::store::Store;

    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!(
        "permaura-fair-use-router-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db");
    let objects = Arc::new(MemoryObjectStore::new());
    let store: Arc<dyn Store> = Arc::new(
        PersistedSqliteStore::open(&path.to_string_lossy(), objects, DEFAULT_OBJECT, None).unwrap(),
    );
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let fair_use = Arc::new(FairUse::new(hosted(1_000, 2_000, 60)));
    fair_use.attach(store.as_ref());
    let state = AppState::new(EnforcementService::new(store, Arc::new(MockHttpClient::new())))
        .with_fair_use(fair_use.clone());
    assert_eq!(fair_use.report().mutating_calls, 0, "seeding is not a request");
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    assert_eq!(app.clone().oneshot(invoke()).await.unwrap().status(), StatusCode::OK);
    assert_eq!(fair_use.report().mutating_calls, 1, "one call, however many rows its audit trail wrote");

    let before = fair_use.report().mutating_calls;
    let resp = app.clone().oneshot(get("/v1/capabilities", seed::DEMO_TOKEN)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(fair_use.report().mutating_calls, before, "listing capabilities changes nothing");
}
