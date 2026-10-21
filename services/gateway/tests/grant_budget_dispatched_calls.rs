//! A dispatched call spends its grant budget whether or not its answer came back, and a call that never left the gateway spends nothing whatever outcome it claims.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, seed};
use tower::ServiceExt;

mod common;

async fn post(app: &axum::Router, uri: &str, token: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

/// Accepts the request (the upstream effect lands) then fails the way `read_capped_bytes` does for an oversized body.
#[derive(Default)]
struct LandsThenOverflows(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl permaura_gateway::connectors::HttpClient for LandsThenOverflows {
    async fn send(
        &self,
        _request: permaura_gateway::connectors::HttpRequest,
    ) -> anyhow::Result<permaura_gateway::connectors::HttpResponse> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        anyhow::bail!("upstream response exceeded the 5242880-byte response cap")
    }
}

/// A connection, a read policy and a `max_calls: 1` total grant for the seeded agent, over `upstream`. Without a
/// credential the connection's calls are refused when the secret is opened, after the attempt and before anything is sent.
async fn gateway_with_one_call(
    upstream: std::sync::Arc<LandsThenOverflows>,
    with_credential: bool,
) -> (axum::Router, permaura_gateway::AppState, String, String) {
    common::isolate_from_the_real_install();
    let state = permaura_gateway::AppState::in_memory_seeded_with_http(upstream);
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_s, conn) =
        post(&app, "/v1/connections", seed::DEMO_TOKEN, serde_json::json!({ "connector": "github", "name": "Budget GitHub" }))
            .await;
    let connection_id = conn["connection_id"].as_str().unwrap().to_string();
    if with_credential {
        post(
            &app,
            &format!("/v1/connections/{connection_id}/credential"),
            seed::DEMO_TOKEN,
            serde_json::json!({ "value": "ghp_budget_0123456789" }),
        )
        .await;
    }
    let (_s, pol) = post(
        &app,
        "/v1/policies",
        seed::DEMO_TOKEN,
        serde_json::json!({ "connection_id": connection_id, "name": "ro", "allow": ["pull_requests.list"] }),
    )
    .await;
    let (s, grant) = post(
        &app,
        "/v1/grants",
        seed::DEMO_TOKEN,
        serde_json::json!({ "policy_id": pol["policy_id"], "target_agent": "codex-cli", "max_calls": 1, "period": "total" }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{grant}");
    (app, state, connection_id, grant["grant_id"].as_str().unwrap().to_string())
}

/// The reproduction: three invokes against a `max_calls: 1` grant whose every answer overflows the cap.
/// The first reaches the upstream and is charged; the next two are refused for budget before anything is sent.
#[tokio::test]
async fn a_dispatched_call_that_errors_spends_its_budget() {
    let upstream = std::sync::Arc::new(LandsThenOverflows::default());
    let (app, state, connection_id, grant_id) = gateway_with_one_call(upstream.clone(), true).await;
    let capability = format!("{connection_id}.pull_requests.list");

    let mut statuses = Vec::new();
    for _ in 0..3 {
        let (s, _body) =
            post(&app, "/v1/invoke", seed::DEMO_TOKEN, serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } }))
                .await;
        statuses.push(s.as_u16());
    }
    let reached = upstream.0.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(reached, 1, "a max_calls=1 grant let the upstream be called {reached} times: {statuses:?}");
    assert_eq!(statuses[0], 500, "the one dispatched call failed the way the upstream made it: {statuses:?}");
    assert!(statuses[1..].iter().all(|s| *s != 500), "the later calls never reached the upstream: {statuses:?}");

    let events = state.service.store().audit_events_from(0, 100_000).unwrap();
    let terminal: Vec<_> = events
        .iter()
        .filter(|e| e.payload.action == capability && e.payload.decision != "attempt")
        .map(|e| (e.payload.decision.as_str(), e.payload.summary["outcome"].as_str().unwrap_or("").to_string()))
        .collect();
    assert_eq!(terminal[0], ("error", "unknown".into()), "{terminal:?}");
    let failed = events.iter().find(|e| e.payload.action == capability && e.payload.decision == "error").unwrap();
    assert_eq!(failed.payload.summary["dispatched"], true, "{}", failed.payload.summary);
    assert!(terminal[1..].iter().all(|(d, _)| *d == "deny"), "{terminal:?}");

    // The chain and the counter agree on the one spent call.
    let windows = [permaura_gateway::store::GrantWindow { grant_id: &grant_id, since_ms: i64::MIN }];
    let counted = state.service.store().count_grant_usage(&windows).unwrap();
    let read = state.service.store().read_grant_usage(&windows).unwrap();
    assert_eq!(counted.total(&grant_id), 1, "the scan counts the dispatched error");
    assert_eq!(read.total(&grant_id), 1, "the live counter was charged with the event");
    assert_eq!(counted.agent(&grant_id, "codex-cli"), 1);
    assert_eq!(read.agent(&grant_id, "codex-cli"), 1);
}

/// The other half of the rule: a call refused after the attempt but before dispatch spends nothing, so a budget
/// cannot be drained by requests that never left the gateway. Here the connection has no credential to open.
#[tokio::test]
async fn a_call_refused_before_dispatch_spends_nothing() {
    let upstream = std::sync::Arc::new(LandsThenOverflows::default());
    let (app, state, connection_id, grant_id) = gateway_with_one_call(upstream.clone(), false).await;
    let capability = format!("{connection_id}.pull_requests.list");

    let (s, body) = post(&app, "/v1/invoke", seed::DEMO_TOKEN, serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(upstream.0.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing was sent");
    let events = state.service.store().audit_events_from(0, 100_000).unwrap();
    let refused = events
        .iter()
        .find(|e| e.payload.action == capability && e.payload.decision == "error")
        .expect("the refusal closes the attempt");
    assert_eq!(refused.payload.summary["outcome"], "refused", "{}", refused.payload.summary);
    assert_eq!(refused.payload.summary["dispatched"], false, "{}", refused.payload.summary);

    let windows = [permaura_gateway::store::GrantWindow { grant_id: &grant_id, since_ms: i64::MIN }];
    assert_eq!(state.service.store().count_grant_usage(&windows).unwrap().total(&grant_id), 0);
    assert_eq!(state.service.store().read_grant_usage(&windows).unwrap().total(&grant_id), 0);

    // And the budget is still there for a real call once the credential is in place.
    post(&app, &format!("/v1/connections/{connection_id}/credential"), seed::DEMO_TOKEN, serde_json::json!({ "value": "ghp_budget_0123456789" })).await;
    let (s, _body) = post(&app, "/v1/invoke", seed::DEMO_TOKEN, serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } })).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "the one budgeted call reached the upstream");
    assert_eq!(upstream.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// The rule itself, on the payloads every counting path reads: a result that came back spends, a dispatched call
/// that never answered spends, and nothing else does.
#[test]
fn only_results_and_dispatched_errors_spend_budget() {
    use permaura_core::AuditPayload;
    use permaura_gateway::store::Store;
    let charged = |decision: &str, summary: serde_json::Value| {
        let mut payload = AuditPayload::new("conn.cap", "conn", decision);
        payload.summary = summary;
        let store = permaura_gateway::store::memory::MemoryStore::new();
        store.append_audit_charged(payload, None).unwrap();
        store
            .count_grant_usage(&[permaura_gateway::store::GrantWindow { grant_id: "g", since_ms: i64::MIN }])
            .unwrap()
            .total("g")
    };
    assert_eq!(charged("allow", serde_json::json!({ "grant_id": "g" })), 1);
    assert_eq!(charged("approved", serde_json::json!({ "grant_id": "g" })), 1);
    assert_eq!(charged("error", serde_json::json!({ "grant_id": "g", "ok": false, "outcome": "unknown", "dispatched": true })), 1);
    assert_eq!(
        charged("error", serde_json::json!({ "grant_id": "g", "ok": false, "outcome": "unknown", "error_kind": "abandoned", "dispatched": true })),
        1
    );
    assert_eq!(
        charged("error", serde_json::json!({ "grant_id": "g", "ok": false, "outcome": "unknown", "error_kind": "interrupted", "dispatched": null })),
        1,
        "a call a dying process cut off may have been sent"
    );
    // Outcome `unknown` is the honest claim about an effect for an error the gateway did not author, such as a KMS or token-endpoint failure; only the trace says whether anything was sent.
    assert_eq!(charged("error", serde_json::json!({ "grant_id": "g", "ok": false, "outcome": "unknown", "dispatched": false })), 0);
    assert_eq!(charged("error", serde_json::json!({ "grant_id": "g", "ok": false, "outcome": "unknown" })), 0);
    assert_eq!(charged("error", serde_json::json!({ "grant_id": "g", "ok": false, "outcome": "refused", "dispatched": false })), 0);
    assert_eq!(charged("error", serde_json::json!({ "grant_id": "g", "ok": false })), 0);
    assert_eq!(charged("error", serde_json::json!({ "ok": false, "outcome": "unknown", "dispatched": true })), 0);
    assert_eq!(charged("deny", serde_json::json!({ "grant_id": "g" })), 0);
    assert_eq!(charged("attempt", serde_json::json!({ "grant_id": "g" })), 0);
    assert_eq!(charged("requires_approval", serde_json::json!({ "grant_id": "g" })), 0);
}

/// An error raised before dispatch that the gateway did not author (here the secret will not open, as a KMS or vault fault would) keeps its honest `unknown` outcome and spends nothing, so an outage of the credential path cannot burn every agent's `max_calls`.
#[tokio::test]
async fn an_error_raised_before_dispatch_spends_nothing_whatever_outcome_it_claims() {
    let upstream = std::sync::Arc::new(LandsThenOverflows::default());
    let (app, state, connection_id, grant_id) = gateway_with_one_call(upstream.clone(), false).await;
    let capability = format!("{connection_id}.pull_requests.list");
    let unopenable = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, b"not-this-gateways-vault-key", b"ghp_budget_0123456789").unwrap();
    let slot = state.service.store().get_connection(&connection_id).unwrap().unwrap().secret_id;
    state
        .service
        .store()
        .put_secret(permaura_core::SecretRecord { id: slot, sealed: unopenable, metadata: Default::default() })
        .unwrap();

    for _ in 0..3 {
        let (s, body) = post(&app, "/v1/invoke", seed::DEMO_TOKEN, serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } })).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "the credential path failed, every time: {body}");
    }
    assert_eq!(upstream.0.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing was sent");
    let events = state.service.store().audit_events_from(0, 100_000).unwrap();
    let errors: Vec<_> = events.iter().filter(|e| e.payload.action == capability && e.payload.decision == "error").collect();
    assert_eq!(errors.len(), 3);
    for e in errors {
        assert_eq!(e.payload.summary["outcome"], "unknown", "{}", e.payload.summary);
        assert_eq!(e.payload.summary["dispatched"], false, "{}", e.payload.summary);
    }
    let windows = [permaura_gateway::store::GrantWindow { grant_id: &grant_id, since_ms: i64::MIN }];
    assert_eq!(state.service.store().count_grant_usage(&windows).unwrap().total(&grant_id), 0);
    assert_eq!(state.service.store().read_grant_usage(&windows).unwrap().total(&grant_id), 0, "the budget is all still there");
}
