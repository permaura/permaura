//! The hot audit store's warning band and hard ceiling, driven through the real router and the real
//! enforcement loop.
//!
//! The ordering rule matters more than the numbers, and it is what most of this file is about: the
//! ceiling gates the decision to execute and never the recording of one. "An audit event is never
//! dropped, at any pressure, for any reason" is a standing protection, so every test here that pushes the
//! store over the ceiling also checks what still gets written.
//!
//! Every credential and transport here is synthetic.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{AuditPayload, ExecutionLocation};
use permaura_gateway::audit_ceiling::{AuditCeiling, AuditCeilingConfig, DENIAL_REASON, REASON};
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse};
use permaura_gateway::error::GatewayError;
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{Session, Store};
use permaura_gateway::{build_router, seed};
use tower::ServiceExt; // for `oneshot`

mod common;

/// A ceiling a test can reach in a handful of rows.
fn ceiling(soft: u64, hard: u64) -> Arc<AuditCeiling> {
    Arc::new(AuditCeiling::new(AuditCeilingConfig {
        soft,
        ceiling: hard,
        // Never suppress: these tests read the bands, not the log, and a throttle that swallowed a
        // band change would make a failure look like a passing test.
        log_interval: std::time::Duration::ZERO,
    }))
}

/// Grow the chain by `n` events, the way ordinary traffic does.
fn fill(store: &dyn Store, n: u64) {
    for i in 0..n {
        store
            .append_audit(AuditPayload::new(format!("filler.{i}"), "synthetic", "deny"))
            .expect("the chain appends");
    }
}

fn params() -> serde_json::Value {
    serde_json::json!({ "owner": "synthetic", "repo": "synthetic" })
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// An upstream that grows the audit chain while it is being called, so a test can put the store
/// over its ceiling in the window between the `"attempt"` and the event that answers it.
struct FillsTheChainMidFlight {
    store: Arc<dyn Store>,
    events: u64,
}

#[async_trait]
impl HttpClient for FillsTheChainMidFlight {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        fill(self.store.as_ref(), self.events);
        Ok(HttpResponse::json(200, serde_json::json!({ "pulls": [] })))
    }
}

/// The refusal itself: HTTP 429, a reason that is not the rate limiter's, and a `Retry-After`.
#[tokio::test]
async fn at_the_ceiling_a_new_execution_is_refused_with_429() {
    let state = common::seeded_with_audit_ceiling(ceiling(2, 4));
    let store = state.service.store().clone();
    fill(store.as_ref(), 4);
    let before = store.audit_len().unwrap();

    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "capability": "github.pull_requests.list",
                        "params": { "owner": "synthetic", "repo": "synthetic" },
                        "reason": "synthetic"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"), "a shed caller needs a backoff");
    let body = body_json(resp).await;
    assert_eq!(
        body["reason"], REASON,
        "a caller cannot tell 'slow down' from 'this store is full' on the status alone"
    );

    // The placement claim: refused at the fence, above the append that fences.
    assert_eq!(store.audit_len().unwrap(), before, "a refusal appends nothing");
}

/// The ordering rule, and the one worth breaking a build over. Once the `"attempt"` is in the chain
/// the execution is under way, and the event that answers it is appended whatever the pressure is.
#[tokio::test]
async fn at_the_ceiling_an_already_executed_action_still_records_its_audit_event() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let session = store.get_session("sess_demo").unwrap().unwrap();
    // Below the ceiling when the call is admitted, well over it by the time the upstream answers.
    let http = Arc::new(FillsTheChainMidFlight { store: store.clone(), events: 50 });
    let service = EnforcementService::new(store.clone(), http)
        .with_audit_ceiling(ceiling(5, 10));

    let outcome = service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("admitted below the ceiling, so it executes");
    assert!(matches!(outcome, InvokeOutcome::Allowed { .. }));

    let decisions: Vec<String> = store
        .audit_events(None)
        .unwrap()
        .iter()
        .map(|e| e.payload.decision.clone())
        .collect();
    assert!(decisions.contains(&"attempt".to_string()));
    assert!(
        decisions.contains(&"allow".to_string()),
        "the record of an execution that happened is never gated on there being room for it"
    );
    assert!(store.audit_len().unwrap() > 10, "and the store really is over its ceiling now");
    assert_eq!(store.verify_audit().unwrap(), None, "the chain is intact");
}

/// The warning band exists so the refusal is the end of a long-signalled condition rather than the
/// first anyone hears of it. Execution is untouched, and the pressure is on `/health` and in what
/// the gateway reports as degraded.
#[tokio::test]
async fn between_soft_and_ceiling_execution_continues_and_health_reports_pressure() {
    let state = common::seeded_with_audit_ceiling(ceiling(3, 1_000));
    let store = state.service.store().clone();
    fill(store.as_ref(), 5);
    let token = common::operator_token(state.clone()).await;

    let session = store.get_session("sess_demo").unwrap().unwrap();
    state
        .service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("the soft band never refuses");

    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["audit_pressure"]["band"], "soft");
    assert_eq!(body["audit_pressure"]["soft"], 3);
    assert_eq!(body["audit_pressure"]["ceiling"], 1_000);
    assert_eq!(body["audit_pressure"]["refused"], 0, "nothing was refused in the soft band");
    let degraded = body["store_degraded"].as_str().expect("the soft band says so out loud");
    assert!(degraded.contains("audit pressure"), "{degraded}");
}

/// That protection, from the other side: at the ceiling the chain must still take every event that
/// is not a new execution. A denial is the cheapest one to drive, and it is also the one an agent
/// can drive at machine speed, which is why the `audit_ceiling` module says what the ceiling does
/// and does not bound.
#[tokio::test]
async fn at_the_ceiling_a_denial_and_a_control_plane_mutation_are_still_appended() {
    let state = common::seeded_with_audit_ceiling(ceiling(2, 4));
    let store = state.service.store().clone();
    let session = store.get_session("sess_demo").unwrap().unwrap();
    fill(store.as_ref(), 4);
    let before = store.audit_len().unwrap();

    // A capability no policy allows: denied by the engine, below the fence, and recorded.
    let outcome = state
        .service
        .invoke(&session, "braintree.transactions.refund", &serde_json::json!({ "amount": 1 }), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("a decision the ceiling does not gate");
    assert!(
        !matches!(outcome, InvokeOutcome::Allowed { .. }),
        "this capability must not execute in this estate"
    );
    assert!(
        store.audit_len().unwrap() > before,
        "a decision that is not a new execution is recorded at any pressure"
    );

    // And a control-plane mutation: revoking a session is exactly what an operator does when a
    // worker is in trouble, so it must not be the thing the trouble takes away.
    let token = common::operator_token(state.clone()).await;
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sessions/sess_demo/revoke")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "revocation keeps working at the ceiling");
    assert!(store.get_session("sess_demo").unwrap().unwrap().revoked);
}

/// A human clearing the backlog is the remedy, so it cannot be gated on the condition it clears.
/// Resolving a held approval executes the held call upstream and appends its own terminal event,
/// both at full pressure.
#[tokio::test]
async fn at_the_ceiling_a_human_can_still_resolve_a_held_approval() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let session: Session = store.get_session("sess_demo").unwrap().unwrap();
    let http = Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let service =
        EnforcementService::new(store.clone(), http).with_audit_ceiling(ceiling(1_000, 5_000));

    // High risk, so the engine escalates it to a human without the policy naming it.
    let held = service
        .invoke(&session, "github.pull_requests.create", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("the hold is created below the ceiling");
    let approval = match held {
        InvokeOutcome::RequiresApproval { approval, .. } => approval,
        _ => panic!("a High-risk capability must be escalated to a human"),
    };

    // Now put the store far over a ceiling the same service will read.
    let service = EnforcementService::new(store.clone(), Arc::new(permaura_gateway::connectors::MockHttpClient::new()))
        .with_audit_ceiling(ceiling(2, 4));
    fill(store.as_ref(), 10);

    // A new execution is refused...
    let refused = service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await;
    match refused {
        Err(GatewayError::TooManyRequests { ref reason, .. }) if reason == REASON => {}
        Err(other) => panic!("the ceiling must be what refused: {other}"),
        Ok(_) => panic!("a new execution must be refused at the ceiling"),
    }

    // ...while the held one a human is clearing is not.
    let resolved = service
        .resolve_approval(&approval.id, true, "bearer", None)
        .await
        .expect("a human resolving a hold is the remedy, not more load");
    assert_eq!(resolved.status, "approved");
    let decisions: Vec<String> = store
        .audit_events(None)
        .unwrap()
        .iter()
        .map(|e| e.payload.decision.clone())
        .collect();
    assert!(
        decisions.contains(&"approved".to_string()),
        "and its own record is appended at full pressure"
    );
}

/// One agent session whose every call is denied (a Pending agent, or one looping on a capability no policy allows) could append a denial per call at its admission rate and carry a self-run gateway to the ceiling in about nine hours, after which every execution was refused for good. Its denials are now bounded: past a short run they are refused before the gate, unrecorded, and another session's execution still runs.
#[tokio::test]
async fn seventy_thousand_denied_calls_from_one_session_do_not_wedge_execution() {
    let state = common::seeded();
    let service = state.service.clone();
    let store = service.store().clone();
    let looping = store.get_session("sess_demo").unwrap().unwrap();
    let mut other = looping.clone();
    other.id = "sess_other".into();
    other.token = "synthetic-other-session-token".into();
    store.put_session(other.clone()).unwrap();

    let (mut denied, mut refused) = (0u32, 0u32);
    for _ in 0..70_000 {
        let refund = serde_json::json!({ "amount": 1 });
        match service.invoke(&looping, "braintree.transactions.refund", &refund, None, ExecutionLocation::LocalOnly).await {
            Ok(InvokeOutcome::Denied { .. }) => denied += 1,
            Err(GatewayError::TooManyRequests { reason, .. }) if reason == DENIAL_REASON => refused += 1,
            Ok(_) => panic!("the refund is never allowed in this estate"),
            Err(e) => panic!("{e}"),
        }
    }

    let outcome = service
        .invoke(&other, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("another session's execution is not wedged");
    assert!(matches!(outcome, InvokeOutcome::Allowed { .. }));
    assert_eq!(denied + refused, 70_000);
    assert!(denied <= 100, "one session records a bounded run of denials, recorded {denied}");
    assert!(store.audit_len().unwrap() < 1_000, "the chain holds {}", store.audit_len().unwrap());
}
