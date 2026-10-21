//! The held-approval ceiling, driven through the real router.
//!
//! `store/memory.rs` has long capped held approvals at 1024, naming the
//! threat in its own comment ("a remote memory-DoS"). `store/sqlite.rs` had no cap, and SQLite is
//! what every hosted worker runs, and a mitigation present only in the store nobody runs in production
//! is worse than none, because it reads as covered. Both stores now refuse the same way, and this
//! file is about what an agent and a human each see when they meet it.
//!
//! Every credential and transport here is synthetic.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::ExecutionLocation;
use permaura_gateway::store::{PendingApproval, MAX_PENDING_APPROVALS};
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt; // for `oneshot`

mod common;

fn app(state: AppState) -> axum::Router {
    build_router(state, "127.0.0.1:7376".parse().unwrap())
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// A hold as the enforcement loop records one.
fn filler(id: &str) -> PendingApproval {
    PendingApproval {
        id: id.into(),
        session_id: "sess_demo".into(),
        capability: "github.pull_requests.create".into(),
        resource: "github_acme".into(),
        message: "Approve?".into(),
        status: "pending".into(),
        grant_id: None,
        policy_id: None,
        params: serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }).into(),
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
    }
}

/// An agent whose call would be held at the ceiling gets a clean, specific refusal rather than a
/// 500 or a silently dropped hold, and a human can still resolve what is already queued, which is
/// the only thing that ever brings the queue back down.
#[tokio::test]
async fn at_the_cap_an_agent_is_refused_cleanly_and_a_human_can_still_resolve() {
    let state = common::seeded();
    let store = state.service.store().clone();
    let session = store.get_session("sess_demo").unwrap().unwrap();

    // One real hold, created the way the enforcement loop creates them: `pull_requests.create` is
    // High risk, so the engine escalates it to a human without the policy naming it.
    let held = state
        .service
        .invoke(
            &session,
            "github.pull_requests.create",
            &serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }),
            Some("synthetic"),
            ExecutionLocation::LocalOnly,
        )
        .await
        .expect("the first hold is well under the cap");
    let approval_id = match held {
        permaura_gateway::service::InvokeOutcome::RequiresApproval { approval, .. } => approval.id,
        _ => panic!("a High-risk capability must be escalated to a human"),
    };

    // Fill the rest of the queue.
    for i in 0..(MAX_PENDING_APPROVALS - 1) {
        store.put_approval(filler(&format!("appr_filler_{i}"))).unwrap();
    }
    assert_eq!(store.list_approvals(Some("pending")).unwrap().len(), MAX_PENDING_APPROVALS);

    // The agent's next call would need a hold, and there is nowhere to put it.
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "capability": "github.pull_requests.create",
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
    assert!(resp.headers().contains_key("retry-after"));
    let body = body_json(resp).await;
    assert_eq!(
        body["reason"], "approval_backlog",
        "the agent is told which ceiling it met, not just that it met one"
    );
    assert_eq!(
        store.list_approvals(Some("pending")).unwrap().len(),
        MAX_PENDING_APPROVALS,
        "a refusal writes nothing: on a hosted worker a write here is a full snapshot upload"
    );

    // The human's side. Resolving is an update to a row that is already there, so it works at the
    // ceiling, and it has to, because it is the only thing that clears it.
    let token = common::operator_token(state.clone()).await;
    let resp = app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/approvals")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "approval_id": approval_id, "approve": false }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "a human must be able to clear the queue");
    assert_eq!(store.get_approval(&approval_id).unwrap().unwrap().status, "denied");
    assert_eq!(
        store.list_approvals(Some("pending")).unwrap().len(),
        MAX_PENDING_APPROVALS - 1,
        "and the slot it freed is real"
    );
}
