//! `/health` as a health *document*, not just a liveness ping.
//!
//! Each field here answers a question that is otherwise unaskable over the wire: without an operator
//! token, without the CLI, and through a tunnel. The point of testing them is that they are load
//! bearing for triage: a demo gateway that reports `posture: real`, or a worker on the public dev KEK
//! that reports `vault_kek: real`, is worse than no field at all, because it stops anyone looking.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::store::PendingApproval;
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

async fn health(state: AppState) -> serde_json::Value {
    let token = common::operator_token(state.clone()).await;
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
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Seed a held approval that was created `age_ms` ago.
fn hold(state: &AppState, id: &str, age_ms: i64) {
    state
        .service
        .store()
        .put_approval(PendingApproval {
            id: id.into(),
            session_id: "sess_health".into(),
            capability: "braintree.transactions.search".into(),
            resource: "braintree_production".into(),
            message: "Approve the held call?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({}).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: now_ms() - age_ms,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
}

#[tokio::test]
async fn the_document_names_the_build_and_the_backend() {
    let json = health(common::seeded()).await;

    // Not asserting a particular sha, only that the field exists and is not the `unknown` sentinel
    // that build.rs falls through to, which would mean the stamping broke.
    let sha = json["build_sha"].as_str().expect("build_sha is a string");
    assert!(!sha.is_empty(), "build_sha must not be empty");

    assert_eq!(json["store_kind"], "memory");
    // The seeded estate is mock transports over a public operator bearer: it must say so.
    assert_eq!(json["posture"], "demo");

    // Which of the two it is depends on what this machine has in `$PERMAURA_HOME`, so the assertion
    // here is that it is one of the two documented spellings and never something a monitor would have
    // to guess at. `health_vault_kek.rs` pins the injected-passphrase case, which is the one that
    // matters (a live worker sealing under the public dev constant).
    let kek = json["vault_kek"].as_str().expect("vault_kek is a string");
    assert!(kek == "real" || kek == "dev", "unexpected vault_kek: {kek}");
}

/// The document says whether a tunnel connector runs pinned to the configuration this machine wrote. This process runs no connector, so both fields are present and null; `permaura start` sets `tunnel_ingress` to `local` when it starts the connector, and to `stopped`, with the reason in `tunnel_stop_reason`, if its guard or `permaura remote disable` ever stops it. `remote_tokens` says whether permaura.com tokens are accepted, null here since this gateway has no resource server.
#[tokio::test]
async fn the_document_states_whether_the_tunnel_connector_is_pinned() {
    let json = health(common::seeded()).await;
    for field in ["tunnel_ingress", "tunnel_stop_reason", "remote_tokens"] {
        assert!(json.get(field).is_some(), "`{field}` is always present: {json}");
        assert!(json[field].is_null(), "no connector runs in a test process: {json}");
    }
}

#[tokio::test]
async fn an_unchecked_release_channel_reports_null_not_current() {
    // The whole point of the tri-state: an install that has never reached the manifest must not be
    // indistinguishable from one that checked and is current.
    let json = health(common::seeded()).await;
    assert!(
        json["manifest_behind"].is_null(),
        "expected null, got {}",
        json["manifest_behind"]
    );
}

#[tokio::test]
async fn a_quiet_queue_is_zero_and_zero() {
    let json = health(common::seeded()).await;
    assert_eq!(json["approvals_pending"], 0);
    assert_eq!(json["approvals_stalled"], 0);
}

#[tokio::test]
async fn a_fresh_hold_is_pending_but_not_yet_stalled() {
    let state = common::seeded();
    hold(&state, "appr_fresh", 60_000);
    let json = health(state).await;
    assert_eq!(json["approvals_pending"], 1);
    assert_eq!(json["approvals_stalled"], 0);
}

#[tokio::test]
async fn a_hold_older_than_the_threshold_is_stalled() {
    // Approvals never expire (APPROVAL_TTL_MS is 0), so depth alone cannot distinguish "a human is
    // deciding" from "nobody was ever notified". This is the field that separates them.
    let state = common::seeded();
    hold(&state, "appr_fresh", 60_000);
    hold(&state, "appr_stale", 45 * 60_000);
    let json = health(state).await;
    assert_eq!(json["approvals_pending"], 2);
    assert_eq!(json["approvals_stalled"], 1);
}

#[tokio::test]
async fn a_resolved_hold_leaves_the_queue() {
    let state = common::seeded();
    hold(&state, "appr_done", 45 * 60_000);
    state
        .service
        .store()
        .set_approval_status("appr_done", "approved")
        .unwrap();
    let json = health(state).await;
    assert_eq!(json["approvals_pending"], 0);
    assert_eq!(json["approvals_stalled"], 0);
}

#[tokio::test]
async fn the_counts_never_name_what_is_being_approved() {
    // `/health` is unauthenticated. A depth is operational; the capability, resource or message
    // would tell an anonymous caller what an operator is currently being asked to authorise.
    let state = common::seeded();
    hold(&state, "appr_secret", 1000);
    let json = health(state).await;
    let doc = serde_json::to_string(&json).unwrap();
    assert!(!doc.contains("braintree_production"), "leaked a resource: {doc}");
    assert!(!doc.contains("Approve the held call"), "leaked a message: {doc}");
    assert!(!doc.contains("appr_secret"), "leaked an approval id: {doc}");
}

/// The document is a fingerprint, so a stranger gets liveness and nothing else.
///
/// Version and `build_sha` say exactly which build to look up, `manifest_behind` says it is an old
/// one, and the counts describe how the operator uses it. None of that was reachable while the
/// hostname was a hash nobody could guess; a gateway can be given a readable name now, so the
/// hostname stopped being the thing keeping strangers out.
#[tokio::test]
async fn an_unauthenticated_caller_gets_liveness_and_no_fingerprint() {
    let resp = build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    // Still 200: an uptime check must be able to tell a live gateway from a dead one, and only this
    // gateway answers with this body, so it still proves the gateway itself is up, not just the edge.
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "permaura-gateway");
    for leaked in [
        "version",
        "build_sha",
        "manifest_behind",
        "posture",
        "store_kind",
        "vault_kek",
        "agents",
        "grants",
        "capabilities",
        "approvals_pending",
        "approvals_stalled",
        "audit_chain_intact",
        "tunnel_ingress",
        "tunnel_stop_reason",
        "remote_tokens",
    ] {
        assert!(
            json.get(leaked).is_none(),
            "`{leaked}` must not be readable without a token",
        );
    }
}
