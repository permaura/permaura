//! A self-run gateway proves on `/health` that it stores the bearer a client is about to present, keyed on the digest it keeps in place of that bearer, so a client can refuse to hand an agent token or an enrolment code to a listener that is not its gateway (the agent-token sibling of the operator-token proof). The proof covers a live session and an enrolment code not yet redeemed, and nothing revoked, expired or unknown.
//!
//! Every token here is synthetic.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::health_proof::{bearer_digest, bearer_key, verify_bearer_proof, BEARER_KEY_HEADER, BEARER_PROOF_HEADER, CHALLENGE_HEADER};
use permaura_gateway::store::EnrolmentCode;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::Value;
use tower::ServiceExt;

mod common;

const PORT: u16 = 7376;
const CHALLENGE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `/health` asked with a challenge and the key of `bearer`, never the bearer itself; the proof it carries, if any.
async fn proof_for(state: &AppState, bearer: &str) -> Option<String> {
    proof_for_from(state, bearer, None).await
}

/// [`proof_for`], with the request forwarded for `forwarded_for` when one is given, as a tunnel or a reverse proxy marks it.
async fn proof_for_from(state: &AppState, bearer: &str, forwarded_for: Option<&str>) -> Option<String> {
    let app = build_router(state.clone(), format!("127.0.0.1:{PORT}").parse().unwrap());
    let mut req = Request::builder().uri("/health");
    if let Some(peer) = forwarded_for {
        req = req.header("x-forwarded-for", peer);
    }
    let req = req
        .header(CHALLENGE_HEADER, CHALLENGE)
        .header(BEARER_KEY_HEADER, bearer_key(&bearer_digest(bearer)))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let proof = resp.headers().get(BEARER_PROOF_HEADER).map(|v| v.to_str().unwrap().to_string());
    let body: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["service"], "permaura-gateway");
    proof
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

#[tokio::test]
async fn a_self_run_gateway_proves_the_bearers_it_stores_and_no_other() {
    let state = common::seeded();
    let store = state.service.store();

    let agent = seed::DEMO_TOKEN;
    let proof = proof_for(&state, agent).await.expect("a live session's bearer is proved");
    assert!(verify_bearer_proof(agent, PORT, CHALLENGE, &proof));
    assert!(!verify_bearer_proof(agent, PORT + 1, CHALLENGE, &proof), "bound to the port it was asked on");

    let code = "ENRL-0000-1111-2222-3333-4444-5555-6666-7777";
    store
        .put_enrolment_code(EnrolmentCode { code: code.into(), label: None, created_at: now_ms(), expires_at: now_ms() + 60_000, used: false })
        .unwrap();
    let proof = proof_for(&state, code).await.expect("a code not yet redeemed is proved, so its first call can be checked too");
    assert!(verify_bearer_proof(code, PORT, CHALLENGE, &proof));

    let expired = "ENRL-8888-9999-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF";
    store
        .put_enrolment_code(EnrolmentCode { code: expired.into(), label: None, created_at: 1, expires_at: 2, used: false })
        .unwrap();
    assert_eq!(proof_for(&state, expired).await.as_deref(), Some("none"), "an expired code is not proved: the gateway says it holds none");
    assert_eq!(proof_for(&state, "tok_never_issued").await.as_deref(), Some("none"), "nor a bearer it never issued");

    let id = store.session_by_token(agent).unwrap().unwrap().id;
    assert!(store.revoke_session(&id).unwrap());
    assert_eq!(proof_for(&state, agent).await.as_deref(), Some("none"), "nor a revoked one");
}

/// A gateway that understands the question but holds no live match says so (`none`), so a client can tell a token to enrol again from a listener that gives no proof at all (an older gateway, or not a gateway).
#[tokio::test]
async fn a_bearer_the_gateway_does_not_hold_is_answered_none() {
    let state = common::seeded();
    let answer = proof_for(&state, "tok_never_issued").await;
    assert_eq!(answer.as_deref(), Some("none"));
    assert!(!verify_bearer_proof("tok_never_issued", PORT, CHALLENGE, "none"));
}

/// A request from off this machine (through a tunnel, a proxy, or a web page) is answered no bearer proof: the scan it costs runs under the store lock every agent call needs, and only a client on this machine has any use for the answer.
#[tokio::test]
async fn a_remote_request_is_answered_no_bearer_proof() {
    let state = common::seeded();
    assert!(proof_for(&state, seed::DEMO_TOKEN).await.is_some(), "the control: asked on this machine, it is proved");
    assert_eq!(proof_for_from(&state, seed::DEMO_TOKEN, Some("203.0.113.9")).await, None, "asked through a forwarder, it is not");
}
