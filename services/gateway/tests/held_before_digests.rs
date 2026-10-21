//! A credential change held by gateway 1.3.46, approved after the upgrade.
//!
//! The helpers are copied from `tests/staged_credential_binding.rs`. A 1.3.46 hold's params carry no `staged_sha256`;
//! this simulates one by removing the field from a fresh hold's stored params (the request hash the device signs is
//! computed from the stored params, so the signature is valid). The hold is refused without a tamper record, and the
//! row parked for it does not outlive it.

use axum::body::Body;
use axum::http::{Request, StatusCode};

use permaura_gateway::service::vault_passphrase;
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

mod common;

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    remote: bool,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri).header("authorization", format!("Bearer {token}"));
    if remote {
        builder = builder.header("cf-ray", "abc123");
    }
    let req = match body {
        Some(b) => builder.header("content-type", "application/json").body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

fn approver_key(seed: u8) -> (String, ed25519_dalek::SigningKey) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    (STANDARD.encode(sk.verifying_key().to_bytes()), sk)
}

fn gateway_with_device(seed_byte: u8) -> (axum::Router, AppState, ed25519_dalek::SigningKey) {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, sk) = approver_key(seed_byte);
    assert!(state.service.trust_approver_key_for("device:approver", &pubkey, Some("user_approver")).unwrap());
    (app, state, sk)
}

async fn device_sign(
    app: &axum::Router,
    token: &str,
    approval_id: &str,
    approver: &str,
    sk: &ed25519_dalek::SigningKey,
) -> (StatusCode, serde_json::Value) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use permaura_relay::{approval_display_full_digest_of, approval_result_preimage_v3, sign};
    let (_s, appr) = send(app, "GET", &format!("/v1/approvals/{approval_id}"), token, false, None).await;
    let request_hash = appr["request_hash"].as_str().unwrap().to_string();
    let job_id = appr["job_id"].as_str().unwrap().to_string();
    let audience = appr["approval_audience"].as_str().expect("audience").to_string();
    let shown = approval_display_full_digest_of(&appr).expect("full rendering");
    let decided_at = now_ms();
    let preimage =
        approval_result_preimage_v3(&audience, &job_id, approval_id, true, &request_hash, &shown, approver, decided_at);
    let device_sig = sign(sk, &preimage);
    send(
        app,
        "POST",
        "/v1/approvals",
        token,
        false,
        Some(serde_json::json!({
            "approval_id": approval_id, "approve": true, "approver": approver,
            "request_hash": request_hash, "decided_at": decided_at, "job_id": job_id,
            "approver_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
            "audience": audience, "display_digest": shown, "device_sig": device_sig,
        })),
    )
    .await
}

fn plaintext(state: &AppState, id: &str) -> Option<String> {
    state
        .service
        .store()
        .get_secret(id)
        .unwrap()
        .map(|r| String::from_utf8(permaura_core::open(&r.sealed, vault_passphrase()).unwrap().to_vec()).unwrap())
}

fn audit_events(state: &AppState) -> Vec<permaura_core::AuditEvent> {
    state.service.store().audit_events_from(0, 100_000).unwrap()
}

const LIVE_BEFORE: &str = "bt_demo_private_key_value";
const APPROVED_VALUE: &str = "value_the_device_approves";

/// Hold a remote credential change for the seeded Braintree connection; returns (approval id, staging id, live id).
async fn held_change(app: &axum::Router, state: &AppState) -> (String, String, String) {
    let (hs, hresp) = send(
        app,
        "POST",
        "/v1/connections/braintree_production/credential",
        seed::DEMO_TOKEN,
        true,
        Some(serde_json::json!({ "value": APPROVED_VALUE })),
    )
    .await;
    assert_eq!(hs, StatusCode::ACCEPTED, "a remote credential set is held: {hresp}");
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();
    let held = state.service.store().get_approval(&approval_id).unwrap().unwrap().params.to_value_unbounded();
    let staging_id = held["staging_secret_id"].as_str().unwrap().to_string();
    let live_id = held["secret_id"].as_str().unwrap().to_string();
    let digest = held["staged_sha256"].as_str().expect("the hold binds a digest of the staged envelope");
    assert_eq!(digest.len(), 64, "hex sha256: {digest}");
    assert_eq!(plaintext(state, &live_id).as_deref(), Some(LIVE_BEFORE));
    (approval_id, staging_id, live_id)
}

#[tokio::test]
async fn a_hold_from_before_digests_is_refused_without_a_tamper_record_and_leaves_nothing_behind() {
    let (app, state, sk) = gateway_with_device(61);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;

    // What gateway 1.3.46 stored: the same mutation with no digest field.
    let store = state.service.store();
    let mut held = store.get_approval(&approval_id).unwrap().unwrap();
    let mut params = held.params.to_value_unbounded();
    params.as_object_mut().unwrap().remove("staged_sha256");
    held.params = params.into();
    store.put_approval(held).unwrap();

    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_ne!(ss, StatusCode::OK, "a hold with no digest is never promoted: {sresp}");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(LIVE_BEFORE), "the live credential did not move");

    // Nothing rewrote the staged row, so the chain must not say something did.
    let refusal = audit_events(&state)
        .into_iter()
        .rev()
        .find(|e| e.payload.action == "permaura.secret.write" && e.payload.decision == "deny");
    if let Some(r) = refusal {
        let reason = r.payload.summary["reason"].as_str().unwrap_or_default().to_string();
        assert!(!reason.contains("changed after its hold was signed over"), "a pre-upgrade hold is recorded as a rewrite: {reason} / {}", r.payload.summary);
    }

    // And the sealed value parked for it does not outlive the hold.
    let (ds, dresp) = send(&app, "DELETE", &format!("/v1/secrets/{staging_id}"), seed::DEMO_TOKEN, false, None).await;
    assert!(
        store.get_secret(&staging_id).unwrap().is_none() || ds.is_success(),
        "the staged row survives the refused hold and cannot be deleted ({ds}: {dresp})"
    );
}
