//! A request a web page sent is remote, whatever its peer address.
//!
//! permaura.com's console reaches a loopback-only self-run gateway straight from the browser, carrying
//! the stored operator bearer, so its TCP peer is loopback and nothing else marked it as coming from
//! off the machine. Code served by permaura.com was treated as the owner at the keyboard: it enrolled
//! the first approver key (and was handed the recovery codes) and applied every loosening edit without
//! the device hold a tunnelled call gets. Browsers always send `Origin` on the cross-origin fetch that
//! path uses, and the gateway's own clients send none, so `Origin` is the signal.
//!
//! Every key, token and host here is synthetic.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const CONSOLE: (&str, &str) = ("origin", "https://permaura.com");

/// What each local client puts on the wire, read off the clients themselves: the CLI and the desktop
/// supervisor are reqwest with no default headers, mcp-stdio is Node's fetch (captured from Node 20,
/// 22 and 26: no `Origin`, and `sec-fetch-mode: cors`), and the desktop app's webview fetches with its
/// own app origin, which no web page can send.
fn local_clients() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("cli", vec![]),
        ("desktop supervisor", vec![]),
        (
            "mcp-stdio",
            vec![
                ("accept", "*/*"),
                ("accept-language", "*"),
                ("sec-fetch-mode", "cors"),
                ("user-agent", "node"),
            ],
        ),
        ("desktop app webview", vec![("origin", "tauri://localhost")]),
    ]
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn pair_body(approver_id: &str, sk: &SigningKey) -> Value {
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = now_ms();
    let preimage = permaura_relay::approver_pairing_preimage(approver_id, &pubkey, issued_at);
    json!({
        "approver_id": approver_id,
        "approver_pubkey": pubkey,
        "issued_at": issued_at,
        "sig": permaura_relay::sign(sk, &preimage),
    })
}

fn pair_a_device(state: &AppState) {
    let sk = SigningKey::from_bytes(&[61; 32]);
    assert!(state.service.trust_approver_key("device:owner", &STANDARD.encode(sk.verifying_key().to_bytes())));
}

/// One request through the real router with no peer address, which the gateway reads as loopback.
async fn send(
    state: &AppState,
    method: &str,
    uri: &str,
    body: Value,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "127.0.0.1:7376")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let resp = app.oneshot(builder.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn widening_policy(id: &str) -> Value {
    json!({ "id": id, "connection_id": "generic_http", "name": id, "allow": ["request"] })
}

fn has_policy(state: &AppState, id: &str) -> bool {
    state.service.store().list_policies().unwrap().iter().any(|p| p.id == id)
}

/// The trust-root takeover: with no device paired, the console's bearer enrolled a key of the
/// page's own choosing over loopback and the response carried the recovery codes.
#[tokio::test]
async fn a_web_page_cannot_enrol_the_first_device() {
    let state = common::seeded();
    let sk = SigningKey::from_bytes(&[62; 32]);
    let (status, body) =
        send(&state, "POST", "/v1/approver-keys/pair", pair_body("device:page", &sk), &[CONSOLE]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("loopback-only"), "{body}");
    assert!(body.get("recovery_codes").is_none(), "{body}");
    assert!(!state.service.any_device_trusted(), "nothing may be trusted on a page's say-so");
}

/// With a device paired, a loosening edit from the page waits for that device, exactly as it does when
/// the same console reaches the gateway through the tunnel.
#[tokio::test]
async fn a_web_page_loosening_a_policy_is_held_for_the_device() {
    let state = common::seeded();
    pair_a_device(&state);
    let (status, body) = send(&state, "POST", "/v1/policies", widening_policy("p_page"), &[CONSOLE]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "requires_approval", "{body}");
    assert_eq!(body["required_tier"], "device_signed", "{body}");
    assert_eq!(body["message"], permaura_gateway::rest::HELD_REQUESTED_NOTE, "{body}");
    assert!(body["approval_id"].as_str().is_some_and(|id| id.starts_with("appr_")), "{body}");
    assert!(!has_policy(&state, "p_page"), "nothing applied before the device signed");
}

/// Replacing a connection's credential from the page is held by reference instead of sealed live.
#[tokio::test]
async fn a_web_page_replacing_a_credential_is_held_for_the_device() {
    let state = common::seeded();
    pair_a_device(&state);
    let store = state.service.store();
    let secret_id = store.get_connection("github_acme").unwrap().unwrap().secret_id;
    let before = store.get_secret(&secret_id).unwrap().map(|s| s.sealed);
    assert!(before.is_some(), "the seeded connection has a live credential to protect");
    let (status, body) = send(
        &state,
        "POST",
        "/v1/connections/github_acme/credential",
        json!({ "value": "synthetic-replacement" }),
        &[CONSOLE],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "requires_approval", "{body}");
    let after = store.get_secret(&secret_id).unwrap().map(|s| s.sealed);
    assert_eq!(after, before, "the live credential is untouched while the hold waits");
}

/// The credential-free session primitive is loopback-only, and a page is not loopback.
#[tokio::test]
async fn a_web_page_cannot_open_an_operator_session() {
    let state = common::seeded();
    let (status, body) = send(&state, "POST", "/v1/sessions", json!({ "agent_id": "codex-cli" }), &[CONSOLE]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// Every browser origin is a page, including the console's own and the development ones.
#[tokio::test]
async fn every_web_origin_is_held() {
    for origin in [
        "https://permaura.com",
        "https://www.permaura.com",
        "https://permaura.lan",
        "http://localhost:3102",
        "http://localhost:1420",
        "https://attacker.example",
        "null",
    ] {
        let state = common::seeded();
        pair_a_device(&state);
        let (status, body) =
            send(&state, "POST", "/v1/policies", widening_policy("p_origin"), &[("origin", origin)]).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{origin}: {body}");
        assert!(!has_policy(&state, "p_origin"), "{origin}");
    }
}

/// The controls: the gateway's own clients are still the owner at the host.
#[tokio::test]
async fn local_clients_keep_loopback_authority() {
    for (client, headers) in local_clients() {
        let state = common::seeded();
        let sk = SigningKey::from_bytes(&[63; 32]);
        let (status, body) =
            send(&state, "POST", "/v1/approver-keys/pair", pair_body("device:first", &sk), &headers).await;
        assert_eq!(status, StatusCode::OK, "{client} enrols the first device over loopback: {body}");
        assert!(state.service.any_device_trusted(), "{client}");

        let (status, body) = send(&state, "POST", "/v1/policies", widening_policy("p_local"), &headers).await;
        assert_eq!(status, StatusCode::CREATED, "{client} applies a loosening edit at once: {body}");
        assert!(has_policy(&state, "p_local"), "{client}");

        let (status, body) =
            send(&state, "POST", "/v1/sessions", json!({ "agent_id": "codex-cli" }), &headers).await;
        assert_eq!(status, StatusCode::CREATED, "{client} still opens a session: {body}");
    }
}

/// With no device paired there is no hold to place, and only what reaches a credential already here is
/// refused (export, a reaching import, taking over a sealed slot, an SSH retarget). Every other edit,
/// loosening included, still applies from the console, so an unpaired gateway can be set up there.
#[tokio::test]
async fn an_unpaired_gateway_still_takes_a_loosening_edit_from_a_page() {
    let state = common::seeded();
    assert!(!state.service.any_device_trusted());
    let (status, body) = send(&state, "POST", "/v1/policies", widening_policy("p_unpaired"), &[CONSOLE]).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(has_policy(&state, "p_unpaired"));
}
