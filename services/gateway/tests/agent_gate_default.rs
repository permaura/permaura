//! The new-agent gate end to end on a self-run gateway with a public URL: real permaura.com-shaped tokens through the resource server and the router.
//!
//! The new-agent gate is on by default from the moment the first device is paired, an agent approved before that keeps working, turning the gate off from off the host waits for the device, and an operator's stored choice outlives the pairing. Every credential is synthetic; the environment is process-global, so it is set once for this binary.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{AgentStatus, Store};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const OWNER_SUB: &str = "user_owner";
const PUBLIC_URL: &str = "https://g-gate.permaura.test";
const AS_ISSUER: &str = "https://permaura.test/api/auth";
const AS_KID: &str = "agent-gate-test-key";
const FLIP: &str = "permaura.agent_gate.default";

fn as_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[47u8; 32])
}

fn oauth_environment() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        common::isolate_from_the_real_install();
        let jwks = json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "kid": AS_KID, "use": "sig", "alg": "EdDSA",
                "x": URL_SAFE_NO_PAD.encode(as_signing_key().verifying_key().to_bytes()),
            }]
        })
        .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local JWKS listener");
        let port = listener.local_addr().expect("JWKS listener address").port();
        std::thread::spawn(move || serve_jwks(listener, jwks));
        std::env::set_var("PERMAURA_PUBLIC_URL", PUBLIC_URL);
        std::env::set_var("PERMAURA_AS_ISSUER", AS_ISSUER);
        std::env::set_var("PERMAURA_AS_JWKS", format!("http://127.0.0.1:{port}/jwks"));
        std::env::set_var("PERMAURA_OWNER_SUB", OWNER_SUB);
    });
}

fn serve_jwks(listener: TcpListener, body: String) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut scratch = [0u8; 2048];
        let _ = stream.read(&mut scratch);
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn sign(claims: Value) -> String {
    let header = json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" });
    let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = as_signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn agent_token(azp: &str) -> String {
    sign(json!({
        "iss": AS_ISSUER, "sub": OWNER_SUB, "aud": format!("{PUBLIC_URL}/mcp"), "azp": azp,
        "iat": now_secs(), "exp": now_secs() + 600, "scope": "openid mcp offline_access", "name": azp,
    }))
}

fn console_token() -> String {
    sign(json!({
        "iss": AS_ISSUER, "sub": OWNER_SUB, "aud": format!("{PUBLIC_URL}/mcp"),
        "exp": now_secs() + 600, "scope": "permaura:operator",
    }))
}

async fn worker() -> AppState {
    oauth_environment();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let oauth = permaura_gateway::oauth::RsConfig::from_env()
        .map(|cfg| Arc::new(permaura_gateway::oauth::OAuthRs::new(cfg)))
        .expect("PERMAURA_PUBLIC_URL makes this gateway a resource server");
    oauth.refresh().await;
    let backend = permaura_gateway::backend::build_backend(store.clone());
    AppState::new(EnforcementService::from_components(
        store,
        Arc::new(MockHttpClient::new()),
        Arc::new(permaura_gateway::connectors::MockCommandRunner::new()),
        backend,
        Some(oauth),
    ))
}

async fn call(state: &AppState, token: &str, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut builder = Request::builder().method(method).uri(uri).header("authorization", format!("Bearer {token}"));
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Pair over loopback with a real possession proof, as the desktop app does on the gateway's own machine.
async fn pair(state: &AppState, approver_id: &str, seed_byte: u8) {
    let sk = SigningKey::from_bytes(&[seed_byte; 32]);
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = now_secs() * 1000;
    let preimage = permaura_relay::approver_pairing_preimage(approver_id, &pubkey, issued_at);
    let body = json!({
        "approver_id": approver_id, "approver_pubkey": pubkey, "issued_at": issued_at,
        "sig": permaura_relay::sign(&sk, &preimage),
    });
    let (status, resp) = call(state, seed::DEMO_TOKEN, "POST", "/v1/approver-keys/pair", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "setup: the first device pairs over loopback: {resp}");
}

async fn connect(state: &AppState, azp: &str) -> AgentStatus {
    let (status, body) = call(state, &agent_token(azp), "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK, "{azp} connects: {body}");
    state.service.store().get_agent(&format!("oauth:{azp}")).unwrap().expect("registered").status
}

async fn gate(state: &AppState) -> (Value, Value) {
    let (status, broker) = call(state, seed::DEMO_TOKEN, "GET", "/v1/broker", None).await;
    assert_eq!(status, StatusCode::OK, "{broker}");
    (broker["require_agent_approval"].clone(), broker["require_agent_approval_source"].clone())
}

fn flips(state: &AppState) -> usize {
    state.service.store().audit_events(None).unwrap().iter().filter(|e| e.payload.action == FLIP).count()
}

#[tokio::test]
async fn a_public_gateway_gates_new_agents_from_its_first_device_on() {
    let state = worker().await;
    assert_eq!(gate(&state).await, (json!(false), json!("default")), "no device yet: off, as before");
    assert_eq!(connect(&state, "client-early").await, AgentStatus::Approved);

    pair(&state, "device:owner", 51).await;
    assert_eq!(gate(&state).await, (json!(true), json!("default")), "the paired device is now the gate");
    assert_eq!(flips(&state), 1, "the flip is in the audit chain");
    assert_eq!(connect(&state, "client-late").await, AgentStatus::Pending);
    assert_eq!(connect(&state, "client-early").await, AgentStatus::Approved, "approved before, unaffected");
}

#[tokio::test]
async fn turning_the_default_gate_off_from_off_the_host_is_held() {
    let state = worker().await;
    pair(&state, "device:owner", 52).await;
    let (status, resp) = call(
        &state,
        &console_token(),
        "POST",
        "/v1/broker/require-approval",
        Some(json!({ "require_agent_approval": false })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "turning the gate off from the console waits for the device: {resp}");
    assert_eq!(resp["required_tier"], "device_signed");
    assert_eq!(gate(&state).await, (json!(true), json!("default")), "still on until the device signs");
    assert_eq!(connect(&state, "client-late").await, AgentStatus::Pending);
}

/// Set at the host before any device existed: confirmed by nobody a device holder controls, and loopback is where a same-user agent stands too, so the first device returns the gate to its default.
#[tokio::test]
async fn a_false_stored_before_any_device_is_cleared_by_the_first_pairing() {
    let state = worker().await;
    let (status, resp) = call(
        &state,
        seed::DEMO_TOKEN,
        "POST",
        "/v1/broker/require-approval",
        Some(json!({ "require_agent_approval": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(gate(&state).await, (json!(false), json!("stored")));

    pair(&state, "device:owner", 53).await;
    assert_eq!(gate(&state).await, (json!(true), json!("default")), "the unanchored choice is cleared");
    assert_eq!(flips(&state), 1);
    assert_eq!(connect(&state, "client-late").await, AgentStatus::Pending);
}

#[tokio::test]
async fn the_environment_switch_is_reported_as_such() {
    let state = worker().await;
    state.service.require_agent_approval_for_this_run();
    assert_eq!(gate(&state).await, (json!(true), json!("environment")));
}
