//! Naming the workspace member behind a shared operator identity, end to end.
//!
//! permaura.com mints every operator token for a hosted gateway with the owner's `sub`, whichever
//! member is acting, and names that member in `act_sub`/`act_name`. These drive a real signed token
//! through the resource server and the router, and pin what the audit chain records from it.
//!
//! Every credential here is synthetic. The environment is process-global, so it is set once for the
//! whole binary before any state exists.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{SessionActor, Store};
use common::build_router;
use permaura_gateway::{seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const OWNER_SUB: &str = "user_owner";
const PUBLIC_URL: &str = "https://g-acting.permaura.test";
const AS_ISSUER: &str = "https://permaura.test/api/auth";
const AS_KID: &str = "acting-member-test-key";

fn as_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[41u8; 32])
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
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The operator token the console mints for a proxied call, optionally naming the acting member.
fn console_token(actor: Option<(&str, &str)>) -> String {
    let mut claims = json!({
        "iss": AS_ISSUER,
        "sub": OWNER_SUB,
        "aud": format!("{PUBLIC_URL}/mcp"),
        "exp": now_secs() + 600,
        "scope": "permaura:operator",
    });
    if let Some((sub, name)) = actor {
        claims["act_sub"] = json!(sub);
        claims["act_name"] = json!(name);
    }
    let header = json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" });
    let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = as_signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

async fn worker() -> AppState {
    oauth_environment();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = Arc::new(MockHttpClient::with_response(HttpResponse::json(201, json!({}))));
    let oauth = permaura_gateway::oauth::RsConfig::from_env()
        .map(|cfg| Arc::new(permaura_gateway::oauth::OAuthRs::new(cfg)))
        .expect("PERMAURA_PUBLIC_URL makes this gateway a resource server");
    oauth.refresh().await;
    let backend = permaura_gateway::backend::build_backend(store.clone());
    AppState::new(EnforcementService::from_components(
        store,
        http,
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

async fn held(state: &AppState) -> String {
    let session = state.service.store().get_session("sess_demo").unwrap().expect("the demo session");
    let params = json!({ "owner": "synthetic", "repo": "synthetic" });
    match state
        .service
        .invoke(&session, "github.pull_requests.create", &params, Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("the call is admitted")
    {
        InvokeOutcome::RequiresApproval { approval, .. } => approval.id,
        _ => panic!("a High-risk capability must be escalated to a human"),
    }
}

fn summary_of(state: &AppState, decision: &str) -> Value {
    let events = state.service.store().audit_events(None).unwrap();
    let found: Vec<_> = events.iter().filter(|e| e.payload.decision == decision).collect();
    assert_eq!(found.len(), 1, "exactly one {decision} event");
    found[0].payload.summary.clone()
}

#[tokio::test]
async fn a_member_approving_through_permaura_com_is_named() {
    let state = worker().await;
    let approval_id = held(&state).await;
    let token = console_token(Some(("user_priya", "Priya Raman")));
    let (status, body) =
        call(&state, &token, "POST", "/v1/approvals", Some(json!({ "approval_id": approval_id, "approve": true }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let summary = summary_of(&state, "approved");
    assert_eq!(summary["method"], "bearer");
    assert_eq!(summary["approver"], format!("operator:{OWNER_SUB}"), "the identity the token proves is unchanged");
    assert_eq!(summary["approver_actor"], "user_priya");
    assert_eq!(summary["approver_name"], "Priya Raman");
}

#[tokio::test]
async fn a_member_denying_through_permaura_com_is_named() {
    let state = worker().await;
    let approval_id = held(&state).await;
    let token = console_token(Some(("user_priya", "Priya Raman")));
    call(&state, &token, "POST", "/v1/approvals", Some(json!({ "approval_id": approval_id, "approve": false }))).await;
    let summary = summary_of(&state, "denied");
    assert_eq!(summary["approver_actor"], "user_priya");
    assert_eq!(summary["approver_name"], "Priya Raman");
}

/// A token that named nobody records nobody. Absent is "not named", and nothing may fill it in with
/// the owner the token was addressed to.
#[tokio::test]
async fn a_token_that_names_nobody_records_nobody() {
    let state = worker().await;
    let approval_id = held(&state).await;
    let (status, body) = call(
        &state,
        &console_token(None),
        "POST",
        "/v1/approvals",
        Some(json!({ "approval_id": approval_id, "approve": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let summary = summary_of(&state, "approved");
    assert_eq!(summary["approver"], format!("operator:{OWNER_SUB}"));
    assert!(summary.get("approver_actor").is_none(), "{summary}");
    assert!(summary.get("approver_name").is_none(), "{summary}");
}

/// A signed resolution is the device's. An actor handed alongside it is not recorded as the
/// approver, and the device's own name is not replaced by a person's.
#[tokio::test]
async fn a_signed_approval_is_not_attributed_to_the_relaying_member() {
    let state = worker().await;
    let token = console_token(Some(("user_priya", "Priya Raman")));
    let (status, _) = call(
        &state,
        &token,
        "POST",
        "/v1/devices/enroll",
        Some(json!({ "name": "Synthetic iPhone", "approver_id": "device:synthetic" })),
    )
    .await;
    assert!(status.is_success(), "{status}");
    let approval_id = held(&state).await;
    let priya = SessionActor { sub: "user_priya".into(), name: Some("Priya Raman".into()), role: None, vault_export: None };
    state
        .service
        .resolve_approval_as(&approval_id, true, "device_signed", Some("device:synthetic"), Some(&priya))
        .await
        .unwrap();
    let summary = summary_of(&state, "approved");
    assert_eq!(summary["approver_name"], "Synthetic iPhone");
    assert!(summary.get("approver_actor").is_none(), "{summary}");
}

#[tokio::test]
async fn a_member_clearing_error_details_is_named() {
    let state = worker().await;
    let token = console_token(Some(("user_priya", "Priya Raman")));
    let (status, _) = call(&state, &token, "DELETE", "/v1/audit/diagnostics", None).await;
    assert_eq!(status, StatusCode::OK);
    let events = state.service.store().audit_events(None).unwrap();
    let purge = events
        .iter()
        .find(|e| e.payload.action == "permaura.audit.diagnostics.purge")
        .expect("the purge is recorded");
    assert_eq!(purge.payload.summary["actor"], "user_priya");
    assert_eq!(purge.payload.summary["actor_name"], "Priya Raman");
}

/// permaura.com's Cloudflare account can push the managed tunnel's connector a configuration
/// of its own, or route private-network traffic through it, so in the second or so before the gateway
/// stops the connector a request carrying its token can arrive from loopback with no forwarder header.
/// It is remote all the same: on a self-run gateway with no paired device, the vault export is refused
/// to it as to any off-host caller, while the gateway's own session bearer on loopback still exports.
#[tokio::test]
async fn a_permaura_com_token_on_loopback_is_remote() {
    let state = worker().await;
    assert!(!state.hosted && !state.service.any_device_trusted());
    let export = json!({ "passphrase": "correct horse battery staple" });
    let (status, body) = call(&state, &console_token(Some(("user_priya", "Priya Raman"))), "POST", "/v1/vault/export", Some(export.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("no device is paired to confirm it"), "{body}");

    let (status, body) = call(&state, seed::DEMO_TOKEN, "POST", "/v1/vault/export", Some(export)).await;
    assert_eq!(status, StatusCode::OK, "a local bearer on loopback is still local: {body}");
}
