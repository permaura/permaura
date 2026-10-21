//! Revoking or removing an OAuth agent has to stop it, end to end.
//!
//! A remote MCP client authenticates with a permaura.com-issued JWT on every request, so its stored
//! session row is not what it presents. These drive real signed tokens through the resource server and
//! the router and pin that a revoked row is refused for that token and for any refreshed one, and that
//! a removed agent that calls again comes back waiting for a decision rather than approved.
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
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{AgentStatus, Store};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const OWNER_SUB: &str = "user_owner";
const PUBLIC_URL: &str = "https://g-revoke.permaura.test";
const AS_ISSUER: &str = "https://permaura.test/api/auth";
const AS_KID: &str = "oauth-revocation-test-key";

fn as_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[43u8; 32])
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

fn sign(claims: Value) -> String {
    let header = json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" });
    let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = as_signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// An access token for the MCP client `azp`. `issued` moves `iat` and `exp`, which is all a refresh
/// changes about the token the client presents.
fn agent_token(azp: &str, issued: i64) -> String {
    sign(json!({
        "iss": AS_ISSUER,
        "sub": OWNER_SUB,
        "aud": format!("{PUBLIC_URL}/mcp"),
        "azp": azp,
        "iat": issued,
        "exp": issued + 600,
        "scope": "openid mcp offline_access",
        "name": "Synthetic MCP client",
    }))
}

fn console_token() -> String {
    sign(json!({
        "iss": AS_ISSUER,
        "sub": OWNER_SUB,
        "aud": format!("{PUBLIC_URL}/mcp"),
        "exp": now_secs() + 600,
        "scope": "permaura:operator",
    }))
}

async fn worker() -> AppState {
    oauth_environment();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    // The attack's shape: the all-agents Default grant reaches something, so an agent that comes back
    // approved is an agent that can act at once.
    let mut default = store.get_grant("gr_default").unwrap().expect("the Default grant");
    default.policy_ids.push("pol_github_prs".into());
    store.update_grant(default).unwrap();
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

fn status_of(state: &AppState, agent_id: &str) -> Option<AgentStatus> {
    state.service.store().get_agent(agent_id).unwrap().map(|a| a.status)
}

#[tokio::test]
async fn a_revoked_oauth_session_refuses_the_same_token_and_a_refreshed_one() {
    let state = worker().await;
    let first = agent_token("client-revoked", now_secs());
    let (status, body) = call(&state, &first, "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK, "the client connects: {body}");
    assert_eq!(status_of(&state, "oauth:client-revoked"), Some(AgentStatus::Approved));

    let (status, body) =
        call(&state, &console_token(), "POST", "/v1/sessions/sess_oauth:client-revoked/revoke", None).await;
    assert_eq!(status, StatusCode::OK, "the owner revokes it: {body}");

    let (status, body) = call(&state, &first, "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the token it already holds stops working: {body}");
    let (status, body) = call(&state, &first, "POST", "/mcp", Some(json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "permaura_invoke", "arguments": { "capability": "github.pull_requests.create", "params": {} } },
    })))
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || body["error"].is_object(),
        "nor through /mcp: {status} {body}"
    );

    let refreshed = agent_token("client-revoked", now_secs() + 5);
    assert_ne!(refreshed, first);
    let (status, body) = call(&state, &refreshed, "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "and neither does a refreshed one: {body}");

    assert!(
        !state.service.bearer_is_live(&refreshed),
        "a refused bearer must not count as live for admission control"
    );
}

#[tokio::test]
async fn an_oauth_agent_revoking_its_own_session_over_mcp_is_stopped() {
    let state = worker().await;
    let token = agent_token("client-self-revoke", now_secs());
    let (status, body) = call(&state, &token, "POST", "/mcp", Some(json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "permaura_revoke_session", "arguments": {} },
    })))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["error"].is_null(), "the revoke is accepted: {body}");

    let (status, body) = call(&state, &token, "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the revoke took effect: {body}");
    let (status, body) = call(&state, &agent_token("client-self-revoke", now_secs() + 5), "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "for a refreshed token too: {body}");
}

#[tokio::test]
async fn a_removed_oauth_agent_that_calls_again_waits_for_approval() {
    let state = worker().await;
    assert!(!state.service.require_agent_approval(), "the new-agent gate is off, the default");
    let token = agent_token("client-removed", now_secs());
    let (status, body) = call(&state, &token, "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body["capabilities"].as_array().unwrap().is_empty(), "approved, the Default grant reaches it: {body}");

    let (status, body) = call(&state, &console_token(), "DELETE", "/v1/agents/oauth:client-removed", None).await;
    assert_eq!(status, StatusCode::OK, "the owner removes it: {body}");
    assert_eq!(status_of(&state, "oauth:client-removed"), None);

    let (status, body) = call(&state, &agent_token("client-removed", now_secs() + 5), "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK, "it may ask again: {body}");
    assert_eq!(
        status_of(&state, "oauth:client-removed"),
        Some(AgentStatus::Pending),
        "but it comes back waiting for a decision, never approved"
    );
    assert_eq!(body["capabilities"], json!([]), "and reaches nothing until then: {body}");

    // A second call while it waits changes nothing, and approving it is the way back.
    call(&state, &token, "GET", "/v1/capabilities", None).await;
    assert_eq!(status_of(&state, "oauth:client-removed"), Some(AgentStatus::Pending));
    let (status, body) =
        call(&state, &console_token(), "POST", "/v1/agents/oauth:client-removed/approve", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(&state, &token, "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body["capabilities"].as_array().unwrap().is_empty(), "approved again: {body}");
}

/// A removal recorded while the agent had no stored row (one pruned after it expired) still lands it
/// Pending when it next calls: the tombstone is written by the removal, not found by it.
#[tokio::test]
async fn a_removal_with_no_stored_session_still_leaves_a_tombstone() {
    let state = worker().await;
    let token = agent_token("client-no-row", now_secs());
    call(&state, &token, "GET", "/v1/capabilities", None).await;
    assert!(state.service.store().delete_session("sess_oauth:client-no-row").unwrap());

    let (status, body) = call(&state, &console_token(), "DELETE", "/v1/agents/oauth:client-no-row", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    call(&state, &token, "GET", "/v1/capabilities", None).await;
    assert_eq!(status_of(&state, "oauth:client-no-row"), Some(AgentStatus::Pending));
}

/// A removal ends the OAuth agent's held calls, and letting the same client back in must not start them again: the readmitted row reuses the session id, so the hold has to be bound to the row it was made under.
#[tokio::test]
async fn a_readmitted_oauth_agent_does_not_revive_the_holds_its_removal_ended() {
    let state = worker().await;
    // A remote caller reaches only a credential that may run remotely.
    let store = state.service.store();
    let mut secret = store.get_secret("sec_github_acme").unwrap().expect("the seeded GitHub secret");
    secret.metadata.allowed_execution_locations.push(permaura_core::ExecutionLocation::RemoteAllowed);
    store.put_secret(secret).unwrap();
    let token = agent_token("client-readmitted", now_secs());
    let (status, held) = call(&state, &token, "POST", "/v1/invoke", Some(json!({
        "capability": "github.pull_requests.create",
        "params": { "owner": "acme", "repo": "web", "title": "queued before the removal", "head": "x", "base": "main" },
    })))
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "the High-risk create is held: {held}");
    let stale = held["approval_id"].as_str().expect("a held call names its approval").to_string();

    let (status, body) = call(&state, &console_token(), "DELETE", "/v1/agents/oauth:client-readmitted", None).await;
    assert_eq!(status, StatusCode::OK, "the owner removes it: {body}");
    // The row may be stamped in the same millisecond as the hold; the comparison is on creation order.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let readmitted = agent_token("client-readmitted", now_secs() + 5);
    call(&state, &readmitted, "GET", "/v1/capabilities", None).await;
    assert_eq!(status_of(&state, "oauth:client-readmitted"), Some(AgentStatus::Pending));
    let (status, body) =
        call(&state, &console_token(), "POST", "/v1/agents/oauth:client-readmitted/approve", None).await;
    assert_eq!(status, StatusCode::OK, "the owner lets it back in: {body}");

    let (status, answer) =
        call(&state, &console_token(), "POST", "/v1/approvals", Some(json!({ "approval_id": stale, "approve": true }))).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "denied", "the card queued before the removal must not run: {answer}");
    assert_eq!(answer["resolution_reason"], "session_ended", "{answer}");

    // The readmitted agent's own new calls are held and run as usual.
    let (status, fresh) = call(&state, &readmitted, "POST", "/v1/invoke", Some(json!({
        "capability": "github.pull_requests.create",
        "params": { "owner": "acme", "repo": "web", "title": "asked after readmission", "head": "y", "base": "main" },
    })))
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{fresh}");
    let (status, answer) = call(
        &state,
        &console_token(),
        "POST",
        "/v1/approvals",
        Some(json!({ "approval_id": fresh["approval_id"], "approve": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "approved", "a hold made under the live row still runs: {answer}");
}

/// A connector that was never removed keeps its held calls when the refresher prunes its session row for age and the client's next call writes a new one: only a removal and readmission ends them.
#[tokio::test]
async fn an_oauth_agents_holds_survive_its_row_being_pruned_and_recreated() {
    let state = worker().await;
    let store = state.service.store();
    let mut secret = store.get_secret("sec_github_acme").unwrap().expect("the seeded GitHub secret");
    secret.metadata.allowed_execution_locations.push(permaura_core::ExecutionLocation::RemoteAllowed);
    store.put_secret(secret).unwrap();

    let token = agent_token("client-pruned", now_secs());
    let (status, held) = call(&state, &token, "POST", "/v1/invoke", Some(json!({
        "capability": "github.pull_requests.create",
        "params": { "owner": "acme", "repo": "web", "title": "queued before the prune", "head": "x", "base": "main" },
    })))
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");

    // What `prune_dead_sessions` does to a row a week past its never-sliding expiry, then the client's next call.
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert!(store.delete_session("sess_oauth:client-pruned").unwrap());
    let (status, body) = call(&state, &agent_token("client-pruned", now_secs() + 5), "GET", "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(status_of(&state, "oauth:client-pruned"), Some(AgentStatus::Approved), "never removed, so still approved");

    let (status, answer) = call(
        &state,
        &console_token(),
        "POST",
        "/v1/approvals",
        Some(json!({ "approval_id": held["approval_id"], "approve": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "approved", "the card queued before the prune still runs: {answer}");
}
