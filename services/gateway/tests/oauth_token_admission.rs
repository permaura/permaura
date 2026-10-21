//! What a permaura.com-signed token buys at this gateway's door, by its class, through the real router.
//!
//! A token the AS minted off an identity-only consent (`openid profile offline_access`, no `mcp`) carries this gateway's audience and its owner's `sub`, so it verifies; it must still open no agent session, because the consent page promised it "gets no access to your gateway, and no ability to act as an agent".
//!
//! Every credential here is synthetic. The environment is process-global, so it is set once for the whole binary before any state exists.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const OWNER_SUB: &str = "user_owner";
const PUBLIC_URL: &str = "https://g-admission.permaura.test";
const AS_ISSUER: &str = "https://permaura.test/api/auth";
const AS_KID: &str = "oauth-token-admission-test-key";

fn as_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[61u8; 32])
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

/// A token for this gateway and its owner, with the scope the AS granted at consent.
fn token_with_scope(azp: &str, scope: &str, exp: i64) -> String {
    sign(json!({
        "iss": AS_ISSUER, "sub": OWNER_SUB, "aud": format!("{PUBLIC_URL}/mcp"), "azp": azp,
        "iat": now_secs(), "exp": exp, "scope": scope, "name": azp,
    }))
}

/// What an MCP client holds after the owner consented to an agent.
fn agent_token(azp: &str) -> String {
    token_with_scope(azp, "openid profile mcp offline_access", now_secs() + 600)
}

/// What a "Sign in with Permaura" client holds after the owner consented to identity only, with the gateway resource introduced at the token endpoint.
fn identity_only_token(azp: &str) -> String {
    token_with_scope(azp, "openid profile offline_access", now_secs() + 600)
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

async fn call(state: &AppState, bearer: Option<&str>, method: &str, uri: &str, body: Option<Value>) -> axum::response::Response {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    app.oneshot(builder.body(body).unwrap()).await.unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn initialize() -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} })
}

// ── An identity-only token is not an agent ──────────────────────────────────────────

#[tokio::test]
async fn an_identity_only_token_opens_no_agent_session_and_registers_no_agent() {
    let state = worker().await;
    let token = identity_only_token("client-sign-in-only");
    let resp = call(&state, Some(&token), "GET", "/v1/capabilities", None).await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(error.contains("`mcp` scope") && error.contains("openid profile offline_access"), "the refusal names the missing scope: {error}");
    assert!(
        state.service.store().get_agent("oauth:client-sign-in-only").unwrap().is_none(),
        "no agent row is created for a token that cannot act as one"
    );

    let resp = call(&state, Some(&token), "POST", "/mcp", Some(initialize())).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "nor through /mcp");
    assert!(state.service.store().get_agent("oauth:client-sign-in-only").unwrap().is_none());
    assert!(!state.service.bearer_is_live(&token), "and it is not a live bearer for admission control");
}

#[tokio::test]
async fn an_mcp_scoped_token_still_opens_an_agent_session() {
    let state = worker().await;
    let token = agent_token("client-mcp");
    let resp = call(&state, Some(&token), "GET", "/v1/capabilities", None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(state.service.store().get_agent("oauth:client-mcp").unwrap().is_some(), "the agent is registered");
    assert!(state.service.bearer_is_live(&token));
}

// ── A lapsed token is told 401 ahead of the shared bucket ─────────────────────────────

/// A hosted worker's admission numbers: 30 a minute, burst 10, per caller, with the one unauthenticated bucket every unresolvable bearer shares.
fn hosted_limits(state: AppState) -> AppState {
    use permaura_gateway::limits::{Limits, LimitsConfig};
    state.with_limits(Arc::new(Limits::new(LimitsConfig::defaults_for(true))))
}

/// What an agent presents once its fifteen-minute token has run out, before it refreshes.
fn lapsed_agent_token(azp: &str) -> String {
    token_with_scope(azp, "openid profile mcp offline_access", now_secs() - 60)
}

/// The same lapse, for a token minted for someone else's gateway: a permaura.com user who is not this gateway's owner, hammering a hostname they read off DNS.
fn strangers_lapsed_token() -> String {
    sign(json!({
        "iss": AS_ISSUER, "sub": "user_stranger", "aud": format!("{PUBLIC_URL}/mcp"), "azp": "client-stranger",
        "iat": now_secs() - 700, "exp": now_secs() - 60, "scope": "openid profile mcp offline_access",
    }))
}

/// A stranger spends the shared unauthenticated bucket with junk bearers, then an agent whose token lapsed calls. It used to get 429 with `Retry-After`; it must get the 401 with the `WWW-Authenticate` challenge that makes it refresh.
#[tokio::test]
async fn a_stranger_draining_the_unauthenticated_bucket_cannot_turn_a_lapsed_agents_401_into_a_429() {
    let state = hosted_limits(worker().await);
    let mut statuses = Vec::new();
    for i in 0..12 {
        let junk = format!("invented-{i}");
        statuses.push(call(&state, Some(&junk), "POST", "/mcp", Some(initialize())).await.status());
    }
    assert_eq!(&statuses[..10], &[StatusCode::UNAUTHORIZED; 10], "the burst is refused one by one: {statuses:?}");
    assert_eq!(statuses[10], StatusCode::TOO_MANY_REQUESTS, "then the shared bucket is spent: {statuses:?}");

    for route in ["/mcp", "/v1/invoke"] {
        let resp = call(&state, Some(&lapsed_agent_token("client-lapsed")), "POST", route, Some(initialize())).await;
        let status = resp.status();
        let challenge = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(String::from);
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}: a lapsed token is told to refresh, not to wait: {body}");
        assert!(
            challenge.as_deref().is_some_and(|c| c.contains(".well-known/oauth-protected-resource/mcp")),
            "{route}: the challenge names this gateway's resource metadata: {challenge:?}"
        );
        assert!(body["error"].as_str().unwrap_or_default().contains("expired"), "{route}: {body}");
    }
    assert!(
        state.service.store().get_agent("oauth:client-lapsed").unwrap().is_none(),
        "answering the lapse registers nothing"
    );
}

/// The other caller the shared bucket used to silence: a client with no token yet, whose first request is how it learns where to sign in. Tokenless requests land in the peer bucket, one address for every caller behind a hosted frontend; now they are challenged ahead of it.
#[tokio::test]
async fn a_tokenless_client_is_always_challenged_rather_than_rate_limited_on_a_public_gateway() {
    let state = hosted_limits(worker().await);
    for i in 0..14 {
        let resp = call(&state, None, "POST", "/mcp", Some(initialize())).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "request {i}: the challenge, never a 429");
        assert!(resp.headers().contains_key("www-authenticate"), "request {i}");
    }
    let resp = call(&state, None, "POST", "/v1/invoke", Some(json!({ "capability": "x", "params": {} }))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The lane is narrow: it is for this gateway's own caller. A stranger's expired token, minted for another operator, stays in the shared bucket and is rate limited with the rest of the junk.
#[tokio::test]
async fn a_strangers_lapsed_token_for_another_operator_stays_in_the_shared_bucket() {
    let state = hosted_limits(worker().await);
    let mut statuses = Vec::new();
    for _ in 0..12 {
        statuses.push(call(&state, Some(&strangers_lapsed_token()), "POST", "/mcp", Some(initialize())).await.status());
    }
    assert_eq!(&statuses[..10], &[StatusCode::UNAUTHORIZED; 10], "{statuses:?}");
    assert_eq!(statuses[10], StatusCode::TOO_MANY_REQUESTS, "a stranger is limited: {statuses:?}");
    // And the owner's lapsed agent is still answered 401 through it.
    let resp = call(&state, Some(&lapsed_agent_token("client-lapsed-2")), "POST", "/mcp", Some(initialize())).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A live token is admitted as before, against its own bucket, and its calls execute.
#[tokio::test]
async fn a_live_agent_token_is_still_admitted_and_counted_against_its_own_bucket() {
    let state = hosted_limits(worker().await);
    for i in 0..12 {
        let junk = format!("junk-{i}");
        call(&state, Some(&junk), "POST", "/mcp", Some(initialize())).await;
    }
    let token = agent_token("client-live");
    let resp = call(&state, Some(&token), "POST", "/mcp", Some(initialize())).await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["serverInfo"]["name"], "permaura-gateway", "{body}");
}

/// The leg the first fix missed: an agent's first call carries its enrolment code, which names no session until that call redeems it, so it shared the bucket with every stranger's junk and sat at 429 until the code expired. A code not yet redeemed has a bucket of its own, keyed by a code the stranger does not hold; junk shaped like a code stays in the shared bucket with the rest.
#[tokio::test]
async fn a_stranger_cannot_keep_an_agents_first_call_with_its_enrolment_code_at_429() {
    let state = hosted_limits(worker().await);
    let mut statuses = Vec::new();
    for i in 0..12 {
        let junk = format!("pgc_ENRL-JUNK-{i:04}-0000-0000");
        statuses.push(call(&state, Some(&junk), "POST", "/mcp", Some(initialize())).await.status());
    }
    assert_eq!(&statuses[..10], &[StatusCode::UNAUTHORIZED; 10], "{statuses:?}");
    assert_eq!(statuses[10], StatusCode::TOO_MANY_REQUESTS, "junk shaped like a code is limited with the rest: {statuses:?}");

    let code = "pgc_ENRL-AB12-CD34-EF56-GH78";
    let now = now_secs() * 1000;
    state
        .service
        .store()
        .put_enrolment_code(permaura_gateway::store::EnrolmentCode {
            code: code.into(),
            label: Some("first call".into()),
            created_at: now,
            expires_at: now + 15 * 60 * 1000,
            used: false,
        })
        .unwrap();
    assert!(state.service.bearer_is_live(code), "an unredeemed code is admitted against its own bucket");
    for attempt in ["the redeeming call", "the call after it"] {
        let resp = call(&state, Some(code), "POST", "/mcp", Some(initialize())).await;
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::OK, "{attempt}: {body}");
        assert_eq!(body["result"]["serverInfo"]["name"], "permaura-gateway", "{attempt}: {body}");
    }
    let session = state.service.store().session_by_token(code).unwrap().expect("the code opened a session");
    assert_eq!(session.role, permaura_gateway::store::SessionRole::Agent);
    assert!(state.service.store().get_agent(&session.agent_id).unwrap().is_some(), "and enrolled its agent");

    let spent = "pgc_ENRL-SPNT-0000-0000-0000";
    state
        .service
        .store()
        .put_enrolment_code(permaura_gateway::store::EnrolmentCode {
            code: spent.into(),
            label: None,
            created_at: now,
            expires_at: now + 15 * 60 * 1000,
            used: true,
        })
        .unwrap();
    assert!(!state.service.bearer_is_live(spent), "a spent code that opened nothing is junk");
    assert_eq!(call(&state, Some(spent), "POST", "/mcp", Some(initialize())).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ── A paused worker serves no agent, by any bearer ───────────────────────────────────

/// `PERMAURA_AGENTS_PAUSED`, which the hosted control plane sets through a lapse's grace and a decommission. A code-enrolled agent's bearer is a stored session the worker resolves itself, so nothing permaura.com stops minting reaches it; the worker has to refuse it, and say why, while the owner's console keeps working.
#[tokio::test]
async fn a_paused_worker_refuses_every_agent_bearer_with_403_and_keeps_the_console() {
    let state = worker().await;
    let code = "pgc_ENRL-PA05-0000-0000-0001";
    let now = now_secs() * 1000;
    state
        .service
        .store()
        .put_enrolment_code(permaura_gateway::store::EnrolmentCode {
            code: code.into(),
            label: Some("ci-bot".into()),
            created_at: now,
            expires_at: now + 15 * 60 * 1000,
            used: false,
        })
        .unwrap();
    assert_eq!(call(&state, Some(code), "POST", "/mcp", Some(initialize())).await.status(), StatusCode::OK, "the code redeems");
    let session = state.service.store().session_by_token(code).unwrap().expect("the code opened a session");
    let mut agent = state.service.store().get_agent(&session.agent_id).unwrap().unwrap();
    agent.status = permaura_gateway::store::AgentStatus::Approved;
    state.service.store().put_agent(agent).unwrap();
    let agent_token = agent_token("client-before-the-lapse");
    assert_eq!(call(&state, Some(&agent_token), "GET", "/v1/capabilities", None).await.status(), StatusCode::OK);

    state.service.pause_agents_for_this_run();
    let tools_call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "permaura_invoke", "arguments": { "capability": "braintree.transactions.search", "params": {} } }
    });
    let invoke = json!({ "capability": "braintree.transactions.search", "params": {} });
    for bearer in [code, agent_token.as_str()] {
        for (method, uri, body) in [("POST", "/mcp", Some(tools_call.clone())), ("POST", "/v1/invoke", Some(invoke.clone()))] {
            let resp = call(&state, Some(bearer), method, uri, body).await;
            let status = resp.status();
            assert!(resp.headers().get("www-authenticate").is_none(), "{uri}: a pause is not a sign-in to redo");
            let body = body_json(resp).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
            assert!(body["error"].as_str().unwrap_or_default().contains("agents are paused"), "{uri}: {body}");
        }
    }

    let operator = token_with_scope("permaura-console", "openid permaura:operator", now_secs() + 600);
    let resp = call(&state, Some(&operator), "GET", "/v1/broker", None).await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["agents_paused"], true, "the console can see the pause: {body}");
    assert_eq!(call(&state, Some(&operator), "GET", "/v1/agents", None).await.status(), StatusCode::OK);
    let resp = call(&state, Some(&operator), "POST", "/v1/agents/enroll", Some(json!({ "label": "new" }))).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "no code is minted for an agent that could not use it");
    let body = body_json(resp).await;
    let refusal = body["error"].as_str().unwrap_or_default();
    assert!(refusal.contains("no agent can be enrolled"), "the operator is told why Add agent did nothing: {body}");
    assert!(!refusal.contains("executed"), "minting a code is not an execution: {body}");
}
