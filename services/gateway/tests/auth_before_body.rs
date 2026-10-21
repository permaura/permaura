//! The bulk routes, `/v1/invoke` and `/mcp` decide who the caller is from the headers before the body is read or parsed.
//!
//! A body no JSON parser accepts tells the two orders apart: parsed first it is a 400, refused first it is the caller's refusal. A body over the route's byte limit does the same for reading: read through the extractor first it is a 413.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{MockCommandRunner, MockHttpClient};
use permaura_gateway::limits::{Limits, LimitsConfig, DEFAULT_BODY_BULK_BYTES, DEFAULT_BODY_EXEC_BYTES};
use permaura_gateway::oauth::{OAuthRs, RsConfig};
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{Session, SessionRole, Store};
use permaura_gateway::vault_bundle::BundlePayload;
use common::build_router;
use permaura_gateway::{seed, AppState};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

mod common;

const BULK_ROUTES: [&str; 5] = [
    "/v1/vault/export",
    "/v1/vault/import/preview",
    "/v1/vault/import",
    "/v1/connections/import-openapi",
    "/v1/connectors/install",
];

const NOT_JSON: &str = "{\"manifest\": [ this is not json";
const AGENT_TOKEN: &str = "tok_test_agent_before_body";
const PUBLIC_URL: &str = "https://g-before-body.permaura.test";
/// Shaped like a permaura.com JWT, so a resource server tries to verify it rather than look it up.
const JWT_SHAPED: &str = "eyJub3QiOiJhIHRva2VuIn0.not-a-jwt.at-all";
const PASSPHRASE: &str = "correct horse battery staple";

fn with_agent(state: AppState) -> AppState {
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_test_agent_before_body".into(),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: AGENT_TOKEN.into(),
            role: SessionRole::Agent,
            created_at: 0,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
    state
}

fn self_run() -> AppState {
    with_agent(common::seeded())
}

/// A hosted worker: an OAuth resource server that has not fetched permaura.com's keys, so a JWT-shaped bearer is answered as warming.
fn resource_server() -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let oauth = Arc::new(OAuthRs::new(RsConfig {
        public_url: PUBLIC_URL.into(),
        mcp_resource: format!("{PUBLIC_URL}/mcp"),
        public_url_aliases: Vec::new(),
        issuer: "https://permaura.test/api/auth".into(),
        jwks_uri: "https://permaura.test/api/auth/jwks".into(),
        owner_sub: Some("user_owner".into()),
    }));
    let backend = permaura_gateway::backend::build_backend(store.clone());
    let service = EnforcementService::from_components(
        store,
        Arc::new(MockHttpClient::new()),
        Arc::new(MockCommandRunner::new()),
        backend,
        Some(oauth),
    );
    with_agent(AppState::new(service).with_limits(Arc::new(Limits::new(LimitsConfig::defaults_for(true)))))
}

async fn post(state: &AppState, uri: &str, bearer: Option<&str>, body: impl Into<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut request = Request::builder().method("POST").uri(uri).header("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(request.body(body.into()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// The reproduction's shape: one-key objects up to about `size` bytes, a tree about 83 times its size once parsed.
fn one_key_objects(size: usize) -> String {
    let mut body = String::from("{\"manifest\":[");
    while body.len() + 24 < size {
        body.push_str("{\"a\":1},");
    }
    body.pop();
    body.push_str("],\"version\":1}");
    body
}

#[tokio::test]
async fn the_bulk_routes_refuse_a_non_operator_before_the_body_is_parsed() {
    let state = self_run();
    for route in BULK_ROUTES {
        let (status, _, body) = post(&state, route, None, NOT_JSON).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}, no bearer: {body}");
        let (status, _, body) = post(&state, route, Some("tok_nobody_holds_this"), NOT_JSON).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}, an unknown bearer: {body}");
        let (status, _, body) = post(&state, route, Some(AGENT_TOKEN), NOT_JSON).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route}, an agent bearer: {body}");
        assert!(body["error"].as_str().unwrap_or_default().contains("operator role required"), "{route}: {body}");
    }
}

/// The layer covers the whole group, so a route added to it later cannot miss it; the price is that a wrong method is a 405 only to an operator.
#[tokio::test]
async fn a_method_the_bulk_routes_do_not_take_is_a_405_to_an_operator_and_a_401_to_a_stranger() {
    let state = self_run();
    for route in BULK_ROUTES {
        for (bearer, want) in [(Some(seed::DEMO_TOKEN), StatusCode::METHOD_NOT_ALLOWED), (None, StatusCode::UNAUTHORIZED)] {
            let mut request = Request::builder().uri(route);
            if let Some(bearer) = bearer {
                request = request.header("authorization", format!("Bearer {bearer}"));
            }
            let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), want, "GET {route}, bearer {bearer:?}");
        }
    }
}

#[tokio::test]
async fn a_bulk_body_over_the_byte_limit_is_still_the_callers_refusal_not_a_413() {
    let state = self_run();
    let oversized = vec![b' '; DEFAULT_BODY_BULK_BYTES + 1024];
    for route in ["/v1/connectors/install", "/v1/vault/import/preview", "/v1/vault/import"] {
        let (status, _, body) = post(&state, route, None, oversized.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}: {body}");
        let (status, _, body) = post(&state, route, Some(AGENT_TOKEN), oversized.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
    }
}

#[tokio::test]
async fn a_warming_resource_server_answers_the_bulk_routes_503_before_the_body() {
    let state = resource_server();
    for route in ["/v1/connectors/install", "/v1/vault/import/preview", "/v1/vault/import"] {
        let (status, _, body) = post(&state, route, Some(JWT_SHAPED), NOT_JSON).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{route}: {body}");
        let (status, _, body) = post(&state, route, None, NOT_JSON).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}: {body}");
    }
}

#[tokio::test]
async fn an_operators_install_still_applies_and_a_malformed_one_is_still_a_400() {
    let state = self_run();
    let manifest = json!({
        "id": "acme-things",
        "name": "Acme",
        "vertical": "devtools",
        "base_url": "https://api.acme-things.example",
        "capabilities": [
            { "id": "things.list", "method": "GET", "path": "/things", "description": "List things" }
        ]
    });
    let body = json!({ "manifest": manifest, "version": 1 }).to_string();
    let (status, _, resp) = post(&state, "/v1/connectors/install", Some(seed::DEMO_TOKEN), body).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    assert!(state.service.store().get_connector_manifest("acme-things").unwrap().is_some());

    let (status, _, resp) = post(&state, "/v1/connectors/install", Some(seed::DEMO_TOKEN), NOT_JSON).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an operator's body is still parsed and judged: {resp}");
}

/// Preview and import in one test because each opens the bundle at the bundle KDF, which one permit serialises.
#[tokio::test]
async fn an_operators_vault_preview_and_import_still_apply() {
    let state = self_run();
    let mut connection = state.service.store().list_connections().unwrap().into_iter().next().expect("the demo estate has a connection");
    connection.id = "conn_imported_before_body".into();
    connection.name = "Imported".into();
    let payload = BundlePayload { connections: vec![connection], ..Default::default() };
    let bundle = permaura_core::seal_bundle(
        PASSPHRASE.as_bytes(),
        serde_json::to_value(payload).unwrap(),
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_source".into(), mode: "self-run".into() },
    )
    .unwrap();
    let body = json!({ "bundle": bundle, "passphrase": PASSPHRASE, "on_conflict": "skip" }).to_string();

    let (status, _, resp) = post(&state, "/v1/vault/import/preview", Some(seed::DEMO_TOKEN), body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let (status, _, resp) = post(&state, "/v1/vault/import", Some(seed::DEMO_TOKEN), body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["written"]["connections"], 1, "{resp}");
    assert!(state.service.store().get_connection("conn_imported_before_body").unwrap().is_some());
}

#[tokio::test]
async fn invoke_resolves_the_bearer_before_the_body() {
    let state = self_run();
    let (status, _, body) = post(&state, "/v1/invoke", Some("tok_nobody_holds_this"), NOT_JSON).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, _, body) = post(&state, "/v1/invoke", None, NOT_JSON).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let oversized = vec![b' '; DEFAULT_BODY_EXEC_BYTES + 1024];
    let (status, _, body) = post(&state, "/v1/invoke", Some("tok_nobody_holds_this"), oversized).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let state = resource_server();
    let (status, _, body) = post(&state, "/v1/invoke", Some(JWT_SHAPED), NOT_JSON).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "the warming answer, before the body: {body}");
}

#[tokio::test]
async fn an_authenticated_invoke_still_runs_and_its_body_is_still_judged() {
    let state = self_run();
    let call = json!({
        "capability": "braintree.transactions.search",
        "params": { "status": "failed", "date": "2026-06-21" },
        "reason": "Summarize yesterday's failed payments."
    });
    let (status, _, body) = post(&state, "/v1/invoke", Some(seed::DEMO_TOKEN), call.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"]["decision"], "allow", "{body}");

    let (status, _, body) = post(&state, "/v1/invoke", Some(seed::DEMO_TOKEN), NOT_JSON).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn mcp_on_a_resource_server_challenges_before_the_body() {
    let state = resource_server();
    let challenge_path = format!("{PUBLIC_URL}/.well-known/oauth-protected-resource/mcp");
    for bearer in [None, Some("tok_nobody_holds_this"), Some(JWT_SHAPED)] {
        let (status, headers, body) = post(&state, "/mcp", bearer, NOT_JSON).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{bearer:?}: {body}");
        let challenge = headers.get("www-authenticate").and_then(|v| v.to_str().ok()).unwrap_or_default();
        assert!(challenge.contains(&challenge_path), "{bearer:?}: {challenge}");
    }

    let (status, _, body) = post(&state, "/mcp", Some(seed::DEMO_TOKEN), NOT_JSON).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a caller the gate admits still has its body parsed: {body}");
    let initialize = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" }).to_string();
    let (status, _, body) = post(&state, "/mcp", Some(seed::DEMO_TOKEN), initialize).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["serverInfo"]["name"], "permaura-gateway", "{body}");
}

// ── Over a real listener ─────────────────────────────────────────────────────────

async fn serve(state: AppState) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state, addr);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    addr
}

/// What a client that sends its whole body before it reads saw: whether the body went out, the response, and whether the socket then ended cleanly rather than by a reset.
struct Exchange {
    body_sent: Result<(), std::io::Error>,
    response: String,
    clean_end: bool,
}

impl Exchange {
    fn status_line(&self) -> &str {
        self.response.lines().next().unwrap_or("<nothing before the socket ended>")
    }
}

/// POST `body_len` bytes over a raw socket the way most clients do, the whole body first and the response after. Without `send_body` only the headers go, as from a client waiting on `100 Continue`.
async fn exchange(addr: SocketAddr, path: &str, extra_headers: &str, body_len: usize, send_body: bool) -> Exchange {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nConnection: close\r\n{extra_headers}\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let body_sent = if send_body { stream.write_all(&vec![b' '; body_len]).await } else { Ok(()) };
    let mut response = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut response)).await;
    Exchange {
        body_sent,
        response: String::from_utf8_lossy(&response).into_owned(),
        clean_end: matches!(read, Ok(Ok(_))),
    }
}

/// A refusal made from the headers still reaches a client in the middle of its upload, and the connection ends cleanly. Undrained, hyper closes it with the rest of the body unread and the client's upload ends in a reset.
#[tokio::test]
async fn a_client_mid_upload_receives_the_refusal_over_a_real_listener() {
    let self_run = serve(self_run()).await;
    let hosted = serve(resource_server()).await;
    let bulk_len = DEFAULT_BODY_BULK_BYTES - 4096;
    let exec_len = DEFAULT_BODY_EXEC_BYTES - 4096;
    let cases = [
        (self_run, "/v1/connectors/install", String::new(), bulk_len, "401"),
        (self_run, "/v1/vault/import", format!("Authorization: Bearer {AGENT_TOKEN}\r\n"), bulk_len, "403"),
        (hosted, "/v1/vault/import/preview", format!("Authorization: Bearer {JWT_SHAPED}\r\n"), bulk_len, "503"),
        (self_run, "/v1/invoke", "Authorization: Bearer tok_nobody_holds_this\r\n".to_string(), exec_len, "401"),
        (hosted, "/mcp", "Authorization: Bearer tok_nobody_holds_this\r\n".to_string(), exec_len, "401"),
    ];
    for (addr, path, headers, len, want) in cases {
        let seen = exchange(addr, path, &headers, len, true).await;
        assert!(seen.body_sent.is_ok(), "{path}: the upload was cut off: {:?}", seen.body_sent);
        assert!(seen.status_line().starts_with(&format!("HTTP/1.1 {want} ")), "{path}: wanted {want}, saw {:?}", seen.status_line());
        assert!(seen.clean_end, "{path}: the connection was reset after the response");
    }
}

#[tokio::test]
async fn the_reproductions_body_is_answered_401_over_a_real_listener() {
    let addr = serve(self_run()).await;
    let hostile = one_key_objects(DEFAULT_BODY_BULK_BYTES - 4096);
    let resp = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("http://{addr}/v1/connectors/install"))
        .header("content-type", "application/json")
        .body(hostile)
        .send()
        .await
        .expect("the client receives a response, not a reset");
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn a_client_waiting_on_100_continue_gets_the_refusal_without_being_asked_for_the_body() {
    let addr = serve(self_run()).await;
    let seen = exchange(addr, "/v1/connectors/install", "Expect: 100-continue\r\n", DEFAULT_BODY_BULK_BYTES - 4096, false).await;
    assert!(seen.status_line().starts_with("HTTP/1.1 401 "), "{:?}", seen.status_line());
    assert!(!seen.response.contains("100 Continue"), "{}", seen.response);
    assert!(seen.clean_end, "nothing was sent, so nothing is left unread to reset on");
}

#[tokio::test]
async fn a_withdrawn_resource_server_preserves_an_opaque_tokens_refusal() {
    let state = resource_server();
    state.service.oauth().unwrap().withdraw();
    let (status, headers, body) = post(&state, "/mcp", Some("synthetic-invalid-opaque"), r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get("www-authenticate").is_none());
    let error = body["error"].as_str().unwrap();
    assert!(error.contains("token"), "the actual bearer failure is retained: {body}");
    assert!(!error.contains("remote access was turned off"), "an opaque-token failure is not a remote-access failure: {body}");
}
