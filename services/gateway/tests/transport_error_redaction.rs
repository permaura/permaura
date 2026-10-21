//! A capability that carries its key in the query string must not hand that key to the agent, or to
//! the logs, when the upstream fails at the transport layer. reqwest renders the full request URL into
//! every send error and every refused redirect, so the text that reaches a REST body, an MCP tool error
//! or a log line has to be built without it.
//!
//! Every credential and upstream here is synthetic, and both upstreams are this test's own loopback
//! servers.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use permaura_core::{seal, Cipher, SecretMetadata, SecretRecord};
use permaura_gateway::connectors::{AuthScheme, HttpMethod, HttpSpec, ReqwestClient};
use permaura_gateway::service::vault_passphrase;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

mod common;

const QUERY_KEY: &str = "sk_query_canary_7f3a91c2";
const CAPABILITY: &str = "github.pull_requests.list";

/// Accepts every connection, reads the request and never answers, so the client's own timeout fires.
async fn silent_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    format!("http://{addr}")
}

/// Answers every connection with a redirect to another host, which a credentialed request refuses.
async fn cross_host_redirect_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                    match sock.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                let response = "HTTP/1.1 307 Temporary Redirect\r\nlocation: https://attacker.example/collect\r\n\
                                content-length: 0\r\nconnection: close\r\n\r\n";
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

/// The seeded estate, with the seeded GitHub list capability re-pointed at `base_url` as an imported
/// capability whose credential travels as `?api_key=`, and its secret replaced with [`QUERY_KEY`].
fn state_pointing_at(base_url: &str) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let mut cap = store.get_capability(CAPABILITY).unwrap().expect("the seeded capability");
    cap.http = Some(HttpSpec {
        method: HttpMethod::Get,
        base_url: base_url.to_string(),
        path: "/v1/items".to_string(),
        auth: AuthScheme::ApiKeyQuery { param: "api_key".to_string() },
        ..HttpSpec::default()
    });
    let secret_id = cap.secret_id.clone();
    store.put_capability(cap).unwrap();
    common::file_as_imported(store.as_ref(), CAPABILITY);
    let sealed = seal(Cipher::Aes256Gcm, vault_passphrase(), QUERY_KEY.as_bytes()).unwrap();
    store
        .put_secret(SecretRecord { id: secret_id, sealed, metadata: SecretMetadata::default() })
        .unwrap();
    let http = Arc::new(ReqwestClient::loopback_for_tests(Duration::from_millis(800)));
    AppState::from_parts(store, http)
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn post(state: &AppState, uri: &str, body: serde_json::Value) -> (u16, String) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Invoke the capability over REST and over MCP with every log line captured, and hold all three to
/// the same rule: the failure is reported, and the key is in none of them.
async fn assert_the_key_never_surfaces(base_url: &str) {
    let state = state_pointing_at(base_url);
    let captured = Captured::default();
    let sink = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let params = serde_json::json!({});
    let (status, rest) =
        post(&state, "/v1/invoke", serde_json::json!({ "capability": CAPABILITY, "params": params })).await;
    assert!(status >= 500, "a transport failure is a server-side error, got {status}: {rest}");
    assert!(rest.contains("upstream"), "the REST body still says what failed: {rest}");
    assert!(!rest.contains(QUERY_KEY), "the REST body carries the query-string key: {rest}");

    let rpc = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "permaura_invoke", "arguments": { "capability": CAPABILITY, "params": params } }
    });
    let (_, mcp) = post(&state, "/mcp", rpc).await;
    assert!(mcp.contains("upstream"), "the MCP error still says what failed: {mcp}");
    assert!(!mcp.contains(QUERY_KEY), "the MCP tool error carries the query-string key: {mcp}");

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("upstream"), "the failure was logged, so the log check is not vacuous: {logs}");
    assert!(!logs.contains(QUERY_KEY), "a log line carries the query-string key: {logs}");
}

#[tokio::test]
async fn a_timed_out_upstream_does_not_echo_the_query_key() {
    assert_the_key_never_surfaces(&silent_server().await).await;
}

#[tokio::test]
async fn a_refused_cross_host_redirect_does_not_echo_the_query_key() {
    assert_the_key_never_surfaces(&cross_host_redirect_server().await).await;
}
