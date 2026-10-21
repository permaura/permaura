//! A hosted worker is Permaura's machine, so an SSH connection on it names a public host
//! or nothing. Before, a tenant could point one at the metadata server, the worker's own loopback or
//! the VPC, and every call opened a TCP connection there. A self-run gateway keeps reaching its own
//! network: a home server or a box on the LAN is what SSH is for there.
//!
//! Every host here is synthetic or a reserved address.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

/// The metadata server by address and by name, the worker's loopback (three spellings), and the VPC.
const NON_PUBLIC: [&str; 7] =
    ["169.254.169.254", "metadata.google.internal", "127.0.0.1", "2130706433", "[::1]", "localhost", "10.0.0.1"];

async fn send(state: &AppState, method: &str, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn ssh_connection(id: &str, host: &str) -> Value {
    json!({
        "id": id,
        "connector": "ssh",
        "name": id,
        "ssh": {
            "host": host,
            "user": "deploy",
            "host_key_sha256": "SHA256:synthetic",
            "exec": [{ "action": "uptime", "args_template": ["uptime"] }],
        },
    })
}

/// The SSH host of every capability on the seeded `ssh_prod` connection.
fn ssh_prod_hosts(state: &AppState) -> Vec<String> {
    let store = state.service.store();
    let conn = store.get_connection("ssh_prod").unwrap().expect("the seeded SSH connection");
    conn.capabilities
        .iter()
        .filter_map(|id| store.get_capability(id).unwrap())
        .filter_map(|cap| cap.ssh.map(|s| s.target.host))
        .collect()
}

fn refused_as_non_public(status: StatusCode, body: &Value) -> bool {
    status == StatusCode::BAD_REQUEST && body["error"].as_str().unwrap_or_default().contains("public addresses only")
}

async fn hosted() -> (AppState, String) {
    let mut state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    state.hosted = true;
    (state, token)
}

#[tokio::test]
async fn a_hosted_worker_refuses_an_ssh_connection_to_a_non_public_host() {
    let (state, token) = hosted().await;
    for (i, host) in NON_PUBLIC.iter().enumerate() {
        let id = format!("ssh_non_public_{i}");
        let (status, body) = send(&state, "POST", "/v1/connections", &token, ssh_connection(&id, host)).await;
        assert!(refused_as_non_public(status, &body), "{host}: {status} {body}");
        assert!(state.service.store().get_connection(&id).unwrap().is_none(), "{host}: nothing was stored");
    }
}

#[tokio::test]
async fn a_hosted_worker_still_adds_an_ssh_connection_to_a_public_host() {
    let (state, token) = hosted().await;
    for (i, host) in ["ssh.example.com", "140.82.112.3"].iter().enumerate() {
        let id = format!("ssh_public_{i}");
        let (status, body) = send(&state, "POST", "/v1/connections", &token, ssh_connection(&id, host)).await;
        assert_eq!(status, StatusCode::CREATED, "{host}: {body}");
    }
}

#[tokio::test]
async fn a_hosted_worker_refuses_an_ssh_edit_to_a_non_public_host() {
    let (state, token) = hosted().await;
    let before = ssh_prod_hosts(&state);
    for host in NON_PUBLIC {
        let (status, body) =
            send(&state, "PATCH", "/v1/connections/ssh_prod", &token, json!({ "ssh": { "host": host } })).await;
        assert!(refused_as_non_public(status, &body), "{host}: {status} {body}");
        assert_eq!(ssh_prod_hosts(&state), before, "{host}: nothing moved");
    }
}

/// Unchanged on a gateway its owner runs: loopback and the LAN are accepted at create and at edit.
#[tokio::test]
async fn a_self_run_gateway_still_reaches_its_own_network_over_ssh() {
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    assert!(!state.hosted);
    for (i, host) in ["127.0.0.1", "10.0.0.1", "nas.local"].iter().enumerate() {
        let id = format!("ssh_lan_{i}");
        let (status, body) = send(&state, "POST", "/v1/connections", &token, ssh_connection(&id, host)).await;
        assert_eq!(status, StatusCode::CREATED, "{host}: {body}");
    }
    let (status, body) =
        send(&state, "PATCH", "/v1/connections/ssh_prod", &token, json!({ "ssh": { "host": "192.168.1.20" } })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(ssh_prod_hosts(&state).iter().all(|h| h == "192.168.1.20"));
}
