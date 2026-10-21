//! An SSH target patch writes its host, user and host key into every SSH capability of the connection. Each is held to the length a real one takes, and the rewritten rows ask the capability-bytes ceiling before they are written. A create is held to the same lengths.
//!
//! Every host and credential here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::{build_router, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

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

/// Every SSH target on the seeded `ssh_prod` connection, as `(host, user, host key)`.
fn ssh_prod_targets(state: &AppState) -> Vec<String> {
    let store = state.service.store();
    let conn = store.get_connection("ssh_prod").unwrap().expect("the seeded SSH connection");
    conn.capabilities
        .iter()
        .filter_map(|id| store.get_capability(id).unwrap())
        .filter_map(|cap| cap.ssh.map(|s| serde_json::to_string(&s.target).unwrap()))
        .collect()
}

#[tokio::test]
async fn an_ssh_target_patch_refuses_a_value_longer_than_a_real_one_and_names_the_field() {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    let before = ssh_prod_targets(&state);
    assert!(!before.is_empty());

    for (field, what, len) in [
        ("host", "ssh host", 254),
        ("user", "ssh user", 257),
        ("host_key_sha256", "ssh host_key_sha256", 16 * 1024 + 1),
        ("user", "ssh user", 200_000),
    ] {
        let (status, body) =
            send(&state, "PATCH", "/v1/connections/ssh_prod", &token, json!({ "ssh": { field: "a".repeat(len) } })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field} {len}: {body}");
        let error = body["error"].as_str().unwrap_or_default();
        assert!(error.contains(what) && error.contains(&format!("{len} bytes")), "{error}");
        assert!(error.len() < 256, "the refusal does not echo the value: {} bytes", error.len());
        assert_eq!(ssh_prod_targets(&state), before, "{field} {len}: nothing moved");
    }

    let at_caps = json!({ "ssh": { "host": "h".repeat(253), "user": "u".repeat(256), "host_key_sha256": "k".repeat(16 * 1024) } });
    let (status, body) = send(&state, "PATCH", "/v1/connections/ssh_prod", &token, at_caps).await;
    assert_eq!(status, StatusCode::OK, "values at each cap are written: {body}");
    assert!(ssh_prod_targets(&state).iter().all(|t| t.contains(&"u".repeat(256))));
}

#[tokio::test]
async fn an_ssh_target_patch_asks_the_capability_bytes_ceiling_before_it_writes() {
    common::isolate_from_the_real_install();
    let probe = common::seeded();
    let token = common::operator_token(probe.clone()).await;
    let held = probe.service.store().capability_bytes().unwrap();
    let state = probe.clone().with_limits(Arc::new(Limits::new(LimitsConfig { capability_bytes: held + 1024, ..LimitsConfig::default() })));
    let before = ssh_prod_targets(&state);
    let rows = before.len();
    assert!(rows > 0);

    // Every SSH capability grows by about 16 KiB, which takes the rows past a ceiling 1 KiB above what they hold.
    let (status, body) =
        send(&state, "PATCH", "/v1/connections/ssh_prod", &token, json!({ "ssh": { "host_key_sha256": "k".repeat(16 * 1024) } })).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(error.contains(&format!("these {rows} capabilities")) && error.contains("ceiling"), "{error}");
    assert_eq!(ssh_prod_targets(&state), before, "nothing moved");
    assert_eq!(state.service.store().capability_bytes().unwrap(), held);

    // A patch that adds nothing to what the rows take is never refused, even at the ceiling.
    let host: Value = serde_json::from_str(&before[0]).unwrap();
    let at_ceiling = probe.with_limits(Arc::new(Limits::new(LimitsConfig { capability_bytes: held, ..LimitsConfig::default() })));
    let (status, body) = send(&at_ceiling, "PATCH", "/v1/connections/ssh_prod", &token, json!({ "ssh": { "host": host["host"] } })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn ssh_connection(id: &str, host: &str, user: &str, host_key: &str) -> Value {
    json!({
        "id": id,
        "connector": "ssh",
        "name": id,
        "ssh": {
            "host": host,
            "user": user,
            "host_key_sha256": host_key,
            "exec": [{ "action": "uptime", "args_template": ["uptime"] }],
        },
    })
}

#[tokio::test]
async fn an_ssh_create_refuses_a_target_value_longer_than_a_patch_may_pin_and_names_the_field() {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    let store = state.service.store();
    let (host, user, key) = ("ssh.example.com", "deploy", "SHA256:synthetic");

    for (what, len, body) in [
        ("ssh host", 254, ssh_connection("ssh_long_host", &"h".repeat(254), user, key)),
        ("ssh user", 257, ssh_connection("ssh_long_user", host, &"u".repeat(257), key)),
        ("ssh host_key_sha256", 16 * 1024 + 1, ssh_connection("ssh_long_key", host, user, &"k".repeat(16 * 1024 + 1))),
        ("ssh user", 200_000, ssh_connection("ssh_huge_user", host, &"u".repeat(200_000), key)),
    ] {
        let id = body["id"].as_str().unwrap().to_string();
        let (status, reply) = send(&state, "POST", "/v1/connections", &token, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what} {len}: {reply}");
        let error = reply["error"].as_str().unwrap_or_default();
        assert!(error.contains(what) && error.contains(&format!("{len} bytes")), "{error}");
        assert!(error.len() < 256, "the refusal does not echo the value: {} bytes", error.len());
        assert!(store.get_connection(&id).unwrap().is_none(), "{what} {len}: nothing was stored");
    }

    let at_caps = ssh_connection("ssh_at_caps", &"h".repeat(253), &"u".repeat(256), &"k".repeat(16 * 1024));
    let (status, reply) = send(&state, "POST", "/v1/connections", &token, at_caps).await;
    assert_eq!(status, StatusCode::CREATED, "values at each cap are kept: {reply}");
}

#[tokio::test]
async fn a_hosted_ssh_create_refuses_an_overlong_host_by_its_length_without_echoing_it() {
    common::isolate_from_the_real_install();
    let mut state = common::seeded();
    state.hosted = true;
    let token = common::operator_token(state.clone()).await;
    let host = format!("{}!", "h".repeat(100_000));
    let body = ssh_connection("ssh_hosted_long_host", &host, "deploy", "SHA256:synthetic");
    let (status, reply) = send(&state, "POST", "/v1/connections", &token, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    let error = reply["error"].as_str().unwrap_or_default();
    assert!(error.contains("ssh host") && error.contains("100001 bytes"), "{}", &error[..error.len().min(200)]);
    assert!(error.len() < 256, "the refusal does not echo the host: {} bytes", error.len());
    assert!(state.service.store().get_connection("ssh_hosted_long_host").unwrap().is_none());
}
