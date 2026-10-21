//! An SSH exec action becomes a capability id, and every audit event on that capability records the id as its action, outside the summary the audit bound cuts. A connection an API call makes takes an action of at most 128 bytes, and an event keeps any longer id it meets (a vault restore, a row an earlier version stored) cut, with its length and digest.
//!
//! Every host and credential here is synthetic.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::ExecutionLocation;
use permaura_gateway::service::InvokeOutcome;
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

fn ssh_connection(id: &str, action: &str) -> Value {
    json!({
        "id": id,
        "connector": "ssh",
        "name": id,
        "ssh": {
            "host": "ssh.example.com",
            "user": "deploy",
            "host_key_sha256": "SHA256:synthetic",
            "exec": [{ "action": action, "args_template": ["uptime"] }],
        },
    })
}

#[tokio::test]
async fn an_ssh_exec_action_past_128_bytes_is_refused_where_an_api_call_creates_the_connection() {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    let store = state.service.store();

    for len in [129, 250_000] {
        let id = format!("ssh_long_{len}");
        let (status, body) = send(&state, "POST", "/v1/connections", &token, ssh_connection(&id, &"a".repeat(len))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{len}: {body}");
        let error = body["error"].as_str().unwrap_or_default();
        assert!(error.contains("ssh exec action") && error.contains(&format!("{len} bytes")), "{error}");
        assert!(error.len() < 256, "the refusal does not echo the action: {} bytes", error.len());
        assert!(store.get_connection(&id).unwrap().is_none(), "{len}: nothing was stored");
    }

    let (status, body) = send(&state, "POST", "/v1/connections", &token, ssh_connection("ssh_at_cap", &"a".repeat(128))).await;
    assert_eq!(status, StatusCode::CREATED, "an action of exactly 128 bytes is kept: {body}");
}

#[tokio::test]
async fn an_audit_event_keeps_a_long_capability_id_cut_with_its_length_and_digest() {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let store = state.service.store();

    // A row no API call can make any more, as a vault restore or a 1.3.52 create leaves it: the seeded SSH capability under a 200 KB id, on a connection the demo agent holds no grant on.
    let template = store
        .get_connection("ssh_prod")
        .unwrap()
        .expect("the seeded SSH connection")
        .capabilities
        .into_iter()
        .find_map(|id| store.get_capability(&id).unwrap().filter(|c| c.ssh.is_some()))
        .expect("a seeded SSH capability");
    let cap_id = format!("ssh_long.{}", "a".repeat(200_000));
    let mut cap = template;
    cap.id = cap_id.clone();
    cap.resource = format!("ssh_long_{}", "r".repeat(200_000));
    store.put_capability(cap).unwrap();
    let mut connection = store.get_connection("ssh_prod").unwrap().unwrap();
    connection.id = "ssh_long".into();
    connection.name = "ssh_long".into();
    connection.capabilities = vec![cap_id.clone()];
    store.put_connection(connection).unwrap();

    let session = store.get_session("sess_demo").unwrap().expect("the demo session");
    let before = store.audit_events(None).unwrap().len();
    let outcome = state
        .service
        .invoke(&session, &cap_id, &json!({}), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("the call is answered");
    assert!(matches!(outcome, InvokeOutcome::Denied { .. }));

    let events = store.audit_events(None).unwrap();
    let recorded = &events[before..];
    assert!(!recorded.is_empty(), "the denial is recorded");
    for event in recorded {
        let whole = serde_json::to_string(&event.payload).unwrap();
        assert!(whole.len() < 8 * 1024, "the event is {} bytes", whole.len());
    }
    let denial = recorded.iter().find(|e| e.payload.decision == "deny").expect("a deny event");
    let digest = permaura_core::audit::sha256_hex(cap_id.as_bytes());
    assert!(denial.payload.action.starts_with("ssh_long.aaaa"), "{}", &denial.payload.action[..64]);
    assert!(
        denial.payload.action.contains(&format!("cut from {} bytes", cap_id.len())) && denial.payload.action.contains(&digest),
        "the cut id keeps its length and digest: {}",
        denial.payload.action
    );
    assert!(denial.payload.resource.contains("cut from"), "{}", denial.payload.resource);
    assert_eq!(store.verify_audit().unwrap(), None, "the chain verifies over the cut events");
}
