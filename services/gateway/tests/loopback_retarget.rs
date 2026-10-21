//! Once a device is paired, a loopback write on the operator bearer alone may not change where an
//! existing credential is sent or how it is presented. The bearer is a 0600 file every process the
//! owner runs can read, so a loopback call is not evidence of a human.
//!
//! Every host and credential here is synthetic.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::SshCredentialKind;
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

fn pair_a_device(state: &AppState) {
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
    let pubkey = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key("device:owner", &pubkey));
}

async fn patch(state: &AppState, uri: &str, token: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    patch_via(state, uri, token, body, None).await
}

/// [`patch`] with one extra header saying where the request came from.
async fn patch_via(
    state: &AppState,
    uri: &str,
    token: &str,
    body: serde_json::Value,
    via: Option<(&str, &str)>,
) -> (StatusCode, serde_json::Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut request = Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    if let Some((name, value)) = via {
        request = request.header(name, value);
    }
    let request = request.body(Body::from(body.to_string())).unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

/// The SSH target of every capability on the seeded `ssh_prod` connection.
fn ssh_targets(state: &AppState) -> Vec<(String, SshCredentialKind)> {
    let store = state.service.store();
    let conn = store.get_connection("ssh_prod").unwrap().expect("the seeded SSH connection");
    conn.capabilities
        .iter()
        .filter_map(|id| store.get_capability(id).unwrap())
        .filter_map(|cap| cap.ssh.map(|s| (s.target.host, s.credential_kind)))
        .collect()
}

/// The attack: over loopback the bearer pointed `ssh_prod` at another host with password auth, and
/// the next call sent the stored key as the password. Held once a device is paired; as before without.
#[tokio::test]
async fn an_ssh_retarget_over_loopback_is_held_once_a_device_is_paired() {
    let retarget = serde_json::json!({
        "ssh": { "host": "collector.attacker.example", "password_auth": true, "insecure": true }
    });
    for paired in [false, true] {
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        if paired {
            pair_a_device(&state);
        }
        let before = ssh_targets(&state);
        assert!(!before.is_empty());
        let (status, body) = patch(&state, "/v1/connections/ssh_prod", &operator, retarget.clone()).await;
        let after = ssh_targets(&state);
        if paired {
            assert_eq!(status, StatusCode::ACCEPTED, "the retarget waits for the device: {body}");
            assert_eq!(body["required_tier"], "device_signed", "{body}");
            assert_eq!(after, before, "nothing moved before the device signed");
        } else {
            assert_eq!(status, StatusCode::OK, "with no device it applies as before: {body}");
            assert!(
                after.iter().all(|(host, kind)| host == "collector.attacker.example" && *kind == SshCredentialKind::Password),
                "{after:?}"
            );
        }
    }
}

/// A rename on the same connection moves no credential, so it still applies at once.
#[tokio::test]
async fn a_rename_over_loopback_still_applies_with_a_device_paired() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    pair_a_device(&state);
    let (status, body) = patch(&state, "/v1/connections/ssh_prod", &operator, serde_json::json!({ "label": "Prod DB" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// With no device paired there is nothing to hold the retarget for, so from
/// permaura.com's console, in the browser or through the tunnel, it is refused. The same edit at the
/// gateway's own host still applies (above), and so does a rename from the console.
#[tokio::test]
async fn an_ssh_retarget_from_a_page_or_the_tunnel_is_refused_while_no_device_is_paired() {
    let retarget = serde_json::json!({
        "ssh": { "host": "collector.attacker.example", "password_auth": true, "insecure": true }
    });
    for via in [("origin", "https://permaura.com"), ("cf-ray", "abc123")] {
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        assert!(!state.service.any_device_trusted());
        let before = ssh_targets(&state);
        let (status, body) =
            patch_via(&state, "/v1/connections/ssh_prod", &operator, retarget.clone(), Some(via)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{via:?}: {body}");
        assert!(
            body["error"].as_str().unwrap_or_default().contains("no device is paired to confirm it"),
            "{body}"
        );
        assert_eq!(ssh_targets(&state), before, "nothing moved");

        let (status, body) =
            patch_via(&state, "/v1/connections/ssh_prod", &operator, serde_json::json!({ "label": "Prod DB" }), Some(via))
                .await;
        assert_eq!(status, StatusCode::OK, "{via:?}: a rename moves no credential: {body}");
    }
}

/// On a paired gateway whose approvals are explicitly opted down nothing holds the retarget, so from a page or the tunnel it is refused as on an unpaired one.
#[tokio::test]
async fn an_ssh_retarget_from_a_page_is_refused_on_an_opted_down_paired_gateway() {
    let retarget = serde_json::json!({
        "ssh": { "host": "collector.attacker.example", "password_auth": true, "insecure": true }
    });
    for via in [("origin", "https://permaura.com"), ("cf-ray", "abc123")] {
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        pair_a_device(&state);
        state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::Approve)).unwrap();
        let before = ssh_targets(&state);
        let (status, body) =
            patch_via(&state, "/v1/connections/ssh_prod", &operator, retarget.clone(), Some(via)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{via:?}: {body}");
        assert_eq!(ssh_targets(&state), before, "nothing moved");
    }
}
