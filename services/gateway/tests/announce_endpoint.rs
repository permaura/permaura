//! `/v1/announce`: how a self-run gateway is handed the credentials it announces holds with, keeps
//! them across a restart, and gives them up when its link is revoked.
//!
//! Every credential here is synthetic, and every config file lives in a temp directory: a test that
//! wrote the real `~/.permaura/config.toml` would reconfigure the developer's own gateway.

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::config::GatewayConfig;
use permaura_gateway::store::{Session, SessionRole};
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

mod common;

const GATEWAY: &str = "gw_V1StGXR8Z5jdHi6BmyT";
const SECRET: &str = "gwa_0123456789abcdefghijklmnopqrstuvwxyzABCDEF";
const ROTATED: &str = "gwa_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvu";
const SECOND: &str = "gwa_secondWorkspaceSecondWorkspaceSecond01";
const GATEWAY_TWO: &str = "gw_secondWorkspaceLink";

/// The ids the gateway says it announces to, in order.
fn link_ids(body: &serde_json::Value) -> Vec<String> {
    body["links"]
        .as_array()
        .expect("links")
        .iter()
        .map(|l| l["gateway_id"].as_str().unwrap().to_string())
        .collect()
}

fn temp_config(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("permaura-announce-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("config.toml")
}

fn state_writing(path: &PathBuf) -> AppState {
    common::seeded().with_config_path(Some(path.clone()))
}

async fn call(
    state: &AppState,
    method: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value, String) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut builder = Request::builder()
        .method(method)
        .uri("/v1/announce")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
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
    let raw = String::from_utf8_lossy(&bytes).to_string();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null), raw)
}

fn set(gateway_id: &str, secret: &str) -> Option<serde_json::Value> {
    Some(serde_json::json!({ "gateway_id": gateway_id, "announce_secret": secret }))
}

/// The whole point: a gateway linked while it runs starts announcing at once, still announces after
/// a restart, and stops keeping the push addresses the control plane now sends to.
#[tokio::test]
async fn a_linked_gateway_announces_now_and_after_a_restart() {
    let path = temp_config("link");
    std::fs::write(&path, "# operator's own\naddr = \"127.0.0.1:7376\"\n").unwrap();
    let state = state_writing(&path);
    state.service.register_push_token("ExponentPushToken[held-before-link]".into());
    assert!(state.service.holds_push_tokens());

    let (status, before, _) = call(&state, "GET", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(before["configured"], false);
    assert_eq!(before["settable"], true);
    assert!(link_ids(&before).is_empty());

    let (status, body, raw) = call(&state, "PUT", set(GATEWAY, SECRET)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["configured"], true);
    assert_eq!(link_ids(&body), vec![GATEWAY]);
    assert_eq!(body["persisted"], true);
    assert_eq!(body["links"][0]["fingerprint"], permaura_gateway::announce::fingerprint(SECRET));
    assert!(!raw.contains(SECRET), "the answer must never carry the secret");

    let live = state.service.announce_links();
    assert_eq!(live.len(), 1, "announcing without a restart");
    assert_eq!(live[0].gateway_id(), GATEWAY);

    // The control plane is the sender now, so the address held as the sender is gone, in memory and
    // in the stored copy a restart would read.
    assert!(!state.service.holds_push_tokens());
    let stored = state
        .service
        .store()
        .get_meta(permaura_gateway::push::DEVICES_META)
        .unwrap()
        .unwrap_or_default();
    assert!(!stored.contains("held-before-link"), "the stored registry kept the address");

    // What a restart reads: both halves, beside the operator's own settings and comment.
    let raw_file = std::fs::read_to_string(&path).unwrap();
    assert!(raw_file.contains("# operator's own"));
    let file = GatewayConfig::load_from(&path).unwrap().unwrap();
    assert_eq!(file.addr.as_deref(), Some("127.0.0.1:7376"));
    assert_eq!(file.announce_links().len(), 1);
    assert_eq!(file.announce_links()[0].gateway_id, GATEWAY);
    assert_eq!(file.announce_links()[0].announce_secret, SECRET);

    // A rotation replaces the secret everywhere it lives.
    let (status, body, _) = call(&state, "PUT", set(GATEWAY, ROTATED)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(link_ids(&body), vec![GATEWAY], "a rotation replaces the link, it does not add one");
    assert_eq!(body["links"][0]["fingerprint"], permaura_gateway::announce::fingerprint(ROTATED));
    let file = GatewayConfig::load_from(&path).unwrap().unwrap();
    assert_eq!(file.announce_links()[0].announce_secret, ROTATED);

    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

/// The whole reason the gateway holds a list: a machine linked into two workspaces announces every
/// hold to both, and linking the second must not take the first one's notifications away.
#[tokio::test]
async fn a_second_workspace_link_is_added_rather_than_replacing_the_first() {
    let path = temp_config("two-links");
    let state = state_writing(&path);
    assert_eq!(call(&state, "PUT", set(GATEWAY, SECRET)).await.0, StatusCode::OK);

    let (status, body, _) = call(&state, "PUT", set(GATEWAY_TWO, SECOND)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(link_ids(&body), vec![GATEWAY, GATEWAY_TWO]);
    assert_eq!(state.service.announce_links().len(), 2);

    // Both survive a restart, each under its own secret.
    let file = GatewayConfig::load_from(&path).unwrap().unwrap();
    let links = file.announce_links();
    assert_eq!(links.len(), 2);
    assert_eq!(links[1].announce_secret, SECOND);

    // Rotating one leaves the other exactly as it was.
    assert_eq!(call(&state, "PUT", set(GATEWAY, ROTATED)).await.0, StatusCode::OK);
    let links = GatewayConfig::load_from(&path).unwrap().unwrap().announce_links();
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].announce_secret, ROTATED);
    assert_eq!(links[1].announce_secret, SECOND);
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

/// Unlinking one workspace must not silence another, and unlinking the last one hands notification
/// back to the gateway itself, or nothing would notify anyone.
#[tokio::test]
async fn revoking_a_link_clears_only_that_link() {
    let path = temp_config("revoke");
    let state = state_writing(&path);
    assert_eq!(call(&state, "PUT", set(GATEWAY, SECRET)).await.0, StatusCode::OK);
    assert_eq!(call(&state, "PUT", set(GATEWAY_TWO, SECOND)).await.0, StatusCode::OK);
    assert!(!state.service.holds_push_tokens());

    let (status, body, _) =
        call(&state, "DELETE", Some(serde_json::json!({ "gateway_id": GATEWAY }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(link_ids(&body), vec![GATEWAY_TWO], "the other link was dropped too");
    assert_eq!(body["configured"], true);

    // An id this gateway does not hold changes nothing and is not an error.
    let (status, body, _) =
        call(&state, "DELETE", Some(serde_json::json!({ "gateway_id": "gw_neverHeardOf" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(link_ids(&body), vec![GATEWAY_TWO]);

    // No id at all: every link goes, and this gateway sends its own notifications again.
    let (status, body, _) = call(&state, "DELETE", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["configured"], false);
    assert!(state.service.announce_links().is_empty());
    assert!(state.service.holds_push_tokens(), "an unlinked gateway is its own sender again");
    let file = GatewayConfig::load_from(&path).unwrap().unwrap();
    assert!(file.announce_links().is_empty());
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

/// The fan-out is bounded: a machine with more links than this is a mistake somewhere, and every
/// hold would pay for it.
#[tokio::test]
async fn a_gateway_will_not_announce_to_more_workspaces_than_the_cap() {
    let state = common::seeded();
    for i in 0..permaura_gateway::announce::MAX_LINKS {
        let id = format!("gw_link{i}");
        assert_eq!(call(&state, "PUT", set(&id, SECRET)).await.0, StatusCode::OK, "link {i}");
    }
    let (status, body, _) = call(&state, "PUT", set("gw_oneTooMany", SECOND)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "too_many_links");
    assert_eq!(state.service.announce_links().len(), permaura_gateway::announce::MAX_LINKS);
}

#[tokio::test]
async fn a_malformed_credential_is_refused_without_being_echoed() {
    let path = temp_config("malformed");
    let state = state_writing(&path);
    let junk = "gwa_not\"long\nenough";
    let (status, _, raw) = call(&state, "PUT", set(GATEWAY, junk)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!raw.contains("not\\\"long"), "the refusal echoed the value");
    assert_eq!(call(&state, "PUT", set("gw bad id", SECRET)).await.0, StatusCode::BAD_REQUEST);
    assert!(state.service.announce_links().is_empty());
    assert!(!path.exists(), "nothing may be written for a refused credential");
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

/// A hosted worker's credentials come from provisioning; one set here would be gone at the next
/// cold start and would disagree with the hash the provisioner stored.
#[tokio::test]
async fn a_hosted_worker_refuses_credentials_over_rest() {
    let mut state = common::seeded();
    state.hosted = true;
    let (status, body, _) = call(&state, "PUT", set(GATEWAY, SECRET)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "hosted");
    let (_, status_body, _) = call(&state, "GET", None).await;
    assert_eq!(status_body["settable"], false);
}

/// With nowhere to write, the credentials still apply, and the answer says they will not survive a
/// restart rather than implying they will.
#[tokio::test]
async fn without_a_config_file_the_answer_says_it_is_for_this_run_only() {
    let state = common::seeded();
    let (status, body, _) = call(&state, "PUT", set(GATEWAY, SECRET)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["persisted"], false);
    assert_eq!(state.service.announce_links().len(), 1);
}

/// An agent token can invoke; it must not be able to point this gateway's announcements elsewhere.
#[tokio::test]
async fn an_agent_token_cannot_set_credentials() {
    let state = common::seeded();
    let agent = "announce-test-agent-token";
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_announce_agent".into(),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: agent.into(),
            role: SessionRole::Agent,
            created_at: 0,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/announce")
                .header("authorization", format!("Bearer {agent}"))
                .header("content-type", "application/json")
                .body(Body::from(set(GATEWAY, SECRET).unwrap().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(state.service.announce_links().is_empty());
}
