//! The session-expiry contract: `GET /v1/sessions` says when each session stops authenticating.
//!
//! The store row has carried `expires_at` since sessions were capped, and the listing never sent it.
//! The desktop filled the gap with a hardcoded zero and rendered every live session as "expired".
//!
//! Same shape as the approval-metadata contract: an absolute unix-ms deadline, ALWAYS present, as a
//! number or an explicit null. Absent and null mean different things to a client, so the field is
//! never omitted.
//!
//! The desktop app reads this field from the listing and tells a missing key from an explicit null.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::store::{Session, SessionRole};
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

async fn list(state: AppState, token: &str) -> Vec<serde_json::Value> {
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri("/v1/sessions")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET /v1/sessions");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    body["sessions"].as_array().expect("a sessions array").clone()
}

fn row<'a>(rows: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    rows.iter().find(|r| r["id"] == id).unwrap_or_else(|| panic!("no row for {id}"))
}

fn agent_session(id: &str, expires_at: Option<i64>) -> Session {
    Session {
        class: Default::default(),
        opened_by: None,
        id: id.into(),
        agent_id: "codex-cli".into(),
        user_id: None,
        device_id: None,
        token: format!("tok_{id}"),
        role: SessionRole::Agent,
        created_at: 1_000,
        revoked: false,
        expires_at,
        last_used_at: Some(2_000),
        actor: None,
    }
}

/// A session exactly as a gateway BEFORE the cap persisted one: no `expires_at`, no `last_used_at`.
/// Sessions are stored as a whole-struct JSON blob, so this is what actually sits in `sessions.data`
/// on a store written by an older build.
const OLD_ROW: &str = r#"{
    "id": "sess_old",
    "agent_id": "codex-cli",
    "user_id": null,
    "device_id": null,
    "token": "tok_sess_old",
    "role": "agent",
    "created_at": 1000,
    "revoked": false
}"#;

#[tokio::test]
async fn a_session_with_an_expiry_lists_it_as_the_absolute_deadline() {
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    state.service.store().put_session(agent_session("sess_capped", Some(9_999_999_999_999))).unwrap();

    let rows = list(state, &token).await;
    assert_eq!(row(&rows, "sess_capped")["expires_at"], serde_json::json!(9_999_999_999_999_i64));
}

#[tokio::test]
async fn a_session_with_no_expiry_lists_an_explicit_null_not_a_missing_field() {
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    state.service.store().put_session(agent_session("sess_uncapped", None)).unwrap();

    let rows = list(state, &token).await;
    let r = row(&rows, "sess_uncapped").as_object().unwrap();
    // `r["expires_at"]` on a Value answers Null for a missing key too, which is the exact confusion
    // this contract exists to prevent. Ask the map whether the key is there.
    assert!(r.contains_key("expires_at"), "expires_at must be present, got {r:?}");
    assert!(r["expires_at"].is_null());
}

#[tokio::test]
async fn every_row_carries_the_field() {
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    state.service.store().put_session(agent_session("sess_a", Some(5_000))).unwrap();
    state.service.store().put_session(agent_session("sess_b", None)).unwrap();

    let rows = list(state, &token).await;
    assert!(rows.len() >= 3, "two agent rows and the operator's own, got {}", rows.len());
    for r in &rows {
        assert!(r.as_object().unwrap().contains_key("expires_at"), "row without expires_at: {r}");
    }
}

#[tokio::test]
async fn an_already_expired_session_still_lists_its_deadline() {
    // The listing reports the row; it does not filter on the clock. A client that wants to say
    // "expired" needs the deadline to say it about.
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    state.service.store().put_session(agent_session("sess_lapsed", Some(1_500))).unwrap();

    let rows = list(state, &token).await;
    assert_eq!(row(&rows, "sess_lapsed")["expires_at"], serde_json::json!(1_500));
}

#[tokio::test]
async fn an_old_row_with_no_expiry_field_lists_as_null() {
    let old: Session = serde_json::from_str(OLD_ROW).expect("a pre-cap session still deserializes");
    assert_eq!(old.expires_at, None);

    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    state.service.store().put_session(old).unwrap();

    let rows = list(state, &token).await;
    let r = row(&rows, "sess_old").as_object().unwrap();
    assert!(r.contains_key("expires_at"));
    assert!(r["expires_at"].is_null());
}

#[tokio::test]
async fn the_row_never_carries_the_bearer_or_the_activity_clock() {
    // `GET /v1/sessions` is AgentAllowed (tests/route_classification.rs), so whatever is on the row
    // is readable by every agent token. The bearer must never be; `last_used_at` is held back because
    // it would publish when the operator was last active.
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    state.service.store().put_session(agent_session("sess_quiet", Some(5_000))).unwrap();

    let rows = list(state, &token).await;
    for r in &rows {
        let r = r.as_object().unwrap();
        assert!(!r.contains_key("token"), "bearer on the wire: {r:?}");
        assert!(!r.contains_key("last_used_at"), "activity clock on the wire: {r:?}");
    }
}

#[tokio::test]
async fn an_agent_token_cannot_read_the_listing() {
    // The listing hands out the ids `permaura_revoke_session` takes, so it is operator-only.
    // An agent bearer used to read every row's deadline, not only its own.
    let state = common::seeded();
    common::isolate_from_the_real_install();
    let reader = agent_session("sess_reader", Some(9_999_999_999_999));
    let reader_token = reader.token.clone();
    state.service.store().put_session(reader).unwrap();
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri("/v1/sessions")
                .header("authorization", format!("Bearer {reader_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
