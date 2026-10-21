//! The SFTP put cap and the execution-route body limit, driven through the real router.
//!
//! These two numbers used to be chosen independently: the connector capped a put at 5 MiB and the
//! body it arrives in was capped at 2 MiB, so every put above roughly 1.5 MiB was refused with a
//! bare 413 that named no cap. The put cap is now derived from the body budget. What is worth
//! proving through the router rather than in a unit test is the ORDER the two apply in: a put at the
//! cap has to survive the body limit, and a put over the cap has to reach the connector so the
//! caller is told which cap it broke.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use permaura_core::{Policy, RiskTier};
use permaura_gateway::connectors::{
    base64_len, SFTP_PUT_BODY_BUDGET_BYTES, SFTP_PUT_ENVELOPE_RESERVE_BYTES, SFTP_PUT_MAX_BYTES,
};
use permaura_gateway::limits::{LimitsConfig, DEFAULT_BODY_EXEC_BYTES, MIN_BODY_EXEC_BYTES};
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt; // for `oneshot`

mod common;

/// A seeded estate in which `ssh.sftp.put` actually reaches the connector.
///
/// Two things are in the way of the shipped demo estate and both are deliberate there: the SSH
/// policy denies `sftp.put` outright (the signature "read-only, writes blocked" shape), and the
/// capability is `High` risk, which the engine escalates to human approval on its own. Neither is
/// what this file is about, because the cap under test lives below both, so the estate is opened
/// up here rather than the test being written against a hold it would then have to resolve.
fn state_where_put_executes() -> AppState {
    let state = common::seeded();
    let store = state.service.store();

    store
        .put_policy(Policy {
            id: "pol_ssh_prod".into(),
            connection_id: "ssh_prod".into(),
            name: "Read + write".into(),
            allow: vec![
                "uptime".into(),
                "sftp.list".into(),
                "sftp.get".into(),
                "sftp.put".into(),
            ],
            deny: vec![],
            requires_approval: vec![],
            notify: vec![],
            device_signed: vec![],
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        })
        .expect("the policy is replaced");

    let mut put = store
        .get_capability("ssh.sftp.put")
        .expect("the store answers")
        .expect("the seed registers ssh.sftp.put");
    put.risk = RiskTier::Medium;
    store.put_capability(put).expect("the capability is replaced");

    state
}

/// The put cap the seeded capability carries. The demo connection asks for 1 MiB and the derivation
/// clamps to the same figure, but reading it back is what keeps this file honest if either moves.
fn seeded_put_cap(state: &AppState) -> u64 {
    let cap = state
        .service
        .store()
        .get_capability("ssh.sftp.put")
        .expect("the store answers")
        .expect("the seed registers ssh.sftp.put");
    match cap.ssh.expect("an ssh spec").op {
        permaura_gateway::connectors::SshOp::SftpPut { max_bytes, .. } => max_bytes,
        other => panic!("expected a put op, got {other:?}"),
    }
}

async fn put_of(state: AppState, raw_bytes: usize) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({
        "capability": "ssh.sftp.put",
        "params": { "path": "upload.bin", "content": B64.encode(vec![b'x'; raw_bytes]) }
    });
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn a_put_just_under_the_cap_goes_through_the_router() {
    let state = state_where_put_executes();
    let cap = seeded_put_cap(&state);
    let (status, json) = put_of(state, cap as usize - 1024).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a put just under the cap was refused: {json}"
    );
    assert_eq!(json["decision"]["decision"], "allow");
    assert_eq!(json["result"]["bytes"], cap - 1024);
}

#[tokio::test]
async fn a_put_just_over_the_cap_is_refused_by_name_rather_than_as_a_413() {
    let state = state_where_put_executes();
    let cap = seeded_put_cap(&state);
    let (status, json) = put_of(state, cap as usize + 1).await;
    assert_ne!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "the body limit answered before the connector could name its cap"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = json.to_string();
    assert!(
        message.contains(&format!("{cap}-byte cap for this capability")),
        "the error did not name the cap: {message}"
    );
}

/// The band between the cap and the body limit is finite, and it is honest to say where it ends: a
/// put far enough over the cap is still cut off by the body limit, because no arrangement of the two
/// numbers can name a cap for a request that was never allowed to arrive.
#[tokio::test]
async fn a_put_beyond_the_body_budget_is_still_a_413() {
    let state = state_where_put_executes();
    let (status, _) = put_of(state, SFTP_PUT_BODY_BUDGET_BYTES as usize).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

// ── The two limits cannot drift ─────────────────────────────────────────────────

/// The compile-time half of this is a `const` assertion in `limits.rs`, which is the one that cannot
/// be skipped. This states the relationship in numbers so a failure reads as a sentence rather than
/// as a failed build with no arithmetic in it.
#[test]
fn the_put_cap_is_derived_from_the_execution_body_limit() {
    assert_eq!(
        SFTP_PUT_BODY_BUDGET_BYTES, DEFAULT_BODY_EXEC_BYTES as u64,
        "the connector's copy of the execution body limit has drifted from the gateway's"
    );
    assert!(
        base64_len(SFTP_PUT_MAX_BYTES) + SFTP_PUT_ENVELOPE_RESERVE_BYTES
            <= DEFAULT_BODY_EXEC_BYTES as u64,
        "a put at the cap cannot be delivered inside the execution body limit"
    );
}

/// The env knob is the other way the two can disagree, so it has a floor rather than only a ceiling.
#[test]
fn the_execution_body_limit_cannot_be_configured_below_what_a_put_needs() {
    assert!(MIN_BODY_EXEC_BYTES <= DEFAULT_BODY_EXEC_BYTES);
    assert_eq!(
        MIN_BODY_EXEC_BYTES as u64,
        base64_len(SFTP_PUT_MAX_BYTES) + SFTP_PUT_ENVELOPE_RESERVE_BYTES
    );
    // Resolved rather than asserted on the constant: `from_env` is where a misconfiguration would
    // land, and an unset variable has to come back as the default it clamps.
    assert_eq!(
        LimitsConfig::from_env().body_exec_bytes,
        DEFAULT_BODY_EXEC_BYTES
    );
}
