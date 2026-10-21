//! The identity anchor on a SELF-RUN gateway: the third recovery authority, and its absence.
//!
//! The route that finished on a 24-hour timer is gone. A timer is not an authority: the
//! operator bearer could silence the notification the delay's safety rested on and then simply wait,
//! so the timer granted on its own exactly what the bearer could not obtain. What replaces it is not
//! another local mechanism, because on one OS user there is no local credential an agent cannot read.
//! It is the anchor a hosted worker already uses, made available to a self-run gateway that has an
//! authorization server to re-authenticate at: a single-use `recovery` ticket permaura.com mints
//! after a fresh sign-in.
//!
//! This binary is separate from `hosted_pairing.rs` for one reason and it is load-bearing: that one
//! sets `PERMAURA_HOSTED=1` process-wide, and the property here is precisely that a NON-hosted
//! gateway accepts this ticket. The environment is global, so the two cannot share a process.
//!
//! The last test is the honest half. A gateway with no OAuth configuration has no third authority at
//! all, and it says so rather than inventing a weaker one.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

const AS_ISSUER: &str = "https://permaura.test";
const AS_KID: &str = "as-recovery-key";
const PUBLIC_URL: &str = "https://g-selfrun.permaura.test";
/// The account this gateway belongs to. It is the seeded operator session's own `user_id` on
/// purpose: `session_may_spend_owner_ticket` requires the ticket and the session to name one and the
/// same account, so a ticket minted for somebody else cannot be spent against this session.
const OWNER_SUB: &str = "sam";

fn as_signing_key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| SigningKey::from_bytes(&[9u8; 32]))
}

/// A SELF-RUN gateway that is also an OAuth resource server: the shape a user gets the moment they
/// turn remote access on. `PERMAURA_HOSTED` is deliberately never set.
fn self_run_oauth_environment() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": AS_KID,
                "use": "sig",
                "alg": "EdDSA",
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

async fn self_run_gateway() -> (AppState, axum::Router) {
    self_run_oauth_environment();
    let state = common::seeded();
    assert!(!state.hosted, "this binary must not run hosted");
    state
        .service
        .oauth()
        .expect("a gateway with PERMAURA_PUBLIC_URL set is an OAuth resource server")
        .refresh()
        .await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    (state, app)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn mint_ticket(claims: Value) -> String {
    let header = json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" });
    let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = as_signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// A well-formed `recovery` ticket. The audience is the recovery resource rather than either
/// control's own path, because one re-authentication answers "my device is gone" and both controls
/// are steps out of that one situation.
fn recovery_ticket(jti: &str) -> String {
    mint_ticket(json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_ms() / 1000 + 180,
        "aud": format!("{PUBLIC_URL}/v1/recovery"),
        "jti": jti,
        "purpose": "recovery",
        "amr": ["pwd", "passkey"],
        "auth_time": now_ms() / 1000 - 20,
        "act_sub": OWNER_SUB,
        "act_name": "Owner",
    }))
}

async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = match body {
        Some(b) => builder.header("content-type", "application/json").body(Body::from(b.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request builds");
    let resp = app.clone().oneshot(request).await.expect("router answers");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Pair the first device over loopback, the way a user does, so the floor is raised and the holds
/// this ticket exists to get past are real. Returns the recovery codes that pairing issued.
async fn pair_first_device(app: &axum::Router, seed_byte: u8, approver_id: &str) -> Vec<String> {
    let sk = SigningKey::from_bytes(&[seed_byte; 32]);
    let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = now_ms();
    let sig = permaura_relay::sign(
        &sk,
        &permaura_relay::approver_pairing_preimage(approver_id, &pk, issued_at),
    );
    let (status, body) = send(
        app,
        "POST",
        "/v1/approver-keys/pair",
        Some(json!({
            "approver_id": approver_id, "approver_pubkey": pk,
            "issued_at": issued_at, "sig": sig,
        })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "setup: the first device pairs: {body}");
    let codes = body["recovery_codes"]
        .as_array()
        .map(|c| c.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // Raising the floor is its own call now: pairing makes the device_signed rung resolvable, it does
    // not answer for every other action. Every test here is about RECOVERING from a raised floor, so
    // the setup has to raise it.
    let (status, body) =
        send(app, "PUT", "/v1/approval-floor", Some(json!({ "floor": "device_signed" })), &[]).await;
    assert_eq!(status, StatusCode::OK, "setup: the floor is raised explicitly: {body}");
    codes
}

/// The property: a fresh re-authentication at permaura.com lowers the floor on a self-run gateway
/// that has one to re-authenticate at, and the ticket is spent doing it.
#[tokio::test]
async fn a_recovery_ticket_lowers_the_floor_once() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 21, "device:owner").await;
    assert!(state.service.require_device_signed_approval(), "setup: the floor is raised");

    // Without any recovery authority the change is held, because a device is trusted.
    let (status, body) =
        send(&app, "PUT", "/v1/approval-floor", Some(json!({ "floor": "approve" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "a bearer alone still only gets a hold: {body}");
    // And the hold names the anchor this gateway actually has.
    let hint = body["recovery"].as_str().unwrap_or_default();
    assert!(hint.contains("permaura.com"), "an OAuth-RS gateway must offer the ticket: {body}");

    let ticket = recovery_ticket("jti-floor-1");
    let (status, body) = send(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(json!({ "floor": "approve" })),
        &[("x-permaura-pairing-ticket", ticket.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a recovery ticket applies it at once: {body}");
    assert!(!state.service.require_device_signed_approval());
    let record = recovery_record(&app, "jti-floor-1").await;
    assert_eq!(record["payload"]["action"], "permaura.approval_floor.set", "{record}");
    let summary = &record["payload"]["summary"];
    assert_eq!(summary["authority"], "recovery_ticket", "{record}");
    assert_eq!((summary["from"].as_str(), summary["to"].as_str()), (Some("device_signed"), Some("approve")), "{record}");
    assert_eq!(summary["actor_sub"], OWNER_SUB, "{record}");
    assert!(summary.get("actor_role").is_some_and(Value::is_null), "the owner's own names no role: {record}");

    // Single use: the same ticket cannot do it again, so one re-authentication buys one control.
    state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::DeviceSigned)).unwrap();
    let (status, body) = send(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(json!({ "floor": "approve" })),
        &[("x-permaura-pairing-ticket", ticket.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a spent ticket must be refused: {body}");
    assert!(state.service.require_device_signed_approval(), "and must change nothing");
}

/// A hosted worker clears an opt-down written while nothing was trusted when its first device pairs,
/// because permaura.com can write one there. On a self-run gateway it cannot, with any ticket it can
/// mint or through any route it reaches the gateway by, so an opt-down an unpaired self-run gateway
/// holds was written at its own machine. That one is the owner's choice and outlives the first
/// pairing, which offers the raise instead.
#[tokio::test]
async fn only_the_gateways_own_machine_can_opt_an_unpaired_self_run_gateway_down() {
    let (state, app) = self_run_gateway().await;
    let floor_ticket = mint_ticket(json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_ms() / 1000 + 180,
        "aud": format!("{PUBLIC_URL}/v1/approval-floor"),
        "jti": "jti-unpaired-floor",
        "purpose": "approval-floor-lower",
        "amr": ["pwd", "otp"],
        "auth_time": now_ms() / 1000 - 20,
        "act_sub": OWNER_SUB,
    }));
    let recovery = recovery_ticket("jti-unpaired-recovery");
    let from_off_the_machine: [&[(&str, &str)]; 5] = [
        &[("cf-ray", "8f00000000000000-SIN")],
        &[("origin", "https://permaura.com")],
        &[("x-forwarded-for", "203.0.113.7")],
        &[("cf-ray", "8f00000000000000-SIN"), ("x-permaura-pairing-ticket", floor_ticket.as_str())],
        &[("origin", "https://permaura.com"), ("x-permaura-pairing-ticket", recovery.as_str())],
    ];
    for headers in from_off_the_machine {
        let (status, body) =
            send(&app, "PUT", "/v1/approval-floor", Some(json!({ "floor": "approve" })), headers).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "an opt-down from off the machine is refused ({headers:?}): {body}");
        assert_eq!(state.service.stored_approval_floor(), None, "and writes nothing ({headers:?})");
    }

    let (status, body) =
        send(&app, "PUT", "/v1/approval-floor", Some(json!({ "floor": "approve" })), &[]).await;
    assert_eq!(status, StatusCode::OK, "the gateway's own machine opts down with nothing paired: {body}");
    let sk = SigningKey::from_bytes(&[25; 32]);
    let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = now_ms();
    let sig = permaura_relay::sign(&sk, &permaura_relay::approver_pairing_preimage("device:owner", &pk, issued_at));
    let (status, body) = send(
        &app,
        "POST",
        "/v1/approver-keys/pair",
        Some(json!({ "approver_id": "device:owner", "approver_pubkey": pk, "issued_at": issued_at, "sig": sig })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        state.service.stored_approval_floor(),
        Some(permaura_gateway::service::ApprovalFloor::Approve),
        "the owner's opt-down outlives the first pairing",
    );
    assert_eq!(body["offer_raise"], true, "and the pairing offers the raise: {body}");
}

/// The other control the same purpose covers: the revocation that empties the keyring, after which
/// nothing is held at all. One ticket, one revocation.
#[tokio::test]
async fn a_recovery_ticket_revokes_the_last_key_once() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 22, "device:owner").await;

    let (status, body) = send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "a bearer alone only gets a hold: {body}");
    assert!(state.service.any_device_trusted(), "and revokes nothing");

    let ticket = recovery_ticket("jti-revoke-1");
    let (status, body) = send(
        &app,
        "DELETE",
        "/v1/approver-keys/device:owner",
        None,
        &[("x-permaura-pairing-ticket", ticket.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a recovery ticket revokes the last key: {body}");
    assert!(!state.service.any_device_trusted());
}

/// A ticket minted for one purpose is not spendable as another. The audience and the `purpose` claim
/// are both pinned, so a floor ticket cannot be re-aimed at recovery even on the endpoint they share.
#[tokio::test]
async fn a_ticket_for_another_purpose_is_not_a_recovery_ticket() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 23, "device:owner").await;

    let wrong_purpose = mint_ticket(json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_ms() / 1000 + 180,
        "aud": format!("{PUBLIC_URL}/v1/approval-floor"),
        "jti": "jti-wrong-purpose",
        "purpose": "approval-floor-lower",
        "amr": ["pwd", "otp"],
        "auth_time": now_ms() / 1000 - 20,
    }));
    let (status, body) = send(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(json!({ "floor": "approve" })),
        &[("x-permaura-pairing-ticket", wrong_purpose.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the wrong purpose must not recover: {body}");
    assert!(state.service.require_device_signed_approval(), "and must change nothing");
}

/// The timer is gone here too, and the refusal names the ticket because this gateway has one.
#[tokio::test]
async fn the_delayed_header_is_refused_and_points_at_the_ticket() {
    let (_state, app) = self_run_gateway().await;
    pair_first_device(&app, 24, "device:owner").await;

    let (status, body) = send(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(json!({ "floor": "approve" })),
        &[("x-permaura-recovery", "delayed")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let err = body["error"].as_str().unwrap_or_default();
    assert!(err.contains("completes on a timer has been removed"), "{body}");
    assert!(err.contains("permaura.com"), "an OAuth-RS gateway must offer the ticket: {body}");
}

/// `GET /v1/recovery` says whether this gateway has the third authority at all, so a console does not
/// offer a route that does not exist here.
#[tokio::test]
async fn the_recovery_status_reports_the_ticket_route() {
    let (_state, app) = self_run_gateway().await;
    let (status, body) = send(&app, "GET", "/v1/recovery", None, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["recovery_ticket_accepted"], true, "{body}");
}

/// A member with broker.manage can have permaura.com mint a recovery ticket for the owner's
/// self-run gateway (`sub` is always the owner), but `act_sub` names them, and their re-authentication
/// must not empty the owner's keyring or lower the floor: either switches off the export hold.
#[tokio::test]
async fn a_members_recovery_ticket_cannot_strip_the_owners_device() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 23, "device:owner").await;
    let ticket = |jti: &str, actor: Option<&str>| {
        let mut claims = json!({
            "sub": OWNER_SUB,
            "iss": AS_ISSUER,
            "exp": now_ms() / 1000 + 180,
            "aud": format!("{PUBLIC_URL}/v1/recovery"),
            "jti": jti,
            "purpose": "recovery",
            "amr": ["pwd", "otp"],
            "auth_time": now_ms() / 1000 - 20,
        });
        if let Some(actor) = actor {
            claims["act_sub"] = json!(actor);
            claims["act_name"] = json!("Member");
        }
        mint_ticket(claims)
    };

    for (jti, actor) in [("jti-member-1", Some("user_member")), ("jti-nobody-1", None)] {
        let t = ticket(jti, actor);
        let (status, body) =
            send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[("x-permaura-pairing-ticket", t.as_str())])
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{actor:?}: {body}");
        assert!(state.service.any_device_trusted(), "the owner's device stays trusted");

        let t = ticket(&format!("{jti}-floor"), actor);
        let (status, body) = send(
            &app,
            "PUT",
            "/v1/approval-floor",
            Some(json!({ "floor": "approve" })),
            &[("x-permaura-pairing-ticket", t.as_str())],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{actor:?}: {body}");
        assert!(state.service.require_device_signed_approval(), "the floor stays raised");
    }
    assert!(state.service.vault_export_hold_required(), "export is still held for the owner's device");
}

/// A recovery ticket naming `actor` with an optional `act_role`, as permaura.com mints one for whoever
/// manages the gateway's organization now.
fn managed_recovery_ticket(jti: &str, actor: &str, role: Option<&str>) -> String {
    let mut claims = json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_ms() / 1000 + 180,
        "aud": format!("{PUBLIC_URL}/v1/recovery"),
        "jti": jti,
        "purpose": "recovery",
        "amr": ["pwd", "otp"],
        "auth_time": now_ms() / 1000 - 20,
        "act_sub": actor,
        "act_name": "Someone",
    });
    if let Some(role) = role {
        claims["act_role"] = json!(role);
    }
    mint_ticket(claims)
}

/// The audit record a recovery ticket left, found by the ticket it spent.
async fn recovery_record(app: &axum::Router, jti: &str) -> Value {
    let (_s, audit) = send(app, "GET", "/v1/audit-events?limit=500", None, &[]).await;
    audit["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .rev()
        .find(|e| e["payload"]["summary"]["ticket_jti"] == jti)
        .unwrap_or_else(|| panic!("no audit record names ticket {jti}: {audit}"))
}

/// The organization's owners and admins manage its gateways completely, and
/// those roles move, so whoever holds one now can recover even though the gateway was linked by somebody
/// else. The record names who did it and the role it rested on.
#[tokio::test]
async fn a_current_owner_or_admin_recovers_and_the_record_names_their_role() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 25, "device:owner").await;

    let t = managed_recovery_ticket("jti-admin-revoke", "user_admin", Some("admin"));
    let (status, body) =
        send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[("x-permaura-pairing-ticket", t.as_str())]).await;
    assert_eq!(status, StatusCode::OK, "an admin's ticket revokes the last key: {body}");
    assert!(!state.service.any_device_trusted());
    let record = recovery_record(&app, "jti-admin-revoke").await;
    let summary = &record["payload"]["summary"];
    assert_eq!(summary["authority"], "recovery_ticket", "{record}");
    assert_eq!(summary["actor_sub"], "user_admin", "{record}");
    assert_eq!(summary["actor_role"], "admin", "{record}");

    pair_first_device(&app, 26, "device:replacement").await;
    let t = managed_recovery_ticket("jti-coowner-floor", "user_coowner", Some(" Owner "));
    let (status, body) = send(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(json!({ "floor": "approve" })),
        &[("x-permaura-pairing-ticket", t.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "another owner's ticket lowers the floor: {body}");
    assert!(!state.service.require_device_signed_approval());
    // Lowering the floor switches every hold off, so it is recorded with the same evidence as the revocation.
    let record = recovery_record(&app, "jti-coowner-floor").await;
    assert_eq!(record["payload"]["action"], "permaura.approval_floor.set", "{record}");
    let summary = &record["payload"]["summary"];
    assert_eq!(summary["authority"], "recovery_ticket", "{record}");
    assert_eq!(summary["actor_sub"], "user_coowner", "{record}");
    assert_eq!(summary["actor_role"], "owner", "{record}");
    assert_eq!(summary["to"], "approve", "{record}");
}

/// The owner's own ticket needs no role, and its record says none was claimed rather than leaving the
/// key out.
#[tokio::test]
async fn the_owners_own_recovery_needs_no_role() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 27, "device:owner").await;
    let t = managed_recovery_ticket("jti-owner-own", OWNER_SUB, None);
    let (status, body) =
        send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[("x-permaura-pairing-ticket", t.as_str())]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!state.service.any_device_trusted());
    let record = recovery_record(&app, "jti-owner-own").await;
    let summary = &record["payload"]["summary"];
    assert!(summary.get("actor_role").is_some_and(Value::is_null), "{record}");
}

/// An `act_role` the web never sends (it sends exactly `owner` or `admin`, and omits the claim for a
/// member) is no standing, whatever it looks like: compared by value, not by presence.
#[tokio::test]
async fn an_unexpected_role_value_is_no_standing() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 29, "device:owner").await;
    for (jti, role) in [
        ("jti-odd-super", json!("superadmin")),
        ("jti-odd-long", json!("administrator")),
        ("jti-odd-space", json!("owner admin")),
        ("jti-odd-empty", json!("")),
        ("jti-odd-list", json!(["admin"])),
    ] {
        let mut claims = json!({
            "sub": OWNER_SUB,
            "iss": AS_ISSUER,
            "exp": now_ms() / 1000 + 180,
            "aud": format!("{PUBLIC_URL}/v1/recovery"),
            "jti": jti,
            "purpose": "recovery",
            "amr": ["pwd", "otp"],
            "auth_time": now_ms() / 1000 - 20,
            "act_sub": "user_member",
        });
        claims["act_role"] = role.clone();
        let t = mint_ticket(claims);
        let (status, body) =
            send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[("x-permaura-pairing-ticket", t.as_str())]).await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
            "{role}: refused, never applied: {status} {body}"
        );
        assert!(state.service.any_device_trusted(), "{role}: the device stays trusted");
    }
}

/// A role the AS has no business asserting for recovery is no role at all, and an unnamed actor cannot
/// lean on one.
#[tokio::test]
async fn any_other_role_or_an_unnamed_actor_is_refused() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 28, "device:owner").await;
    for (jti, role) in [("jti-role-member", "member"), ("jti-role-viewer", "viewer"), ("jti-role-staff", "owner,admin")] {
        let t = managed_recovery_ticket(jti, "user_member", Some(role));
        let (status, body) =
            send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[("x-permaura-pairing-ticket", t.as_str())]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{role}: {body}");
        assert!(body["error"].as_str().unwrap_or_default().contains("owner or admin of its organization"), "{body}");
        assert!(state.service.any_device_trusted(), "{role}: the device stays trusted");
        let record = recovery_record(&app, jti).await;
        assert_eq!(record["payload"]["decision"], "deny", "the refused attempt is on the record: {record}");
        assert_eq!(record["payload"]["summary"]["actor_sub"], "user_member", "{record}");
    }
    let mut claims = json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_ms() / 1000 + 180,
        "aud": format!("{PUBLIC_URL}/v1/recovery"),
        "jti": "jti-role-unnamed",
        "purpose": "recovery",
        "amr": ["pwd", "otp"],
        "auth_time": now_ms() / 1000 - 20,
    });
    claims["act_role"] = json!("admin");
    let t = mint_ticket(claims);
    let (status, body) = send(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(json!({ "floor": "approve" })),
        &[("x-permaura-pairing-ticket", t.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(state.service.require_device_signed_approval(), "the floor stays raised");
}

/// The other recovery authority on a self-run gateway: a recovery code lowers the floor, and the record
/// says which code did it, as the revocation's does.
#[tokio::test]
async fn a_recovery_code_floor_lowering_is_recorded() {
    let (state, app) = self_run_gateway().await;
    let sk = SigningKey::from_bytes(&[29u8; 32]);
    let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = now_ms();
    let sig = permaura_relay::sign(&sk, &permaura_relay::approver_pairing_preimage("device:owner", &pk, issued_at));
    let (status, paired) = send(
        &app,
        "POST",
        "/v1/approver-keys/pair",
        Some(json!({ "approver_id": "device:owner", "approver_pubkey": pk, "issued_at": issued_at, "sig": sig })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{paired}");
    let code = paired["recovery_codes"][0].as_str().expect("the first pairing issues recovery codes").to_string();
    let (status, body) = send(&app, "PUT", "/v1/approval-floor", Some(json!({ "floor": "device_signed" })), &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(json!({ "floor": "approve" })),
        &[("x-permaura-recovery-code", code.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!state.service.require_device_signed_approval());
    let (_s, audit) = send(&app, "GET", "/v1/audit-events?limit=500", None, &[]).await;
    let record = audit["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .rev()
        .find(|e| e["payload"]["action"] == "permaura.approval_floor.set")
        .unwrap_or_else(|| panic!("the floor lowering is not in the audit chain: {audit}"));
    let summary = &record["payload"]["summary"];
    assert_eq!(summary["authority"], "recovery_code", "{record}");
    assert!(summary["recovery_code_index"].is_u64(), "{record}");
    assert_eq!(summary["to"], "approve", "{record}");
}

// ── revocation from off the gateway's own machine ──────────────────────────────────────

/// What a tunnelled request carries, so the gateway reads it as remote.
const TUNNELLED: (&str, &str) = ("cf-ray", "abc123");

/// A well-formed `approver-revoke` ticket for one approver id.
fn revoke_ticket(jti: &str, approver_id: &str) -> String {
    revoke_ticket_by(jti, approver_id, OWNER_SUB)
}

/// [`revoke_ticket`] from `actor`, which the AS names in `act_sub`.
fn revoke_ticket_by(jti: &str, approver_id: &str, actor: &str) -> String {
    mint_ticket(json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_ms() / 1000 + 180,
        "aud": format!("{PUBLIC_URL}/v1/approver-keys/revoke"),
        "jti": jti,
        "purpose": "approver-revoke",
        "approver_id": approver_id,
        "amr": ["pwd", "totp"],
        "auth_time": now_ms() / 1000 - 20,
        "act_sub": actor,
        "act_name": "Owner",
    }))
}

/// Trust a second key directly, so a revocation of either leaves the other behind.
fn trust_second_key(state: &AppState, seed_byte: u8, approver_id: &str) {
    let sk = SigningKey::from_bytes(&[seed_byte; 32]);
    let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key(approver_id, &pk), "setup: {approver_id} is trusted");
}

fn trusted(state: &AppState, approver_id: &str) -> bool {
    state.service.approver_keyring_snapshot().trusted_key(approver_id).is_some()
}

/// The newest `permaura.approver.pair` record.
async fn last_keyring_record(app: &axum::Router) -> Value {
    let (_s, audit) = send(app, "GET", "/v1/audit-events?limit=500", None, &[]).await;
    audit["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .rev()
        .find(|e| e["payload"]["action"] == "permaura.approver.pair")
        .unwrap_or_else(|| panic!("no keyring record: {audit}"))
}

/// At the gateway's own machine the operator bearer is the whole authority for a revocation that leaves another key behind.
#[tokio::test]
async fn a_revocation_at_the_gateways_own_machine_needs_only_the_bearer() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 40, "device:owner").await;
    trust_second_key(&state, 41, "device:second");

    let (status, body) = send(&app, "DELETE", "/v1/approver-keys/device:second", None, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!trusted(&state, "device:second"));
    assert!(trusted(&state, "device:owner"));
    let record = last_keyring_record(&app).await;
    assert_eq!(record["payload"]["summary"]["authority"], "operator_revocation", "{record}");
}

/// From off the machine the same revocation takes an `approver-revoke` ticket bound to that device, and the record names who stepped up and how.
#[tokio::test]
async fn a_revocation_from_off_the_machine_takes_a_ticket_bound_to_the_device() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 42, "device:owner").await;
    trust_second_key(&state, 43, "device:second");

    let (status, body) = send(&app, "DELETE", "/v1/approver-keys/device:second", None, &[TUNNELLED]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let err = body["error"].as_str().unwrap_or_default();
    assert!(err.starts_with("step-up required:") && err.contains("'approver-revoke'"), "{body}");
    assert!(trusted(&state, "device:second"));

    let wrong = revoke_ticket("jti-remote-wrong", "device:owner");
    let (status, body) = send(
        &app,
        "DELETE",
        "/v1/approver-keys/device:second",
        None,
        &[TUNNELLED, ("x-permaura-pairing-ticket", wrong.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a ticket for another device is refused: {body}");
    assert!(trusted(&state, "device:second"));

    let t = revoke_ticket("jti-remote-1", "device:second");
    let (status, body) = send(
        &app,
        "DELETE",
        "/v1/approver-keys/device:second",
        None,
        &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!trusted(&state, "device:second"));
    let summary = last_keyring_record(&app).await["payload"]["summary"].clone();
    assert_eq!(summary["authority"], "self_run_owner_ticket", "{summary}");
    assert_eq!(summary["ticket_jti"], "jti-remote-1", "{summary}");
    assert_eq!(summary["actor_sub"], OWNER_SUB, "{summary}");
    assert_eq!(summary["amr"], json!(["pwd", "totp"]), "{summary}");
    assert_eq!(summary["emptied_keyring"], false, "{summary}");
}

/// The emptying revocation from off the machine takes the ticket AND the recovery authority: the ticket alone only queues it for the device.
#[tokio::test]
async fn a_remote_emptying_revocation_takes_the_ticket_and_the_recovery_authority() {
    let (state, app) = self_run_gateway().await;
    let codes = pair_first_device(&app, 44, "device:owner").await;

    let (status, body) =
        send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[TUNNELLED, ("x-permaura-recovery-code", codes[0].as_str())])
            .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a code without the step-up is not enough: {body}");

    let t = revoke_ticket("jti-empty-1", "device:owner");
    let (status, body) =
        send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str())])
            .await;
    assert_eq!(status, StatusCode::ACCEPTED, "the ticket alone is held for the device: {body}");
    assert!(trusted(&state, "device:owner"));
    let held = last_keyring_record(&app).await;
    assert_eq!(held["payload"]["decision"], "requires_approval", "{held}");
    assert_eq!(held["payload"]["summary"]["ticket_jti"], "jti-empty-1", "{held}");

    let t = revoke_ticket("jti-empty-2", "device:owner");
    let (status, body) = send(
        &app,
        "DELETE",
        "/v1/approver-keys/device:owner",
        None,
        &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str()), ("x-permaura-recovery-code", codes[0].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["emptied_keyring"], true, "{body}");
    assert!(!state.service.any_device_trusted());
    let summary = last_keyring_record(&app).await["payload"]["summary"].clone();
    assert_eq!(summary["authority"], "recovery_code", "{summary}");
    assert_eq!(summary["ticket_jti"], "jti-empty-2", "{summary}");
    assert_eq!(summary["amr"], json!(["pwd", "totp"]), "{summary}");
    assert_eq!(summary["emptied_keyring"], true, "{summary}");
}

/// A recovery ticket is itself the step-up, so from off the machine it still empties the keyring on its own: one header cannot carry two tickets.
#[tokio::test]
async fn a_remote_recovery_ticket_is_the_step_up_for_the_emptying_revocation() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 45, "device:owner").await;
    let t = recovery_ticket("jti-remote-recovery");
    let (status, body) =
        send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str())])
            .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!state.service.any_device_trusted());
    let record = recovery_record(&app, "jti-remote-recovery").await;
    assert_eq!(record["payload"]["summary"]["authority"], "recovery_ticket", "{record}");
}

/// A recovery ticket asserting only an authenticator code is refused like any other weak step-up, and recorded.
#[tokio::test]
async fn a_code_only_recovery_ticket_is_refused_and_recorded() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 46, "device:owner").await;
    let t = mint_ticket(json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_ms() / 1000 + 180,
        "aud": format!("{PUBLIC_URL}/v1/recovery"),
        "jti": "jti-recovery-totp-only",
        "purpose": "recovery",
        "amr": ["totp"],
        "auth_time": now_ms() / 1000 - 20,
        "act_sub": OWNER_SUB,
    }));
    let (status, body) =
        send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[("x-permaura-pairing-ticket", t.as_str())]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(state.service.any_device_trusted());
    let record = recovery_record(&app, "jti-recovery-totp-only").await;
    assert_eq!(record["payload"]["decision"], "deny", "{record}");
    assert_eq!(record["payload"]["summary"]["authority"], "recovery_ticket", "{record}");
    assert_eq!(record["payload"]["summary"]["amr"], json!(["totp"]), "{record}");
}

/// Recovery keeps two factors while a step-up takes one: a recovery ticket naming the password, a passkey or the phone on its own is refused and recorded, and the device stays trusted.
#[tokio::test]
async fn a_single_method_recovery_ticket_is_refused_and_recorded() {
    for (n, amr) in [
        json!(["pwd"]),
        json!(["passkey"]),
        json!(["device"]),
        json!(["pwd", "new-device"]),
        json!(["passkey", "new-device"]),
        json!(["new-device", "backup"]),
    ]
        .into_iter()
        .enumerate()
    {
        let (state, app) = self_run_gateway().await;
        pair_first_device(&app, 70 + n as u8, "device:owner").await;
        let jti = format!("jti-recovery-single-{n}");
        let t = mint_ticket(json!({
            "sub": OWNER_SUB,
            "iss": AS_ISSUER,
            "exp": now_ms() / 1000 + 180,
            "aud": format!("{PUBLIC_URL}/v1/recovery"),
            "jti": jti,
            "purpose": "recovery",
            "amr": amr,
            "auth_time": now_ms() / 1000 - 20,
            "act_sub": OWNER_SUB,
        }));
        let (status, body) =
            send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[("x-permaura-pairing-ticket", t.as_str())]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{amr}: {body}");
        assert!(body.to_string().contains("the password and a second factor"), "{amr}: {body}");
        assert!(state.service.any_device_trusted(), "{amr}");
        let record = recovery_record(&app, &jti).await;
        assert_eq!(record["payload"]["decision"], "deny", "{record}");
        assert_eq!(record["payload"]["summary"]["authority"], "recovery_ticket", "{record}");
        assert_eq!(record["payload"]["summary"]["amr"], amr, "{record}");
        assert_eq!(
            record["payload"]["summary"]["reason"],
            "ticket refused: its amr does not hold the password and a second factor, two different strong methods, or one strong method and a backup code",
            "{record}"
        );
    }
}

/// An account with no password recovers with two different strong methods in place of the password and a second factor, or with one strong method and a backup code: a passkey and the phone, or an authenticator code and a backup code, revoke the last key.
#[tokio::test]
async fn a_passwordless_recovery_ticket_revokes_the_last_key() {
    for (n, amr) in [json!(["passkey", "device"]), json!(["totp", "backup"])].into_iter().enumerate() {
        let (state, app) = self_run_gateway().await;
        pair_first_device(&app, 77 + n as u8, "device:owner").await;
        let t = mint_ticket(json!({
            "sub": OWNER_SUB,
            "iss": AS_ISSUER,
            "exp": now_ms() / 1000 + 180,
            "aud": format!("{PUBLIC_URL}/v1/recovery"),
            "jti": format!("jti-recovery-passwordless-{n}"),
            "purpose": "recovery",
            "amr": amr,
            "auth_time": now_ms() / 1000 - 20,
            "act_sub": OWNER_SUB,
        }));
        let (status, body) =
            send(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[("x-permaura-pairing-ticket", t.as_str())]).await;
        assert_eq!(status, StatusCode::OK, "{amr}: {body}");
        assert!(!state.service.any_device_trusted(), "{amr}");
    }
}

/// From off the machine, a revocation by somebody other than the owner of a device not shown to be theirs
/// waits for a device rather than applying at once, and the device it would remove may confirm it.
#[tokio::test]
async fn a_remote_revocation_by_someone_other_than_the_owner_waits_for_a_device() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 48, "device:owner").await;
    trust_second_key(&state, 49, "device:second");
    let t = revoke_ticket_by("jti-remote-admin", "device:second", "user_priya");
    let (status, body) = send(
        &app,
        "DELETE",
        "/v1/approver-keys/device:second",
        None,
        &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(trusted(&state, "device:second"), "nothing was revoked yet");
    let held = state.service.store().get_approval(body["approval_id"].as_str().unwrap()).unwrap().expect("the hold");
    assert_eq!(held.requested_by.and_then(|r| r.person).as_deref(), Some("user_priya"));
    let record = last_keyring_record(&app).await;
    assert_eq!(record["payload"]["decision"], "requires_approval", "{record}");
    assert_eq!(record["payload"]["summary"]["authority"], "self_run_owner_ticket", "{record}");
}

// ── issuing recovery codes from off the gateway's own machine ──────────────────────────

/// A well-formed `recovery-codes-issue` ticket: the account step-up permaura.com mints for issuing a fresh set from the phone or the console.
fn issue_ticket(jti: &str) -> String {
    issue_ticket_with(jti, json!({}))
}

fn issue_ticket_with(jti: &str, overrides: Value) -> String {
    let mut claims = json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_ms() / 1000 + 180,
        "aud": format!("{PUBLIC_URL}/v1/recovery-codes"),
        "jti": jti,
        "purpose": "recovery-codes-issue",
        "amr": ["pwd", "device"],
        "auth_time": now_ms() / 1000 - 20,
        "act_sub": OWNER_SUB,
        "act_name": "Owner",
    });
    for (k, v) in overrides.as_object().cloned().unwrap_or_default() {
        claims[k] = v;
    }
    mint_ticket(claims)
}

/// The body a trusted device sends to ask for a set: its signature over this gateway's device-control preimage.
fn device_signed(state: &AppState, seed_byte: u8, approver_id: &str) -> Value {
    let sk = SigningKey::from_bytes(&[seed_byte; 32]);
    let audience = state.service.approval_audience().expect("approval audience");
    let issued_at = now_ms();
    let sig = permaura_relay::sign(
        &sk,
        &permaura_relay::device_control_preimage_v2(&audience, "recovery-codes", approver_id, "", issued_at),
    );
    json!({ "approver_id": approver_id, "issued_at": issued_at, "sig": sig, "audience": audience })
}

/// The `deny` records a recovery-code issue with no step-up ticket leaves.
async fn no_ticket_refusals(app: &axum::Router) -> usize {
    let (_s, audit) = send(app, "GET", "/v1/audit-events?limit=500", None, &[]).await;
    audit["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|e| {
            e["payload"]["action"] == "permaura.approver.pair"
                && e["payload"]["decision"] == "deny"
                && e["payload"]["summary"]["purpose"] == "recovery-codes-issue"
                && e["payload"]["summary"]["reason"].as_str().is_some_and(|r| r.contains("no step-up ticket"))
        })
        .count()
}

fn issued(body: &Value) -> usize {
    body["recovery_codes"].as_array().map(Vec::len).unwrap_or(0)
}

/// The CLI on the gateway's own machine issues on the device signature alone, exactly as before: placement is the account's proof there.
#[tokio::test]
async fn issuing_recovery_codes_at_the_gateways_own_machine_needs_no_ticket() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 50, "device:owner").await;
    let (status, body) = send(&app, "POST", "/v1/recovery-codes", Some(device_signed(&state, 50, "device:owner")), &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(issued(&body), 8, "{body}");
}

/// From off the machine the signature is not enough: the request needs a `recovery-codes-issue` ticket beside it, and the ticket alone is not
/// enough either. The record names who stepped up and how, and the ticket is spent.
#[tokio::test]
async fn issuing_recovery_codes_from_off_the_machine_takes_a_ticket_beside_the_signature() {
    let (state, app) = self_run_gateway().await;
    let codes = pair_first_device(&app, 51, "device:owner").await;

    // The step-up challenge every other ticket route answers, 401 rather than a 403 a client cannot act on, and on the record.
    let refusals_before = no_ticket_refusals(&app).await;
    let (status, body) =
        send(&app, "POST", "/v1/recovery-codes", Some(device_signed(&state, 51, "device:owner")), &[TUNNELLED]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a signature alone is a step-up challenge remotely: {body}");
    let err = body["error"].as_str().unwrap_or_default();
    assert!(err.contains("'recovery-codes-issue'") && err.contains("x-permaura-pairing-ticket"), "the challenge names the ticket: {body}");
    assert!(err.contains("own machine"), "and the local alternative: {body}");
    assert_eq!(issued(&body), 0);
    assert_eq!(no_ticket_refusals(&app).await, refusals_before + 1, "the refusal is recorded");

    let (status, body) = send(
        &app,
        "POST",
        "/v1/recovery-codes",
        None,
        &[TUNNELLED, ("x-permaura-recovery-code", codes[0].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a current code alone is challenged remotely too: {body}");
    assert_eq!(no_ticket_refusals(&app).await, refusals_before + 2);

    let t = issue_ticket("jti-issue-bare");
    let (status, body) =
        send(&app, "POST", "/v1/recovery-codes", None, &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str())]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the ticket does not stand in for the device: {body}");
    assert_eq!(issued(&body), 0);

    let t = issue_ticket("jti-issue-1");
    let (status, body) = send(
        &app,
        "POST",
        "/v1/recovery-codes",
        Some(device_signed(&state, 51, "device:owner")),
        &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(issued(&body), 8, "{body}");
    let summary = recovery_record(&app, "jti-issue-1").await["payload"]["summary"].clone();
    assert_eq!(summary["authority"], "device_signed_request", "{summary}");
    assert_eq!(summary["actor_sub"], OWNER_SUB, "{summary}");
    assert_eq!(summary["amr"], json!(["pwd", "device"]), "{summary}");
    assert_eq!(summary["regenerated"], true, "{summary}");

    let (status, body) = send(
        &app,
        "POST",
        "/v1/recovery-codes",
        Some(device_signed(&state, 51, "device:owner")),
        &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a spent ticket is spent: {body}");
    assert_eq!(issued(&body), 0);
}

/// A current code with the ticket still issues remotely: the step-up is added to whichever authority the request already carried.
#[tokio::test]
async fn a_remote_code_with_the_ticket_issues_a_fresh_set() {
    let (_state, app) = self_run_gateway().await;
    let codes = pair_first_device(&app, 52, "device:owner").await;
    let t = issue_ticket("jti-issue-code");
    let (status, body) = send(
        &app,
        "POST",
        "/v1/recovery-codes",
        None,
        &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str()), ("x-permaura-recovery-code", codes[0].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let summary = recovery_record(&app, "jti-issue-code").await["payload"]["summary"].clone();
    assert_eq!(summary["authority"], "recovery_code", "{summary}");
}

/// A ticket minted for another purpose, another gateway or another account, or one asserting fewer than the password and a second factor, does not issue codes.
#[tokio::test]
async fn a_ticket_for_another_purpose_gateway_or_account_cannot_issue_recovery_codes() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 53, "device:owner").await;
    let wrong = [
        ("a recovery ticket", recovery_ticket("jti-wrong-recovery")),
        ("an approver-revoke ticket", revoke_ticket("jti-wrong-revoke", "device:owner")),
        (
            "an issuing ticket for another gateway",
            issue_ticket_with("jti-wrong-aud", json!({ "aud": "https://g-other.permaura.test/v1/recovery-codes" })),
        ),
        ("an issuing ticket for another account", issue_ticket_with("jti-wrong-sub", json!({ "sub": "someone-else" }))),
        ("an issuing ticket naming the purpose on another audience", issue_ticket_with("jti-wrong-path", json!({ "aud": format!("{PUBLIC_URL}/v1/recovery") }))),
        ("a backup-code-only issuing ticket", issue_ticket_with("jti-wrong-amr", json!({ "amr": ["backup"] }))),
        ("a password-only issuing ticket", issue_ticket_with("jti-wrong-amr-pwd", json!({ "amr": ["pwd"] }))),
        ("a passkey-only issuing ticket", issue_ticket_with("jti-wrong-amr-passkey", json!({ "amr": ["passkey"] }))),
    ];
    for (what, t) in wrong {
        let (status, body) = send(
            &app,
            "POST",
            "/v1/recovery-codes",
            Some(device_signed(&state, 53, "device:owner")),
            &[TUNNELLED, ("x-permaura-pairing-ticket", t.as_str())],
        )
        .await;
        assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN, "{what}: {status} {body}");
        assert_eq!(issued(&body), 0, "{what}: {body}");
    }
    let record = recovery_record(&app, "jti-wrong-amr").await;
    assert_eq!(record["payload"]["decision"], "deny", "{record}");
    assert_eq!(record["payload"]["summary"]["approver_id"], "recovery-codes", "{record}");
    assert_eq!(record["payload"]["summary"]["purpose"], "recovery-codes-issue", "{record}");
    assert_eq!(record["payload"]["summary"]["authority"], "self_run_owner_ticket", "{record}");
}

// ── Removing a device alone on a self-run gateway ──────────────────────────────────────────

/// From off the machine, a removal by somebody other than the owner applies at once through either delete route when permaura.com signed `remove_alone` on the ticket, and the record names the capability and the actor; a forged claim is refused with its ticket.
#[tokio::test]
async fn a_self_run_removal_the_ticket_may_make_alone_applies_at_once() {
    for (n, route) in ["/v1/approver-keys", "/v1/devices"].into_iter().enumerate() {
        let (state, app) = self_run_gateway().await;
        pair_first_device(&app, 50 + n as u8 * 2, "device:owner").await;
        trust_second_key(&state, 51 + n as u8 * 2, "device:second");
        let alone = mint_ticket(json!({
            "sub": OWNER_SUB,
            "iss": AS_ISSUER,
            "exp": now_ms() / 1000 + 180,
            "aud": format!("{PUBLIC_URL}/v1/approver-keys/revoke"),
            "jti": format!("jti-alone-{n}"),
            "purpose": "approver-revoke",
            "approver_id": "device:second",
            "amr": ["pwd", "totp"],
            "auth_time": now_ms() / 1000 - 20,
            "act_sub": "user_priya",
            "act_name": "Priya",
            "remove_alone": true,
        }));
        let (status, body) = send(&app, "DELETE", &format!("{route}/device:second"), None, &[TUNNELLED, ("x-permaura-pairing-ticket", alone.as_str())]).await;
        assert_eq!(status, StatusCode::OK, "{route}: {body}");
        assert!(!trusted(&state, "device:second"), "{route}");
        assert!(trusted(&state, "device:owner"));
        let record = last_keyring_record(&app).await;
        assert_eq!(record["payload"]["summary"]["authority"], "self_run_owner_ticket", "{record}");
        assert_eq!(record["payload"]["summary"]["remove_alone"], true, "{record}");
        assert_eq!(record["payload"]["summary"]["capability"], "device.remove.any", "{record}");
        assert_eq!(record["payload"]["summary"]["actor_sub"], "user_priya", "{record}");
    }
}

/// A `remove_alone` claim added to a valid ticket's payload breaks its signature, so the ticket is refused and the removal neither applies nor waits.
#[tokio::test]
async fn a_self_run_forged_remove_alone_claim_is_ignored() {
    let (state, app) = self_run_gateway().await;
    pair_first_device(&app, 56, "device:owner").await;
    trust_second_key(&state, 57, "device:second");
    let valid = revoke_ticket_by("jti-alone-forged", "device:second", "user_priya");
    let parts: Vec<&str> = valid.split('.').collect();
    let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    claims["remove_alone"] = json!(true);
    let forged = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes()), parts[2]);
    let (status, body) = send(&app, "DELETE", "/v1/approver-keys/device:second", None, &[TUNNELLED, ("x-permaura-pairing-ticket", forged.as_str())]).await;
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN, "{status}: {body}");
    assert!(trusted(&state, "device:second"));
}

// ── An approver id of the form user:<account> on a self-run gateway ───────────────────────────

/// At the gateway's own machine a pairing under `user:<account>` must name that same account as its person: another person, or none, is refused and nothing is trusted.
#[tokio::test]
async fn a_self_run_pairing_under_a_user_id_must_name_that_account() {
    let (state, app) = self_run_gateway().await;
    let sk = SigningKey::from_bytes(&[58; 32]);
    let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    let body = |approver_id: &str, person: Option<&str>| {
        let issued_at = now_ms();
        let sig = permaura_relay::sign(&sk, &permaura_relay::approver_pairing_preimage(approver_id, &pk, issued_at));
        let mut body = json!({ "approver_id": approver_id, "approver_pubkey": pk, "issued_at": issued_at, "sig": sig });
        if let Some(person) = person {
            body["person"] = json!(person);
        }
        body
    };
    for person in [Some("user_priya"), None] {
        let (status, resp) = send(&app, "POST", "/v1/approver-keys/pair", Some(body("user:user_owner", person)), &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{person:?}: {resp}");
        assert!(!trusted(&state, "user:user_owner"));
    }
    let (status, resp) = send(&app, "POST", "/v1/approver-keys/pair", Some(body("user:user_priya", Some("user_priya"))), &[]).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(trusted(&state, "user:user_priya"));
}
