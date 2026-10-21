//! Approver pairing on a HOSTED (Mode C) worker: the identity anchor that replaces loopback.
//!
//! A hosted worker is a per-tenant Cloud Run container. It is directly internet-exposed, it has no
//! loopback client a human could be standing at, and `compute_is_remote` therefore reports every
//! request as remote. The positional anchor that authorises device enrolment on a local or tunnelled
//! gateway simply does not exist there, so pairing is opened behind a substitute: an owner-scoped
//! OAuth operator session PLUS a single-use, purpose-bound, audience-bound step-up ticket the
//! Authorization Server mints after a fresh re-authentication.
//!
//! These tests exist for the failure modes of that substitute, because it is the only thing standing
//! between the internet and the gateway's trust root. Every one of them drives REAL Ed25519 keys
//! through the REAL verification paths: the AS's signing key through the RS's JWKS cache, and the
//! device's signing key through `verify_ticket`, the pairing possession proof and
//! `verify_signed_approval`. A "paired device" IS a key, so nothing here is mocked or stubbed: a
//! test that faked either signature would prove nothing about the property it claims to protect.
//!
//! The properties pinned here, in the order they matter:
//!  - a ticket is REQUIRED (401, a step-up challenge, not a flat 403 the console cannot act on);
//!  - a ticket is non-transferable across audience, purpose, approver id, key and account;
//!  - a ticket is SINGLE USE, so it never degrades into a reusable bearer for its 180s lifetime;
//!  - the ticket alone enrols exactly ONE device, and every later device needs hardware that this
//!    worker already trusts to co-sign: an AS compromise can never join a device to a live keyring;
//!  - and, in the other direction, revoking every device must leave the tenant a way back in, or a
//!    lost phone bricks a hosted control plane permanently.
//!
//! What is NOT opened stays closed, and the last two tests are the regression guard for that:
//! `POST /v1/sessions` mints an Operator token with no authentication whatsoever (`reject_if_remote`
//! is its entire gate), and `POST /v1/shutdown` stops the worker. Neither may ever learn about
//! pairing tickets.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

use permaura_gateway::store::{
    PendingApproval, Session, SessionActor, SessionRole, APPROVAL_EXPIRED, CONTROL_PLANE_HOLD_TTL_MS,
};
use common::build_router;
use permaura_gateway::{seed, AppState};

mod common;

// ── the hosted deployment these tests model ──────────────────────────────────────────

/// The account this worker is provisioned for (`PERMAURA_OWNER_SUB`). It matches the seeded demo
/// operator session's `user_id`, because the last check in `pairing_authority` ties the ticket's
/// `sub` to the session's user: a stolen ticket must not be spendable on someone else's session.
const OWNER_SUB: &str = "sam";

/// The org member who actually re-authenticates in these tests, deliberately NOT [`OWNER_SUB`].
///
/// A hosted worker belongs to an organisation, and any member the org has given `device.manage` to
/// can obtain a pairing ticket for it. Every such ticket carries the owner in `sub`, because that is
/// how a ticket is pinned to one worker, so `sub` cannot be the actor and a suite that made them the
/// same string would never notice if the gateway conflated them.
const ACTOR_SUB: &str = "user_priya";

/// That member's display name, as the AS supplies it. Self-set text: recorded for legibility, never
/// matched on.
const ACTOR_NAME: &str = "Priya Raman";

/// The worker's public base URL. Ticket audiences are derived from it per endpoint, so it is what
/// makes a ticket minted for another gateway (or for this gateway's MCP resource) non-spendable.
const PUBLIC_URL: &str = "https://g-hosted.permaura.test";

/// The Authorization Server's issuer, as it appears in every `iss` claim.
const AS_ISSUER: &str = "https://permaura.test/api/auth";

/// The `kid` of the one Ed25519 key the fake AS publishes.
const AS_KID: &str = "as-test-k1";

const PAIR_TICKET_HEADER: &str = "x-permaura-pairing-ticket";

/// The AS's signing key. The gateway learns its PUBLIC half the only way it ever does (by fetching
/// the JWKS), so these tests exercise key selection and signature verification for real.
fn as_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[171u8; 32])
}

/// Stand up a fake Authorization Server JWKS endpoint and point the process at it, exactly once.
///
/// The RS's key cache is private and is only ever filled by an HTTP fetch, so injecting a key means
/// actually serving one. The listener lives on a detached OS thread rather than a tokio task because
/// every `#[tokio::test]` builds and drops its own runtime, and a server tied to the first test's
/// runtime would vanish under the rest.
///
/// The environment is process-global and these tests run in parallel, so every value here is the
/// same for every test and is set before any `AppState` exists. `PERMAURA_HOSTED` also selects the
/// store-backed keyring persistence a real hosted worker uses, which is the placement the
/// trust-on-first-use branch depends on being able to re-read.
fn hosted_environment() {
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

        std::env::set_var("PERMAURA_HOSTED", "1");
        // A hosted worker is handed its KEK from Secret Manager: `PERMAURA_HOSTED=1` deliberately
        // skips the on-disk fallback, because a Cloud Run filesystem is ephemeral and a regenerated
        // key would orphan the vault on the next cold start. So the harness has to supply one, exactly
        // as the provisioner does, which mounts it as a file. Before the gateway refused to start
        // without a real KEK, this file got the public dev constant instead and the omission was
        // invisible.
        // One file per process: nextest runs each test in its own process, and a shared path let one
        // truncate it while another was reading, which read as no KEK at all.
        let kek = std::env::temp_dir().join(format!("permaura-hosted-pairing-vault-kek-{}", std::process::id()));
        std::fs::write(&kek, "test-hosted-vault-kek").expect("write the KEK file");
        std::env::set_var("PERMAURA_VAULT_PASSPHRASE_FILE", &kek);
        std::env::set_var("PERMAURA_PUBLIC_URL", PUBLIC_URL);
        std::env::set_var("PERMAURA_AS_ISSUER", AS_ISSUER);
        std::env::set_var("PERMAURA_AS_JWKS", format!("http://127.0.0.1:{port}/jwks"));
        std::env::set_var("PERMAURA_OWNER_SUB", OWNER_SUB);
    });
}

/// Answer every connection with the same JWKS document. Deliberately minimal: it only ever sees the
/// RS's own `GET`, so the request is drained and discarded rather than parsed.
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

/// A hosted worker with its JWKS already loaded, so verification is synchronous from the first
/// request. `refresh()` is awaited rather than left to the background task `spawn_refresh` started,
/// because a test that raced it would fail as "unknown signing key" and look like a ticket bug.
async fn hosted_gateway() -> (AppState, axum::Router) {
    hosted_environment();
    let state = common::seeded();
    assert!(state.hosted, "PERMAURA_HOSTED must have been read before this AppState was built");
    state
        .service
        .oauth()
        .expect("a hosted worker with PERMAURA_PUBLIC_URL set is an OAuth resource server")
        .refresh()
        .await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    (state, app)
}

// ── minting tickets and pairing blobs ────────────────────────────────────────────────

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_secs() -> i64 {
    now_ms() / 1000
}

/// The gateway's public-key fingerprint scheme, replicated because `service::key_fingerprint` is
/// crate-internal. It must stay byte-identical: the AS pins a ticket to `pubkey_fp`, and a
/// fingerprint computed any other way would reject the very key the ticket was minted for.
fn key_fingerprint(pubkey_b64: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(pubkey_b64.as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Sign a JWS the way the AS does: EdDSA over `header.payload`, both URL-safe base64 unpadded.
fn mint_ticket(claims: Value) -> String {
    let header = json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" });
    let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = as_signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// A well-formed `approver-pair` ticket. Every refusal test starts from this and breaks exactly one
/// claim, so an assertion cannot pass because the ticket happened to be malformed elsewhere. The actor
/// is an organization admin, as the web stamps in `act_role`, because a worker's first device takes
/// that standing; [`pair_claims_by`] builds a member's.
fn pair_claims(jti: &str, approver_id: &str, pubkey_b64: &str) -> Value {
    json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_secs() + 180,
        "aud": format!("{PUBLIC_URL}/v1/approver-keys/pair"),
        "jti": jti,
        "purpose": "approver-pair",
        "approver_id": approver_id,
        "pubkey_fp": key_fingerprint(pubkey_b64),
        "amr": ["pwd", "passkey"],
        "auth_time": now_secs() - 20,
        // The member who re-authenticated, which `sub` never names.
        "act_sub": ACTOR_SUB,
        "act_name": ACTOR_NAME,
        "act_role": "admin",
    })
}

/// A well-formed `approval-floor-lower` ticket. Binding is `None` for this purpose (there is only
/// one floor), so the audience and the purpose claim are the whole authorisation. The actor claims
/// are present because the AS puts them on every ticket it mints, whatever the purpose.
fn floor_claims(jti: &str) -> Value {
    json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_secs() + 180,
        "aud": format!("{PUBLIC_URL}/v1/approval-floor"),
        "jti": jti,
        "purpose": "approval-floor-lower",
        "amr": ["pwd", "otp"],
        "auth_time": now_secs() - 20,
        "act_sub": ACTOR_SUB,
        "act_name": ACTOR_NAME,
    })
}

/// [`floor_claims`] from `actor` with `role` as the web stamps it in `act_role`.
fn floor_claims_by(jti: &str, actor: &str, role: Option<&str>) -> Value {
    let mut claims = floor_claims(jti);
    claims["act_sub"] = json!(actor);
    if let Some(role) = role {
        claims["act_role"] = json!(role);
    }
    claims
}

/// A well-formed `approver-revoke` ticket for one approver id: what every revocation on a hosted
/// worker presents. Its audience names the action rather than a route, because two routes reach it.
fn revoke_claims(jti: &str, approver_id: &str) -> Value {
    json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_secs() + 180,
        "aud": format!("{PUBLIC_URL}/v1/approver-keys/revoke"),
        "jti": jti,
        "purpose": "approver-revoke",
        "approver_id": approver_id,
        "amr": ["pwd", "device"],
        "auth_time": now_secs() - 20,
        "act_sub": ACTOR_SUB,
        "act_name": ACTOR_NAME,
    })
}

/// A device's signing key, from a fixed seed so a test can deliberately reuse or collide one.
fn device_key(seed_byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed_byte; 32])
}

fn pubkey_of(sk: &SigningKey) -> String {
    STANDARD.encode(sk.verifying_key().to_bytes())
}

/// The pairing blob a phone or watch exports: the real possession proof, an Ed25519 signature over
/// the canonical pairing preimage. Never faked: the endpoint verifies it before spending a ticket.
fn pair_body(approver_id: &str, sk: &SigningKey) -> Value {
    let pubkey = pubkey_of(sk);
    let issued_at = now_ms();
    let preimage = permaura_relay::approver_pairing_preimage(approver_id, &pubkey, issued_at);
    json!({
        "approver_id": approver_id,
        "approver_pubkey": pubkey,
        "issued_at": issued_at,
        "sig": permaura_relay::sign(sk, &preimage),
    })
}

// ── driving the router ───────────────────────────────────────────────────────────────

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// One request through the real router, with the operator bearer and any extra headers a test needs.
async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    for (k, v) in extra {
        builder = builder.header(*k, *v);
    }
    let req = match body {
        Some(b) => builder.body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// `POST /v1/approver-keys/pair`, optionally presenting a step-up ticket.
async fn pair(app: &axum::Router, body: Value, ticket: Option<&str>) -> (StatusCode, Value) {
    let extra: Vec<(&str, &str)> =
        ticket.map(|t| vec![(PAIR_TICKET_HEADER, t)]).unwrap_or_default();
    send(app, "POST", "/v1/approver-keys/pair", Some(body), &extra).await
}

/// `PUT /v1/approval-floor`, optionally presenting a step-up ticket.
async fn put_floor(app: &axum::Router, floor: &str, ticket: Option<&str>) -> (StatusCode, Value) {
    let extra: Vec<(&str, &str)> =
        ticket.map(|t| vec![(PAIR_TICKET_HEADER, t)]).unwrap_or_default();
    send(app, "PUT", "/v1/approval-floor", Some(json!({ "floor": floor })), &extra).await
}

/// `DELETE /v1/approver-keys/:approver_id`, optionally presenting a step-up ticket.
async fn revoke_key(
    app: &axum::Router,
    approver_id: &str,
    ticket: Option<&str>,
) -> (StatusCode, Value) {
    let extra: Vec<(&str, &str)> =
        ticket.map(|t| vec![(PAIR_TICKET_HEADER, t)]).unwrap_or_default();
    send(app, "DELETE", &format!("/v1/approver-keys/{approver_id}"), None, &extra).await
}

/// Pair a device through the whole ceremony, asserting it landed. Used by tests whose subject is what
/// happens AFTER a device is trusted, so a failure there reads as a setup error, not as the property.
async fn pair_ok(app: &axum::Router, jti: &str, approver_id: &str, sk: &SigningKey) {
    let ticket = mint_ticket(pair_claims(jti, approver_id, &pubkey_of(sk)));
    let (status, resp) = pair(app, pair_body(approver_id, sk), Some(&ticket)).await;
    assert_eq!(status, StatusCode::OK, "setup: pairing {approver_id} should have landed: {resp}");
}

/// Co-sign a held control-plane approval as an already-trusted device, exactly as the phone does:
/// fetch the signing inputs the gateway exposes, sign the canonical preimage with the REAL key, and
/// post the signature back. The gateway verifies it against its own trusted copy of that key.
async fn co_sign(
    app: &axum::Router,
    approval_id: &str,
    approver: &str,
    sk: &SigningKey,
) -> (StatusCode, Value) {
    let (_s, appr) = send(app, "GET", &format!("/v1/approvals/{approval_id}"), None, &[]).await;
    let request_hash = appr["request_hash"].as_str().expect("held approval exposes request_hash");
    let job_id = appr["job_id"].as_str().expect("held approval exposes job_id");
    let audience = appr["approval_audience"].as_str().expect("held approval exposes its audience");
    let shown = permaura_relay::approval_display_full_digest_of(&appr).expect("held approval serves its full rendering");
    let decided_at = now_ms();
    let preimage = permaura_relay::approval_result_preimage_v3(
        audience,
        job_id,
        approval_id,
        true,
        request_hash,
        &shown,
        approver,
        decided_at,
    );
    let body = json!({
        "approval_id": approval_id,
        "approve": true,
        "approver": approver,
        "request_hash": request_hash,
        "decided_at": decided_at,
        "job_id": job_id,
        "approver_pubkey": pubkey_of(sk),
        "audience": audience,
        "display_digest": shown,
        "device_sig": permaura_relay::sign(sk, &preimage),
    });
    send(app, "POST", "/v1/approvals", Some(body), &[]).await
}

/// Every `permaura.approver.pair` event in the audit chain, newest last.
async fn pairing_audit(app: &axum::Router) -> Vec<Value> {
    let (_s, audit) = send(app, "GET", "/v1/audit-events?limit=200", None, &[]).await;
    audit["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e["payload"]["action"] == "permaura.approver.pair")
        .collect()
}

fn trusted(state: &AppState, approver_id: &str) -> bool {
    state.service.approver_keyring_snapshot().trusted_key(approver_id).is_some()
}

// ── the ticket is required, and it is non-transferable ───────────────────────────────

/// No ticket at all. The answer must be 401 and not 403: a hosted console CAN satisfy this request,
/// it just has to send the owner through a fresh re-authentication first, and a 403 tells it the
/// opposite: that the door is shut and there is nothing to do.
#[tokio::test]
async fn pairing_without_a_ticket_asks_for_a_step_up_rather_than_denying() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(1);

    let (status, resp) = pair(&app, pair_body("device:alpha", &sk), None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a missing pairing ticket is a step-up challenge, not a denial: {resp}"
    );
    let err = resp["error"].as_str().unwrap_or_default();
    assert!(err.contains(PAIR_TICKET_HEADER), "the challenge must name the header to use: {err}");
    assert!(err.contains("approver-pair"), "the challenge must name the purpose to ask for: {err}");
    assert!(!trusted(&state, "device:alpha"), "nothing may be enrolled without a ticket");
}

/// An expired ticket. `exp` is checked by the same code path that guards every access token, so this
/// pins that a ticket cannot outlive its short TTL and be presented later from a log or a proxy.
#[tokio::test]
async fn pairing_refuses_an_expired_ticket() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(2);
    let mut claims = pair_claims("tkt-expired", "device:alpha", &pubkey_of(&sk));
    claims["exp"] = json!(now_secs() - 10);

    let (status, resp) = pair(&app, pair_body("device:alpha", &sk), Some(&mint_ticket(claims))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "an expired ticket must be refused: {resp}");
    assert!(!trusted(&state, "device:alpha"));
}

/// A ticket minted for the MCP resource. This is the substitution that would matter most in
/// practice: MCP access tokens are handed to third-party clients (ChatGPT, Claude) and are long-lived
/// by comparison, so if one could be presented where a ticket is demanded, every connected agent
/// would hold the power to enrol its own approver key.
#[tokio::test]
async fn pairing_refuses_a_ticket_minted_for_the_mcp_resource() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(3);
    let mut claims = pair_claims("tkt-mcp-aud", "device:alpha", &pubkey_of(&sk));
    claims["aud"] = json!(format!("{PUBLIC_URL}/mcp"));

    let (status, resp) = pair(&app, pair_body("device:alpha", &sk), Some(&mint_ticket(claims))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a token minted for the MCP resource is not a pairing ticket: {resp}"
    );
    assert!(!trusted(&state, "device:alpha"));
}

/// Right audience, wrong purpose. Audience and purpose are checked independently on purpose, so that
/// an AS change which got one of them wrong cannot make the two ticket classes interchangeable.
#[tokio::test]
async fn pairing_refuses_a_ticket_for_a_different_purpose() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(4);
    let mut claims = pair_claims("tkt-wrong-purpose", "device:alpha", &pubkey_of(&sk));
    claims["purpose"] = json!("approval-floor-lower");

    let (status, resp) = pair(&app, pair_body("device:alpha", &sk), Some(&mint_ticket(claims))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a floor-lowering ticket must not enrol a key even at the pairing audience: {resp}"
    );
    assert!(!trusted(&state, "device:alpha"));
}

/// The ticket names one approver id; the body enrols another. Without this pinning a ticket would
/// authorise "an enrolment" rather than "this enrolment".
#[tokio::test]
async fn pairing_refuses_a_ticket_bound_to_another_approver_id() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(5);
    let claims = pair_claims("tkt-other-id", "device:the-owners-phone", &pubkey_of(&sk));

    let (status, resp) = pair(&app, pair_body("device:alpha", &sk), Some(&mint_ticket(claims))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a ticket must not enrol an approver id it was not minted for: {resp}"
    );
    assert!(!trusted(&state, "device:alpha"));
}

/// The ticket names the right approver id but a different KEY. This is the interception case: whoever
/// holds a ticket in flight must not be able to keep the id and swap in a key of their own, which is
/// the only version of this attack that actually gains them anything.
#[tokio::test]
async fn pairing_refuses_a_ticket_bound_to_another_public_key() {
    let (state, app) = hosted_gateway().await;
    let owners_key = device_key(6);
    let attackers_key = device_key(7);
    let claims = pair_claims("tkt-other-key", "device:alpha", &pubkey_of(&owners_key));

    let (status, resp) =
        pair(&app, pair_body("device:alpha", &attackers_key), Some(&mint_ticket(claims))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a ticket must not enrol a key it was not minted for: {resp}"
    );
    assert!(!trusted(&state, "device:alpha"), "the attacker's key must not be trusted");
}

/// The AS asserts a re-authentication older than the step-up window. The whole value of a ticket is
/// that a human proved themselves *just now*; one minted off a stale session proves only that they
/// once signed in, which is what the operator bearer already tells us.
#[tokio::test]
async fn pairing_refuses_a_stale_re_authentication() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(8);
    let mut claims = pair_claims("tkt-stale-auth", "device:alpha", &pubkey_of(&sk));
    // STEP_UP_MAX_AGE_SECS is 300; a few seconds past it is enough and keeps the test honest about
    // where the boundary is rather than passing on an obviously absurd value.
    claims["auth_time"] = json!(now_secs() - 305);

    let (status, resp) = pair(&app, pair_body("device:alpha", &sk), Some(&mint_ticket(claims))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a ticket minted off a stale re-authentication must be refused: {resp}"
    );
    assert!(!trusted(&state, "device:alpha"));
}

/// REPLAY: the property that keeps a ticket from degrading into a 180-second reusable bearer.
///
/// The first spend enrols the owner's phone. The second presents a ticket carrying the SAME `jti`,
/// re-minted for an attacker's own approver id and key: everything about it verifies, and only the
/// store's single-use ledger stands in the way. It must be refused there, and refused with 401
/// (re-authenticate) rather than 202: a 202 would mean the spend happened after the hold decision,
/// which would leave the attacker's enrolment sitting in the queue waiting for a tap.
#[tokio::test]
async fn a_pairing_ticket_cannot_be_replayed_for_a_second_device() {
    let (state, app) = hosted_gateway().await;
    let owners_key = device_key(9);
    let attackers_key = device_key(10);

    let first = mint_ticket(pair_claims("tkt-once", "device:alpha", &pubkey_of(&owners_key)));
    let (status, resp) = pair(&app, pair_body("device:alpha", &owners_key), Some(&first)).await;
    assert_eq!(status, StatusCode::OK, "the first spend of a valid ticket enrols: {resp}");

    let replay = mint_ticket(pair_claims("tkt-once", "device:evil", &pubkey_of(&attackers_key)));
    let (status, resp) = pair(&app, pair_body("device:evil", &attackers_key), Some(&replay)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a jti may be spent exactly once, whatever it is re-minted around: {resp}"
    );
    assert!(
        resp["error"].as_str().unwrap_or_default().contains("spent"),
        "the refusal must say the ticket is spent, so the console knows to re-authenticate: {resp}"
    );
    assert!(!trusted(&state, "device:evil"), "a replayed ticket must not enrol anything");
    assert!(trusted(&state, "device:alpha"), "the legitimate first enrolment stands");
}

// ── first device, later devices, and the way back ────────────────────────────────────

/// TRUST ON FIRST USE. On a worker whose keyring is empty there is no hardware to co-sign with, so
/// the ticket alone must be enough or a hosted tenant could never pair anything. The enrolment has to
/// be real: trusted afterwards, and recorded in the audit chain under the anchor that permitted it,
/// because on a hosted worker that record is the only evidence the owner ever gets that the
/// first-use enrolment was tied to a live sign-in rather than to a leaked bearer.
#[tokio::test]
async fn the_first_device_on_a_hosted_worker_is_trusted_on_first_use() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(11);
    let ticket = mint_ticket(pair_claims("tkt-first", "device:alpha", &pubkey_of(&sk)));

    let (status, resp) = pair(&app, pair_body("device:alpha", &sk), Some(&ticket)).await;
    assert_eq!(status, StatusCode::OK, "the first device enrols immediately: {resp}");
    assert_eq!(resp["approver_id"], "device:alpha");
    assert_eq!(resp["trusted"], true);
    assert!(trusted(&state, "device:alpha"), "the key must actually be in the keyring afterwards");
    assert_eq!(
        state.service.approver_keyring_snapshot().trusted_key("device:alpha"),
        Some(pubkey_of(&sk).as_str()),
        "the key trusted must be the exact key that proved possession"
    );

    let events = pairing_audit(&app).await;
    let allow = events
        .iter()
        .find(|e| e["payload"]["decision"] == "allow")
        .expect("a first-use enrolment must be in the audit chain");
    let summary = &allow["payload"]["summary"];
    assert_eq!(summary["approver_id"], "device:alpha");
    assert_eq!(
        summary["authority"], "hosted_owner_ticket",
        "a ticket-anchored enrolment must never be recorded as a device co-signature"
    );
    // The ticket evidence. `PairingAuthority::audit_detail` exists for exactly this record: its own
    // doc says it is "the only evidence an owner has afterwards that a trust-on-first-use enrolment
    // was tied to a live sign-in rather than to a leaked bearer", and a REFUSED attempt and a HELD
    // one both carry it. The one enrolment that actually landed on nothing but a ticket must carry
    // it too, or the chain records that "a ticket" permitted the trust root to be written without
    // recording WHICH ticket or what re-authentication the AS asserted, and the owner reviewing it
    // afterwards cannot tell a legitimate first-use pairing from one an attacker drove.
    assert_eq!(
        summary["ticket_jti"], "tkt-first",
        "the spent ticket must be named in the allow record: {allow}"
    );
    assert!(
        summary["auth_time"].is_i64(),
        "the asserted re-authentication time must be carried into the allow record: {allow}"
    );
    assert!(
        summary["amr"].is_array(),
        "the asserted authentication factors must be carried into the allow record: {allow}"
    );
    // And WHO. `sub` is pinned to the owner because that is how a ticket is addressed to one worker,
    // so `auth_time` and `amr` alone only say that somebody with `device.manage` re-authenticated.
    // The owner's notice email asks them whether they did this; a chain that cannot distinguish the
    // owner from a colleague cannot answer, which is the whole reason the record is kept.
    assert_eq!(
        summary["actor_sub"], ACTOR_SUB,
        "the record must name the member who stepped up, not the account the worker belongs to: {allow}"
    );
    assert_eq!(summary["actor_name"], ACTOR_NAME, "{allow}");
    assert_ne!(
        summary["actor_sub"], OWNER_SUB,
        "an actor derived from `sub` would name the owner for something a colleague did: {allow}"
    );
}

/// A permaura.com older than the actor claim can still enrol a later device, held for a co-signature
/// (the first takes owner or admin standing, which a ticket naming nobody cannot show), and the record
/// it produces has to say "nobody was named", not quietly imply the owner. An omitted key reads as the
/// owner to anyone who knows `sub` is pinned to them, so absence is written as an explicit null.
#[tokio::test]
async fn an_enrolment_from_an_as_that_names_no_actor_records_an_explicit_null() {
    let (_state, app) = hosted_gateway().await;
    pair_ok(&app, "tkt-no-actor-first", "device:first", &device_key(30)).await;
    let sk = device_key(31);
    let mut claims = pair_claims("tkt-no-actor", "device:legacy", &pubkey_of(&sk));
    claims.as_object_mut().unwrap().remove("act_sub");
    claims.as_object_mut().unwrap().remove("act_name");

    let (status, resp) = pair(&app, pair_body("device:legacy", &sk), Some(&mint_ticket(claims))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "an older AS must still be able to enrol a later device: {resp}");

    let events = pairing_audit(&app).await;
    let held = events
        .iter()
        .find(|e| e["payload"]["decision"] == "requires_approval" && e["payload"]["summary"]["approver_id"] == "device:legacy")
        .expect("the enrolment must be in the audit chain");
    let summary = &held["payload"]["summary"];
    assert!(
        summary.get("actor_sub").is_some(),
        "the actor key must be present even when nobody was named: {held}"
    );
    assert!(summary["actor_sub"].is_null(), "an unnamed actor is null, not the owner: {held}");
}

/// The SECOND device is held for a co-signature from hardware this worker already trusts. This is
/// what bounds an AS compromise: forged tickets can enrol at most one key on a worker that has none,
/// and can never join a device to a keyring that is already live.
#[tokio::test]
async fn a_second_device_is_held_until_an_already_trusted_device_co_signs() {
    let (state, app) = hosted_gateway().await;
    let first = device_key(12);
    let second = device_key(13);

    let t1 = mint_ticket(pair_claims("tkt-2a", "device:alpha", &pubkey_of(&first)));
    let (status, _) = pair(&app, pair_body("device:alpha", &first), Some(&t1)).await;
    assert_eq!(status, StatusCode::OK);

    let t2 = mint_ticket(pair_claims("tkt-2b", "device:beta", &pubkey_of(&second)));
    let (status, held) = pair(&app, pair_body("device:beta", &second), Some(&t2)).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "a ticket alone must not join a device to a live keyring: {held}"
    );
    assert_eq!(held["required_tier"], "device_signed");
    assert_eq!(
        held["action"], "permaura.approver.pair",
        "the console must be able to tell a pending enrolment from a pending policy edit"
    );
    assert!(!trusted(&state, "device:beta"), "nothing is trusted while the hold is outstanding");

    let approval_id = held["approval_id"].as_str().expect("held enrolment carries an approval id");
    let (status, resolved) = co_sign(&app, approval_id, "device:alpha", &first).await;
    assert_eq!(status, StatusCode::OK, "the already-trusted device's signature applies it: {resolved}");
    assert!(trusted(&state, "device:beta"), "the co-signed enrolment must land");
    assert_eq!(
        state.service.approver_keyring_snapshot().trusted_key("device:beta"),
        Some(pubkey_of(&second).as_str()),
        "the held enrolment must trust the exact key it was queued for"
    );
}

/// The device being enrolled cannot co-sign its own enrolment. It is not a check written into the
/// pairing path: it is structural, because `verify_signed_approval` resolves a signer through the
/// keyring and the device being enrolled is by definition not in it yet. Pinned here because a future
/// change that resolved the signer from anything the request carries would silently remove it, and
/// the second-device rule would collapse back to "a ticket plus a key the caller already holds".
#[tokio::test]
async fn the_device_being_enrolled_cannot_co_sign_its_own_enrolment() {
    let (state, app) = hosted_gateway().await;
    let first = device_key(14);
    let second = device_key(15);

    let t1 = mint_ticket(pair_claims("tkt-3a", "device:alpha", &pubkey_of(&first)));
    assert_eq!(pair(&app, pair_body("device:alpha", &first), Some(&t1)).await.0, StatusCode::OK);

    let t2 = mint_ticket(pair_claims("tkt-3b", "device:beta", &pubkey_of(&second)));
    let (status, held) = pair(&app, pair_body("device:beta", &second), Some(&t2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();

    let (status, resp) = co_sign(&app, approval_id, "device:beta", &second).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the device being enrolled must not be able to vouch for itself: {resp}"
    );
    assert!(!trusted(&state, "device:beta"), "a self-co-signed enrolment must not land");

    // And the hold is still there for a device that actually can satisfy it.
    let (status, _) = co_sign(&app, approval_id, "device:alpha", &first).await;
    assert_eq!(status, StatusCode::OK);
    assert!(trusted(&state, "device:beta"));
}

/// THE ANTI-BRICK PROPERTY. Revoke every device and the co-signature requirement has nobody left to
/// satisfy it: on a worker with no host to pair from, a rule that held the next enrolment for a
/// signature from a revoked device would lock the tenant out of their own control plane forever. So
/// the branch keys off a USABLE trusted key, not the sticky `ever_enrolled` flag, and pairing falls
/// back to the ticket-only path. This is the difference between "lost my phone" and "lost my gateway".
///
/// The recovery path is two step-ups, not one: a ticket to revoke the last device, then a ticket to
/// pair the replacement. Both are re-authentications the owner can perform from anywhere; neither
/// needs a host, and the worker is never left in a state nothing can act on.
#[tokio::test]
async fn after_revoking_every_device_pairing_falls_back_to_the_ticket_only_path() {
    let (state, app) = hosted_gateway().await;
    let replacement = device_key(17);

    pair_ok(&app, "tkt-4a", "device:alpha", &device_key(16)).await;
    assert!(state.service.any_device_trusted());

    let revoke = mint_ticket(admin_revoke_claims("tkt-4-revoke", "device:alpha"));
    let (status, resp) = revoke_key(&app, "device:alpha", Some(&revoke)).await;
    assert_eq!(status, StatusCode::OK, "an owner or admin may always revoke the last device: {resp}");
    assert!(!state.service.any_device_trusted(), "no usable device is left to co-sign");
    assert!(
        state.service.any_device_enrolled(),
        "the sticky enrolment flag must stay set: the approval floor depends on it"
    );

    let t2 = mint_ticket(pair_claims("tkt-4b", "device:gamma", &pubkey_of(&replacement)));
    let (status, resp) = pair(&app, pair_body("device:gamma", &replacement), Some(&t2)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "with no usable device left, the ticket alone must enrol a replacement: {resp}"
    );
    assert!(trusted(&state, "device:gamma"), "the tenant is back in control of their own worker");
}

/// REVOKE-THEN-PAIR, the way trust-on-first-use gets re-armed.
///
/// Emptying the keyring flips the trust root from "a co-signature is required" back to "trust on
/// first use", so a compromised control plane holding nothing but an operator token could revoke the
/// tenant's only device and then walk straight through the re-opened first-use branch with a key of
/// its own. Every hosted revocation takes a step-up ticket, this one included.
#[tokio::test]
async fn revoking_the_last_device_takes_the_same_anchor_as_pairing() {
    let (state, app) = hosted_gateway().await;
    let attacker = device_key(21);
    pair_ok(&app, "tkt-6a", "device:alpha", &device_key(20)).await;

    let (status, resp) = revoke_key(&app, "device:alpha", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an operator bearer alone must not be able to re-arm trust-on-first-use: {resp}"
    );
    assert!(
        resp["error"].as_str().unwrap_or_default().contains("'approver-revoke'"),
        "the challenge must name the purpose to ask for: {resp}"
    );
    assert!(trusted(&state, "device:alpha"), "the refused revocation must not have landed");

    // And the attacker cannot get to the first-use branch the other way either: the keyring is still
    // live, so its own enrolment is held for the device it was trying to remove.
    let t = mint_ticket(pair_claims("tkt-6b", "device:evil", &pubkey_of(&attacker)));
    let (status, held) = pair(&app, pair_body("device:evil", &attacker), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the keyring is still live, so this is held: {held}");
    assert!(!trusted(&state, "device:evil"));
}

/// A PAIRING ticket must not be spendable as a revocation. Each purpose is its own token class
/// (separate `purpose` claim, separate audience, separate single-use ledger scope), precisely so that
/// obtaining one step-up never quietly grants another.
#[tokio::test]
async fn a_pairing_ticket_cannot_be_spent_revoking_the_last_device() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(22);
    pair_ok(&app, "tkt-7a", "device:alpha", &sk).await;

    let wrong = mint_ticket(pair_claims("tkt-7b", "device:alpha", &pubkey_of(&sk)));
    let (status, resp) = revoke_key(&app, "device:alpha", Some(&wrong)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a ticket minted to enrol a key must not retire the trust root instead: {resp}"
    );
    assert!(trusted(&state, "device:alpha"));

    let right = mint_ticket(admin_revoke_claims("tkt-7c", "device:alpha"));
    let (status, resp) = revoke_key(&app, "device:alpha", Some(&right)).await;
    assert_eq!(status, StatusCode::OK, "the purpose-matched ticket does spend: {resp}");
    assert!(!trusted(&state, "device:alpha"));
}

/// Every revocation on a hosted worker is a device action and takes a step-up, the last key or not:
/// no ticket asks for one (401), a ticket for another device is refused outright (403), and a ticket
/// spends once.
#[tokio::test]
async fn revoking_any_device_takes_a_ticket_bound_to_that_device() {
    let (state, app) = hosted_gateway().await;
    let first = device_key(23);
    let second = device_key(24);
    pair_ok(&app, "tkt-8a", "device:alpha", &first).await;

    let t2 = mint_ticket(pair_claims("tkt-8b", "device:beta", &pubkey_of(&second)));
    let (status, held) = pair(&app, pair_body("device:beta", &second), Some(&t2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();
    assert_eq!(co_sign(&app, approval_id, "device:alpha", &first).await.0, StatusCode::OK);
    assert!(trusted(&state, "device:beta"));

    let (status, resp) = revoke_key(&app, "device:beta", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a non-last revocation asks for a step-up: {resp}");
    let err = resp["error"].as_str().unwrap_or_default();
    assert!(err.starts_with("step-up required:"), "{resp}");
    assert!(err.contains("'approver-revoke'") && err.contains(PAIR_TICKET_HEADER), "{resp}");
    assert!(trusted(&state, "device:beta"));

    let for_alpha = mint_ticket(revoke_claims("tkt-8c", "device:alpha"));
    let (status, resp) = revoke_key(&app, "device:beta", Some(&for_alpha)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a ticket for another device is refused outright: {resp}");
    assert!(trusted(&state, "device:beta"));
    assert!(trusted(&state, "device:alpha"));

    let for_beta = mint_ticket(revoke_claims("tkt-8d", "device:beta"));
    let (status, resp) = revoke_key(&app, "device:beta", Some(&for_beta)).await;
    assert_eq!(status, StatusCode::OK, "the bound ticket revokes: {resp}");
    assert!(!trusted(&state, "device:beta"));
    assert!(trusted(&state, "device:alpha"), "the remaining co-signer is untouched");

    let (status, resp) = revoke_key(&app, "device:beta", Some(&for_beta)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a spent ticket is refused: {resp}");
}

/// `DELETE /v1/devices/:id` revokes the device's approver key on the way past, so it is a second
/// route to the same loosening and is gated identically. A guard on one route only would be no guard
/// at all: the control plane would simply use the other one.
#[tokio::test]
async fn revoking_the_last_device_through_the_device_route_is_gated_the_same_way() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(25);
    let approver_id = "device:delta";

    let (status, enrolled) = send(
        &app,
        "POST",
        "/v1/devices/enroll",
        Some(json!({
            "name": "the owner's phone",
            "approver_id": approver_id,
            "approver_pubkey": pubkey_of(&sk),
        })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup: {enrolled}");
    let device_id = enrolled["device_id"].as_str().expect("an enrolled device has an id").to_string();
    pair_ok(&app, "tkt-9a", approver_id, &sk).await;

    let (status, resp) = send(&app, "DELETE", &format!("/v1/devices/{device_id}"), None, &[]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the device route must not be the way around the step-up: {resp}"
    );
    assert!(trusted(&state, approver_id), "the key must still be trusted after the refusal");

    let ticket = mint_ticket(admin_revoke_claims("tkt-9b", approver_id));
    let (status, resp) =
        send(&app, "DELETE", &format!("/v1/devices/{device_id}"), None, &[(PAIR_TICKET_HEADER, &ticket)])
            .await;
    assert_eq!(status, StatusCode::OK, "with the anchor, the owner retires their own device: {resp}");
    assert!(!trusted(&state, approver_id));
}

// ── Emptying the keyring is an owner's or admin's decision ────────────────────────────

/// A revoke ticket as permaura.com mints it for an owner or admin of the organization: the member's
/// claims plus `act_role`, the standing a recovery ticket already carries.
fn admin_revoke_claims(jti: &str, approver_id: &str) -> Value {
    let mut claims = revoke_claims(jti, approver_id);
    claims["act_role"] = json!("admin");
    claims
}

/// The attack chain, first link: a plain member holding `device.manage` revokes the last trusted
/// approver (the owner's phone) with a ticket bound to it. Refused, with a reason that says who can,
/// and recorded, so the second link (the member pairing their own device on the reopened first-use
/// branch) is still held for the owner's co-signature.
#[tokio::test]
async fn a_member_cannot_revoke_the_last_trusted_approver() {
    let (state, app) = hosted_gateway().await;
    let owner_phone = device_key(80);
    let members_phone = device_key(81);
    pair_ok(&app, "tkt-last-1a", "device:owner-phone", &owner_phone).await;

    let ticket = mint_ticket(revoke_claims("tkt-last-1b", "device:owner-phone"));
    let (status, resp) = revoke_key(&app, "device:owner-phone", Some(&ticket)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a member must not empty the keyring: {resp}");
    assert!(
        resp["error"].as_str().unwrap_or_default().contains("owner or admin"),
        "the refusal says who can do it: {resp}"
    );
    assert!(trusted(&state, "device:owner-phone"), "the refused revocation did not land");

    let refusal = pairing_audit(&app).await.pop().expect("the refusal is recorded");
    let summary = &refusal["payload"]["summary"];
    assert_eq!(refusal["payload"]["decision"], "deny", "{refusal}");
    assert_eq!(summary["approver_id"], "device:owner-phone", "{refusal}");
    assert_eq!(summary["actor_sub"], ACTOR_SUB, "the owner can see which member tried: {refusal}");
    assert!(summary["revoked"].is_null(), "nothing was revoked: {refusal}");

    let t = mint_ticket(pair_claims("tkt-last-1c", "device:members-phone", &pubkey_of(&members_phone)));
    let (status, held) = pair(&app, pair_body("device:members-phone", &members_phone), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the keyring is still live, so the member's key is held: {held}");
    assert!(!trusted(&state, "device:members-phone"));

    // An AS too old to name the actor, or one naming a role that carries no standing, is refused the same way.
    let mut unnamed = revoke_claims("tkt-last-1d", "device:owner-phone");
    unnamed.as_object_mut().unwrap().remove("act_sub");
    let mut claims = vec![unnamed];
    for (jti, role) in [("tkt-last-1e", "member"), ("tkt-last-1f", "superadmin"), ("tkt-last-1g", "owner,admin")] {
        let mut odd = revoke_claims(jti, "device:owner-phone");
        odd["act_role"] = json!(role);
        claims.push(odd);
    }
    for claims in claims {
        let (status, resp) = revoke_key(&app, "device:owner-phone", Some(&mint_ticket(claims))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    }
    assert!(trusted(&state, "device:owner-phone"));
}

/// The sibling route: `DELETE /v1/devices/:id` revokes the device's approver key on the way past, so
/// it must refuse a member the same emptying revocation.
#[tokio::test]
async fn a_member_cannot_empty_the_keyring_through_the_device_route() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(82);
    let approver_id = "device:owner-watch";
    let (status, enrolled) = send(
        &app,
        "POST",
        "/v1/devices/enroll",
        Some(json!({ "name": "the owner's watch", "approver_id": approver_id, "approver_pubkey": pubkey_of(&sk) })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup: {enrolled}");
    let device_id = enrolled["device_id"].as_str().expect("an enrolled device has an id").to_string();
    pair_ok(&app, "tkt-last-2a", approver_id, &sk).await;

    let member = mint_ticket(revoke_claims("tkt-last-2b", approver_id));
    let (status, resp) =
        send(&app, "DELETE", &format!("/v1/devices/{device_id}"), None, &[(PAIR_TICKET_HEADER, &member)]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the device route is not a way around it: {resp}");
    assert!(trusted(&state, approver_id));

    let admin = mint_ticket(admin_revoke_claims("tkt-last-2c", approver_id));
    let (status, resp) =
        send(&app, "DELETE", &format!("/v1/devices/{device_id}"), None, &[(PAIR_TICKET_HEADER, &admin)]).await;
    assert_eq!(status, StatusCode::OK, "an admin may: {resp}");
    assert!(!trusted(&state, approver_id));
}

/// One by one is the same end state. A member keeps today's rule while another approver stays
/// trusted, and is refused at the revocation that would leave none.
#[tokio::test]
async fn a_member_may_revoke_while_another_approver_stays_trusted_but_not_the_last() {
    let (state, app) = hosted_gateway().await;
    let alpha = device_key(83);
    let beta = device_key(84);
    pair_ok(&app, "tkt-last-3a", "device:alpha", &alpha).await;
    let t = mint_ticket(pair_claims("tkt-last-3b", "device:beta", &pubkey_of(&beta)));
    let (status, held) = pair(&app, pair_body("device:beta", &beta), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(co_sign(&app, held["approval_id"].as_str().unwrap(), "device:alpha", &alpha).await.0, StatusCode::OK);

    let (status, resp) =
        revoke_key(&app, "device:beta", Some(&mint_ticket(revoke_claims("tkt-last-3c", "device:beta")))).await;
    assert_eq!(status, StatusCode::OK, "a revocation that leaves alpha trusted keeps today's rule: {resp}");
    assert_eq!(resp["emptied_keyring"], false);

    let (status, resp) =
        revoke_key(&app, "device:alpha", Some(&mint_ticket(revoke_claims("tkt-last-3d", "device:alpha")))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the last one is refused: {resp}");
    assert!(trusted(&state, "device:alpha"));
}

/// Two members each revoking one of the last two approvers at the same moment: the check runs under
/// the control-plane lock, so exactly one lands and the keyring is never emptied.
#[tokio::test]
async fn two_concurrent_member_revocations_cannot_empty_the_keyring_between_them() {
    let (state, app) = hosted_gateway().await;
    let alpha = device_key(85);
    let beta = device_key(86);
    pair_ok(&app, "tkt-last-4a", "device:alpha", &alpha).await;
    let t = mint_ticket(pair_claims("tkt-last-4b", "device:beta", &pubkey_of(&beta)));
    let (_s, held) = pair(&app, pair_body("device:beta", &beta), Some(&t)).await;
    assert_eq!(co_sign(&app, held["approval_id"].as_str().unwrap(), "device:alpha", &alpha).await.0, StatusCode::OK);

    let ta = mint_ticket(revoke_claims("tkt-last-4c", "device:alpha"));
    let tb = mint_ticket(revoke_claims("tkt-last-4d", "device:beta"));
    let (a, b) = tokio::join!(revoke_key(&app, "device:alpha", Some(&ta)), revoke_key(&app, "device:beta", Some(&tb)));
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::FORBIDDEN], "{a:?} {b:?}");
    assert!(state.service.any_device_trusted(), "one approver is still trusted");
}

/// The controls: the owner's own ticket and an organization owner's or admin's empty the keyring as
/// before, and the record says on what standing.
#[tokio::test]
async fn an_owner_or_admin_may_revoke_the_last_trusted_approver() {
    let (state, app) = hosted_gateway().await;
    pair_ok(&app, "tkt-last-5a", "device:alpha", &device_key(87)).await;
    let (status, resp) =
        revoke_key(&app, "device:alpha", Some(&mint_ticket(admin_revoke_claims("tkt-last-5b", "device:alpha")))).await;
    assert_eq!(status, StatusCode::OK, "an admin may empty it: {resp}");
    assert_eq!(resp["emptied_keyring"], true);
    let last = pairing_audit(&app).await.pop().expect("recorded");
    assert_eq!(last["payload"]["summary"]["actor_role"], "admin", "{last}");
    assert!(!state.service.any_device_trusted());

    pair_ok(&app, "tkt-last-5c", "device:beta", &device_key(88)).await;
    let mut owners_own = revoke_claims("tkt-last-5d", "device:beta");
    owners_own["act_sub"] = json!(OWNER_SUB);
    let (status, resp) = revoke_key(&app, "device:beta", Some(&mint_ticket(owners_own))).await;
    assert_eq!(status, StatusCode::OK, "the owner may always revoke their own last device: {resp}");
    assert!(!state.service.any_device_trusted());
}

// ── A hosted worker's first trusted device takes owner or admin standing ────────────────────

/// A pairing ticket from `actor` (unnamed when `None`) with `role` as the web stamps it in `act_role`.
fn pair_claims_by(jti: &str, approver_id: &str, sk: &SigningKey, actor: Option<&str>, role: Option<&str>) -> Value {
    let mut claims = pair_claims(jti, approver_id, &pubkey_of(sk));
    let obj = claims.as_object_mut().unwrap();
    obj.remove("act_role");
    obj.remove("act_sub");
    if let Some(actor) = actor {
        obj.insert("act_sub".into(), json!(actor));
    }
    if let Some(role) = role {
        obj.insert("act_role".into(), json!(role));
    }
    claims
}

/// The first device a hosted worker trusts is the root every later device is co-signed from, so a
/// member's ticket cannot pair it, and neither can an unnamed actor's or one naming a role with no
/// standing. Refused, recorded, and nothing is trusted.
#[tokio::test]
async fn a_member_cannot_pair_a_hosted_workers_first_device() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(110);
    let id = "device:members-phone";
    for (jti, actor, role) in [
        ("tkt-first-1a", Some(ACTOR_SUB), None),
        ("tkt-first-1b", None, None),
        ("tkt-first-1c", Some(ACTOR_SUB), Some("member")),
        ("tkt-first-1d", Some(ACTOR_SUB), Some("superadmin")),
    ] {
        let t = mint_ticket(pair_claims_by(jti, id, &sk, actor, role));
        let (status, resp) = pair(&app, pair_body(id, &sk), Some(&t)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{jti}: {resp}");
        assert!(resp["error"].as_str().unwrap_or_default().contains("owner or admin"), "the refusal says who can: {resp}");
    }
    assert!(!state.service.any_device_trusted(), "nothing was trusted");
    let refusal = pairing_audit(&app).await.pop().expect("the refusal is recorded");
    assert_eq!(refusal["payload"]["decision"], "deny", "{refusal}");
    assert_eq!(refusal["payload"]["summary"]["approver_id"], id, "{refusal}");
}

/// The window the web's mint-time check leaves: a member's ticket minted while the owner's phone was
/// trusted stays valid for minutes, and an admin's revocation of that phone can land inside them once the
/// phone confirms it. Spent afterwards, it must not make the member's device the worker's only approver.
#[tokio::test]
async fn a_members_ticket_minted_before_the_keyring_emptied_cannot_pair_after() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, members_phone) = (device_key(111), device_key(112));
    let t = mint_ticket(pair_claims_by("tkt-first-2a", "device:owner-phone", &owner_phone, Some(OWNER_SUB), None));
    let (status, resp) = pair(&app, pair_body("device:owner-phone", &owner_phone), Some(&t)).await;
    assert_eq!(status, StatusCode::OK, "setup: the owner pairs their phone: {resp}");
    let members_ticket =
        mint_ticket(pair_claims_by("tkt-first-2b", "device:members-phone", &members_phone, Some(ACTOR_SUB), None));

    let mut admin = revoke_claims("tkt-first-2c", "device:owner-phone");
    admin["act_role"] = json!("admin");
    let (status, held) = revoke_key(&app, "device:owner-phone", Some(&mint_ticket(admin))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "setup: an admin asks to empty the keyring: {held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "setup: the owner's phone confirms its own removal: {resp}");
    assert!(!state.service.any_device_trusted());

    let (status, resp) = pair(&app, pair_body("device:members-phone", &members_phone), Some(&members_ticket)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(!trusted(&state, "device:members-phone"), "the member's device did not become the trust root");
}

/// The controls: the owner's own ticket and an organization owner's or admin's pair the first device,
/// and once a device is trusted a member's ticket still enrols theirs, held for a co-signature as before.
#[tokio::test]
async fn an_owner_or_admin_may_pair_the_first_device_and_a_member_joins_after() {
    for (jti, actor, role) in [
        ("tkt-first-3a", OWNER_SUB, None),
        ("tkt-first-3b", ACTOR_SUB, Some("admin")),
        ("tkt-first-3c", ACTOR_SUB, Some("owner")),
    ] {
        let (state, app) = hosted_gateway().await;
        let sk = device_key(113);
        let t = mint_ticket(pair_claims_by(jti, "device:first", &sk, Some(actor), role));
        let (status, resp) = pair(&app, pair_body("device:first", &sk), Some(&t)).await;
        assert_eq!(status, StatusCode::OK, "{jti}: {resp}");
        assert!(trusted(&state, "device:first"));

        let members_phone = device_key(114);
        let t = mint_ticket(pair_claims_by(&format!("{jti}-m"), "device:members-phone", &members_phone, Some(ACTOR_SUB), None));
        let (status, held) = pair(&app, pair_body("device:members-phone", &members_phone), Some(&t)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{jti}: a member's later device is held, not refused: {held}");
    }
}

// ── A two-person rule counts people, not devices ─────────────────────────────────────

/// A pairing ticket minted for `actor`, the account that stepped up on the phone doing the pairing.
fn pair_claims_as(jti: &str, approver_id: &str, pubkey_b64: &str, actor: &str) -> Value {
    let mut claims = pair_claims(jti, approver_id, pubkey_b64);
    claims["act_sub"] = json!(actor);
    claims
}

/// Pair a second device for `actor`, held for and co-signed by `co_signer`, the way a Watch pairs
/// through its iPhone or a colleague's phone joins a keyring the owner's phone already holds.
async fn pair_held_for(
    app: &axum::Router,
    jti: &str,
    approver_id: &str,
    sk: &SigningKey,
    actor: &str,
    co_signer: (&str, &SigningKey),
) {
    let ticket = mint_ticket(pair_claims_as(jti, approver_id, &pubkey_of(sk), actor));
    let (status, held) = pair(app, pair_body(approver_id, sk), Some(&ticket)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "setup: {held}");
    let approval_id = held["approval_id"].as_str().expect("a held enrolment names its approval");
    let (status, resp) = co_sign(app, approval_id, co_signer.0, co_signer.1).await;
    assert_eq!(status, StatusCode::OK, "setup: co-signing {approver_id}: {resp}");
}

/// A held agent call that a `device_signed_quorum: 2` policy holds for two people.
fn seed_two_person_hold(state: &AppState, approval_id: &str) {
    let store = state.service.store();
    store
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: format!("sess_{approval_id}"),
            agent_id: "codex-cli".into(),
            user_id: Some("agent-owner".into()),
            device_id: None,
            token: String::new(),
            role: SessionRole::Operator,
            created_at: now_ms(),
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
    store
        .put_approval(PendingApproval {
            id: approval_id.into(),
            session_id: format!("sess_{approval_id}"),
            capability: "braintree.transactions.search".into(),
            resource: "braintree_production".into(),
            message: "Approve the held call?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: json!({ "status": "failed" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: now_ms(),
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "device_signed".into(),
            required_signatures: 2,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
}

/// The defect on a hosted worker: Priya pairs her iPhone, then her Watch through it (the
/// Watch's ticket is minted by her own account on her own phone), and approves a two-person hold
/// from both. She is one person, so it stays pending for somebody else.
#[tokio::test]
async fn one_persons_phone_and_watch_cannot_satisfy_a_two_person_rule() {
    let (state, app) = hosted_gateway().await;
    let (phone, watch) = (device_key(90), device_key(91));
    pair_ok(&app, "tkt-p02-1a", "device:priya-iphone", &phone).await;
    pair_held_for(&app, "tkt-p02-1b", "device:priya-watch", &watch, ACTOR_SUB, ("device:priya-iphone", &phone)).await;

    seed_two_person_hold(&state, "appr_p02_1");
    let (status, first) = co_sign(&app, "appr_p02_1", "device:priya-iphone", &phone).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    let (status, second) = co_sign(&app, "appr_p02_1", "device:priya-watch", &watch).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the Watch is the same person as the phone: {second}");
    assert_eq!(second["status"], "pending", "{second}");
    assert_eq!(second["people_signed"], 1, "{second}");
    assert_eq!(second["collected_signatures"], 1, "progress counts people: {second}");
    assert_eq!(second["required_signatures"], 2, "{second}");
}

/// The control: two people's devices satisfy it, and the resolution's audit record says two people.
#[tokio::test]
async fn two_peoples_devices_satisfy_a_two_person_rule() {
    let (state, app) = hosted_gateway().await;
    let (priya, omar) = (device_key(92), device_key(93));
    pair_ok(&app, "tkt-p02-2a", "device:priya-iphone", &priya).await;
    pair_held_for(&app, "tkt-p02-2b", "device:omar-iphone", &omar, "user_omar", ("device:priya-iphone", &priya)).await;

    seed_two_person_hold(&state, "appr_p02_2");
    assert_eq!(co_sign(&app, "appr_p02_2", "device:priya-iphone", &priya).await.0, StatusCode::ACCEPTED);
    let (status, done) = co_sign(&app, "appr_p02_2", "device:omar-iphone", &omar).await;
    assert_eq!(status, StatusCode::OK, "a second person completes it: {done}");
    assert_eq!(done["status"], "approved", "{done}");
    assert_eq!(done["people_signed"], 2, "{done}");

    let (_s, audit) = send(&app, "GET", "/v1/audit-events?limit=200", None, &[]).await;
    let resolved = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|e| e["payload"]["summary"]["people_signed"].is_number())
        .cloned()
        .unwrap_or_default();
    assert_eq!(resolved["payload"]["summary"]["people_signed"], 2, "{audit}");
}

/// Keys paired before keys named a person: bound to nobody, they never supply the second person, so a
/// two-person hold they sign stays pending. Re-pairing through the ordinary ceremony binds each to the
/// account that stepped up. The first person bound, and that person's other device, apply at once
/// because neither can raise a quorum; a second person is held for a trusted device to confirm, as a
/// new device would be. Then two people's devices count as two, and one person's two still as one.
#[tokio::test]
async fn keys_paired_before_the_change_count_once_until_each_is_paired_again() {
    let (state, app) = hosted_gateway().await;
    let (priya, priya_watch, omar) = (device_key(94), device_key(97), device_key(95));
    assert!(state.service.trust_approver_key("device:priya-old", &pubkey_of(&priya)));
    assert!(state.service.trust_approver_key("device:priya-watch-old", &pubkey_of(&priya_watch)));
    assert!(state.service.trust_approver_key("device:omar-old", &pubkey_of(&omar)));

    seed_two_person_hold(&state, "appr_p02_3a");
    assert_eq!(co_sign(&app, "appr_p02_3a", "device:priya-old", &priya).await.0, StatusCode::ACCEPTED);
    let (status, stuck) = co_sign(&app, "appr_p02_3a", "device:omar-old", &omar).await;
    assert_eq!(status, StatusCode::ACCEPTED, "two unbound keys are never two people: {stuck}");
    assert_eq!(stuck["people_signed"], 1, "{stuck}");

    let (_s, keys) = send(&app, "GET", "/v1/approver-keys", None, &[]).await;
    assert!(
        keys["keys"].as_array().unwrap().iter().all(|k| k["person_bound"] == false),
        "the census says which keys need pairing again: {keys}"
    );

    for (jti, id, sk) in [("tkt-p02-3b", "device:priya-old", &priya), ("tkt-p02-3c", "device:priya-watch-old", &priya_watch)] {
        let ticket = mint_ticket(pair_claims_as(jti, id, &pubkey_of(sk), ACTOR_SUB));
        let (status, resp) = pair(&app, pair_body(id, sk), Some(&ticket)).await;
        assert_eq!(status, StatusCode::OK, "binding the first person, then her other device: {resp}");
        assert_eq!(resp["person_bound"], true, "{resp}");
    }

    let ticket = mint_ticket(pair_claims_as("tkt-p02-3d", "device:omar-old", &pubkey_of(&omar), "user_omar"));
    let (status, held) = pair(&app, pair_body("device:omar-old", &omar), Some(&ticket)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "a second person waits for a co-signer: {held}");
    assert_eq!(held["already_trusted"], true, "{held}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:omar-old"), None);
    let held_id = held["approval_id"].as_str().unwrap().to_string();
    let (status, resp) = co_sign(&app, &held_id, "device:priya-old", &priya).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:omar-old"), Some("user_omar"));

    seed_two_person_hold(&state, "appr_p02_3e");
    assert_eq!(co_sign(&app, "appr_p02_3e", "device:priya-old", &priya).await.0, StatusCode::ACCEPTED);
    let (status, same) = co_sign(&app, "appr_p02_3e", "device:priya-watch-old", &priya_watch).await;
    assert_eq!(status, StatusCode::ACCEPTED, "her Watch is still her: {same}");
    let (status, done) = co_sign(&app, "appr_p02_3e", "device:omar-old", &omar).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["status"], "approved", "{done}");
}

/// A key already bound to one person is not re-attributed by a ticket naming another: the device is
/// trusted, so a hold would be one it could co-sign itself. It has to be revoked and paired again.
#[tokio::test]
async fn a_bound_key_is_not_re_attributed_by_another_persons_ticket() {
    let (state, app) = hosted_gateway().await;
    let watch = device_key(96);
    pair_ok(&app, "tkt-p02-4a", "device:priya-watch", &watch).await;
    let ticket = mint_ticket(pair_claims_as("tkt-p02-4b", "device:priya-watch", &pubkey_of(&watch), "user_omar"));
    let (status, resp) = pair(&app, pair_body("device:priya-watch", &watch), Some(&ticket)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:priya-watch"), Some(ACTOR_SUB));
}

/// The key list groups keys by person without naming anyone, so a console can say which quorums the
/// paired devices can reach: one opaque handle per person, shared by that person's devices, absent for
/// a key bound to nobody or revoked, and a count of the people a quorum can reach, counted as the
/// quorum counts them.
#[tokio::test]
async fn the_key_list_groups_keys_by_an_opaque_person_handle() {
    let (state, app) = hosted_gateway().await;
    let (phone, watch, omar, old, gone) = (device_key(130), device_key(131), device_key(132), device_key(133), device_key(134));
    pair_ok(&app, "tkt-handle-1", "device:priya-iphone", &phone).await;
    pair_held_for(&app, "tkt-handle-2", "device:priya-watch", &watch, ACTOR_SUB, ("device:priya-iphone", &phone)).await;
    pair_held_for(&app, "tkt-handle-3", "device:omar-iphone", &omar, "user_omar", ("device:priya-iphone", &phone)).await;
    assert!(state.service.trust_approver_key("device:old", &pubkey_of(&old)));
    pair_held_for(&app, "tkt-handle-4", "device:gone", &gone, "user_gone", ("device:priya-iphone", &phone)).await;
    let mut revoke = revoke_claims("tkt-handle-5", "device:gone");
    revoke["act_sub"] = json!("user_gone");
    assert_eq!(revoke_key(&app, "device:gone", Some(&mint_ticket(revoke))).await.0, StatusCode::OK);

    let (status, list) = send(&app, "GET", "/v1/approver-keys", None, &[]).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let handle = |id: &str| {
        list["keys"].as_array().unwrap().iter().find(|k| k["approver_id"] == id).expect("listed")["person_handle"].clone()
    };
    let priya = handle("device:priya-iphone");
    assert!(priya.as_str().is_some_and(|h| h.len() == 16), "{list}");
    assert_eq!(handle("device:priya-watch"), priya, "one person's devices share a handle: {list}");
    assert!(handle("device:omar-iphone").is_string() && handle("device:omar-iphone") != priya, "{list}");
    assert!(handle("device:old").is_null(), "a key bound to nobody has no handle: {list}");
    assert!(handle("device:gone").is_null(), "a revoked key has no handle: {list}");
    assert!(!list.to_string().contains(ACTOR_SUB) && !list.to_string().contains("user_omar"), "no account is named: {list}");
    assert_eq!(list["reachable_people"], 2, "Priya and Omar; the unbound key adds nobody beside them: {list}");
}

// ── what the co-signer is actually shown ─────────────────────────────────────────────

/// The co-signature is only worth anything if the human can see the exact diff. A prompt reading
/// `Trust “device:beta” to approve` with no key names no key at all, so a co-signer has no way to tell the
/// owner's watch from an attacker's key presented under the same id: they would be tapping approve
/// on a string they cannot check against anything.
#[tokio::test]
async fn a_held_enrolment_names_the_key_the_co_signer_is_being_asked_to_trust() {
    let (_state, app) = hosted_gateway().await;
    let second = device_key(26);
    pair_ok(&app, "tkt-10a", "device:alpha", &device_key(27)).await;

    let t2 = mint_ticket(pair_claims("tkt-10b", "device:beta", &pubkey_of(&second)));
    let (status, held) = pair(&app, pair_body("device:beta", &second), Some(&t2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");

    let fp = key_fingerprint(&pubkey_of(&second));
    let title = held["action_description"].as_str().expect("a held enrolment carries its title");
    assert!(title.contains(&fp), "the title must name the key being enrolled: {title}");
    assert_eq!(held["key_fp"], fp, "and the console gets the same fingerprint to render");
    assert_eq!(held["message"], permaura_gateway::rest::HELD_PAIRING_REQUESTED_NOTE, "the ticket names who is pairing: {held}");
}

/// For pairings: a held pairing that records who is pairing says the person pairing it cannot confirm it on their own device while someone else's is trusted, unless they are the owner; one whose ticket names nobody keeps the note that asks whether you are pairing it yourself. The wording is pinned because the phone mirrors it.
#[tokio::test]
async fn a_held_pairing_says_who_may_confirm_it_by_whether_it_records_who_is_pairing() {
    assert_eq!(
        permaura_gateway::rest::HELD_PAIRING_REQUESTED_NOTE,
        "Approve only if you know who is pairing this device and agree with it. Unless they are the gateway's owner, the person pairing it cannot confirm it from their own device while a device paired to someone else is trusted."
    );
    let (state, app) = hosted_gateway().await;
    pair_ok(&app, "tkt-cr06p-1", "device:alpha", &device_key(242)).await;
    let named = device_key(243);
    let t = mint_ticket(pair_claims_by("tkt-cr06p-2", "device:named", &named, Some(ACTOR_SUB), None));
    let (status, held) = pair(&app, pair_body("device:named", &named), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["message"], permaura_gateway::rest::HELD_PAIRING_REQUESTED_NOTE, "{held}");
    assert!(approval_row(&state, held["approval_id"].as_str().unwrap()).requested_by.is_some());

    let nobody = device_key(244);
    let t = mint_ticket(pair_claims_by("tkt-cr06p-3", "device:nobody", &nobody, None, None));
    let (status, held) = pair(&app, pair_body("device:nobody", &nobody), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["message"], permaura_gateway::rest::HELD_PAIRING_NOTE, "{held}");
    assert!(approval_row(&state, held["approval_id"].as_str().unwrap()).requested_by.is_none());
}

/// REPLACEMENT. `ApproverKeyring::add` inserts over an existing approver id, so enrolling a second key
/// under an id that already holds one does not add a device: it RETIRES the key currently trusted
/// there. A co-signer asked to "trust a device" would be rotating a trust root without being told, so
/// the prompt has to say which key it displaces.
#[tokio::test]
async fn a_held_replacement_says_which_key_it_would_retire() {
    let (state, app) = hosted_gateway().await;
    let original = device_key(28);
    let rotated = device_key(29);
    pair_ok(&app, "tkt-11a", "device:alpha", &original).await;

    let t2 = mint_ticket(pair_claims("tkt-11b", "device:alpha", &pubkey_of(&rotated)));
    let (status, held) = pair(&app, pair_body("device:alpha", &rotated), Some(&t2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "a rotation is held like any other later enrolment: {held}");

    let title = held["action_description"].as_str().expect("a held rotation carries its title");
    assert!(
        title.starts_with("Replace the trusted key"),
        "a rotation must not read like a first enrolment: {title}"
    );
    assert!(
        title.contains(&key_fingerprint(&pubkey_of(&original))),
        "the title must name the key being retired: {title}"
    );
    assert!(
        title.contains(&key_fingerprint(&pubkey_of(&rotated))),
        "and the key replacing it: {title}"
    );
    assert_eq!(
        state.service.approver_keyring_snapshot().trusted_key("device:alpha"),
        Some(pubkey_of(&original).as_str()),
        "nothing rotates while the hold is outstanding",
    );
}

// ── the approval floor: the other half of the one-way door ───────────────────────────

/// Lowering the floor is a trust-root relaxation and needs the same anchor as pairing. Raising it is
/// fail-safe and must stay reachable from anywhere, including a hosted console that has no ticket
/// (asserted in the same test), because a change that closed the raise would be a security regression
/// dressed up as consistency.
#[tokio::test]
async fn lowering_the_approval_floor_on_hosted_is_refused_without_a_ticket() {
    let (state, app) = hosted_gateway().await;

    let (status, resp) = put_floor(&app, "device_signed", None).await;
    assert_eq!(status, StatusCode::OK, "raising the floor is fail-safe and needs no ticket: {resp}");
    assert_eq!(resp["signed_approvals_required"], true);

    let (status, resp) = put_floor(&app, "approve", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "re-opening bearer approvals needs a fresh step-up: {resp}"
    );
    assert!(
        state.service.require_device_signed_approval(),
        "the floor must be exactly where the refused call found it"
    );

    let (status, resp) = put_floor(&app, "default", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "clearing the override can lower the floor too, so it takes the same anchor: {resp}"
    );
}

/// With a usable device enrolled, a ticket is necessary but not sufficient: the opt-down is held for
/// that device to co-sign. Otherwise a compromised control plane holding one forged ticket could turn
/// off the very requirement that makes the tenant's phone matter, on a worker whose hardware is
/// working perfectly. The ticket alone suffices only in the recovery case above, where nothing is
/// left to ask.
#[tokio::test]
async fn lowering_the_approval_floor_is_held_for_a_trusted_device_then_applied() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(18);

    let t1 = mint_ticket(pair_claims("tkt-5a", "device:alpha", &pubkey_of(&sk)));
    assert_eq!(pair(&app, pair_body("device:alpha", &sk), Some(&t1)).await.0, StatusCode::OK);
    // Raising the floor is its own call now: enrolling makes the device_signed rung resolvable, it
    // does not answer for every other action. This test is about LOWERING it, so it has to be up.
    state
        .service
        .set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::DeviceSigned))
        .unwrap();
    assert!(state.service.require_device_signed_approval(), "setup: the floor is raised");

    let ticket = mint_ticket(floor_claims("tkt-5b"));
    let (status, held) = put_floor(&app, "approve", Some(&ticket)).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "a ticket alone must not re-open bearer approvals while hardware still works: {held}"
    );
    assert!(
        state.service.require_device_signed_approval(),
        "the floor must not move while the hold is outstanding"
    );

    let approval_id = held["approval_id"].as_str().expect("held opt-down carries an approval id");
    let (status, resp) = co_sign(&app, approval_id, "device:alpha", &sk).await;
    assert_eq!(status, StatusCode::OK, "the trusted device's signature applies the opt-down: {resp}");
    assert!(
        !state.service.require_device_signed_approval(),
        "once the device has co-signed, bearer approve-tier resolution is open again"
    );
    let floor = floor_records(&app).await;
    assert_eq!(floor.len(), 1, "one opt-down, one record: {floor:?}");
    assert_eq!(floor[0]["payload"]["summary"]["authority"], "device_cosigned", "{:?}", floor[0]);
}

/// Every floor lowering the guarded funnel applies, as the audit chain records it.
async fn floor_records(app: &axum::Router) -> Vec<Value> {
    let (_s, audit) = send(app, "GET", "/v1/audit-events?limit=200", None, &[]).await;
    audit["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e["payload"]["action"] == "permaura.approval_floor.set")
        .collect()
}

// ── what hosted pairing must never leak into ─────────────────────────────────────────

/// Mode B keeps the loopback-only rule, with a perfectly valid ticket in hand. This asymmetry is the
/// point rather than an oversight: a tunnelled gateway HAS a host, so its owner can always walk to
/// the machine, and the positional anchor is strictly stronger than anything the control plane can
/// assert about identity. Extending the substitute to Mode B would mean a compromised permaura.com
/// could enrol its own key on gateways that never needed the substitute at all.
#[tokio::test]
async fn a_tunnelled_gateway_still_refuses_pairing_with_a_valid_ticket() {
    hosted_environment();
    let mut state = common::seeded();
    // Same binary, same OAuth resource server, same owner: the ONE difference is that this gateway
    // has a host a human could be standing at.
    state.hosted = false;
    state.service.oauth().expect("resource server").refresh().await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    let sk = device_key(19);
    let ticket = mint_ticket(pair_claims("tkt-tunnelled", "device:alpha", &pubkey_of(&sk)));
    let (status, resp) = send(
        &app,
        "POST",
        "/v1/approver-keys/pair",
        Some(pair_body("device:alpha", &sk)),
        &[("cf-ray", "abc123"), (PAIR_TICKET_HEADER, &ticket)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Mode B pairing stays loopback-only, ticket or no ticket: {resp}"
    );
    assert!(
        resp["error"].as_str().unwrap_or_default().contains("loopback-only"),
        "the refusal must be the loopback rule, not a ticket complaint: {resp}"
    );
    assert!(!trusted(&state, "device:alpha"));

    // The floor's lowering branch is anchored the same way and must refuse identically.
    let floor_ticket = mint_ticket(floor_claims("tkt-tunnelled-floor"));
    let (status, resp) = send(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(json!({ "floor": "approve" })),
        &[("cf-ray", "abc123"), (PAIR_TICKET_HEADER, &floor_ticket)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "Mode B floor lowering stays loopback-only: {resp}");
}

/// Mode B must reach the loopback rule BEFORE it looks at the bearer.
///
/// A tunnelled caller can never pair, whatever credential it holds, so the honest answer is 403: the
/// status that means "you may not do this". Checking the bearer first turns a missing or stale one
/// into a 401, which tells the console the opposite: go and authenticate, then come back. It would
/// send a Mode B user round an authentication loop for a door that is shut to them by placement, and
/// it is a behaviour change from every release before hosted pairing existed.
#[tokio::test]
async fn a_tunnelled_gateway_answers_the_loopback_rule_before_it_inspects_the_bearer() {
    hosted_environment();
    let mut state = common::seeded();
    state.hosted = false;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let sk = device_key(30);

    for (label, auth) in [("no bearer at all", None), ("a bearer that resolves to nothing", Some("Bearer not-a-real-token"))] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/approver-keys/pair")
            .header("content-type", "application/json")
            .header("cf-ray", "abc123");
        if let Some(value) = auth {
            builder = builder.header("authorization", value);
        }
        let req = builder
            .body(Body::from(pair_body("device:alpha", &sk).to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Mode B with {label} must hear the loopback rule, not a step-up invitation: {body}"
        );
        assert!(
            body["error"].as_str().unwrap_or_default().contains("loopback-only"),
            "with {label}: {body}"
        );
    }
    assert!(!trusted(&state, "device:alpha"));
}

/// REGRESSION GUARD. `POST /v1/sessions` and `POST /v1/shutdown` stay closed on a hosted worker,
/// forever, and a pairing ticket must not open either.
///
/// `create_session` has no authentication of any kind (`reject_if_remote` is its entire gate), and
/// it mints an Operator-role token. Opening it on a hosted worker would hand operator authority to
/// anyone who can reach the URL, which on Cloud Run is the whole internet. `shutdown` stops the
/// tenant's worker. Both are presented here WITH a valid ticket precisely so that a later change
/// which generalises the pairing anchor across the operator plane fails this test rather than
/// shipping.
#[tokio::test]
async fn sessions_and_shutdown_stay_closed_on_a_hosted_worker() {
    let (_state, app) = hosted_gateway().await;
    let sk = device_key(20);
    let ticket = mint_ticket(pair_claims("tkt-regression", "device:alpha", &pubkey_of(&sk)));

    let (status, resp) = send(
        &app,
        "POST",
        "/v1/sessions",
        Some(json!({ "agent_id": "codex-cli", "user_id": OWNER_SUB })),
        &[(PAIR_TICKET_HEADER, &ticket)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "session-open mints an Operator token with no credential and must stay closed: {resp}"
    );
    assert!(resp["token"].is_null(), "no token may be minted on a hosted worker: {resp}");

    let (status, resp) =
        send(&app, "POST", "/v1/shutdown", None, &[(PAIR_TICKET_HEADER, &ticket)]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a pairing ticket must never be able to stop the tenant's worker: {resp}"
    );
}

// ── the keyring must be enumerable, or a trusted key becomes unrevocable ──────────────

/// A key paired WITHOUT a push-device row (a simulator build, a user who declined notifications,
/// any Apple Watch) is fully trusted and completely absent from `GET /v1/devices`, because that
/// endpoint used to list the push registry alone, which pairing does not write to. Both revoke surfaces read that
/// list, so before `GET /v1/approver-keys` existed such a key could not be seen; and combined with
/// the sticky device-signed floor, losing that device left the tenant unable to approve (the device
/// is gone), unable to revoke (nothing listed it) and unable to pair a replacement (held for a
/// co-signature only the lost device could give). This asserts the whole way out: it is listed, and
/// it is revocable by approver id with no device row anywhere.
#[tokio::test]
async fn a_key_with_no_push_device_row_is_listed_and_revocable() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(40);
    pair_ok(&app, "tkt-list-1", "device:watch", &sk).await;

    let (status, devices) = send(&app, "GET", "/v1/devices", None, &[]).await;
    assert_eq!(status, StatusCode::OK, "{devices}");
    // Pairing writes the keyring, never the push registry, and the device list is built from the
    // keyring first, so the key is listed here too, under its approver id, with nothing registered.
    let row = devices["devices"]
        .as_array()
        .and_then(|d| d.iter().find(|d| d["approver_id"] == "device:watch").cloned())
        .expect("a trusted key with no registration is still a device: {devices}");
    assert_eq!(row["id"], "device:watch");
    assert_eq!(row["is_trusted"], true);
    assert_eq!(row["has_push_token"], false);

    let (status, listed) = send(&app, "GET", "/v1/approver-keys", None, &[]).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let keys = listed["keys"].as_array().expect("the census is an array");
    let entry = keys
        .iter()
        .find(|k| k["approver_id"] == "device:watch")
        .expect("a trusted key must be listed even with no device row");
    assert_eq!(entry["key_fp"], key_fingerprint(&pubkey_of(&sk)), "listed by the fingerprint the ticket and the audit chain use");
    assert_eq!(entry["trusted"], true);
    assert_eq!(entry["revoked"], false);
    assert!(entry["device_id"].is_null(), "nothing registered it for push, and the list says so");
    assert_eq!(
        listed["approval_floor"], "approve",
        "the envelope reports the floor, and pairing this key did not raise it: the policy decides",
    );

    // And it can be retired by that id alone, under the same ticket `DELETE /v1/devices/:id` would
    // have taken, which keeps the two surfaces consistent when only one of them can see the key.
    let (status, resp) = revoke_key(&app, "device:watch", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the step-up rule does not depend on a device row: {resp}");
    let ticket = mint_ticket(admin_revoke_claims("tkt-list-2", "device:watch"));
    let (status, resp) = revoke_key(&app, "device:watch", Some(&ticket)).await;
    assert_eq!(status, StatusCode::OK, "an approver id is enough to revoke: {resp}");
    assert!(!trusted(&state, "device:watch"));

    let (_s, listed) = send(&app, "GET", "/v1/approver-keys", None, &[]).await;
    let entry = listed["keys"]
        .as_array()
        .and_then(|k| k.iter().find(|k| k["approver_id"] == "device:watch"))
        .expect("a revoked key stays listed: the floor it raised is still in force");
    assert_eq!(entry["trusted"], false);
    assert_eq!(entry["revoked"], true);
}

/// An agent token must not be able to read the trust state. This is not secret material, but it is
/// the map of what would have to be compromised to forge an approval, and the listing endpoints on
/// this gateway are operator-only as a class.
#[tokio::test]
async fn listing_approver_keys_is_operator_only() {
    let (_state, app) = hosted_gateway().await;
    let req = Request::builder()
        .method("GET")
        .uri("/v1/approver-keys")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "unauthenticated callers see nothing");
}

// ── the published operator token can spend a ticket ──────────────────────────────────

/// Seed an operator session shaped like the one a worker mints for ITSELF at boot
/// (`seed::clean_bootstrap`): a real token, published to `operator.token`, and `user_id: None`
/// because nothing at bootstrap knows an account id.
fn put_operator_session(state: &AppState, id: &str, token: &str, user_id: Option<&str>) {
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: id.to_string(),
            agent_id: "operator".into(),
            user_id: user_id.map(str::to_string),
            device_id: None,
            token: token.to_string(),
            role: SessionRole::Operator,
            created_at: now_ms(),
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .expect("seeding a session cannot fail on the in-memory store");
}

/// Send a request as a specific bearer rather than the seeded demo operator.
async fn send_as(
    app: &axum::Router,
    bearer: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"));
    for (k, v) in extra {
        builder = builder.header(*k, *v);
    }
    let req = match body {
        Some(b) => builder.body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// THE FILE TOKEN MUST WORK. `clean_bootstrap` mints the operator session a hosted worker publishes
/// to `operator.token`, and it has no `user_id`: nothing at bootstrap knows the account id. Tying
/// the ticket to the session by requiring `user_id == ticket.sub` therefore refused every
/// ticket-bearing CLI call outright, which took `permaura approver pair --ticket` and
/// `permaura approver revoke --ticket` out of service on the only mode that has them.
///
/// The rule that replaces it is narrow: a session naming NOBODY is accepted, a session naming
/// SOMEBODY ELSE is still refused. Both halves are asserted here, because only the second one is
/// load-bearing: a change that accepted any session would pass a test that checked the first alone.
#[tokio::test]
async fn the_published_operator_token_can_spend_a_ticket_but_another_users_session_cannot() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(41);
    put_operator_session(&state, "sess_boot", "pgt_published", None);
    put_operator_session(&state, "sess_other", "pgt_someone_else", Some("user_someone_else"));

    let ticket = mint_ticket(pair_claims("tkt-file-1", "device:cli", &pubkey_of(&sk)));
    let (status, resp) = send_as(
        &app,
        "pgt_someone_else",
        "POST",
        "/v1/approver-keys/pair",
        Some(pair_body("device:cli", &sk)),
        &[(PAIR_TICKET_HEADER, &ticket)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a session belonging to a different account must never spend this worker's ticket: {resp}"
    );
    assert!(!trusted(&state, "device:cli"));

    let (status, resp) = send_as(
        &app,
        "pgt_published",
        "POST",
        "/v1/approver-keys/pair",
        Some(pair_body("device:cli", &sk)),
        &[(PAIR_TICKET_HEADER, &ticket)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the worker's own published bearer must be able to pair: {resp}");
    assert!(trusted(&state, "device:cli"), "the CLI path is the fallback a stranded owner reaches for");
}

// ── the escape hatch has to lead somewhere ───────────────────────────────────────────

/// THE RECOVERY ACTUALLY RECOVERS. Lowering the floor exists so a tenant whose devices are all gone
/// can resolve approvals from the console again. It did not work: every non-tightening control-plane
/// mutation arriving over the broker was held for a device signature on the strength of the STICKY
/// `ever_enrolled` flag, which survives revocation, and each hold carries the `device_signed` tier
/// that the per-approval gate refuses to bearer-resolve whatever the floor says. So an owner could
/// perform the loosening (two step-ups, a revocation and an opt-down) and find their control plane
/// exactly as frozen as before, with a queue of holds nothing on earth could sign.
///
/// The hold is now conditioned on the gateway still REQUIRING a device signature. The first half of
/// this test is the guard that this did not simply delete the rule: while the floor stands, the
/// mutation is still held.
#[tokio::test]
async fn lowering_the_floor_actually_gives_the_control_plane_back() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(50);
    pair_ok(&app, "tkt-esc-1", "device:lost", &sk).await;

    // While the floor stands, nothing has changed: the mutation is held and a bearer cannot resolve it.
    let (status, held) =
        send(&app, "POST", "/v1/agents/register", Some(json!({ "name": "before" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the device-signed hold is unchanged while the floor stands: {held}");
    let approval_id = held["approval_id"].as_str().expect("a held mutation carries an approval id");
    let (status, refused) = send(
        &app,
        "POST",
        "/v1/approvals",
        Some(json!({ "approval_id": approval_id, "approve": true, "approver": "user:owner" })),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "and a bare bearer cannot resolve a device_signed hold: {refused}"
    );

    // The phone is gone. Revoke it, then re-open bearer approvals: the two step-ups the design
    // promises, in the order it promises them.
    let revoke = mint_ticket(admin_revoke_claims("tkt-esc-2", "device:lost"));
    assert_eq!(revoke_key(&app, "device:lost", Some(&revoke)).await.0, StatusCode::OK);
    let floor = mint_ticket(floor_claims_by("tkt-esc-3", ACTOR_SUB, Some("admin")));
    let (status, lowered) = put_floor(&app, "approve", Some(&floor)).await;
    assert_eq!(status, StatusCode::OK, "with nothing left to co-sign, the ticket alone applies: {lowered}");
    assert!(!state.service.require_device_signed_approval());
    // The step-up that re-opened bearer approvals is on the record, with who stepped up.
    let records = floor_records(&app).await;
    let summary = &records.last().expect("the floor lowering is recorded")["payload"]["summary"];
    assert_eq!(summary["authority"], "hosted_owner_ticket", "{summary}");
    assert_eq!(summary["ticket_jti"], "tkt-esc-3", "{summary}");
    assert_eq!(summary["actor_sub"], ACTOR_SUB, "{summary}");
    assert!(
        state.service.any_device_enrolled(),
        "the sticky flag is still set: this test would pass trivially if it were not"
    );

    // THE PROPERTY: the tenant can now change their own control plane again.
    let (status, applied) =
        send(&app, "POST", "/v1/agents/register", Some(json!({ "name": "after" })), &[]).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "after the loosening the owner authorised, a control-plane change must not still be held for \
         hardware that no longer exists: {applied}"
    );
}

/// The same clause must not let a compromised control plane loosen its own way out. Raising the floor
/// is reachable from anywhere; lowering it is not, and the hold comes straight back when the floor
/// does. Without this, "hold only while a signature is required" would be a switch the broker could
/// flick.
#[tokio::test]
async fn the_hold_returns_the_moment_the_floor_does() {
    let (_state, app) = hosted_gateway().await;
    let sk = device_key(51);
    pair_ok(&app, "tkt-esc-4", "device:alpha", &sk).await;
    let revoke = mint_ticket(admin_revoke_claims("tkt-esc-5", "device:alpha"));
    assert_eq!(revoke_key(&app, "device:alpha", Some(&revoke)).await.0, StatusCode::OK);
    let floor = mint_ticket(floor_claims_by("tkt-esc-6", ACTOR_SUB, Some("admin")));
    assert_eq!(put_floor(&app, "approve", Some(&floor)).await.0, StatusCode::OK);

    let (status, resp) = put_floor(&app, "device_signed", None).await;
    assert_eq!(status, StatusCode::OK, "raising the floor stays ticket-free and reachable: {resp}");
    let (status, held) =
        send(&app, "POST", "/v1/agents/register", Some(json!({ "name": "again" })), &[]).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "with the floor back up, a broker mutation is held again: {held}"
    );
}

// ── every refusal is recorded, and every record names a real key ─────────────────────

/// A REPLAYED TICKET IS THE EVENT. Every claim on it verified, which means the AS really minted it
/// for this worker's owner, and something is now presenting it a second time. The spend used to
/// return before any audit write, so the one refusal that says "somebody else has your ticket" was
/// the only refusal nothing recorded, on a hosted worker, where the chain is the sole after-the-fact
/// evidence an owner has.
#[tokio::test]
async fn a_replayed_pairing_ticket_is_written_to_the_audit_chain() {
    let (state, app) = hosted_gateway().await;
    let owners = device_key(52);
    let attacker = device_key(53);

    let first = mint_ticket(pair_claims("tkt-replay-audit", "device:alpha", &pubkey_of(&owners)));
    assert_eq!(pair(&app, pair_body("device:alpha", &owners), Some(&first)).await.0, StatusCode::OK);

    // Same jti, re-minted for the attacker's own id and key: everything verifies, the single-use
    // ledger is the only thing in the way.
    let replay = mint_ticket(pair_claims("tkt-replay-audit", "device:evil", &pubkey_of(&attacker)));
    let (status, resp) = pair(&app, pair_body("device:evil", &attacker), Some(&replay)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a spent jti is refused: {resp}");
    assert!(!trusted(&state, "device:evil"));

    let events = pairing_audit(&app).await;
    let replay_event = events
        .iter()
        .find(|e| e["payload"]["summary"]["approver_id"] == "device:evil")
        .expect("the replay must be in the chain: it is the sharpest signal this feature emits");
    assert_eq!(replay_event["payload"]["decision"], "deny");
    assert_eq!(replay_event["payload"]["summary"]["ticket_jti"], "tkt-replay-audit");
    assert_eq!(replay_event["payload"]["summary"]["authority"], "hosted_owner_ticket");
    assert_eq!(
        replay_event["payload"]["summary"]["key_fp"],
        key_fingerprint(&pubkey_of(&attacker)),
        "the record must name the key the replay tried to enrol, not the one that legitimately landed"
    );
    let reason = replay_event["payload"]["summary"]["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("replay"), "the reason must say what happened: {reason}");
}

/// The revocation that empties the keyring is the one whose authority most needs recording: it is
/// what returns the worker to trusting the next device that turns up. A record naming only
/// `operator_revocation` describes a bearer, which is precisely the credential that was NOT
/// sufficient; the step-up that was is what the chain has to carry.
#[tokio::test]
async fn the_revocation_record_names_the_step_up_that_authorised_it() {
    let (_state, app) = hosted_gateway().await;
    let sk = device_key(54);
    pair_ok(&app, "tkt-rev-audit-1", "device:alpha", &sk).await;

    let ticket = mint_ticket(admin_revoke_claims("tkt-rev-audit-2", "device:alpha"));
    assert_eq!(revoke_key(&app, "device:alpha", Some(&ticket)).await.0, StatusCode::OK);

    let events = pairing_audit(&app).await;
    let last = events.last().expect("the revocation was recorded");
    assert_eq!(last["payload"]["decision"], "deny");
    assert_eq!(last["payload"]["summary"]["authority"], "hosted_owner_ticket");
    assert_eq!(last["payload"]["summary"]["ticket_jti"], "tkt-rev-audit-2");
    assert_eq!(last["payload"]["summary"]["actor_sub"], ACTOR_SUB);
    assert_eq!(last["payload"]["summary"]["emptied_keyring"], true);
    assert_eq!(last["payload"]["summary"]["amr"], json!(["pwd", "device"]), "the factors the AS asserted belong in the record: {last}");
    assert!(
        last["payload"]["summary"]["auth_time"].as_i64().is_some(),
        "and when they were asserted: {last}"
    );
}

/// One sign-in method is a whole step-up: a ticket naming only the password, only a passkey or only the phone, a phone in its first day (`new-device`) included, pairs a worker's first device.
#[tokio::test]
async fn a_single_sign_in_method_is_a_step_up() {
    for (n, method) in ["pwd", "passkey", "device", "new-device"].into_iter().enumerate() {
        let (state, app) = hosted_gateway().await;
        let sk = device_key(245 + n as u8);
        let approver_id = format!("device:single-{method}");
        let mut claims = pair_claims(&format!("tkt-single-{method}"), &approver_id, &pubkey_of(&sk));
        claims["amr"] = json!([method]);
        let (status, resp) = pair(&app, pair_body(&approver_id, &sk), Some(&mint_ticket(claims))).await;
        assert_eq!(status, StatusCode::OK, "{method}: {resp}");
        assert!(trusted(&state, &approver_id), "{method}");
    }
}

/// A step-up is one sign-in method: the password, a passkey or the phone. A ticket asserting only an emailed code verifies as the AS's own, so its refusal is recorded with what it asserted.
#[tokio::test]
async fn a_code_only_step_up_is_refused_and_recorded() {
    let (state, app) = hosted_gateway().await;
    pair_ok(&app, "tkt-amr-1", "device:alpha", &device_key(57)).await;

    let mut claims = revoke_claims("tkt-amr-2", "device:alpha");
    claims["amr"] = json!(["otp"]);
    let (status, resp) = revoke_key(&app, "device:alpha", Some(&mint_ticket(claims))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("password, passkey or phone approval"), "{resp}");
    assert!(trusted(&state, "device:alpha"));

    let events = pairing_audit(&app).await;
    let refusal = events.last().expect("the refusal is recorded");
    let summary = &refusal["payload"]["summary"];
    assert_eq!(refusal["payload"]["decision"], "deny", "{refusal}");
    assert_eq!(summary["approver_id"], "device:alpha", "{refusal}");
    assert_eq!(summary["ticket_jti"], "tkt-amr-2", "{refusal}");
    assert_eq!(summary["amr"], json!(["otp"]), "{refusal}");
    assert_eq!(summary["purpose"], "approver-revoke", "{refusal}");
    assert_eq!(summary["actor_sub"], ACTOR_SUB, "{refusal}");
}

/// A revocation must name the key it untrusted, and that key comes from the KEYRING. Reading it from
/// the push registry produced `None` for every approver that never registered for notifications, and
/// `.unwrap_or_default()` then hashed the empty string into a perfectly well-formed fingerprint of
/// nothing, written into the chain as though it identified the revoked key. A reader matching it
/// against a pairing notice would be comparing against a fabrication.
#[tokio::test]
async fn a_revocation_records_the_key_it_actually_untrusted() {
    let (_state, app) = hosted_gateway().await;
    let first = device_key(55);
    let second = device_key(56);
    let empty_fp = key_fingerprint("");

    pair_ok(&app, "tkt-fp-1", "device:alpha", &first).await;
    let t2 = mint_ticket(pair_claims("tkt-fp-2", "device:beta", &pubkey_of(&second)));
    let (status, held) = pair(&app, pair_body("device:beta", &second), Some(&t2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();
    assert_eq!(co_sign(&app, approval_id, "device:alpha", &first).await.0, StatusCode::OK);

    // Neither device ever called /v1/devices/enroll, so neither has a push row.
    let ticket = mint_ticket(revoke_claims("tkt-fp-3", "device:beta"));
    let (status, resp) = revoke_key(&app, "device:beta", Some(&ticket)).await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    let events = pairing_audit(&app).await;
    let last = events.last().expect("the revocation was recorded");
    assert_eq!(
        last["payload"]["summary"]["key_fp"],
        key_fingerprint(&pubkey_of(&second)),
        "the record names the key the keyring held, which no push row ever knew: {last}"
    );
    assert_ne!(last["payload"]["summary"]["key_fp"], empty_fp);
    assert_eq!(last["payload"]["summary"]["authority"], "hosted_owner_ticket");
    assert_eq!(last["payload"]["summary"]["emptied_keyring"], false);

    // An approver this worker has never heard of has no key to name, so the field is ABSENT rather
    // than a hash of nothing.
    let ticket = mint_ticket(revoke_claims("tkt-fp-4", "device:never-existed"));
    let (status, resp) = revoke_key(&app, "device:never-existed", Some(&ticket)).await;
    assert_eq!(status, StatusCode::OK, "revoking an unknown approver is a no-op, not an error: {resp}");
    let events = pairing_audit(&app).await;
    let last = events.last().expect("even a no-op revocation is recorded");
    assert_eq!(last["payload"]["summary"]["approver_id"], "device:never-existed");
    assert!(
        last["payload"]["summary"]["key_fp"].is_null(),
        "an unknown key must be an absent field, never the fingerprint of an empty string: {last}"
    );
}

// ── the 202 has to be honest about what it is asking for ─────────────────────────────

/// RE-PAIRING THE SAME KEY IS NOT AN ENROLMENT. A phone that lost its local state and re-ran the
/// ceremony presents the same approver id and the same key, and the trust state after is identical
/// to the trust state before. Holding it produced a 202 telling the owner that "another paired
/// device must confirm this", which, on the common version of this, is the phone in their hand.
///
/// It is safe to short-circuit because reaching the mutation at all required a possession proof
/// signed with that key's PRIVATE half: only the device itself can produce one, and anyone who could
/// would already be able to sign approvals as it.
#[tokio::test]
async fn re_pairing_an_already_trusted_key_is_already_done_rather_than_held() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(57);
    pair_ok(&app, "tkt-nop-1", "device:alpha", &sk).await;

    let again = mint_ticket(pair_claims("tkt-nop-2", "device:alpha", &pubkey_of(&sk)));
    let (status, resp) = pair(&app, pair_body("device:alpha", &sk), Some(&again)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "re-pairing the key that is already trusted changes nothing and must not be held: {resp}"
    );
    assert_eq!(resp["trusted"], true);
    assert_eq!(resp["key_fp"], key_fingerprint(&pubkey_of(&sk)));
    assert_eq!(
        state.service.approver_keyring_snapshot().trusted_key("device:alpha"),
        Some(pubkey_of(&sk).as_str()),
    );

    let last = pairing_audit(&app).await.pop().expect("the re-pair is still recorded");
    assert_eq!(last["payload"]["decision"], "allow");
    assert_eq!(
        last["payload"]["summary"]["already_trusted"], true,
        "the chain must separate a re-pair that changed nothing from the enrolment that armed the gate: {last}"
    );

    // A DIFFERENT key under the same id is a rotation of the trust root and is still held: the
    // short-circuit must be about the exact key, never about the approver id.
    let rotated = device_key(58);
    let rotate = mint_ticket(pair_claims("tkt-nop-3", "device:alpha", &pubkey_of(&rotated)));
    let (status, held) = pair(&app, pair_body("device:alpha", &rotated), Some(&rotate)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "a new key under a live id still needs a co-signature: {held}");
    assert_eq!(
        state.service.approver_keyring_snapshot().trusted_key("device:alpha"),
        Some(pubkey_of(&sk).as_str()),
        "and nothing rotates while that hold is outstanding",
    );
}

/// A held change says when it lapses, as an absolute deadline a day after it was held, on
/// both hold producers, since a client cannot tell them apart from the status code. The field is
/// never omitted and never `0`: a client that reads a missing field as zero renders a hold that
/// expired in 1970 and greys itself out immediately, which is the desktop approval card.
///
/// The expected deadline is written out here rather than read from the gateway, so changing it fails
/// this test rather than silently changing what clients are promised.
#[tokio::test]
async fn a_held_mutation_says_when_it_expires() {
    let (state, app) = hosted_gateway().await;
    let first = device_key(59);
    let second = device_key(60);
    let day = 24 * 60 * 60 * 1000;

    pair_ok(&app, "tkt-ttl-1", "device:alpha", &first).await;
    let t2 = mint_ticket(pair_claims("tkt-ttl-2", "device:beta", &pubkey_of(&second)));
    let (status, held) = pair(&app, pair_body("device:beta", &second), Some(&t2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let row = approval_row(&state, held["approval_id"].as_str().unwrap());
    assert_eq!(held["expires_at"], json!(row.created_at + day), "a held enrolment lapses a day after it was held: {held}");

    // And the generic control-plane hold, which a client cannot distinguish by status code.
    let (status, held) =
        send(&app, "POST", "/v1/agents/register", Some(json!({ "name": "ttl" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let row = approval_row(&state, held["approval_id"].as_str().unwrap());
    assert_eq!(held["expires_at"], json!(row.created_at + day), "every held change lapses a day after it was held: {held}");
}

/// The held floor-lowering must say what to do next. It is the recovery control, and the state it is
/// reached in is "my device is gone", so a 202 whose only content is "a trusted device must
/// co-sign" is a dead end unless it also names the step that reopens it.
#[tokio::test]
async fn a_held_floor_lowering_names_the_way_out() {
    let (_state, app) = hosted_gateway().await;
    let sk = device_key(61);
    pair_ok(&app, "tkt-hint-1", "device:alpha", &sk).await;

    let ticket = mint_ticket(floor_claims("tkt-hint-2"));
    let (status, held) = put_floor(&app, "approve", Some(&ticket)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let recovery = held["recovery"].as_str().unwrap_or_default();
    assert!(
        recovery.contains("revoke"),
        "the dead end has to name the step that opens it: {held}"
    );
}

// ── a cold start that races an unreachable AS must not be a five-minute outage ────────

/// UNKNOWN KID NOW TRIGGERS A REFETCH, RATE-LIMITED ON THE CLOCK ALONE.
///
/// A Mode C worker fetches the JWKS once at boot and then every 300s. Cold-start during a brief
/// permaura.com blip and the cache stays empty, so EVERY token is refused for up to five minutes with
/// `unknown signing key (kid)`, which reads like a key-rotation fault and is nothing of the sort.
///
/// The fix cannot be "fetch on every miss": verification runs before any authentication has
/// succeeded, so that would let anyone who can reach the gateway drive one outbound request at the AS
/// per token they invent. The gate is therefore on time and on nothing the caller controls (not the
/// `kid`, not the identity, not a counter), which is exactly what this asserts: a hundred misses
/// inside the window produce zero further fetches.
#[tokio::test]
async fn an_unknown_kid_refetches_the_jwks_at_most_once_per_window() {
    let (state, _app) = hosted_gateway().await;
    let oauth = state.service.oauth().expect("a hosted worker is a resource server").clone();
    let t0 = 1_000_000i64;

    assert!(oauth.request_jwks_refetch(t0), "the first miss after a cold start must refetch");
    for i in 0..100 {
        assert!(
            !oauth.request_jwks_refetch(t0 + i % 30),
            "no volume of unknown kids may amplify: miss {i} must not fetch"
        );
    }
    assert!(
        !oauth.request_jwks_refetch(t0 + 29),
        "still inside the window one second before it closes"
    );
    assert!(oauth.request_jwks_refetch(t0 + 30), "and open again once the window has passed");
}

// ── a hosted worker has no business writing to anyone's home directory ───────────────

/// `PERMAURA_HOSTED=1` did not suppress `publish_operator_token`. On Cloud Run the file is pointless:
/// nothing there reads it, and the CLI reaches a hosted worker over its public URL. On a
/// developer's Mac it is worse than pointless: starting a hosted-mode gateway for testing overwrote
/// the operator token belonging to their real local gateway and broke its CLI pairing, which is how
/// this was found.
#[tokio::test]
async fn a_hosted_worker_publishes_no_operator_token() {
    hosted_environment();
    assert!(
        permaura_gateway::operator_token_path().is_none(),
        "a hosted worker must not write an operator token to a home directory it does not own",
    );
}

/// `GET /v1/devices` is the complete list of what can sign, keyring first. A key paired without ever
/// registering for notifications (a Watch, a simulator, a phone that declined them) has no registry
/// row and used to be invisible here, so the one list a console offered revocation from could not show
/// the approver that most needed it. Such a row carries the approver id as its id, and revoking by
/// that id revokes the key.
#[tokio::test]
async fn the_device_list_is_the_keyring_and_a_keyring_only_row_can_be_revoked_by_its_approver_id() {
    let (state, app) = hosted_gateway().await;
    let first = device_key(31);
    let second = device_key(32);
    pair_ok(&app, "tkt-dl-a", "device:alpha", &first).await;
    let t2 = mint_ticket(pair_claims("tkt-dl-b", "device:beta", &pubkey_of(&second)));
    let (status, held) = pair(&app, pair_body("device:beta", &second), Some(&t2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().expect("held enrolment carries an approval id");
    let (status, _) = co_sign(&app, approval_id, "device:alpha", &first).await;
    assert_eq!(status, StatusCode::OK);
    assert!(trusted(&state, "device:beta"));

    let (status, listed) = send(&app, "GET", "/v1/devices", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let rows = listed["devices"].as_array().expect("devices");
    let beta = rows
        .iter()
        .find(|d| d["approver_id"] == "device:beta")
        .expect("a paired key with no registration is still listed");
    assert_eq!(beta["id"], "device:beta", "no registration, so the approver id is the row's id");
    assert_eq!(beta["is_trusted"], true);
    assert_eq!(beta["has_signing_key"], true);
    assert!(beta["name"].is_null());
    assert!(rows.iter().any(|d| d["approver_id"] == "device:alpha" && d["is_trusted"] == true));

    let ticket = mint_ticket(revoke_claims("tkt-dl-c", "device:beta"));
    let (status, resp) =
        send(&app, "DELETE", "/v1/devices/device:beta", None, &[(PAIR_TICKET_HEADER, &ticket)]).await;
    assert_eq!(status, StatusCode::OK, "revoking a keyring-only row by its approver id: {resp}");
    assert!(!trusted(&state, "device:beta"), "the key is what got revoked");
    let (_s, listed) = send(&app, "GET", "/v1/devices", None, &[]).await;
    let beta = listed["devices"].as_array().unwrap().iter().find(|d| d["approver_id"] == "device:beta").cloned();
    assert_eq!(beta.map(|b| b["is_trusted"].clone()), Some(json!(false)), "still listed, no longer trusted");
}

// ── Whoever asked for a held change does not confirm it alone ────────────────────────

/// An operator session as the console mints one for `actor` on this worker: the owner's `sub`, the
/// acting member named beside it, and `role` when permaura.com stamps one.
fn put_console_session(state: &AppState, token: &str, actor: &str, role: Option<&str>) {
    put_console_session_standing(state, token, actor, role, None);
}

/// A console session for a member permaura.com signed as holding Export the vault (`vault_export: true` on the operator token).
fn put_exporter_console_session(state: &AppState, token: &str, actor: &str, role: Option<&str>) {
    put_console_session_standing(state, token, actor, role, Some(true));
}

fn put_console_session_standing(state: &AppState, token: &str, actor: &str, role: Option<&str>, vault_export: Option<bool>) {
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: format!("sess_console_{token}"),
            agent_id: format!("operator:{OWNER_SUB}"),
            user_id: Some(OWNER_SUB.into()),
            device_id: None,
            token: token.to_string(),
            role: SessionRole::Operator,
            created_at: now_ms(),
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: Some(SessionActor { sub: actor.into(), name: None, role: role.map(str::to_string), vault_export }),
        })
        .expect("seeding a session cannot fail on the in-memory store");
}

const OWNER_CONSOLE: &str = "pgt_console_owner";
const MEMBER_CONSOLE: &str = "pgt_console_member";
const ADMIN_CONSOLE: &str = "pgt_console_admin";
/// The same member as an admin whom permaura.com also signs as holding Export the vault.
const EXPORTER_CONSOLE: &str = "pgt_console_exporter";

/// A team on a hosted worker: the owner's phone, bound to the owner and paired first, and a member's
/// phone, bound to the member and co-signed by the owner's. Console sessions for the owner, the member
/// and the same member as an admin.
async fn team(state: &AppState, app: &axum::Router, tag: &str) -> (SigningKey, SigningKey) {
    let (owner_phone, member_phone) = (device_key(130), device_key(131));
    let t = mint_ticket(pair_claims_by(&format!("{tag}-o"), "device:owner-phone", &owner_phone, Some(OWNER_SUB), Some("owner")));
    let (status, resp) = pair(app, pair_body("device:owner-phone", &owner_phone), Some(&t)).await;
    assert_eq!(status, StatusCode::OK, "setup: the owner pairs first: {resp}");
    pair_held_for(app, &format!("{tag}-m"), "device:member-phone", &member_phone, ACTOR_SUB, ("device:owner-phone", &owner_phone)).await;
    put_console_session(state, OWNER_CONSOLE, OWNER_SUB, None);
    put_console_session(state, MEMBER_CONSOLE, ACTOR_SUB, None);
    put_console_session(state, ADMIN_CONSOLE, ACTOR_SUB, Some("admin"));
    put_exporter_console_session(state, EXPORTER_CONSOLE, ACTOR_SUB, Some("admin"));
    (owner_phone, member_phone)
}

fn is_self_approval_refusal(status: StatusCode, resp: &Value) -> bool {
    status == StatusCode::FORBIDDEN && resp["error"].as_str().unwrap_or_default().contains("self-approval refused")
}

fn widening_policy(id: &str) -> Value {
    json!({ "id": id, "connection_id": "generic_http", "name": id, "allow": ["request"] })
}

fn has_policy(state: &AppState, id: &str) -> bool {
    state.service.store().list_policies().unwrap().iter().any(|p| p.id == id)
}

/// The SSH target host of every capability on the seeded `ssh_prod` connection.
fn ssh_hosts(state: &AppState) -> Vec<String> {
    let store = state.service.store();
    let conn = store.get_connection("ssh_prod").unwrap().expect("the seeded SSH connection");
    conn.capabilities
        .iter()
        .filter_map(|id| store.get_capability(id).unwrap())
        .filter_map(|cap| cap.ssh.map(|s| s.target.host))
        .collect()
}

const RETARGET: &str = r#"{"ssh":{"host":"collector.attacker.example","password_auth":true,"insecure":true}}"#;

/// A member's policy change, held for a device, is not confirmed by the member's own phone; the owner's is.
#[tokio::test]
async fn a_members_own_phone_cannot_confirm_the_members_policy_change() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-sod-1").await;
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_member")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();

    let (status, resp) = co_sign(&app, approval_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    assert!(!has_policy(&state, "p_member"), "the member's own phone applied nothing");

    let (status, resp) = co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "a different trusted person confirms it: {resp}");
    assert!(has_policy(&state, "p_member"));
}

/// On a paired worker: the floor lowering a member asks for is not theirs to confirm.
#[tokio::test]
async fn a_members_own_phone_cannot_confirm_the_members_floor_lowering() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-sod-2").await;
    state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::DeviceSigned)).unwrap();
    let (status, held) = put_floor(&app, "approve", Some(&mint_ticket(floor_claims("tkt-sod-2f")))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();

    let (status, resp) = co_sign(&app, approval_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    assert!(state.service.require_device_signed_approval(), "the floor did not move");

    let (status, resp) = co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(!state.service.require_device_signed_approval());
}

/// A member pairing another device of their own is co-signed by someone else, not by the member's phone.
#[tokio::test]
async fn a_members_own_phone_cannot_confirm_the_members_next_device() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-sod-3").await;
    let tablet = device_key(132);
    let t = mint_ticket(pair_claims_as("tkt-sod-3t", "device:member-tablet", &pubkey_of(&tablet), ACTOR_SUB));
    let (status, held) = pair(&app, pair_body("device:member-tablet", &tablet), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();

    let (status, resp) = co_sign(&app, approval_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    assert!(!trusted(&state, "device:member-tablet"));

    let (status, resp) = co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(trusted(&state, "device:member-tablet"));
}

/// An admin's SSH retarget is held, and the admin's own phone cannot confirm it while the owner's can. The owner's own retarget is confirmed on the owner's own phone: the owner can always make a change with their own signed device.
#[tokio::test]
async fn an_ssh_retarget_is_confirmed_by_someone_other_than_who_asked() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-sod-4").await;
    let before = ssh_hosts(&state);
    let body: Value = serde_json::from_str(RETARGET).unwrap();
    let (status, held) = send_as(&app, EXPORTER_CONSOLE, "PATCH", "/v1/connections/ssh_prod", Some(body.clone()), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();

    let (status, resp) = co_sign(&app, approval_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    assert_eq!(ssh_hosts(&state), before, "nothing moved");

    let (status, resp) = co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(ssh_hosts(&state).iter().all(|h| h == "collector.attacker.example"));

    let back = json!({ "ssh": { "host": "collector2.example.com" } });
    let (status, held) = send_as(&app, OWNER_CONSOLE, "PATCH", "/v1/connections/ssh_prod", Some(back), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "the owner's own retarget on the owner's own phone: {resp}");
    assert!(ssh_hosts(&state).iter().all(|h| h == "collector2.example.com"));
}

/// Narrowed by the export standing: a member holds `connector.manage` but not the standing a vault export takes, so
/// the core refuses them a change of host or a switch to password auth, and so does an admin whose token carries no
/// signed `vault_export` claim; the owner's and an Export holder's are held for a device as usual.
#[tokio::test]
async fn a_member_without_export_standing_cannot_move_an_ssh_credential() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-sod-5").await;
    let before = ssh_hosts(&state);
    for patch in [
        json!({ "ssh": { "host": "collector.attacker.example" } }),
        json!({ "ssh": { "password_auth": true } }),
        json!({ "ssh": { "port": 2222, "user": "root" } }),
        json!({ "ssh": { "host_key_sha256": "SHA256:attacker" } }),
    ] {
        for bearer in [MEMBER_CONSOLE, ADMIN_CONSOLE, seed::DEMO_TOKEN] {
            let (status, resp) = send_as(&app, bearer, "PATCH", "/v1/connections/ssh_prod", Some(patch.clone()), &[]).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{bearer} {patch}: {resp}");
            let error = resp["error"].as_str().unwrap_or_default();
            assert!(error.contains("standing a vault export does") && error.contains("holds Export the vault"), "{resp}");
        }
    }
    assert_eq!(ssh_hosts(&state), before, "nothing moved");
    for bearer in [MEMBER_CONSOLE, ADMIN_CONSOLE] {
        let (status, resp) =
            send_as(&app, bearer, "PATCH", "/v1/connections/ssh_prod", Some(json!({ "label": "Prod" })), &[]).await;
        assert_eq!(status, StatusCode::OK, "a rename moves no credential: {resp}");
    }

    for bearer in [EXPORTER_CONSOLE, OWNER_CONSOLE] {
        let patch = json!({ "ssh": { "host": format!("{bearer}.example") } });
        let (status, resp) = send_as(&app, bearer, "PATCH", "/v1/connections/ssh_prod", Some(patch), &[]).await;
        assert_eq!(status, StatusCode::ACCEPTED, "an Export holder's retarget is held for a device: {resp}");
    }
}

/// With no device paired to a hosted worker, a credential repoint is refused outright rather than applied on the bearer.
#[tokio::test]
async fn an_unpaired_hosted_worker_refuses_a_credential_repoint() {
    let (state, app) = hosted_gateway().await;
    put_console_session(&state, OWNER_CONSOLE, OWNER_SUB, None);
    assert!(!state.service.any_device_trusted());
    let before = ssh_hosts(&state);
    let body: Value = serde_json::from_str(RETARGET).unwrap();
    let (status, resp) = send_as(&app, OWNER_CONSOLE, "PATCH", "/v1/connections/ssh_prod", Some(body), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("no device is paired"), "{resp}");
    assert_eq!(ssh_hosts(&state), before, "nothing moved");
}

/// An admin's vault export is not confirmed by the admin's own phone.
#[tokio::test]
async fn an_admins_own_phone_cannot_confirm_their_vault_export() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-sod-6").await;
    let (status, held) =
        send_as(&app, ADMIN_CONSOLE, "POST", "/v1/vault/export", Some(json!({ "passphrase": "correct horse battery" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();
    let (status, resp) = co_sign(&app, approval_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    let (status, resp) = co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
}

/// The single-person escape: a solo owner's own phone still confirms the owner's change, because nobody
/// else could.
#[tokio::test]
async fn a_solo_owners_own_phone_still_confirms_their_change() {
    let (state, app) = hosted_gateway().await;
    let phone = device_key(133);
    let t = mint_ticket(pair_claims_by("tkt-sod-7", "device:owner-phone", &phone, Some(OWNER_SUB), Some("owner")));
    assert_eq!(pair(&app, pair_body("device:owner-phone", &phone), Some(&t)).await.0, StatusCode::OK);
    put_console_session(&state, OWNER_CONSOLE, OWNER_SUB, None);
    let (status, held) = send_as(&app, OWNER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_solo")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:owner-phone", &phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has_policy(&state, "p_solo"));
}

/// A key paired before keys named a person cannot show it is not the requester's, so while a key bound
/// to someone else is trusted, it does not confirm a named member's change; the bound key does.
#[tokio::test]
async fn an_unbound_key_defers_to_a_key_bound_to_someone_else() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-sod-8").await;
    let legacy = device_key(134);
    assert!(state.service.trust_approver_key("device:legacy", &pubkey_of(&legacy)), "setup: a key bound to nobody");
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_legacy")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();
    let (status, resp) = co_sign(&app, approval_id, "device:legacy", &legacy).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("paired to nobody in particular"), "{resp}");
    let (status, resp) = co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
}

// ── Separation of duty survives revoking the people who could confirm ─────────────────

/// A revoke ticket for `approver_id` from `actor`, with `role` as the web stamps it in `act_role`.
fn revoke_claims_by(jti: &str, approver_id: &str, actor: &str, role: Option<&str>) -> Value {
    let mut claims = revoke_claims(jti, approver_id);
    claims["act_sub"] = json!(actor);
    if let Some(role) = role {
        claims["act_role"] = json!(role);
    }
    claims
}

async fn revoke_as(app: &axum::Router, jti: &str, approver_id: &str, actor: &str, role: Option<&str>) -> (StatusCode, Value) {
    revoke_key(app, approver_id, Some(&mint_ticket(revoke_claims_by(jti, approver_id, actor, role)))).await
}

const EXPORT_PASSPHRASE: &str = "correct horse battery";

/// An admin's export request, answered with its hold.
async fn admin_export(app: &axum::Router) -> Value {
    let (status, held) =
        send_as(app, ADMIN_CONSOLE, "POST", "/v1/vault/export", Some(json!({ "passphrase": EXPORT_PASSPHRASE })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    held
}

async fn collect_export(app: &axum::Router, held: &Value) -> (StatusCode, Value) {
    let body = json!({
        "passphrase": EXPORT_PASSPHRASE,
        "approval_id": held["approval_id"],
        "resume_secret": held["resume_secret"],
    });
    send_as(app, ADMIN_CONSOLE, "POST", "/v1/vault/export", Some(body), &[]).await
}

fn approval_row(state: &AppState, approval_id: &str) -> PendingApproval {
    state.service.store().get_approval(approval_id).unwrap().expect("the hold")
}

/// The attack's two steps: an admin whose phone is refused for their own export revokes the owner's phone
/// and confirms on their own. The revocation of somebody else's device waits for a device of somebody other
/// than the admin, the admin's phone confirms neither it nor the export, and the owner's phone confirms both.
#[tokio::test]
async fn a_manager_cannot_revoke_the_owners_phone_to_confirm_their_own_export() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-opr65-1").await;
    let export = admin_export(&app).await;
    let export_id = export["approval_id"].as_str().unwrap();
    let (status, resp) = co_sign(&app, export_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");

    let (status, held) = revoke_as(&app, "tkt-opr65-1r", "device:owner-phone", ACTOR_SUB, Some("admin")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the owner's phone is not the admin's to remove at once: {held}");
    assert!(trusted(&state, "device:owner-phone"), "nothing was revoked yet");
    let revocation_id = held["approval_id"].as_str().expect("a held revocation names its approval");
    let record = pairing_audit(&app).await.pop().expect("the held revocation is recorded");
    assert_eq!(record["payload"]["decision"], "requires_approval", "{record}");
    assert_eq!(record["payload"]["summary"]["approval_id"], revocation_id, "{record}");
    assert_eq!(record["payload"]["summary"]["actor_sub"], ACTOR_SUB, "{record}");

    let (status, resp) = co_sign(&app, export_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    let (status, resp) = co_sign(&app, revocation_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    assert!(trusted(&state, "device:owner-phone"));
    assert_eq!(approval_row(&state, export_id).status, "pending");

    let (status, resp) = co_sign(&app, export_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "the owner confirms the export: {resp}");
    let (status, bundle) = collect_export(&app, &export).await;
    assert_eq!(status, StatusCode::OK, "{bundle}");
    assert_eq!(bundle["format"], permaura_core::BUNDLE_FORMAT);
    let (status, resp) = co_sign(&app, revocation_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "the device being removed may consent to it: {resp}");
    assert!(!trusted(&state, "device:owner-phone"));
}

/// The record half: a device that was independent of the requester when they asked, and is revoked before
/// anyone confirms, does not make the requester's own device enough. Here the owner removes their own phone,
/// which applies at once; the hold says so, and asking again holds a new export the keyring as it is now decides.
#[tokio::test]
async fn a_device_revoked_after_the_request_does_not_lower_what_confirming_it_takes() {
    let (state, app) = hosted_gateway().await;
    let (_owner_phone, member_phone) = team(&state, &app, "tkt-opr65-2").await;
    let export = admin_export(&app).await;
    let export_id = export["approval_id"].as_str().unwrap();

    let (status, resp) = revoke_as(&app, "tkt-opr65-2r", "device:owner-phone", OWNER_SUB, None).await;
    assert_eq!(status, StatusCode::OK, "the owner's own revocation applies at once: {resp}");
    assert!(!trusted(&state, "device:owner-phone"));

    let (status, resp) = co_sign(&app, export_id, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    let err = resp["error"].as_str().unwrap_or_default();
    assert!(err.contains("has since been revoked") && err.contains("Ask for it again"), "{resp}");
    assert_eq!(approval_row(&state, export_id).status, "pending");
    assert_eq!(collect_export(&app, &export).await.0, StatusCode::BAD_REQUEST, "nothing to collect");

    let again = admin_export(&app).await;
    assert_ne!(again["approval_id"], export["approval_id"]);
    let (status, resp) = co_sign(&app, again["approval_id"].as_str().unwrap(), "device:member-phone", &member_phone).await;
    assert_eq!(status, StatusCode::OK, "nobody else's device is trusted now, so the admin's confirms it: {resp}");
    assert_eq!(collect_export(&app, &again).await.0, StatusCode::OK);
}

/// A held change can only be asked for once while it waits, so a stranded one is retired when it is asked
/// for again, rather than answered with a hold nobody can sign.
#[tokio::test]
async fn a_stranded_change_is_held_afresh_when_it_is_asked_for_again() {
    let (state, app) = hosted_gateway().await;
    let (_owner_phone, member_phone) = team(&state, &app, "tkt-opr65-3").await;
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_stranded")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let first = held["approval_id"].as_str().unwrap().to_string();
    assert_eq!(revoke_as(&app, "tkt-opr65-3r", "device:owner-phone", OWNER_SUB, None).await.0, StatusCode::OK);

    let (status, resp) = co_sign(&app, &first, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "{status}: {resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("has since been revoked"), "{resp}");
    assert!(!has_policy(&state, "p_stranded"));

    let (status, held) = send_as(&app, MEMBER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_stranded")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let second = held["approval_id"].as_str().unwrap().to_string();
    assert_ne!(second, first, "the stranded hold is not the answer");
    let retired = approval_row(&state, &first);
    assert_eq!((retired.status.as_str(), retired.resolution_reason.as_deref()), ("denied", Some("independence_revoked")));
    let (status, resp) = co_sign(&app, &second, "device:member-phone", &member_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has_policy(&state, "p_stranded"));
}

/// Taking the devices away one at a time ends the same way: an admin removes their own phone at once, and
/// the owner's phone, the last one, waits for a device, so an export is still held for it.
#[tokio::test]
async fn a_manager_cannot_empty_the_keyring_of_other_peoples_devices_at_once() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-opr65-4").await;
    let (status, resp) = revoke_as(&app, "tkt-opr65-4a", "device:member-phone", ACTOR_SUB, Some("admin")).await;
    assert_eq!(status, StatusCode::OK, "the admin's own phone goes at once: {resp}");
    let (status, held) = revoke_as(&app, "tkt-opr65-4b", "device:owner-phone", ACTOR_SUB, Some("admin")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert!(state.service.any_device_trusted(), "the owner's phone is still trusted");
    assert!(held["action_description"].as_str().unwrap_or_default().contains("the last trusted device"), "{held}");
    admin_export(&app).await;
}

/// A key paired before keys named a person is not shown to be the actor's, so a manager's removal of it waits too.
#[tokio::test]
async fn a_manager_cannot_remove_a_key_bound_to_nobody_at_once() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-opr65-5").await;
    assert!(state.service.trust_approver_key("device:legacy", &pubkey_of(&device_key(168))));
    let (status, held) = revoke_as(&app, "tkt-opr65-5r", "device:legacy", ACTOR_SUB, Some("admin")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert!(trusted(&state, "device:legacy"));
    assert!(held["action_description"].as_str().unwrap_or_default().ends_with("from the trusted devices, so it can no longer approve anything"), "{held}");
}

/// A control: the owner removes a member's phone at once.
#[tokio::test]
async fn the_owner_still_revokes_a_members_phone_at_once() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-opr65-6").await;
    let (status, resp) = revoke_as(&app, "tkt-opr65-6a", "device:member-phone", OWNER_SUB, None).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(!trusted(&state, "device:member-phone"));
}

/// A control: a member removes their own phone at once.
#[tokio::test]
async fn a_member_still_revokes_their_own_phone_at_once() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-opr65-7").await;
    let (status, resp) = revoke_as(&app, "tkt-opr65-7a", "device:member-phone", ACTOR_SUB, None).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(!trusted(&state, "device:member-phone"));
    assert!(trusted(&state, "device:owner-phone"));
}

// ── The floor on a hosted worker no device is trusted on ──────────────────────────────

/// The floor read back from `/v1/devices`: the effective floor, the stored override, and whether it is an explicit opt-down.
async fn devices_floor(app: &axum::Router) -> (Value, Value, Value) {
    let (status, body) = send(app, "GET", "/v1/devices", None, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (body["approval_floor"].clone(), body["approval_floor_override"].clone(), body["approvals_opted_down"].clone())
}

/// A default member's ticket, and one naming nobody, cannot lower the floor of a worker no device is
/// trusted on: it would apply on the ticket alone and outlive the owner's next pairing.
#[tokio::test]
async fn a_member_cannot_lower_the_floor_while_no_device_is_trusted() {
    let (state, app) = hosted_gateway().await;
    for (jti, claims) in [
        ("tkt-hf-1a", floor_claims("tkt-hf-1a")),
        ("tkt-hf-1b", floor_claims_by("tkt-hf-1b", ACTOR_SUB, Some("member"))),
        ("tkt-hf-1c", {
            let mut c = floor_claims("tkt-hf-1c");
            c.as_object_mut().unwrap().remove("act_sub");
            c
        }),
    ] {
        let (status, resp) = put_floor(&app, "approve", Some(&mint_ticket(claims))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{jti}: {resp}");
        assert!(resp["error"].as_str().unwrap_or_default().contains("owner or admin"), "{resp}");
    }
    assert_eq!(state.service.stored_approval_floor(), None, "nothing was stored");
    assert_eq!(devices_floor(&app).await.2, false);
    let refusal = pairing_audit(&app).await.pop().expect("the refusal is recorded");
    assert_eq!(refusal["payload"]["decision"], "deny", "{refusal}");
    assert_eq!(refusal["payload"]["summary"]["approver_id"], "approval-floor", "{refusal}");
}

/// The owner's own ticket and an organization owner's or admin's still apply it, the opt-down is
/// visible in `/v1/devices` where the effective floor alone cannot show it, and the audit row records
/// the stored values rather than `approve` to `approve`.
#[tokio::test]
async fn an_owner_or_admin_may_opt_down_and_every_read_says_so() {
    for (jti, actor, role) in [("tkt-hf-2a", OWNER_SUB, None), ("tkt-hf-2b", ACTOR_SUB, Some("admin")), ("tkt-hf-2c", ACTOR_SUB, Some("owner"))] {
        let (state, app) = hosted_gateway().await;
        assert_eq!(devices_floor(&app).await, (json!("approve"), Value::Null, json!(false)), "the untouched default");
        let (status, resp) = put_floor(&app, "approve", Some(&mint_ticket(floor_claims_by(jti, actor, role)))).await;
        assert_eq!(status, StatusCode::OK, "{jti}: {resp}");
        assert_eq!(resp["approvals_opted_down"], true, "{resp}");
        assert_eq!(state.service.stored_approval_floor(), Some(permaura_gateway::service::ApprovalFloor::Approve));
        assert_eq!(devices_floor(&app).await, (json!("approve"), json!("approve"), json!(true)), "{jti}: the explicit opt-down is visible");
        let record = floor_records(&app).await.pop().expect("the opt-down is recorded");
        let summary = &record["payload"]["summary"];
        assert_eq!((summary["from"].as_str(), summary["to"].as_str()), (Some("default"), Some("approve")), "{summary}");
        assert_eq!(summary["effective"], "approve", "{summary}");
    }
}

/// An opt-down written while no device was trusted does not survive the next first pairing,
/// so the owner's device arms the holds a gateway nobody touched would have. The reproduction:
/// after the opt-down and an admin's pairing, a remote agent registration is held (202)
/// rather than applied (201).
#[tokio::test]
async fn an_opt_down_written_with_no_device_trusted_does_not_survive_the_first_pairing() {
    let (state, app) = hosted_gateway().await;
    let (status, resp) = put_floor(&app, "approve", Some(&mint_ticket(floor_claims_by("tkt-hf-3a", ACTOR_SUB, Some("admin"))))).await;
    assert_eq!(status, StatusCode::OK, "setup: {resp}");
    let sk = device_key(140);
    pair_ok(&app, "tkt-hf-3b", "device:admins-phone", &sk).await;
    assert_eq!(state.service.stored_approval_floor(), None, "the unanchored opt-down was cleared");
    assert_eq!(devices_floor(&app).await.2, false);
    let record = floor_records(&app).await.pop().expect("the clearing is recorded");
    let summary = &record["payload"]["summary"];
    assert_eq!((summary["from"].as_str(), summary["to"].as_str()), (Some("approve"), Some("default")), "{summary}");

    let (status, held) = send(&app, "POST", "/v1/agents/register", Some(json!({ "name": "after-pairing" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the device holds are armed: {held}");
}

/// The control: an opt-down a trusted device confirmed is not cleared by pairing another device.
#[tokio::test]
async fn an_opt_down_a_device_confirmed_survives_a_later_pairing() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(141);
    pair_ok(&app, "tkt-hf-4a", "device:first", &sk).await;
    let (status, held) = put_floor(&app, "approve", Some(&mint_ticket(floor_claims("tkt-hf-4b")))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:first", &sk).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(state.service.stored_approval_floor(), Some(permaura_gateway::service::ApprovalFloor::Approve));
    let second = device_key(142);
    pair_held_for(&app, "tkt-hf-4c", "device:second", &second, ACTOR_SUB, ("device:first", &sk)).await;
    assert_eq!(state.service.stored_approval_floor(), Some(permaura_gateway::service::ApprovalFloor::Approve));
}

// ── A two-person rule taken out of force keeps its mark ───────────────────────────────

/// A two-person rule on `generic_http`'s `request` for every agent, as an owner would set one.
fn two_person_rule(state: &AppState) {
    let store = state.service.store();
    store
        .put_policy(permaura_core::Policy {
            id: "p_2p".into(),
            connection_id: "generic_http".into(),
            name: "Two people".into(),
            allow: vec![],
            deny: vec![],
            requires_approval: vec![],
            notify: vec![],
            device_signed: vec!["request".into()],
            device_signed_quorum: 2,
            redact_fields: Vec::new(),
        })
        .unwrap();
    store
        .put_grant(permaura_core::Grant {
            grant_id: "g_2p".into(),
            name: "Two people".into(),
            enabled: true,
            is_default: false,
            policy_ids: vec!["p_2p".into()],
            agents: permaura_core::GrantAgents::AllAgents,
            period: permaura_core::GrantPeriod::Total,
            overall_limit: None,
            default_per_agent_limit: None,
            expires_at: None,
        })
        .unwrap();
}

/// `p_2p` with `request` on one list, as the console sends it.
fn p_2p(list: &str) -> Value {
    json!({ "connection_id": "generic_http", "name": "Two people", list: ["request"] })
}

/// The probe's split loosening: moving the action to deny tightens and applies, and putting it back at
/// auto needs the two people the rule took, not one. The member's phone may be one of them; the hold
/// completes when the owner's signs. A change signed at the mark clears it.
#[tokio::test]
async fn a_two_person_rule_split_into_deny_and_re_permit_still_needs_two_people() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-hw-1").await;
    two_person_rule(&state);

    let (status, resp) = send_as(&app, MEMBER_CONSOLE, "PUT", "/v1/policies/p_2p", Some(p_2p("deny")), &[]).await;
    assert_eq!(status, StatusCode::OK, "step one tightens and applies: {resp}");
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "PUT", "/v1/policies/p_2p", Some(p_2p("allow")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["required_signatures"], 2, "step two takes the rule's two people: {held}");
    let approval_id = held["approval_id"].as_str().unwrap();

    let (status, resp) = co_sign(&app, approval_id, "device:member-phone", &member_phone).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the member may be one of the two: {resp}");
    let (status, resp) = co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(state.service.store().get_policy("p_2p").unwrap().unwrap().allow.contains(&"request".to_string()));

    let (status, resp) = send_as(&app, MEMBER_CONSOLE, "PUT", "/v1/policies/p_2p", Some(p_2p("deny")), &[]).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "PUT", "/v1/policies/p_2p", Some(p_2p("allow")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["required_signatures"], 1, "the change two people signed cleared the mark: {held}");
}

/// The same split through grants: disabling the grant that carries the rule tightens, and binding a lax
/// policy through a new grant needs the rule's two people.
#[tokio::test]
async fn a_two_person_rule_split_through_a_new_grant_still_needs_two_people() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-hw-2").await;
    two_person_rule(&state);
    let (status, resp) = send_as(&app, MEMBER_CONSOLE, "PATCH", "/v1/grants/g_2p", Some(json!({ "enabled": false })), &[]).await;
    assert_eq!(status, StatusCode::OK, "disabling the grant tightens: {resp}");
    state
        .service
        .store()
        .put_policy(permaura_core::Policy {
            id: "p_lax".into(),
            connection_id: "generic_http".into(),
            name: "Lax".into(),
            allow: vec!["request".into()],
            deny: vec![],
            requires_approval: vec![],
            notify: vec![],
            device_signed: vec![],
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        })
        .unwrap();
    let grant = json!({ "grant_id": "g_lax", "name": "Lax", "policy_ids": ["p_lax"], "all_agents": true });
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "POST", "/v1/grants", Some(grant), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["required_signatures"], 2, "{held}");
}

/// Lowering the floor switches every device hold off, so it needs the highest quorum in force.
#[tokio::test]
async fn a_floor_lowering_needs_the_highest_quorum_in_force() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-hw-3").await;
    two_person_rule(&state);
    state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::DeviceSigned)).unwrap();
    let (status, held) = put_floor(&app, "approve", Some(&mint_ticket(floor_claims("tkt-hw-3f")))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["required_signatures"], 2, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();
    assert_eq!(co_sign(&app, approval_id, "device:member-phone", &member_phone).await.0, StatusCode::ACCEPTED);
    assert!(state.service.require_device_signed_approval(), "one person did not lower it");
    assert_eq!(co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await.0, StatusCode::OK);
    assert!(!state.service.require_device_signed_approval());
}

/// The brick escape: on a one-device gateway the floor quorum is capped at the one person the keyring
/// can put behind a hold, so a single owner whose rule asks for two can still lower it and get on.
#[tokio::test]
async fn a_single_owner_on_a_one_device_gateway_is_not_bricked_by_a_two_person_rule() {
    let (state, app) = hosted_gateway().await;
    let phone = device_key(150);
    let t = mint_ticket(pair_claims_by("tkt-hw-4", "device:owner-phone", &phone, Some(OWNER_SUB), Some("owner")));
    assert_eq!(pair(&app, pair_body("device:owner-phone", &phone), Some(&t)).await.0, StatusCode::OK);
    two_person_rule(&state);
    state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::DeviceSigned)).unwrap();
    let floor = mint_ticket(floor_claims_by("tkt-hw-4f", OWNER_SUB, None));
    let (status, held) = put_floor(&app, "approve", Some(&floor)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["required_signatures"], 1, "capped at the people who can sign: {held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:owner-phone", &phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    put_console_session(&state, OWNER_CONSOLE, OWNER_SUB, None);
    let (status, resp) = send_as(&app, OWNER_CONSOLE, "PUT", "/v1/policies/p_2p", Some(p_2p("allow")), &[]).await;
    assert_eq!(status, StatusCode::OK, "with the floor down the owner edits the rule: {resp}");
}

// ── A key under an existing approver id is replaced by its person or a manager ────────────────

/// A member cannot pair a key of their own under the owner's approver id: it would retire the owner's
/// key as a revocation does, and repeated per device leave the member the only approver.
#[tokio::test]
async fn a_member_cannot_replace_the_owners_key_under_the_owners_id() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-rk-1").await;
    let intruder = device_key(160);
    let t = mint_ticket(pair_claims_by("tkt-rk-1x", "device:owner-phone", &intruder, Some(ACTOR_SUB), None));
    let (status, resp) = pair(&app, pair_body("device:owner-phone", &intruder), Some(&t)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("not yours to replace"), "{resp}");
    assert_eq!(
        state.service.approver_keyring_snapshot().trusted_key("device:owner-phone"),
        Some(pubkey_of(&owner_phone).as_str()),
        "the owner's key is still the one trusted"
    );
    let refusal = pairing_audit(&app).await.pop().expect("the refusal is recorded");
    assert_eq!(refusal["payload"]["decision"], "deny", "{refusal}");
}

/// Each person replaces their own key, held for a device of someone else's.
#[tokio::test]
async fn a_member_and_the_owner_each_replace_their_own_key() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-rk-2").await;
    let member_new = device_key(161);
    let t = mint_ticket(pair_claims_by("tkt-rk-2m", "device:member-phone", &member_new, Some(ACTOR_SUB), None));
    let (status, held) = pair(&app, pair_body("device:member-phone", &member_new), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(state.service.approver_keyring_snapshot().trusted_key("device:member-phone"), Some(pubkey_of(&member_new).as_str()));

    let owner_new = device_key(162);
    let t = mint_ticket(pair_claims_by("tkt-rk-2o", "device:owner-phone", &owner_new, Some(OWNER_SUB), None));
    let (status, held) = pair(&app, pair_body("device:owner-phone", &owner_new), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:member-phone", &member_new).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(state.service.approver_keyring_snapshot().trusted_key("device:owner-phone"), Some(pubkey_of(&owner_new).as_str()));
}

/// An organization owner or admin may replace another person's key, held as before.
#[tokio::test]
async fn a_manager_may_replace_another_persons_key() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-rk-3").await;
    let replacement = device_key(163);
    let t = mint_ticket(pair_claims_by("tkt-rk-3a", "device:member-phone", &replacement, Some("user_admin"), Some("admin")));
    let (status, held) = pair(&app, pair_body("device:member-phone", &replacement), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
}

/// A key paired before keys named a person belongs to nobody the gateway can name, so only a manager replaces it.
#[tokio::test]
async fn a_key_bound_to_nobody_takes_a_manager_to_replace() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-rk-4").await;
    let legacy = device_key(164);
    assert!(state.service.trust_approver_key("device:legacy", &pubkey_of(&legacy)), "setup: a key bound to nobody");
    let replacement = device_key(165);
    let t = mint_ticket(pair_claims_by("tkt-rk-4m", "device:legacy", &replacement, Some(ACTOR_SUB), None));
    let (status, resp) = pair(&app, pair_body("device:legacy", &replacement), Some(&t)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    let t = mint_ticket(pair_claims_by("tkt-rk-4a", "device:legacy", &replacement, Some(ACTOR_SUB), Some("admin")));
    let (status, held) = pair(&app, pair_body("device:legacy", &replacement), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
}

/// A held replacement retires only the key it was approved to replace: one that took its place since is
/// not retired by the old approval.
#[tokio::test]
async fn a_held_replacement_cannot_retire_a_key_that_took_its_place() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-rk-5").await;
    let member_new = device_key(166);
    let t = mint_ticket(pair_claims_by("tkt-rk-5m", "device:member-phone", &member_new, Some(ACTOR_SUB), None));
    let (status, held) = pair(&app, pair_body("device:member-phone", &member_new), Some(&t)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let since = device_key(167);
    assert!(state.service.trust_approver_key_for("device:member-phone", &pubkey_of(&since), Some(ACTOR_SUB)).unwrap());
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("has changed since"), "{resp}");
    assert_eq!(state.service.approver_keyring_snapshot().trusted_key("device:member-phone"), Some(pubkey_of(&since).as_str()));
}

// ── On a hosted worker: an import filling an existing connection's empty slot ─────────────

/// A bundle carrying nothing but a value for `secret_id`.
fn lone_secret_bundle(secret_id: &str) -> Value {
    let payload = permaura_gateway::vault_bundle::BundlePayload {
        connections: vec![],
        policies: vec![],
        grants: vec![],
        capabilities: vec![],
        secrets: vec![permaura_gateway::vault_bundle::BundleSecret {
            id: secret_id.into(),
            metadata: Default::default(),
            custody: "local".into(),
            value: permaura_gateway::vault_bundle::SecretValue::new(b"synthetic-upstream-token".to_vec()),
        }],
        agents: vec![],
        excluded: Default::default(),
    };
    let bundle = permaura_core::seal_bundle(
        b"correct horse battery staple",
        serde_json::to_value(payload).unwrap(),
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_source".into(), mode: "self-run".into() },
    )
    .unwrap();
    serde_json::to_value(bundle).unwrap()
}

/// The audit reason the newest event for `action` records.
async fn latest_reason(app: &axum::Router, action: &str) -> Option<String> {
    let (_s, audit) = send(app, "GET", "/v1/audit-events?limit=500", None, &[]).await;
    audit["events"]
        .as_array()?
        .iter()
        .rev()
        .find(|e| e["payload"]["action"] == action)
        .and_then(|e| e["payload"]["summary"]["reason"].as_str().map(str::to_string))
}

/// A slot fill does what `POST /v1/secrets` does with the same credential. With no device paired nothing
/// holds either, so both write it (200 for the import, 201 for the create, neither held nor refused) and
/// record why with the same reason; once a device is paired both are held for it.
#[tokio::test]
async fn a_hosted_import_filling_an_empty_slot_does_what_a_secret_write_does() {
    let (state, app) = hosted_gateway().await;
    let store = state.service.store();
    let import = json!({ "bundle": lone_secret_bundle("sec_braintree_prod"), "passphrase": "correct horse battery staple", "on_conflict": "skip" });
    let write = json!({ "id": "sec_braintree_prod", "value": "synthetic-upstream-token" });

    store.delete_secret("sec_braintree_prod").unwrap();
    let (status, body) = send(&app, "POST", "/v1/vault/import", Some(import.clone()), &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(store.get_secret("sec_braintree_prod").unwrap().is_some(), "the slot fill writes it");
    store.delete_secret("sec_braintree_prod").unwrap();
    let (status, body) = send(&app, "POST", "/v1/secrets", Some(write.clone()), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(store.get_secret("sec_braintree_prod").unwrap().is_some(), "so does POST /v1/secrets");
    let import_reason = latest_reason(&app, "permaura.vault.import").await;
    let write_reason = latest_reason(&app, "permaura.secret.write").await;
    assert!(import_reason.is_some(), "the import records why nothing held it");
    assert_eq!(import_reason, write_reason, "one reason for one write");

    pair_ok(&app, "tkt-opr12", "device:alpha", &device_key(170)).await;
    store.delete_secret("sec_braintree_prod").unwrap();
    let (status, body) = send(&app, "POST", "/v1/vault/import", Some(import), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["held"][0]["secret_id"], "sec_braintree_prod", "{body}");
    let (status, body) = send(&app, "POST", "/v1/secrets", Some(write), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(store.get_secret("sec_braintree_prod").unwrap().is_none(), "both are held for the device");
}

// ── On a hosted worker: installing a connector ───────────────────────────────────────

/// A member's lookalike connector. With no device paired there is nothing to hold its install for, so
/// a hosted worker refuses it; once a device is paired it is held for that device.
#[tokio::test]
async fn a_hosted_connector_install_is_refused_unpaired_and_held_paired() {
    let (state, app) = hosted_gateway().await;
    let install = json!({
        "manifest": {
            "id": "paddle-billing",
            "name": "Paddle",
            "logo": "paddle",
            "vertical": "payments",
            "base_url": "https://api.paddle-billing.net",
            "capabilities": [{ "id": "transactions.list", "method": "GET", "path": "/transactions" }]
        },
        "version": 1
    });
    let (status, body) = send(&app, "POST", "/v1/connectors/install", Some(install.clone()), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("no device is paired"), "{body}");
    assert!(state.service.store().get_connector_manifest("paddle-billing").unwrap().is_none());

    pair_ok(&app, "tkt-cross02", "device:alpha", &device_key(180)).await;
    let (status, body) = send(&app, "POST", "/v1/connectors/install", Some(install), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["required_tier"], "device_signed", "{body}");
    assert!(state.service.store().get_connector_manifest("paddle-billing").unwrap().is_none());
}

// ── The new-agent gate on a hosted worker ─────────────────────────────────────────────

/// An MCP client's access token for this worker, as the AS mints it after the owner's consent.
fn hosted_agent_token(azp: &str) -> String {
    mint_ticket(json!({
        "iss": AS_ISSUER, "sub": OWNER_SUB, "aud": format!("{PUBLIC_URL}/mcp"), "azp": azp,
        "iat": now_secs(), "exp": now_secs() + 600, "scope": "openid mcp offline_access", "name": azp,
    }))
}

async fn hosted_agent_status(state: &AppState, app: &axum::Router, azp: &str) -> permaura_gateway::store::AgentStatus {
    let req = Request::builder()
        .method("GET")
        .uri("/v1/capabilities")
        .header("authorization", format!("Bearer {}", hosted_agent_token(azp)))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{azp} connects");
    state.service.store().get_agent(&format!("oauth:{azp}")).unwrap().expect("registered").status
}

/// With no device a hosted worker lands a consenting agent Approved, as before; the first device paired turns the gate on (recorded), and from then on a new agent waits for a decision the device takes.
#[tokio::test]
async fn the_first_device_on_a_hosted_worker_turns_the_new_agent_gate_on() {
    use permaura_gateway::store::AgentStatus;
    let (state, app) = hosted_gateway().await;
    let (_s, broker) = send(&app, "GET", "/v1/broker", None, &[]).await;
    assert_eq!(broker["require_agent_approval"], false, "{broker}");
    assert_eq!(broker["require_agent_approval_source"], "default", "{broker}");
    assert_eq!(hosted_agent_status(&state, &app, "client-gate-early").await, AgentStatus::Approved);

    pair_ok(&app, "tkt-gate", "device:gate", &device_key(71)).await;
    let (_s, broker) = send(&app, "GET", "/v1/broker", None, &[]).await;
    assert_eq!(broker["require_agent_approval"], true, "{broker}");
    assert_eq!(broker["require_agent_approval_source"], "default", "{broker}");
    let (_s, audit) = send(&app, "GET", "/v1/audit-events?limit=200", None, &[]).await;
    let flip = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["payload"]["action"] == "permaura.agent_gate.default")
        .cloned()
        .expect("the flip is in the audit chain");
    assert_eq!(flip["payload"]["summary"]["to"], true, "{flip}");
    assert_eq!(flip["payload"]["summary"]["authority"], "hosted_owner_ticket", "{flip}");

    assert_eq!(hosted_agent_status(&state, &app, "client-gate-late").await, AgentStatus::Pending);
    assert_eq!(hosted_agent_status(&state, &app, "client-gate-early").await, AgentStatus::Approved);
}

/// A hosted worker answers every request as remote, so before a device exists anyone holding a console bearer, the control plane included, can store `false` unheld. The first device paired clears it back to the default and says why.
#[tokio::test]
async fn a_false_stored_remotely_before_the_first_device_is_cleared_by_it() {
    use permaura_gateway::store::AgentStatus;
    let (state, app) = hosted_gateway().await;
    let (status, body) =
        send(&app, "POST", "/v1/broker/require-approval", Some(json!({ "require_agent_approval": false })), &[]).await;
    assert_eq!(status, StatusCode::OK, "no device, nothing to hold it for: {body}");
    let (_s, broker) = send(&app, "GET", "/v1/broker", None, &[]).await;
    assert_eq!(broker["require_agent_approval"], false, "{broker}");
    assert_eq!(broker["require_agent_approval_source"], "stored", "{broker}");

    pair_ok(&app, "tkt-gate-unanchored", "device:gate-unanchored", &device_key(72)).await;
    let (_s, broker) = send(&app, "GET", "/v1/broker", None, &[]).await;
    assert_eq!(broker["require_agent_approval"], true, "{broker}");
    assert_eq!(broker["require_agent_approval_source"], "default", "{broker}");
    assert_ne!(
        state
            .service
            .store()
            .get_meta(permaura_gateway::store::BROKER_REQUIRE_AGENT_APPROVAL_META)
            .unwrap()
            .as_deref(),
        Some("false"),
        "the stored false is gone"
    );
    let (_s, audit) = send(&app, "GET", "/v1/audit-events?limit=200", None, &[]).await;
    let flip = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["payload"]["action"] == "permaura.agent_gate.default")
        .cloned()
        .expect("the clearing is in the audit chain");
    assert_eq!(flip["payload"]["summary"]["cleared_stored_choice"], true, "{flip}");
    assert!(
        flip["payload"]["summary"]["reason"].as_str().unwrap().contains("before any device"),
        "{flip}"
    );
    assert_eq!(hosted_agent_status(&state, &app, "client-gate-after-clear").await, AgentStatus::Pending);
}

// ── A hold made before this gateway recorded who asked ─────────────────────────────

/// The member's held loosening as the release before requesters were recorded left it: the same row, naming nobody, made before this build first started.
async fn a_pre_upgrade_member_hold(state: &AppState, app: &axum::Router, policy: &str) -> String {
    let (status, held) = send_as(app, MEMBER_CONSOLE, "POST", "/v1/policies", Some(widening_policy(policy)), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let id = held["approval_id"].as_str().unwrap().to_string();
    let store = state.service.store();
    let mut row = store.get_approval(&id).unwrap().expect("the held row");
    assert!(row.requested_by.is_some(), "this build records the member");
    row.requested_by = None;
    row.created_at -= 60_000;
    store.put_approval(row).unwrap();
    state.service.note_hold_requesters_recorded_since().unwrap();
    id
}

#[tokio::test]
async fn a_hold_made_before_requesters_were_recorded_is_confirmed_only_by_the_owners_device() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-opr70-1").await;
    let id = a_pre_upgrade_member_hold(&state, &app, "p_legacy").await;

    let (status, resp) = co_sign(&app, &id, "device:member-phone", &member_phone).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    let err = resp["error"].as_str().unwrap_or_default();
    assert!(err.contains("before this gateway recorded who asked"), "the refusal says why: {resp}");
    assert!(err.contains("ask for the change again"), "and what to do: {resp}");
    assert!(!has_policy(&state, "p_legacy"), "the member's phone applied nothing");

    let (status, resp) = co_sign(&app, &id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "the owner's own device confirms it: {resp}");
    assert!(has_policy(&state, "p_legacy"));
}

/// The boundary is the first start of a build that records requesters, so a later restart does not move it past holds made since.
#[tokio::test]
async fn the_requester_boundary_is_set_once() {
    let (state, _app) = hosted_gateway().await;
    state.service.note_hold_requesters_recorded_since().unwrap();
    let first = state.service.store().get_meta(permaura_gateway::store::HOLD_REQUESTERS_RECORDED_SINCE_META).unwrap();
    assert!(first.as_deref().is_some_and(|v| v.parse::<i64>().is_ok()), "{first:?}");
    std::thread::sleep(std::time::Duration::from_millis(5));
    state.service.note_hold_requesters_recorded_since().unwrap();
    let again = state.service.store().get_meta(permaura_gateway::store::HOLD_REQUESTERS_RECORDED_SINCE_META).unwrap();
    assert_eq!(again, first);
}

/// The control: a hold made after the boundary that names nobody (the bearer named no acting member) is confirmed as it always was.
#[tokio::test]
async fn a_hold_naming_nobody_made_after_the_boundary_is_unchanged() {
    let (state, app) = hosted_gateway().await;
    let (_owner_phone, member_phone) = team(&state, &app, "tkt-opr70-3").await;
    state.service.note_hold_requesters_recorded_since().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    put_operator_session(&state, "sess_opr70_nobody", "pgt_opr70_nobody", None);
    let (status, held) = send_as(&app, "pgt_opr70_nobody", "POST", "/v1/policies", Some(widening_policy("p_nobody")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let id = held["approval_id"].as_str().unwrap();
    assert!(state.service.store().get_approval(id).unwrap().unwrap().requested_by.is_none(), "the bearer named nobody");
    let (status, resp) = co_sign(&app, id, "device:member-phone", &member_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has_policy(&state, "p_nobody"));
}

// ── An import moves a stored credential only where a PATCH could ─────────────────────────────

/// Every capability on the seeded `ssh_prod` connection, pinned at `host` and carrying no credential of its own: imported with `replace`, the stored SSH key goes to `host` on the next call.
fn ssh_retarget_bundle(state: &AppState, host: &str) -> Value {
    let store = state.service.store();
    let connection = store.get_connection("ssh_prod").unwrap().expect("the seeded SSH connection");
    let capabilities = connection
        .capabilities
        .iter()
        .filter_map(|id| store.get_capability(id).unwrap())
        .map(|mut cap| {
            cap.ssh.as_mut().expect("an SSH capability").target.host = host.into();
            permaura_gateway::vault_bundle::CapabilityRecord::from(&cap)
        })
        .collect();
    let payload = permaura_gateway::vault_bundle::BundlePayload {
        connections: vec![],
        policies: vec![],
        grants: vec![],
        capabilities,
        secrets: vec![],
        agents: vec![],
        excluded: Default::default(),
    };
    let bundle = permaura_core::seal_bundle(
        b"correct horse battery staple",
        serde_json::to_value(payload).unwrap(),
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_admins_own".into(), mode: "self-run".into() },
    )
    .unwrap();
    serde_json::to_value(bundle).unwrap()
}

fn import_req(bundle: Value, on_conflict: &str) -> Value {
    json!({ "bundle": bundle, "passphrase": "correct horse battery staple", "on_conflict": on_conflict })
}

/// With no device paired to a hosted worker, an import that points the stored SSH key at a host of the bundle's choosing is refused for an admin and for the owner alike, as the same change through PATCH is.
#[tokio::test]
async fn an_unpaired_hosted_worker_refuses_an_import_that_moves_a_stored_credential() {
    let (state, app) = hosted_gateway().await;
    put_console_session(&state, OWNER_CONSOLE, OWNER_SUB, None);
    put_console_session(&state, ADMIN_CONSOLE, ACTOR_SUB, Some("admin"));
    assert!(!state.service.any_device_trusted());
    let before = ssh_hosts(&state);
    let bundle = ssh_retarget_bundle(&state, "collector.attacker.example");
    for bearer in [ADMIN_CONSOLE, OWNER_CONSOLE, seed::DEMO_TOKEN] {
        let (status, resp) = send_as(&app, bearer, "POST", "/v1/vault/import", Some(import_req(bundle.clone(), "replace")), &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{bearer}: {resp}");
        assert!(resp["error"].as_str().unwrap_or_default().contains("no device is paired"), "{resp}");
    }
    assert_eq!(ssh_hosts(&state), before, "nothing moved");
    assert_eq!(
        latest_reason(&app, "permaura.vault.import").await.as_deref(),
        Some("refused on a hosted worker no device is paired to")
    );
    let (status, preview) =
        send_as(&app, ADMIN_CONSOLE, "POST", "/v1/vault/import/preview", Some(import_req(bundle, "replace")), &[]).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(!preview["broker_refusals"].as_array().unwrap().is_empty(), "the preview says so first: {preview}");
}

/// With the floor opted down on a paired worker nothing holds, so as through PATCH a member, an admin without Export or a session naming nobody who may import may still not move a stored credential, while the owner and a signed Export holder apply it.
#[tokio::test]
async fn an_opted_down_hosted_worker_takes_export_standing_to_import_a_credential_move() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-cr02-1").await;
    state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::Approve)).unwrap();
    assert!(!state.service.control_plane_hold_required(true) && !state.service.vault_export_hold_required(), "paired, and nothing holds");
    let before = ssh_hosts(&state);
    let bundle = ssh_retarget_bundle(&state, "collector.attacker.example");
    for bearer in [MEMBER_CONSOLE, ADMIN_CONSOLE, seed::DEMO_TOKEN] {
        let (status, resp) = send_as(&app, bearer, "POST", "/v1/vault/import", Some(import_req(bundle.clone(), "replace")), &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{bearer}: {resp}");
        assert!(resp["error"].as_str().unwrap_or_default().contains("standing a vault export does"), "{resp}");
    }
    assert_eq!(ssh_hosts(&state), before, "nothing moved");
    for bearer in [MEMBER_CONSOLE, ADMIN_CONSOLE] {
        let (status, preview) =
            send_as(&app, bearer, "POST", "/v1/vault/import/preview", Some(import_req(bundle.clone(), "replace")), &[]).await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert!(!preview["broker_refusals"].as_array().unwrap().is_empty(), "{bearer}: {preview}");
    }

    for (bearer, host) in [(EXPORTER_CONSOLE, "admins-host.example"), (OWNER_CONSOLE, "owners-host.example")] {
        let bundle = ssh_retarget_bundle(&state, host);
        let (status, resp) = send_as(&app, bearer, "POST", "/v1/vault/import", Some(import_req(bundle, "replace")), &[]).await;
        assert_eq!(status, StatusCode::OK, "{bearer}: {resp}");
        assert!(ssh_hosts(&state).iter().all(|h| h == host), "{bearer}: {:?}", ssh_hosts(&state));
    }
}

/// The owner's own import that moves a credential keeps the rule it had: refused on a bearer while a device is paired and holds (an import is never held for one), applied once approvals are opted down.
#[tokio::test]
async fn the_owners_import_that_moves_a_credential_keeps_its_rule() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-cr02-2").await;
    let before = ssh_hosts(&state);
    let (status, resp) = send_as(
        &app,
        OWNER_CONSOLE,
        "POST",
        "/v1/vault/import",
        Some(import_req(ssh_retarget_bundle(&state, "owners-host.example"), "replace")),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("a paired device must sign"), "{resp}");
    assert_eq!(ssh_hosts(&state), before);

    state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::Approve)).unwrap();
    let (status, resp) = send_as(
        &app,
        OWNER_CONSOLE,
        "POST",
        "/v1/vault/import",
        Some(import_req(ssh_retarget_bundle(&state, "owners-host.example"), "replace")),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(ssh_hosts(&state).iter().all(|h| h == "owners-host.example"));
}

/// An import that moves no stored credential is untouched by any of this, even for a member on an unpaired worker: the same bundle skipping what is already here, and a credential nothing names yet.
#[tokio::test]
async fn an_import_that_moves_no_credential_is_unchanged() {
    let (state, app) = hosted_gateway().await;
    put_console_session(&state, MEMBER_CONSOLE, ACTOR_SUB, None);
    let before = ssh_hosts(&state);
    let (status, resp) = send_as(
        &app,
        MEMBER_CONSOLE,
        "POST",
        "/v1/vault/import",
        Some(import_req(ssh_retarget_bundle(&state, "collector.attacker.example"), "skip")),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(ssh_hosts(&state), before, "skipped, so nothing moved");
    let (status, resp) =
        send_as(&app, MEMBER_CONSOLE, "POST", "/v1/vault/import", Some(import_req(lone_secret_bundle("sec_cr02_new"), "replace")), &[]).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(state.service.store().get_secret("sec_cr02_new").unwrap().is_some());
}

// ── A held change lapses a day after it was held ─────────────────────────────────

/// Move a held row back in time by `ms`, its deadline with it, as if it had been held that much earlier.
fn age_hold(state: &AppState, approval_id: &str, ms: i64) {
    let store = state.service.store();
    let mut row = store.get_approval(approval_id).unwrap().expect("the hold");
    row.created_at -= ms;
    row.expires_at = row.expires_at.map(|at| at - ms);
    store.put_approval(row).unwrap();
}

/// The audit events filed against `approval_id`.
async fn audit_of(app: &axum::Router, approval_id: &str) -> Vec<Value> {
    let (_s, audit) = send(app, "GET", "/v1/audit-events?limit=200", None, &[]).await;
    audit["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e["payload"]["summary"]["approval_id"] == approval_id)
        .collect()
}

/// The defect: an admin's held removal of the owner's phone waited for ever. It now lapses a day after it was
/// held; past that no device confirms it, the sweep retires it as `expired` and records it, and asking again
/// holds a fresh one that the owner's phone can still confirm.
#[tokio::test]
async fn a_held_revocation_lapses_a_day_after_it_was_held() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-opr97-1").await;
    let (status, held) = revoke_as(&app, "tkt-opr97-1r", "device:owner-phone", ACTOR_SUB, Some("admin")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let id = held["approval_id"].as_str().unwrap().to_string();
    let row = approval_row(&state, &id);
    assert_eq!(row.expires_at, Some(row.created_at + CONTROL_PLANE_HOLD_TTL_MS), "a held revocation is given a day");
    assert_eq!(held["expires_at"], json!(row.expires_at), "and its 202 says when that ends: {held}");

    age_hold(&state, &id, CONTROL_PLANE_HOLD_TTL_MS + 60_000);
    let (status, resp) = co_sign(&app, &id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    let err = resp["error"].as_str().unwrap_or_default();
    assert!(err.contains("expired before anyone confirmed it") && err.contains("ask for the change again"), "{resp}");
    let err = state
        .service
        .resolve_approval(&id, true, "device_signed", Some("device:owner-phone"))
        .await
        .expect_err("past its deadline a held change is not applied by any route");
    assert!(err.to_string().contains("expired"), "{err}");
    assert!(trusted(&state, "device:owner-phone"), "nothing was revoked");

    assert_eq!(state.service.retire_expired_holds(now_ms()).unwrap(), vec![id.clone()]);
    let retired = approval_row(&state, &id);
    assert_eq!((retired.status.as_str(), retired.resolution_reason.as_deref()), (APPROVAL_EXPIRED, Some(APPROVAL_EXPIRED)));
    let records = audit_of(&app, &id).await;
    let ended = records.iter().find(|e| e["payload"]["summary"]["method"] == "expired").expect("the retirement is recorded");
    assert_eq!(ended["payload"]["decision"], "denied", "{ended}");
    assert_eq!(ended["payload"]["action"], "permaura.policy.write", "{ended}");
    assert_eq!(ended["payload"]["summary"]["requested_by"]["person"], ACTOR_SUB, "{ended}");
    assert!(state.service.retire_expired_holds(now_ms()).unwrap().is_empty(), "retired once");
    let (_s, served) = send(&app, "GET", &format!("/v1/approvals/{id}"), None, &[]).await;
    assert_eq!(served["status"], APPROVAL_EXPIRED, "{served}");
    assert!(trusted(&state, "device:owner-phone"));

    let (status, again) = revoke_as(&app, "tkt-opr97-1s", "device:owner-phone", ACTOR_SUB, Some("admin")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "asking again holds afresh: {again}");
    assert_ne!(again["approval_id"], held["approval_id"]);
    let (status, resp) = co_sign(&app, again["approval_id"].as_str().unwrap(), "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(!trusted(&state, "device:owner-phone"));
}

/// The control: inside its day a held revocation is untouched by the sweep and confirmed as before.
#[tokio::test]
async fn a_held_revocation_inside_its_day_is_still_confirmed() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-opr97-2").await;
    let (status, held) = revoke_as(&app, "tkt-opr97-2r", "device:owner-phone", ACTOR_SUB, Some("admin")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let id = held["approval_id"].as_str().unwrap().to_string();
    age_hold(&state, &id, CONTROL_PLANE_HOLD_TTL_MS - 60_000);

    assert!(state.service.retire_expired_holds(now_ms()).unwrap().is_empty());
    assert_eq!(approval_row(&state, &id).status, "pending");
    let (status, resp) = co_sign(&app, &id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(!trusted(&state, "device:owner-phone"));
    assert!(audit_of(&app, &id).await.iter().all(|e| e["payload"]["summary"]["method"] != "expired"));
}

/// A held change an earlier build stored with no deadline lapses a day after it was held too, and is served with
/// that deadline, so the card and the refusal agree. A held agent call stored the same way still never lapses.
#[tokio::test]
async fn a_held_change_stored_without_a_deadline_lapses_a_day_after_it_was_held() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-opr97-3").await;
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_ageless")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let id = held["approval_id"].as_str().unwrap().to_string();
    let store = state.service.store();
    let mut row = store.get_approval(&id).unwrap().unwrap();
    row.expires_at = None;
    store.put_approval(row).unwrap();
    let row = approval_row(&state, &id);
    let (_s, served) = send(&app, "GET", &format!("/v1/approvals/{id}"), None, &[]).await;
    assert_eq!(served["expires_at"], json!(row.created_at + CONTROL_PLANE_HOLD_TTL_MS), "{served}");

    age_hold(&state, &id, CONTROL_PLANE_HOLD_TTL_MS + 60_000);
    let (status, resp) = co_sign(&app, &id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("expired"), "{resp}");
    assert!(!has_policy(&state, "p_ageless"));
    assert_eq!(state.service.retire_expired_holds(now_ms()).unwrap(), vec![id.clone()]);
    assert_eq!(approval_row(&state, &id).status, APPROVAL_EXPIRED);

    seed_two_person_hold(&state, "appr_opr97_agent_call");
    age_hold(&state, "appr_opr97_agent_call", 30 * CONTROL_PLANE_HOLD_TTL_MS);
    let agent_call = approval_row(&state, "appr_opr97_agent_call");
    assert_eq!((agent_call.expires_at, agent_call.deadline()), (None, None), "a held agent call keeps waiting");
    assert!(state.service.retire_expired_holds(now_ms()).unwrap().is_empty());
    assert_eq!(approval_row(&state, "appr_opr97_agent_call").status, "pending");
}

// ── Who asked, as the approval queue shows it ─────────────────────────────────────────────

/// A held change served from the approval routes says who asked as the approver-key list names people, so the requester's own device can recognise its request: the member's held loosening carries the same `person_handle` `GET /v1/approver-keys` lists the member's phone under, and the note says the person who asked cannot confirm it. A held agent call carries no `requested_by` at all.
#[tokio::test]
async fn a_held_change_says_who_asked_by_the_handle_the_key_list_uses() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-opr96-1").await;
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_opr96")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["message"], permaura_gateway::rest::HELD_REQUESTED_NOTE, "{held}");
    assert!(held["message"].as_str().unwrap().starts_with("Approve only if"), "the prefix the phone keys on");
    let id = held["approval_id"].as_str().unwrap().to_string();

    let (_s, keys) = send(&app, "GET", "/v1/approver-keys", None, &[]).await;
    let member_handle = keys["keys"]
        .as_array()
        .or_else(|| keys.as_array())
        .expect("the key list")
        .iter()
        .find(|k| k["approver_id"] == "device:member-phone")
        .map(|k| k["person_handle"].clone())
        .expect("the member's phone is listed");
    assert!(member_handle.is_string(), "{keys}");

    let (_s, one) = send(&app, "GET", &format!("/v1/approvals/{id}"), None, &[]).await;
    assert_eq!(one["requested_by"], json!({ "person_handle": member_handle, "required_independence": "independent" }), "{one}");
    assert!(!one.to_string().contains(ACTOR_SUB), "never the account id: {one}");
    let (_s, list) = send(&app, "GET", "/v1/approvals?status=pending", None, &[]).await;
    let listed = list["approvals"].as_array().or_else(|| list.as_array()).expect("the list").iter().find(|a| a["id"] == id).cloned().expect("listed");
    assert_eq!(listed["requested_by"], one["requested_by"]);

    // All three parts, when the hold records a device too.
    let mut row = approval_row(&state, &id);
    row.requested_by.as_mut().unwrap().device_id = Some("phone-priya".into());
    state.service.store().put_approval(row).unwrap();
    let (_s, one) = send(&app, "GET", &format!("/v1/approvals/{id}"), None, &[]).await;
    assert_eq!(
        one["requested_by"],
        json!({ "person_handle": member_handle, "device_id": "phone-priya", "required_independence": "independent" }),
        "{one}"
    );

    seed_two_person_hold(&state, "appr_opr96_agent_call");
    let (_s, agent_call) = send(&app, "GET", "/v1/approvals/appr_opr96_agent_call", None, &[]).await;
    assert!(agent_call.get("requested_by").is_none(), "{agent_call}");
}

// ── The note under the buttons, by whether the hold records who asked ──────────────────────────

/// The requester note, word for word, since the phone mirrors it: the requester's own device is refused only while a device paired to someone else is trusted, and never the owner's.
#[test]
fn the_requester_note_says_when_the_requesters_own_device_is_refused() {
    assert_eq!(
        permaura_gateway::rest::HELD_REQUESTED_NOTE,
        "Approve only if you know who asked for this change and agree with it. Unless they are the gateway's owner, the person who asked cannot confirm it from their own device while a device paired to someone else is trusted."
    );
    assert!(permaura_gateway::rest::HELD_REMOTE_NOTE.starts_with("Approve only if"));
}

/// For trust-root holds: lowering the floor on a ticket that names the actor carries the requester wording, one on a ticket that names nobody keeps the note that asks whether you made the change. Both texts are pinned because the phone mirrors them.
#[tokio::test]
async fn a_held_trust_root_change_says_who_may_confirm_it_by_whether_it_records_who_asked() {
    assert_eq!(
        permaura_gateway::rest::HELD_TRUST_REQUESTED_NOTE,
        "Approve only if you know who asked for this change and agree with it. It changes what approvals need, so a device you already trust has to confirm it. Unless they are the gateway's owner, the person who asked cannot confirm it from their own device while a device paired to someone else is trusted."
    );
    assert_eq!(
        permaura_gateway::rest::HELD_TRUST_NOTE,
        "Approve only if you made this change. It changes what approvals need, so a device you already trust has to confirm it."
    );
    for (n, names_actor) in [true, false].into_iter().enumerate() {
        let (state, app) = hosted_gateway().await;
        let sk = device_key(245 + n as u8);
        let t = mint_ticket(pair_claims(&format!("tkt-cr06t-{n}a"), "device:alpha", &pubkey_of(&sk)));
        assert_eq!(pair(&app, pair_body("device:alpha", &sk), Some(&t)).await.0, StatusCode::OK);
        state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::DeviceSigned)).unwrap();

        let mut claims = floor_claims(&format!("tkt-cr06t-{n}b"));
        if !names_actor {
            claims.as_object_mut().unwrap().remove("act_sub");
        }
        let (status, held) = put_floor(&app, "approve", Some(&mint_ticket(claims))).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{held}");
        let row = approval_row(&state, held["approval_id"].as_str().unwrap());
        if names_actor {
            assert_eq!(held["message"], permaura_gateway::rest::HELD_TRUST_REQUESTED_NOTE, "the ticket names the actor: {held}");
            assert!(row.requested_by.is_some());
        } else {
            assert_eq!(held["message"], permaura_gateway::rest::HELD_TRUST_NOTE, "the ticket names nobody: {held}");
            assert!(row.requested_by.is_none());
        }
    }
}

/// A remote hold that names nobody keeps the note that asks the approver whether they made the change: only a device of the gateway's owner can confirm such a hold.
#[tokio::test]
async fn a_held_change_that_names_nobody_keeps_the_owners_note() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-opr96-2").await;
    put_operator_session(&state, "sess_opr96_nobody", "pgt_opr96_nobody", None);
    let (status, held) = send_as(&app, "pgt_opr96_nobody", "POST", "/v1/policies", Some(widening_policy("p_opr96_nobody")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["message"], permaura_gateway::rest::HELD_REMOTE_NOTE, "{held}");
    let id = held["approval_id"].as_str().unwrap();
    let (_s, one) = send(&app, "GET", &format!("/v1/approvals/{id}"), None, &[]).await;
    assert!(one.get("requested_by").is_none(), "{one}");
}

// ── The owner's signed device confirms any held change ─────────────────────────────────────

/// The owner can always make a change with their own signed device: the owner's phone confirms the owner's own held change while a member's device is trusted too, and a member's change; a member's phone still cannot confirm the member's own change, and still confirms the owner's.
#[tokio::test]
async fn the_owners_device_confirms_any_held_change_and_nobody_else_is_exempt() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-own-1").await;
    let hold_as = |console: &'static str, policy: &'static str| {
        let app = app.clone();
        async move {
            let (status, held) = send_as(&app, console, "POST", "/v1/policies", Some(widening_policy(policy)), &[]).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{held}");
            held["approval_id"].as_str().unwrap().to_string()
        }
    };

    let owners = hold_as(OWNER_CONSOLE, "p_owners_own").await;
    assert_eq!(approval_row(&state, &owners).requested_by.and_then(|r| r.person).as_deref(), Some(OWNER_SUB));
    let (status, resp) = co_sign(&app, &owners, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "the owner's own change on the owner's own phone: {resp}");
    assert!(has_policy(&state, "p_owners_own"));

    let members = hold_as(MEMBER_CONSOLE, "p_members").await;
    let (status, resp) = co_sign(&app, &members, "device:member-phone", &member_phone).await;
    assert!(is_self_approval_refusal(status, &resp), "a member's own phone is still refused: {status}: {resp}");
    let (status, resp) = co_sign(&app, &members, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has_policy(&state, "p_members"));

    let owners_again = hold_as(OWNER_CONSOLE, "p_owners_again").await;
    let (status, resp) = co_sign(&app, &owners_again, "device:member-phone", &member_phone).await;
    assert_eq!(status, StatusCode::OK, "a member's phone still confirms the owner's change: {resp}");
    assert!(has_policy(&state, "p_owners_again"));
}

/// The exemption is from the requester rule, not from a two-person rule: a held change that takes two people still takes two after the owner's phone signs.
#[tokio::test]
async fn the_owners_device_does_not_lower_a_quorum() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-own-2").await;
    let (status, held) = send_as(&app, OWNER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_two")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let id = held["approval_id"].as_str().unwrap();
    let mut row = approval_row(&state, id);
    row.required_signatures = 2;
    state.service.store().put_approval(row).unwrap();

    let (status, resp) = co_sign(&app, id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::ACCEPTED, "one of two: {resp}");
    assert!(!has_policy(&state, "p_two"));
    let (status, resp) = co_sign(&app, id, "device:member-phone", &member_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has_policy(&state, "p_two"));
}

/// The key list says which keys are the owner's, so a device can tell up front that the requester rule does not apply to it.
#[tokio::test]
async fn the_key_list_marks_the_owners_keys() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-own-3").await;
    let (_s, keys) = send(&app, "GET", "/v1/approver-keys", None, &[]).await;
    let rows = keys["keys"].as_array().or_else(|| keys.as_array()).expect("the key list").clone();
    let is_owner = |id: &str| rows.iter().find(|k| k["approver_id"] == id).map(|k| k["is_owner"].clone());
    assert_eq!(is_owner("device:owner-phone"), Some(json!(true)), "{keys}");
    assert_eq!(is_owner("device:member-phone"), Some(json!(false)), "{keys}");
}

// ── Removing a device alone: an admin action under `device.remove.any` ────────────────────────

/// An `approver-revoke` ticket permaura.com signed `remove_alone: true` for, from `actor` as an admin.
fn remove_alone_claims(jti: &str, approver_id: &str, actor: &str) -> Value {
    let mut claims = revoke_claims_by(jti, approver_id, actor, Some("admin"));
    claims["remove_alone"] = json!(true);
    claims
}

/// A member permaura.com says may remove any device alone removes the owner's phone at once, through either delete route, and the record says it applied under that capability and who did it. Without the claim the same removal waits for a device, as separation of duty holds it.
#[tokio::test]
async fn a_ticket_that_may_remove_alone_removes_anyones_device_at_once_on_both_routes() {
    for (n, route) in ["/v1/approver-keys", "/v1/devices"].into_iter().enumerate() {
        let (state, app) = hosted_gateway().await;
        team(&state, &app, &format!("tkt-ra-{n}")).await;
        let held = mint_ticket(revoke_claims_by(&format!("tkt-ra-{n}-held"), "device:owner-phone", ACTOR_SUB, Some("admin")));
        let (status, body) = send(&app, "DELETE", &format!("{route}/device:owner-phone"), None, &[(PAIR_TICKET_HEADER, &held)]).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{route}, no claim: {body}");
        assert!(trusted(&state, "device:owner-phone"), "{route}");

        let alone = mint_ticket(remove_alone_claims(&format!("tkt-ra-{n}-alone"), "device:owner-phone", ACTOR_SUB));
        let (status, body) = send(&app, "DELETE", &format!("{route}/device:owner-phone"), None, &[(PAIR_TICKET_HEADER, &alone)]).await;
        assert_eq!(status, StatusCode::OK, "{route}: {body}");
        assert!(!trusted(&state, "device:owner-phone"), "{route}");
        let record = pairing_audit(&app).await.pop().expect("the removal is recorded");
        assert_eq!(record["payload"]["decision"], "deny", "{record}");
        assert_eq!(record["payload"]["summary"]["remove_alone"], true, "{record}");
        assert_eq!(record["payload"]["summary"]["capability"], "device.remove.any", "{record}");
        assert_eq!(record["payload"]["summary"]["actor_sub"], ACTOR_SUB, "{record}");
    }
}

/// The claim counts only under the AS's signature: the same claim added to a valid ticket's payload, or on a ticket signed with another key, is refused with the ticket, and nothing is removed.
#[tokio::test]
async fn a_forged_remove_alone_claim_is_ignored() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-ra-forged").await;
    let valid = mint_ticket(revoke_claims_by("tkt-ra-forged-a", "device:owner-phone", ACTOR_SUB, Some("admin")));
    let parts: Vec<&str> = valid.split('.').collect();
    let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    claims["remove_alone"] = json!(true);
    let tampered = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes()), parts[2]);

    let wrong_key = {
        let claims = remove_alone_claims("tkt-ra-forged-b", "device:owner-phone", ACTOR_SUB);
        let header = json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
            URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes())
        );
        let sig = device_key(222).sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    };
    for forged in [tampered, wrong_key] {
        let (status, body) = send(&app, "DELETE", "/v1/approver-keys/device:owner-phone", None, &[(PAIR_TICKET_HEADER, &forged)]).await;
        assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN, "{status}: {body}");
        assert!(trusted(&state, "device:owner-phone"));
    }
}

// ── A collect where no export is held ────────────────────────────────────────────────────────

/// An export request that names an approval to collect, on a worker that holds no export for it.
fn invented_collects() -> [Value; 3] {
    [
        json!({ "passphrase": EXPORT_PASSPHRASE, "approval_id": "appr_invented", "resume_secret": "invented" }),
        json!({ "passphrase": EXPORT_PASSPHRASE, "approval_id": "appr_invented" }),
        json!({ "passphrase": EXPORT_PASSPHRASE, "resume_secret": "invented" }),
    ]
}

/// Each invented collect is refused with a 400 that says to ask again, and no bundle; a plain export is still served.
async fn refuses_invented_collects_but_serves_an_export(app: &axum::Router) {
    for body in invented_collects() {
        let (status, resp) = send_as(app, ADMIN_CONSOLE, "POST", "/v1/vault/export", Some(body.clone()), &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {resp}");
        let error = resp["error"].as_str().unwrap_or_default();
        assert!(error.contains("holds no export to collect") && error.contains("send a new export request"), "{resp}");
        assert!(resp.get("format").is_none(), "no bundle: {resp}");
    }
    let (status, bundle) = send_as(app, ADMIN_CONSOLE, "POST", "/v1/vault/export", Some(json!({ "passphrase": EXPORT_PASSPHRASE })), &[]).await;
    assert_eq!(status, StatusCode::OK, "{bundle}");
    assert_eq!(bundle["format"], permaura_core::BUNDLE_FORMAT);
}

/// The attack: on a hosted worker no device is trusted on, an export carrying an invented `approval_id` or `resume_secret` had those fields ignored and was answered with the whole vault, so the proxy's collect exemption skipped the fresh step-up. It is refused now.
#[tokio::test]
async fn an_unpaired_hosted_worker_refuses_a_collect_it_holds_nothing_for() {
    let (state, app) = hosted_gateway().await;
    put_console_session(&state, ADMIN_CONSOLE, ACTOR_SUB, Some("admin"));
    assert!(!state.service.vault_export_hold_required());
    refuses_invented_collects_but_serves_an_export(&app).await;
}

/// The same with a device paired and approvals opted down, which also holds nothing.
#[tokio::test]
async fn an_opted_down_worker_refuses_a_collect_it_holds_nothing_for() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-cr09-2").await;
    state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::Approve)).unwrap();
    assert!(!state.service.vault_export_hold_required());
    refuses_invented_collects_but_serves_an_export(&app).await;
}

/// A named collect is resolved against its hold even when no hold would be required now. An export held while a device was trusted, whose last device then went away before anyone confirmed it, is refused with a 400 that asks for a new request, rather than collected on the step-up alone; the new request is served.
#[tokio::test]
async fn a_hold_that_lapsed_with_the_last_device_is_not_collected() {
    let (state, app) = hosted_gateway().await;
    team(&state, &app, "tkt-cr09-4").await;
    let held = admin_export(&app).await;
    for (n, device) in ["device:member-phone", "device:owner-phone"].into_iter().enumerate() {
        let (status, resp) = revoke_as(&app, &format!("tkt-cr09-4r{n}"), device, OWNER_SUB, None).await;
        assert_eq!(status, StatusCode::OK, "{device}: {resp}");
    }
    assert!(!state.service.vault_export_hold_required(), "no device is left to hold an export");
    let (status, resp) = collect_export(&app, &held).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    let error = resp["error"].as_str().unwrap_or_default();
    assert!(error.contains("no longer trusted") && error.contains("send a new export request"), "{resp}");
    assert!(resp.get("format").is_none(), "no bundle: {resp}");
    let (status, bundle) = send_as(&app, ADMIN_CONSOLE, "POST", "/v1/vault/export", Some(json!({ "passphrase": EXPORT_PASSPHRASE })), &[]).await;
    assert_eq!(status, StatusCode::OK, "the new request is served: {bundle}");
    assert_eq!(bundle["format"], permaura_core::BUNDLE_FORMAT);
}

/// The control: where an export is held, the real collect is unchanged.
#[tokio::test]
async fn a_held_export_is_still_collected() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-cr09-3").await;
    let held = admin_export(&app).await;
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let (status, bundle) = collect_export(&app, &held).await;
    assert_eq!(status, StatusCode::OK, "{bundle}");
    assert_eq!(bundle["format"], permaura_core::BUNDLE_FORMAT);
}

// ── An approver id of the form user:<account> ────────────────────────────────────────────────

/// Only the named account pairs a key under `user:<account>`: an admin's first pairing on an empty worker under `user:<owner>` and a member's beside the owner's phone are refused before anything is trusted or held, while the owner's own is accepted.
#[tokio::test]
async fn only_the_named_account_pairs_under_a_user_id() {
    let (state, app) = hosted_gateway().await;
    let sk = device_key(240);
    let id = format!("user:{OWNER_SUB}");
    let t = mint_ticket(pair_claims_by("tkt-cr10-1", &id, &sk, Some(ACTOR_SUB), Some("admin")));
    let (status, resp) = pair(&app, pair_body(&id, &sk), Some(&t)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("user:<account>"), "{resp}");
    assert!(!state.service.any_device_trusted(), "the empty worker stays empty");

    team(&state, &app, "tkt-cr10-2").await;
    let t = mint_ticket(pair_claims_by("tkt-cr10-3", &id, &sk, Some(ACTOR_SUB), None));
    let (status, resp) = pair(&app, pair_body(&id, &sk), Some(&t)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(!trusted(&state, &id));
    let pending = state.service.store().list_approvals(Some("pending")).unwrap();
    assert!(pending.iter().all(|a| !a.params.to_string().contains(&id)), "nothing was held for it");

    let t = mint_ticket(pair_claims_by("tkt-cr10-4", &id, &sk, Some(OWNER_SUB), Some("owner")));
    let (status, resp) = pair(&app, pair_body(&id, &sk), Some(&t)).await;
    assert!(status == StatusCode::OK || status == StatusCode::ACCEPTED, "the owner names themselves: {status}: {resp}");
}

/// An entry under `user:<owner>` the owner never bound (seeded straight into the keyring, as an earlier build let a member pair it) is not the owner's device: no `is_owner`, and it cannot confirm an admin's own held change, which the owner's bound phone still can.
#[tokio::test]
async fn an_unbound_user_id_is_never_the_owners_device() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, _member_phone) = team(&state, &app, "tkt-cr10-5").await;
    let forged = device_key(241);
    let id = format!("user:{OWNER_SUB}");
    assert!(state.service.trust_approver_key(&id, &pubkey_of(&forged)));

    let (_s, keys) = send(&app, "GET", "/v1/approver-keys", None, &[]).await;
    let rows = keys["keys"].as_array().or_else(|| keys.as_array()).expect("the key list").clone();
    let is_owner = |approver: &str| rows.iter().find(|k| k["approver_id"] == approver).map(|k| k["is_owner"].clone());
    assert_eq!(is_owner(&id), Some(json!(false)), "{keys}");
    assert_eq!(is_owner("device:owner-phone"), Some(json!(true)), "{keys}");

    let (status, held) = send_as(&app, ADMIN_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_cr10")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap();
    let (status, resp) = co_sign(&app, approval_id, &id, &forged).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(!has_policy(&state, "p_cr10"));
    let (status, resp) = co_sign(&app, approval_id, "device:owner-phone", &owner_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(has_policy(&state, "p_cr10"));
}

// ── The credential-move standing follows Export the vault, not the admin role ──────────────────────

fn vault_export_events(audit: &Value) -> usize {
    audit["events"].as_array().map(|a| a.iter().filter(|e| e["payload"]["action"] == "permaura.vault.export").count()).unwrap_or(0)
}

/// The retarget, under the new rule. An admin whose phone is the only trusted device, and whose
/// operator token carries no signed `vault_export`, is refused the retarget outright: nothing is held, nothing moves,
/// and the offboarding playbook's premise (no export event, nothing taken) stays true. The same member signed as an
/// Export holder gets the hold the owner would, with the device signature still on top.
#[tokio::test]
async fn an_admin_without_export_standing_cannot_move_a_stored_ssh_credential_even_alone() {
    let (state, app) = hosted_gateway().await;
    let admin_phone = device_key(150);
    let t = mint_ticket(pair_claims_by("tkt-adm-b", "device:admin-phone", &admin_phone, Some(ACTOR_SUB), Some("admin")));
    let (status, resp) = pair(&app, pair_body("device:admin-phone", &admin_phone), Some(&t)).await;
    assert_eq!(status, StatusCode::OK, "an admin may pair the first device: {resp}");
    put_console_session(&state, ADMIN_CONSOLE, ACTOR_SUB, Some("admin"));
    put_exporter_console_session(&state, EXPORTER_CONSOLE, ACTOR_SUB, Some("admin"));
    let before = ssh_hosts(&state);

    let body: Value = serde_json::from_str(RETARGET).unwrap();
    let (status, resp) = send_as(&app, ADMIN_CONSOLE, "PATCH", "/v1/connections/ssh_prod", Some(body.clone()), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "an admin role alone is not export standing: {resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("holds Export the vault"), "{resp}");
    assert_eq!(ssh_hosts(&state), before, "nothing moved");
    let pending = state.service.store().list_approvals(Some("pending")).unwrap();
    assert!(pending.is_empty(), "nothing was held either: {pending:?}");
    let (_s, audit) = send(&app, "GET", "/v1/audit-events?limit=500", None, &[]).await;
    assert_eq!(vault_export_events(&audit), 0);

    let (status, held) = send_as(&app, EXPORTER_CONSOLE, "PATCH", "/v1/connections/ssh_prod", Some(body), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "signed as an Export holder, the same change is held for a device: {held}");
    assert_eq!(held["required_tier"], "device_signed");
    assert_eq!(ssh_hosts(&state), before, "held, not applied");
}

/// The same move after an opt-down, under the new rule. The admin may still opt the floor down (an owner-or-admin
/// control, confirmed on the only trusted device), but with nothing left to hold, an import that moves the stored
/// credential still takes the signed export standing: refused for the admin role, applied for the Export holder.
#[tokio::test]
async fn an_admin_without_export_standing_cannot_import_a_credential_move_after_opting_down() {
    let (state, app) = hosted_gateway().await;
    let admin_phone = device_key(151);
    let t = mint_ticket(pair_claims_by("tkt-adm-ba", "device:admin-phone", &admin_phone, Some(ACTOR_SUB), Some("admin")));
    assert_eq!(pair(&app, pair_body("device:admin-phone", &admin_phone), Some(&t)).await.0, StatusCode::OK);
    put_console_session(&state, ADMIN_CONSOLE, ACTOR_SUB, Some("admin"));
    put_exporter_console_session(&state, EXPORTER_CONSOLE, ACTOR_SUB, Some("admin"));

    let (status, held) = put_floor(&app, "approve", Some(&mint_ticket(floor_claims_by("tkt-adm-bf", ACTOR_SUB, Some("admin"))))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the opt-down is held for the only device: {held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:admin-phone", &admin_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(!state.service.vault_export_hold_required() && !state.service.control_plane_hold_required(true));
    let before = ssh_hosts(&state);

    let bundle = ssh_retarget_bundle(&state, "admins-host.example");
    let (status, resp) = send_as(&app, ADMIN_CONSOLE, "POST", "/v1/vault/import", Some(import_req(bundle.clone(), "replace")), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("holds Export the vault"), "{resp}");
    assert_eq!(ssh_hosts(&state), before, "nothing moved");
    assert_eq!(latest_reason(&app, "permaura.vault.import").await.as_deref(), Some("the requester lacks the standing a vault export takes"));

    let (status, resp) = send_as(&app, EXPORTER_CONSOLE, "POST", "/v1/vault/import", Some(import_req(bundle, "replace")), &[]).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(ssh_hosts(&state).iter().all(|h| h == "admins-host.example"));
}

// ── Binding a new connection to a stored credential is a credential move ────────────────────────────

/// A credential stored here that no connection binds, as a free-standing secret or one a deleted connection left behind.
fn put_unbound_credential(state: &AppState, id: &str) {
    common::isolate_from_the_real_install();
    let sealed = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, permaura_gateway::service::vault_passphrase(), b"root:hunter2")
        .expect("seal");
    state
        .service
        .store()
        .put_secret(permaura_core::SecretRecord { id: id.into(), sealed, metadata: Default::default() })
        .expect("seeding a secret cannot fail on the in-memory store");
}

fn ssh_connection_over(id: &str) -> Value {
    json!({
        "id": id, "connector": "ssh", "name": "Taken over",
        "ssh": { "host": "attacker.example", "user": "root", "host_key_sha256": "SHA256:attackerfingerprint", "password_auth": true, "sftp_root": "/srv" },
    })
}

/// A new connection over a stored credential is refused even to the owner while no device is trusted, and with the floor opted down takes the signed export standing PATCH and import take.
#[tokio::test]
async fn a_new_connection_over_a_stored_credential_takes_export_standing() {
    let (state, app) = hosted_gateway().await;
    put_unbound_credential(&state, "sec_orphan_ssh");
    put_console_session(&state, OWNER_CONSOLE, OWNER_SUB, None);
    let (status, resp) = send_as(&app, OWNER_CONSOLE, "POST", "/v1/connections", Some(ssh_connection_over("orphan_ssh")), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no device is paired to confirm anything: {resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("no device is paired"), "{resp}");

    let admin_phone = device_key(152);
    let t = mint_ticket(pair_claims_by("tkt-adm-c", "device:admin-phone", &admin_phone, Some(ACTOR_SUB), Some("admin")));
    assert_eq!(pair(&app, pair_body("device:admin-phone", &admin_phone), Some(&t)).await.0, StatusCode::OK);
    put_console_session(&state, ADMIN_CONSOLE, ACTOR_SUB, Some("admin"));
    put_console_session(&state, MEMBER_CONSOLE, ACTOR_SUB, None);
    put_exporter_console_session(&state, EXPORTER_CONSOLE, ACTOR_SUB, Some("admin"));
    let (status, held) = put_floor(&app, "approve", Some(&mint_ticket(floor_claims_by("tkt-adm-cf", ACTOR_SUB, Some("admin"))))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let (status, resp) = co_sign(&app, held["approval_id"].as_str().unwrap(), "device:admin-phone", &admin_phone).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(!state.service.vault_export_hold_required(), "paired, and nothing holds");

    for bearer in [ADMIN_CONSOLE, MEMBER_CONSOLE] {
        let (status, resp) = send_as(&app, bearer, "POST", "/v1/connections", Some(ssh_connection_over("orphan_ssh")), &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{bearer}: {resp}");
        let error = resp["error"].as_str().unwrap_or_default();
        assert!(error.contains("would take over the credential already in 'sec_orphan_ssh'") && error.contains("holds Export the vault"), "{resp}");
    }
    assert!(state.service.store().get_connection("orphan_ssh").unwrap().is_none(), "nothing was bound");

    let (status, resp) = send_as(&app, EXPORTER_CONSOLE, "POST", "/v1/connections", Some(ssh_connection_over("orphan_ssh")), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "an Export holder may, with nothing left to hold it: {resp}");
}

/// An admin without the signed claim cannot import a connection that binds a staged row or whose empty `secret_id` derives a stored slot, nor re-sync one already planted.
#[tokio::test]
async fn an_admin_without_export_standing_cannot_reach_a_stored_credential_through_an_imported_slot() {
    let (state, app) = hosted_gateway().await;
    let (_owner_phone, _member_phone) = team(&state, &app, "tkt-adm-d").await;
    put_unbound_credential(&state, "sec_orphan_wp");
    let wordpress = |id: &str| {
        json!({
            "id": id, "connector": "wordpress", "name": "Site", "label": "WordPress", "secret_id": "", "capabilities": [],
            "source": { "kind": "wordpress", "url": "https://attacker.example", "rest_root": "https://attacker.example/wp-json/", "abilities": true, "synced_at": 0 },
        })
    };
    let bundle_of = |connection: Value| {
        let payload = json!({ "connections": [connection], "policies": [], "grants": [], "capabilities": [], "secrets": [], "agents": [] });
        let bundle = permaura_core::seal_bundle(
            b"correct horse battery staple",
            payload,
            1_754_500_000_000,
            permaura_core::BundleSource { gateway_id: "gw_admins_own".into(), mode: "self-run".into() },
        )
        .unwrap();
        import_req(serde_json::to_value(bundle).unwrap(), "skip")
    };

    let mut binds_a_staged_row = wordpress("binds_staged");
    binds_a_staged_row["secret_id"] = json!(permaura_gateway::secret_inventory::mint_staging_secret_id());
    let (status, resp) = send_as(&app, ADMIN_CONSOLE, "POST", "/v1/vault/import", Some(bundle_of(binds_a_staged_row)), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("parked for a device signature"), "{resp}");
    let (status, resp) = send_as(&app, ADMIN_CONSOLE, "POST", "/v1/vault/import", Some(bundle_of(wordpress("orphan_wp"))), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("holds Export the vault"), "{resp}");
    assert_eq!(latest_reason(&app, "permaura.vault.import").await.as_deref(), Some("the requester lacks the standing a vault export takes"));
    assert!(state.service.store().get_connection("orphan_wp").unwrap().is_none());

    let planted: permaura_core::Connection = serde_json::from_value(wordpress("orphan_wp")).unwrap();
    state.service.store().put_connection(planted).unwrap();
    for bearer in [ADMIN_CONSOLE, OWNER_CONSOLE] {
        let (status, resp) = send_as(&app, bearer, "POST", "/v1/connections/orphan_wp/resync", Some(json!({ "sources": ["abilities"], "dry_run": true })), &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{bearer}: {resp}");
    }
    assert_eq!(state.service.store().get_connection("orphan_wp").unwrap().unwrap().secret_id, "");
}

/// After permaura.com names a new owner at a check-in, the RS accepts the new owner's tokens, and the owner's-device exemption and the key list's `is_owner` follow the new owner rather than the boot-time pin.
#[tokio::test]
async fn the_owner_device_exemption_follows_the_live_owner_after_a_repin() {
    let (state, app) = hosted_gateway().await;
    let (owner_phone, member_phone) = team(&state, &app, "tkt-ca01").await;

    // The organization is handed over to Priya; the check-in names her and the RS moves.
    assert!(state.service.repin_owner(ACTOR_SUB, true, None, None).unwrap(), "the binding moves");
    assert_eq!(state.service.oauth().unwrap().owner_sub().as_deref(), Some(ACTOR_SUB));

    let (_s, keys) = send(&app, "GET", "/v1/approver-keys", None, &[]).await;
    let rows = keys["keys"].as_array().or_else(|| keys.as_array()).expect("the key list").clone();
    let is_owner = |id: &str| rows.iter().find(|k| k["approver_id"] == id).map(|k| k["is_owner"].clone());
    let former_marked = is_owner("device:owner-phone");
    let new_marked = is_owner("device:member-phone");

    // The former owner (still a member, acting through the console) asks for a loosening change and confirms it on their own phone.
    let (status, held) = send_as(&app, OWNER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_ca01_former")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let former = held["approval_id"].as_str().unwrap().to_string();
    let (former_status, former_resp) = co_sign(&app, &former, "device:owner-phone", &owner_phone).await;

    // The new owner asks for one and confirms it on their own phone.
    let (status, held) = send_as(&app, MEMBER_CONSOLE, "POST", "/v1/policies", Some(widening_policy("p_ca01_new")), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let new = held["approval_id"].as_str().unwrap().to_string();
    let (new_status, new_resp) = co_sign(&app, &new, "device:member-phone", &member_phone).await;

    eprintln!("is_owner former={former_marked:?} new={new_marked:?}; former self-confirm {former_status}: {former_resp}; new owner self-confirm {new_status}: {new_resp}");
    assert_eq!(former_marked, Some(json!(false)), "the key list still marks the former owner's phone as the owner's");
    assert_eq!(new_marked, Some(json!(true)), "the key list does not mark the new owner's phone");
    assert!(is_self_approval_refusal(former_status, &former_resp), "the former owner confirmed their own held change alone: {former_status}: {former_resp}");
    assert_eq!(new_status, StatusCode::OK, "the new owner's phone is refused on the new owner's own change: {new_resp}");
}
