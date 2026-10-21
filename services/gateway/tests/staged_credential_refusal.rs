//! A credential change that is refused leaves nothing behind, and the credential route is charged like `POST /v1/secrets`.
//!
//! A remote credential write while a device is paired is staged under a `sec:staging:` row and held. A hold refused at
//! the pending ceiling used to stage the row first and never remove it, and the credential route added secret rows the
//! plan allowance never saw while staged rows counted against it afterwards.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::allowances::{Allowance, Allowances, AllowancesConfig};
use permaura_gateway::secret_inventory::is_staging_secret_id;
use common::build_router;
use permaura_gateway::{seed, AppState};
use tower::ServiceExt;

mod common;

const CONNECTION: &str = "braintree_production";

async fn send(app: &axum::Router, uri: &str, remote: bool, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json");
    if remote {
        builder = builder.header("cf-ray", "abc123");
    }
    let resp = app.clone().oneshot(builder.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

fn with_device(state: AppState) -> (axum::Router, AppState) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key_for("device:approver", &pubkey, Some("user_approver")).unwrap());
    (build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()), state)
}

fn staged_rows(state: &AppState) -> usize {
    state.service.store().list_secret_ids().unwrap().iter().filter(|id| is_staging_secret_id(id)).count()
}

fn secrets_limited_to(limit: u64) -> AppState {
    let config = AllowancesConfig { secrets: Some(limit), ..Default::default() };
    common::seeded_with_allowances(Arc::new(Allowances::new(config).with_log_interval(std::time::Duration::ZERO)))
}

#[tokio::test]
async fn a_credential_hold_refused_at_the_pending_ceiling_stages_nothing() {
    let (app, state) = with_device(common::seeded());
    let uri = format!("/v1/connections/{CONNECTION}/credential");
    let (s, first) = send(&app, &uri, true, serde_json::json!({ "value": "first" })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{first}");
    let store = state.service.store();
    let template = store.get_approval(first["approval_id"].as_str().unwrap()).unwrap().unwrap();
    for i in 1..permaura_gateway::store::MAX_PENDING_APPROVALS {
        let mut filler = template.clone();
        filler.id = format!("appr_filler_{i}");
        let mut params = filler.params.to_value_unbounded();
        params["staging_secret_id"] = serde_json::json!(format!("unused_{i}"));
        filler.params = params.into();
        store.put_approval(filler).unwrap();
    }
    assert_eq!(store.list_approvals(Some("pending")).unwrap().len(), permaura_gateway::store::MAX_PENDING_APPROVALS);
    assert_eq!(staged_rows(&state), 1);

    for n in 0..3 {
        let (s, body) = send(&app, &uri, true, serde_json::json!({ "value": format!("refused {n}") })).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    }
    assert_eq!(staged_rows(&state), 1, "a refused hold must not leave a staged row behind");
}

#[tokio::test]
async fn a_first_credential_is_charged_to_the_secrets_allowance() {
    let probe = common::seeded();
    let slot = probe.service.store().get_connection(CONNECTION).unwrap().unwrap().secret_id;
    let at = probe.service.allowance_count(Allowance::Secrets).unwrap() - 1;
    let state = secrets_limited_to(at);
    assert!(state.service.store().delete_secret(&slot).unwrap(), "the connection starts with no credential");
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let before = state.service.store().list_secret_ids().unwrap().len();
    let (s, body) =
        send(&app, &format!("/v1/connections/{CONNECTION}/credential"), false, serde_json::json!({ "value": "v" })).await;
    assert_eq!(s, StatusCode::CONFLICT, "a first credential at the ceiling is refused: {body}");
    assert_eq!(body["allowance"], "secrets");
    assert_eq!(state.service.store().list_secret_ids().unwrap().len(), before, "the refusal wrote no row");
}

#[tokio::test]
async fn a_staged_row_is_not_charged_to_the_secrets_allowance() {
    let at = common::seeded().service.allowance_count(Allowance::Secrets).unwrap();
    let (app, state) = with_device(secrets_limited_to(at + 1));
    let (s, held) =
        send(&app, &format!("/v1/connections/{CONNECTION}/credential"), true, serde_json::json!({ "value": "held" })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{held}");
    assert_eq!(staged_rows(&state), 1);
    assert_eq!(state.service.allowance_count(Allowance::Secrets).unwrap(), at);
    let (s, body) = send(&app, "/v1/secrets", false, serde_json::json!({ "id": "sec_last_slot", "value": "v" })).await;
    assert_eq!(s, StatusCode::CREATED, "the plan's last slot is still free while a change is held: {body}");
}

#[cfg(feature = "sqlite")]
fn sqlite_state_with_device(tag: &str) -> (axum::Router, AppState, String) {
    common::isolate_from_the_real_install();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("permaura-gw-policy-a-01-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db").to_string_lossy().into_owned();
    let store: Arc<dyn permaura_gateway::store::Store> =
        Arc::new(permaura_gateway::store::sqlite::SqliteStore::open(&path).unwrap());
    seed::seed(store.as_ref()).unwrap();
    let http = Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let state = AppState::new(permaura_gateway::service::EnforcementService::new(store, http));
    let (app, state) = with_device(state);
    (app, state, path)
}

#[cfg(feature = "sqlite")]
fn pending_naming(state: &AppState, staging_secret_id: &str) -> usize {
    state
        .service
        .store()
        .list_approvals(Some("pending"))
        .unwrap()
        .iter()
        .filter(|a| a.params.to_value_unbounded()["staging_secret_id"] == staging_secret_id)
        .count()
}

/// The hold is written and a later step fails (here its audit record; on hosted, the upload after a local commit). The
/// staged row is what that hold promotes, so it stays.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_hold_recorded_before_a_later_failure_keeps_its_staged_row() {
    let (app, state, path) = sqlite_state_with_device("recorded");
    let side = rusqlite::Connection::open(&path).unwrap();
    side.execute_batch(
        "CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_events \
         BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
    )
    .unwrap();
    let (s, body) =
        send(&app, &format!("/v1/connections/{CONNECTION}/credential"), true, serde_json::json!({ "value": "v" })).await;
    assert!(s.is_server_error(), "the hold's audit record failed: {s} {body}");
    let staged: Vec<String> =
        state.service.store().list_secret_ids().unwrap().into_iter().filter(|id| is_staging_secret_id(id)).collect();
    assert_eq!(staged.len(), 1, "the recorded hold's staged row is kept");
    assert_eq!(pending_naming(&state, &staged[0]), 1, "and the hold naming it is pending");
}

/// The hold itself is never written: nothing names the staged row, so it is removed.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_hold_that_was_never_recorded_removes_its_staged_row() {
    let (app, state, path) = sqlite_state_with_device("unrecorded");
    let side = rusqlite::Connection::open(&path).unwrap();
    side.execute_batch(
        "CREATE TRIGGER refuse_approval BEFORE INSERT ON approvals \
         BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
    )
    .unwrap();
    let (s, body) =
        send(&app, &format!("/v1/connections/{CONNECTION}/credential"), true, serde_json::json!({ "value": "v" })).await;
    assert!(s.is_server_error(), "the hold could not be written: {s} {body}");
    assert_eq!(staged_rows(&state), 0, "an unrecorded hold leaves no staged row");
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

async fn get(app: &axum::Router, uri: &str) -> serde_json::Value {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn device_approve(app: &axum::Router, approval_id: &str) -> (StatusCode, serde_json::Value) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use permaura_relay::{approval_display_full_digest_of, approval_result_preimage_v3, sign};
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let appr = get(app, &format!("/v1/approvals/{approval_id}")).await;
    let request_hash = appr["request_hash"].as_str().unwrap().to_string();
    let job_id = appr["job_id"].as_str().unwrap().to_string();
    let audience = appr["approval_audience"].as_str().expect("audience").to_string();
    let shown = approval_display_full_digest_of(&appr).expect("full rendering");
    let decided_at = now_ms();
    let approver = "device:approver";
    let preimage =
        approval_result_preimage_v3(&audience, &job_id, approval_id, true, &request_hash, &shown, approver, decided_at);
    send(
        app,
        "/v1/approvals",
        false,
        serde_json::json!({
            "approval_id": approval_id, "approve": true, "approver": approver,
            "request_hash": request_hash, "decided_at": decided_at, "job_id": job_id,
            "approver_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
            "audience": audience, "display_digest": shown, "device_sig": sign(&sk, &preimage),
        }),
    )
    .await
}

/// Staged rows are not charged, so two first credentials held while one slot was free both pass the hold-time check.
/// The second to be approved finds the slot taken and is refused rather than promoted past the plan.
#[tokio::test]
async fn first_credentials_held_at_the_last_slot_cannot_both_promote() {
    const SECOND: &str = "fal";
    let probe = common::seeded();
    let braintree_slot = probe.service.store().get_connection(CONNECTION).unwrap().unwrap().secret_id;
    let second_slot = probe.service.store().get_connection(SECOND).unwrap().unwrap().secret_id;
    assert!(probe.service.store().get_secret(&second_slot).unwrap().is_none(), "the second connection starts with no credential");
    let limit = probe.service.allowance_count(Allowance::Secrets).unwrap();
    let (app, state) = with_device(secrets_limited_to(limit));
    assert!(state.service.store().delete_secret(&braintree_slot).unwrap());

    let mut holds = Vec::new();
    for connection in [CONNECTION, SECOND] {
        let (s, held) =
            send(&app, &format!("/v1/connections/{connection}/credential"), true, serde_json::json!({ "value": "v" })).await;
        assert_eq!(s, StatusCode::ACCEPTED, "one slot is free when {connection} is held: {held}");
        holds.push(held["approval_id"].as_str().unwrap().to_string());
    }

    let (s, body) = device_approve(&app, &holds[0]).await;
    assert!(s.is_success(), "{s} {body}");
    assert_eq!(state.service.allowance_count(Allowance::Secrets).unwrap(), limit);

    let (s, body) = device_approve(&app, &holds[1]).await;
    assert_eq!(s, StatusCode::CONFLICT, "the second promotion is refused at the ceiling: {body}");
    assert_eq!(body["allowance"], "secrets", "{body}");
    assert!(body.to_string().contains("approved but not saved"), "{body}");
    assert!(state.service.store().get_secret(&second_slot).unwrap().is_none());
    assert_eq!(state.service.allowance_count(Allowance::Secrets).unwrap(), limit, "the plan is not overshot");
    assert_eq!(staged_rows(&state), 0, "the refused promotion's staged row is released");
}

/// One free Secrets slot, the connection's own credential the row that would take it; the state is limited to what the seed holds.
fn one_free_secrets_slot() -> (axum::Router, AppState, u64) {
    let probe = common::seeded();
    let slot = probe.service.store().get_connection(CONNECTION).unwrap().unwrap().secret_id;
    let limit = probe.service.allowance_count(Allowance::Secrets).unwrap();
    let state = secrets_limited_to(limit);
    assert!(state.service.store().delete_secret(&slot).unwrap());
    (build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()), state, limit)
}

/// Both requests see the last free slot, then wait behind another control-plane change; only one may take it once they run.
async fn race_for_the_last_slot(
    app: &axum::Router,
    state: &AppState,
    first: (&str, serde_json::Value),
    second: (&str, serde_json::Value),
) -> [(StatusCode, serde_json::Value); 2] {
    let guard = state.service.control_plane_mutex().lock().await;
    let mut a = Box::pin(send(app, first.0, true, first.1));
    let mut b = Box::pin(send(app, second.0, true, second.1));
    assert!(tokio::time::timeout(std::time::Duration::from_millis(100), &mut a).await.is_err(), "the first write waits on the lock");
    assert!(tokio::time::timeout(std::time::Duration::from_millis(100), &mut b).await.is_err(), "the second write waits on the lock");
    drop(guard);
    let (a, b) = tokio::join!(a, b);
    [a, b]
}

#[tokio::test]
async fn concurrent_first_credentials_cannot_spend_the_same_last_slot() {
    let (app, state, limit) = one_free_secrets_slot();
    let first = format!("/v1/connections/{CONNECTION}/credential");
    let results = race_for_the_last_slot(
        &app,
        &state,
        (&first, serde_json::json!({ "value": "synthetic-first" })),
        ("/v1/connections/fal/credential", serde_json::json!({ "value": "synthetic-second" })),
    )
    .await;
    let statuses: Vec<_> = results.iter().map(|r| r.0).collect();
    assert!(statuses.contains(&StatusCode::OK) && statuses.contains(&StatusCode::CONFLICT), "{results:?}");
    assert_eq!(state.service.allowance_count(Allowance::Secrets).unwrap(), limit, "{results:?}");
}

#[tokio::test]
async fn sequential_first_credentials_enforce_the_last_slot() {
    let (app, state, limit) = one_free_secrets_slot();
    let a = send(&app, &format!("/v1/connections/{CONNECTION}/credential"), true, serde_json::json!({ "value": "synthetic-first" })).await;
    let b = send(&app, "/v1/connections/fal/credential", true, serde_json::json!({ "value": "synthetic-second" })).await;
    assert_eq!(a.0, StatusCode::OK, "{a:?}");
    assert_eq!(b.0, StatusCode::CONFLICT, "{b:?}");
    assert_eq!(state.service.allowance_count(Allowance::Secrets).unwrap(), limit);
}

/// A first credential and a new `POST /v1/secrets` row share the allowance, so they cannot both take the last slot either.
#[tokio::test]
async fn a_first_credential_and_a_new_secret_cannot_spend_the_same_last_slot() {
    let (app, state, limit) = one_free_secrets_slot();
    let first = format!("/v1/connections/{CONNECTION}/credential");
    let results = race_for_the_last_slot(
        &app,
        &state,
        (&first, serde_json::json!({ "value": "synthetic-first" })),
        ("/v1/secrets", serde_json::json!({ "id": "sec_cross_route", "value": "synthetic-second" })),
    )
    .await;
    let won = results.iter().filter(|r| r.0.is_success()).count();
    assert_eq!(won, 1, "{results:?}");
    assert!(results.iter().any(|r| r.0 == StatusCode::CONFLICT), "{results:?}");
    assert_eq!(state.service.allowance_count(Allowance::Secrets).unwrap(), limit, "{results:?}");
}

/// Rewriting a secret that exists adds no row, so it still lands with the gateway at its ceiling.
#[tokio::test]
async fn a_rotation_at_the_ceiling_still_lands() {
    let probe = common::seeded();
    let slot = probe.service.store().get_connection(CONNECTION).unwrap().unwrap().secret_id;
    let state = secrets_limited_to(probe.service.allowance_count(Allowance::Secrets).unwrap());
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (s, body) = send(&app, &format!("/v1/connections/{CONNECTION}/credential"), true, serde_json::json!({ "value": "rotated" })).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["rotated"], true, "{body}");
    let (s, body) = send(&app, &format!("/v1/secrets/{slot}/rotate"), true, serde_json::json!({ "value": "rotated again" })).await;
    assert!(s.is_success(), "{s} {body}");
}

/// Staged bytes, not only the hold count, bound what credential changes can park; with the default bounds, four values at the body limit fit one requester and a fifth is refused without a row.
#[tokio::test]
async fn staged_credential_bytes_are_bounded_per_requester() {
    let (app, state) = with_device(common::seeded());
    let uri = format!("/v1/connections/{CONNECTION}/credential");
    let value = "v".repeat(250 * 1024);
    for n in 0..4 {
        let (s, body) = send(&app, &uri, true, serde_json::json!({ "value": value })).await;
        assert_eq!(s, StatusCode::ACCEPTED, "hold {n}: {body}");
    }
    let (s, body) = send(&app, &uri, true, serde_json::json!({ "value": value })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.to_string().contains("one requester may have waiting"), "{body}");
    assert_eq!(staged_rows(&state), 4, "a refused change stages nothing");
    let (s, body) = send(&app, &uri, true, serde_json::json!({ "value": "short" })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "a small change still fits under the bound: {body}");
}

/// The gateway-wide bound counts every staged row, the same way through `POST /v1/secrets` as through a connection's credential route.
#[tokio::test]
async fn staged_credential_bytes_are_bounded_per_gateway() {
    use permaura_gateway::limits::{Limits, LimitsConfig};
    let limits = LimitsConfig { staged_bytes_per_gateway: 160 * 1024, ..LimitsConfig::default() };
    let (app, state) = with_device(common::seeded().with_limits(Arc::new(Limits::new(limits))));
    let slot = state.service.store().get_connection(CONNECTION).unwrap().unwrap().secret_id;
    let value = "v".repeat(20 * 1024);
    let (s, body) = send(&app, &format!("/v1/connections/{CONNECTION}/credential"), true, serde_json::json!({ "value": value })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let (s, body) = send(&app, "/v1/secrets", true, serde_json::json!({ "id": slot, "value": value })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let (s, body) = send(&app, "/v1/secrets", true, serde_json::json!({ "id": slot, "value": value })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.to_string().contains("on this gateway"), "{body}");
    assert_eq!(staged_rows(&state), 2, "a refused change stages nothing");
}

/// The OAuth connect callback added a secret row past the Secrets allowance, outside the publication rule.
#[tokio::test]
async fn an_oauth_connection_is_charged_to_the_secrets_allowance() {
    use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
    common::isolate_from_the_real_install();
    let at = common::seeded().service.allowance_count(Allowance::Secrets).unwrap();
    let state_with = |limit: u64, http: Arc<MockHttpClient>| {
        let store: Arc<dyn permaura_gateway::store::Store> = Arc::new(permaura_gateway::store::memory::MemoryStore::new());
        seed::seed(store.as_ref()).unwrap();
        let config = AllowancesConfig { secrets: Some(limit), ..Default::default() };
        let allowances = Arc::new(Allowances::new(config).with_log_interval(std::time::Duration::ZERO));
        AppState::new(permaura_gateway::service::EnforcementService::new(store, http).with_allowances(allowances))
    };
    let start = |app: axum::Router| async move {
        send(&app, "/v1/connections/gh-oauth/oauth/start", false, serde_json::json!({
            "client_id": "synthetic-client", "client_secret": "synthetic-secret",
            "redirect_uri": "http://127.0.0.1:7376/oauth/callback",
        }))
        .await
    };
    let new_connection = |app: axum::Router| async move {
        let (s, body) = send(&app, "/v1/connections/from-preset", false, serde_json::json!({ "preset_id": "github", "name": "OAuth", "id": "gh-oauth" })).await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
    };

    // At the ceiling, the dance is refused before it starts.
    let state = state_with(at, Arc::new(MockHttpClient::new()));
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    new_connection(app.clone()).await;
    let (s, body) = start(app.clone()).await;
    assert_eq!(s, StatusCode::CONFLICT, "a first OAuth credential at the ceiling is refused: {body}");
    assert_eq!(body["allowance"], "secrets");

    // Started with a slot free, which another secret then takes: the callback refuses rather than overshooting.
    let http = Arc::new(MockHttpClient::new());
    let state = state_with(at + 1, http.clone());
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    new_connection(app.clone()).await;
    let (s, started) = start(app.clone()).await;
    assert_eq!(s, StatusCode::OK, "{started}");
    let url = started["authorize_url"].as_str().unwrap();
    let state_token = url.split("state=").nth(1).and_then(|s| s.split('&').next()).unwrap().to_string();
    let (s, body) = send(&app, "/v1/secrets", false, serde_json::json!({ "id": "sec_last_slot", "value": "v" })).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    http.push_response(HttpResponse::json(200, serde_json::json!({ "access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600 })));
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(format!("/oauth/callback?code=c&state={state_token}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let page = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&page).contains("Could not store the credential"), "{}", String::from_utf8_lossy(&page));
    assert_eq!(state.service.allowance_count(Allowance::Secrets).unwrap(), at + 1, "the ceiling held");
}

/// A bundle that fills two connections' empty credential slots with `bytes` of value each, sent remotely to a gateway with a paired device so both fills are held.
async fn import_two_fills(app: &axum::Router, state: &AppState, bytes: usize) -> (StatusCode, serde_json::Value) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let store = state.service.store();
    let mut slots: Vec<String> = store
        .list_connections()
        .unwrap()
        .into_iter()
        .map(|c| c.secret_id)
        .filter(|id| store.get_secret(id).unwrap().is_some())
        .collect();
    slots.sort();
    slots.dedup();
    slots.truncate(2);
    assert_eq!(slots.len(), 2, "two connections with a credential");
    for slot in &slots {
        assert!(store.delete_secret(slot).unwrap(), "{slot} starts empty");
    }
    let value = STANDARD.encode("v".repeat(bytes));
    let secrets: Vec<serde_json::Value> = slots
        .iter()
        .map(|id| serde_json::json!({ "id": id, "metadata": {}, "custody": "local_vault", "value": value }))
        .collect();
    let payload = serde_json::json!({ "connections": [], "policies": [], "grants": [], "capabilities": [], "secrets": secrets, "agents": [] });
    let bundle = permaura_core::seal_bundle(
        b"correct horse battery staple",
        payload,
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_other".into(), mode: "self-run".into() },
    )
    .unwrap();
    let body = serde_json::json!({ "bundle": serde_json::to_value(bundle).unwrap(), "passphrase": "correct horse battery staple", "on_conflict": "skip" });
    send(app, "/v1/vault/import", true, body).await
}

fn import_refusals(state: &AppState) -> Vec<serde_json::Value> {
    let events = state.service.store().audit_events(None).unwrap();
    events
        .into_iter()
        .filter(|e| e.payload.action == "permaura.vault.import" && e.payload.decision == "deny")
        .map(|e| e.payload.summary)
        .collect()
}

/// The empty-queue rule, for a vault import: its fills are checked against the held-changes budget together, and a set alone in the queue is held whatever its rows take, so an import is never refused for the queue's total where no retry could clear it. Here two slots an earlier version stored with 40 KiB ids make fills past the budget's 64 KiB floor.
#[tokio::test]
async fn a_vault_imports_fills_alone_in_the_queue_are_held_whatever_they_take() {
    let (app, state) = with_device(with_held_changes_budget(1));
    let store = state.service.store();
    let mut moved = 0;
    for mut connection in store.list_connections().unwrap() {
        let Some(mut secret) = store.get_secret(&connection.secret_id).unwrap() else { continue };
        let long = format!("0{moved}{}", "s".repeat(40 * 1024));
        secret.id = long.clone();
        store.put_secret(secret).unwrap();
        connection.secret_id = long;
        store.put_connection(connection).unwrap();
        moved += 1;
        if moved == 2 {
            break;
        }
    }
    assert_eq!(moved, 2);
    let (s, resp) = import_two_fills(&app, &state, 64).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{}", resp.to_string().chars().take(400).collect::<String>());
    let held = store.pending_control_plane_hold_bytes().unwrap();
    assert!(held > state.service.memory().control_plane_held_total_bytes(), "both fills held past the budget, alone in the queue: {held}");
    assert_eq!(store.count_pending_approvals().unwrap(), 2);
}

/// A vault import's held fills are checked against the staged-bytes bound together, so a refusal stages none of them rather than the first few.
#[tokio::test]
async fn a_vault_import_over_the_staged_bound_stages_none_of_its_fills() {
    use permaura_gateway::limits::{Limits, LimitsConfig};
    let limits = LimitsConfig { staged_bytes_per_gateway: 160 * 1024, ..LimitsConfig::default() };
    let (app, state) = with_device(common::seeded().with_limits(Arc::new(Limits::new(limits))));
    let (s, resp) = import_two_fills(&app, &state, 30 * 1024).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{resp}");
    assert_eq!(staged_rows(&state), 0, "a refused import stages none of its fills");
    assert_eq!(import_refusals(&state).len(), 1, "and the chain records the refused import");
}

/// The fills are checked against the pending-approval ceiling together too, so an import with two fills and one free slot stages neither and records why.
#[tokio::test]
async fn a_vault_import_past_the_pending_ceiling_stages_none_of_its_fills() {
    let (app, state) = with_device(common::seeded());
    let uri = format!("/v1/connections/{CONNECTION}/credential");
    let (s, first) = send(&app, &uri, true, serde_json::json!({ "value": "first" })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{first}");
    let store = state.service.store();
    let template = store.get_approval(first["approval_id"].as_str().unwrap()).unwrap().unwrap();
    for i in 1..permaura_gateway::store::MAX_PENDING_APPROVALS - 1 {
        let mut filler = template.clone();
        filler.id = format!("appr_filler_{i}");
        let mut params = filler.params.to_value_unbounded();
        params["staging_secret_id"] = serde_json::json!(format!("unused_{i}"));
        filler.params = params.into();
        store.put_approval(filler).unwrap();
    }
    assert_eq!(store.count_pending_approvals().unwrap(), permaura_gateway::store::MAX_PENDING_APPROVALS - 1);
    let staged = staged_rows(&state);

    let (s, resp) = import_two_fills(&app, &state, 64).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{resp}");
    let said = resp.to_string();
    assert!(said.contains("hold 2 approvals") && said.contains("room for 1 more"), "the refusal names the import's own fills and the free slots: {resp}");
    assert!(!said.contains("already holds"), "the gateway is not at its ceiling: {resp}");
    assert_eq!(staged_rows(&state), staged, "neither fill is staged");
    assert_eq!(store.count_pending_approvals().unwrap(), permaura_gateway::store::MAX_PENDING_APPROVALS - 1, "and neither is held");
    let refusals = import_refusals(&state);
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert_eq!(refusals[0]["fills"], 2);
}

/// A gateway whose held changes may take `held_total_bytes`; no body for a change to arrive in keeps the budget's floor, one change and the rest of its row, at 64 KiB.
fn with_held_changes_budget(held_total_bytes: u64) -> AppState {
    use permaura_gateway::limits::LimitsConfig;
    common::isolate_from_the_real_install();
    let store: Arc<dyn permaura_gateway::store::Store> = Arc::new(permaura_gateway::store::memory::MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let config = LimitsConfig { held_total_bytes, body_default_bytes: 0, body_bulk_bytes: 0, ..LimitsConfig::default() };
    let service = permaura_gateway::service::EnforcementService::new(store, Arc::new(permaura_gateway::connectors::MockHttpClient::new()))
        .with_memory_budget(permaura_gateway::memory::MemoryBudget::from_config(&config));
    AppState::new(service)
}

/// A held change of about 128 KiB already waiting, since a change alone in the queue is held whatever it takes; returns its row's bytes.
fn hold_a_large_change(state: &AppState) -> u64 {
    let mutation = permaura_gateway::policy_guard::Mutation::AgentUpsert {
        agent: permaura_gateway::store::Agent::approved("agent-large", "n".repeat(64 * 1024), 1),
    };
    let row = state.service.control_plane_hold_bytes("permaura.policy.write", &mutation, "Create an agent?", None).unwrap();
    state.service.hold_mutation_approval("permaura.policy.write", &mutation, "Create an agent?", None).expect("alone in the queue, it is held");
    assert_eq!(state.service.store().pending_control_plane_hold_bytes().unwrap(), row);
    row
}

/// A credential hold the held-changes budget refuses takes its staged row with it, so a refusal there stages nothing either.
#[tokio::test]
async fn a_credential_hold_refused_at_the_held_changes_budget_stages_nothing() {
    let (app, state) = with_device(with_held_changes_budget(1));
    hold_a_large_change(&state);
    let uri = format!("/v1/connections/{CONNECTION}/credential");
    let (s, body) = send(&app, &uri, true, serde_json::json!({ "value": "first" })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["reason"], "held_params", "{body}");
    assert_eq!(staged_rows(&state), 0, "the refused hold's staged row is removed");
    assert_eq!(state.service.store().count_pending_approvals().unwrap(), 1, "only the change already waiting");
}

/// A vault import's fills are checked together against the held-changes budget too, so one that fits the first fill but not both stages neither, instead of holding the first and stopping at the second.
#[tokio::test]
async fn a_vault_import_past_the_held_changes_budget_stages_none_of_its_fills() {
    let (probe_app, probe) = with_device(with_held_changes_budget(64 * 1024 * 1024));
    let waiting = hold_a_large_change(&probe);
    let (s, resp) = import_two_fills(&probe_app, &probe, 64).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{resp}");
    let both = probe.service.store().pending_control_plane_hold_bytes().unwrap() - waiting;
    assert_eq!(probe.service.store().count_pending_approvals().unwrap(), 3);

    let (app, state) = with_device(with_held_changes_budget(waiting + both - 1));
    assert_eq!(hold_a_large_change(&state), waiting);
    let (s, resp) = import_two_fills(&app, &state, 64).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{resp}");
    assert!(resp.to_string().contains("these 2"), "the refusal names the import's own fills: {resp}");
    assert_eq!(staged_rows(&state), 0, "neither fill is staged");
    assert_eq!(state.service.store().count_pending_approvals().unwrap(), 1, "and neither is held");
    let refusals = import_refusals(&state);
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert_eq!(refusals[0]["fills"], 2);
}

/// Staged rows no waiting change names count toward the gateway's bound, and the refusal says that only deleting them frees the space.
#[tokio::test]
async fn the_gateway_bound_refusal_names_staged_rows_nothing_waits_for() {
    use permaura_gateway::limits::{Limits, LimitsConfig};
    let limits = LimitsConfig { staged_bytes_per_gateway: 160 * 1024, ..LimitsConfig::default() };
    let (app, state) = with_device(common::seeded().with_limits(Arc::new(Limits::new(limits))));
    let uri = format!("/v1/connections/{CONNECTION}/credential");
    let value = "v".repeat(30 * 1024);
    let (s, held) = send(&app, &uri, true, serde_json::json!({ "value": value })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{held}");
    let store = state.service.store();
    let mut approval = store.get_approval(held["approval_id"].as_str().unwrap()).unwrap().unwrap();
    approval.status = "expired".into();
    store.put_approval(approval).unwrap();
    assert_eq!(staged_rows(&state), 1, "the row stays behind its hold");

    let (s, body) = send(&app, &uri, true, serde_json::json!({ "value": value })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let text = body.to_string();
    assert!(text.contains("no waiting change names any more") && text.contains("DELETE /v1/secrets/"), "{text}");
    assert!(!text.contains("approve or deny"), "nothing is waiting to be approved: {text}");
}

fn limited(limits: permaura_gateway::limits::LimitsConfig) -> AppState {
    common::seeded().with_limits(Arc::new(permaura_gateway::limits::Limits::new(limits)))
}

fn slot_of(state: &AppState) -> String {
    state.service.store().get_connection(CONNECTION).unwrap().unwrap().secret_id
}

/// A staged row is counted as stored, labels included, so a payload moved from the value into the labels meets the same bound.
#[tokio::test]
async fn the_labels_of_a_staged_credential_count_toward_the_bound() {
    use permaura_gateway::limits::LimitsConfig;
    let limits = LimitsConfig { staged_bytes_per_gateway: 160 * 1024, secret_metadata_bytes: 64 * 1024, ..LimitsConfig::default() };
    let (app, state) = with_device(limited(limits));
    let slot = slot_of(&state);
    let labels = vec!["A".repeat(60_000)];
    for n in 0..2 {
        let (s, body) = send(&app, "/v1/secrets", true, serde_json::json!({ "id": slot, "value": "x", "labels": labels })).await;
        assert_eq!(s, StatusCode::ACCEPTED, "hold {n}: {body}");
    }
    let (s, body) = send(&app, "/v1/secrets", true, serde_json::json!({ "id": slot, "value": "x", "labels": labels })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "a one-byte value with 60,000 bytes of labels is counted as the row it stages: {body}");
    assert!(body.to_string().contains("on this gateway"), "{body}");
    assert_eq!(staged_rows(&state), 2, "a refused change stages nothing");
}

/// Labels past the metadata cap are refused before anything is sealed, staged or written, whether the write would be held or applied, and the cap is on the whole metadata rather than one label.
#[tokio::test]
async fn oversized_labels_are_refused_before_anything_is_written() {
    let (app, state) = with_device(common::seeded());
    let slot = slot_of(&state);
    let before = state.service.store().get_secret(&slot).unwrap();
    let one_long = serde_json::json!(["A".repeat(250_000)]);
    let many_short: Vec<String> = (0..1_000).map(|i| format!("label-{i}")).collect();
    for labels in [one_long, serde_json::json!(many_short)] {
        let (s, body) = send(&app, "/v1/secrets", true, serde_json::json!({ "id": slot, "value": "x", "labels": labels })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.to_string().contains("metadata"), "the refusal says what is over: {body}");
        assert_eq!(staged_rows(&state), 0, "nothing was staged");
        assert_eq!(state.service.store().get_secret(&slot).unwrap(), before, "and the live credential is untouched");

        let (s, body) = send(&app, "/v1/secrets", false, serde_json::json!({ "id": "sec_fresh", "value": "x", "labels": labels })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
        assert!(state.service.store().get_secret("sec_fresh").unwrap().is_none(), "a refused create writes no row");
    }
}

/// The cap and the counted labels leave a real credential alone: a private key with the labels a person gives one is held over the broker and written locally.
#[tokio::test]
async fn a_realistic_credential_with_normal_labels_is_accepted() {
    let (app, state) = with_device(common::seeded());
    let slot = slot_of(&state);
    let key = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", "b3BlbnNzaC1rZXktdjEAAAAA".repeat(140));
    let labels = serde_json::json!(["Production web servers (Acme Inc.)", "production", "deploy-key", "ssh", "rotated-2026-10", "owner:platform-team"]);
    let (s, body) = send(&app, "/v1/secrets", true, serde_json::json!({ "id": slot, "value": key, "labels": labels })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    assert_eq!(staged_rows(&state), 1);
    let (s, body) = send(&app, "/v1/secrets", false, serde_json::json!({ "id": "sec_deploy_key", "value": key, "labels": labels })).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let row = state.service.store().get_secret("sec_deploy_key").unwrap().expect("written");
    assert_eq!(row.metadata.labels.len(), 6);
}

/// A bundle carrying `secrets` (each `{id, metadata}` with a short value), imported locally or over the broker.
async fn import_secrets(app: &axum::Router, remote: bool, secrets: Vec<(String, serde_json::Value)>) -> (StatusCode, serde_json::Value) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let value = STANDARD.encode("imported value");
    let secrets: Vec<serde_json::Value> = secrets
        .into_iter()
        .map(|(id, metadata)| serde_json::json!({ "id": id, "metadata": metadata, "custody": "local_vault", "value": value }))
        .collect();
    let payload = serde_json::json!({ "connections": [], "policies": [], "grants": [], "capabilities": [], "secrets": secrets, "agents": [] });
    let bundle = permaura_core::seal_bundle(
        b"correct horse battery staple",
        payload,
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_other".into(), mode: "self-run".into() },
    )
    .unwrap();
    let body = serde_json::json!({ "bundle": serde_json::to_value(bundle).unwrap(), "passphrase": "correct horse battery staple", "on_conflict": "skip" });
    send(app, "/v1/vault/import", remote, body).await
}

/// A vault bundle meets the same metadata cap, for a secret it writes and for a credential fill it would hold for a device, and a bundle with ordinary labels still imports.
#[tokio::test]
async fn a_vault_import_respects_the_metadata_cap() {
    let oversized = serde_json::json!({ "labels": ["A".repeat(8 * 1024)] });
    let ordinary = serde_json::json!({ "labels": ["production", "billing"], "risk_classification": "critical" });

    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (s, body) = import_secrets(&app, false, vec![("sec_imported".into(), oversized.clone())]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("sec_imported"), "the refusal names the secret: {body}");
    assert!(state.service.store().get_secret("sec_imported").unwrap().is_none(), "nothing was written");
    let (s, body) = import_secrets(&app, false, vec![("sec_imported".into(), ordinary)]).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(state.service.store().get_secret("sec_imported").unwrap().expect("written").metadata.labels, ["production", "billing"]);

    let (app, state) = with_device(common::seeded());
    let slot = slot_of(&state);
    assert!(state.service.store().delete_secret(&slot).unwrap(), "{slot} starts empty, so the bundle fills it");
    let (s, body) = import_secrets(&app, true, vec![(slot.clone(), oversized)]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(staged_rows(&state), 0, "a refused fill is not staged");
    assert!(state.service.store().get_secret(&slot).unwrap().is_none());
}

/// On the store that ships, the requester's share is read from each hold's two fields, so its bound still fires on the right person's rows.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn the_requester_bound_holds_on_the_sqlite_store() {
    use permaura_gateway::limits::{Limits, LimitsConfig};
    let (_, state, _path) = sqlite_state_with_device("cr1-04");
    let limits = LimitsConfig { staged_bytes_per_requester: 160 * 1024, ..LimitsConfig::default() };
    let state = state.with_limits(Arc::new(Limits::new(limits)));
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let uri = format!("/v1/connections/{CONNECTION}/credential");
    let value = "v".repeat(20 * 1024);
    for n in 0..2 {
        let (s, body) = send(&app, &uri, true, serde_json::json!({ "value": value })).await;
        assert_eq!(s, StatusCode::ACCEPTED, "hold {n}: {body}");
    }
    let (s, body) = send(&app, &uri, true, serde_json::json!({ "value": value })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.to_string().contains("one requester may have waiting"), "{body}");
    assert_eq!(staged_rows(&state), 2, "a refused change stages nothing");
}
