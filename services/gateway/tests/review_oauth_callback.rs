//! A connector OAuth callback writes only into the connection, provider,
//! slot and credential its dance was started against, and only through the audited credential write.
//!
//! Began as four probes. The two that reproduced a defect, a connection replaced by another
//! connector and a newer credential overwritten with no event, now assert the refusal the fix
//! produces. The control (a remote start with no device enrolled) and its corroborating probe (a
//! callback after its starting session is revoked) reproduced none, and still complete. The other
//! refusals and the rollback came with the fix, and the success-path tests assert "Connected".
//! Synthetic credentials, an in-memory or scratch SQLite store, and a mock HTTP seam only: nothing
//! reaches a provider.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse, MockHttpClient};
use permaura_gateway::oauth_connect::{from_sealed_bytes, to_sealed_json};
use permaura_gateway::oauth_credential::{OAuthCredential, OAuthLayer};
use permaura_gateway::service::vault_passphrase;
use permaura_gateway::store::Store;
use permaura_gateway::vault_bundle::{self, BundlePayload, ImportOptions};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tokio::sync::{Notify, Semaphore};
use tower::ServiceExt;

const CONNECTION: &str = "review-gh";
const SLOT: &str = "sec_review-gh";
const CLIENT_SECRET: &str = "synthetic-client-secret";
const SECRET_WRITE: &str = "permaura.secret.write";
const OUT_OF_DATE: &str = "This authorization is out of date";

async fn send(app: &Router, method: &str, path: &str, body: Option<Value>, remote: bool) -> (StatusCode, String) {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    if remote {
        r = r.header("x-forwarded-for", "203.0.113.90");
    }
    let body = match body {
        Some(b) => {
            r = r.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(r.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    (status, String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap())
}

async fn create(app: &Router, preset: &str) {
    let (status, body) =
        send(app, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": preset, "name": "Review", "id": CONNECTION })), false)
            .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn delete(app: &Router) {
    let (status, body) = send(app, "DELETE", &format!("/v1/connections/{CONNECTION}"), None, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn write_credential(app: &Router, value: &str) {
    let (status, body) =
        send(app, "POST", &format!("/v1/connections/{CONNECTION}/credential"), Some(json!({ "value": value })), false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn app_over(state: &AppState) -> Router {
    build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
}

async fn setup() -> (AppState, Router, Arc<MockHttpClient>) {
    common::isolate_from_the_real_install();
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::in_memory_seeded_with_http(http.clone());
    let app = app_over(&state);
    create(&app, "github").await;
    (state, app, http)
}

/// Start the dance and return its `state`.
async fn start(app: &Router, remote: bool) -> String {
    let (status, body) = send(
        app,
        "POST",
        &format!("/v1/connections/{CONNECTION}/oauth/start"),
        Some(json!({
            "client_id": "synthetic-client",
            "client_secret": CLIENT_SECRET,
            "redirect_uri": "http://127.0.0.1:7376/oauth/callback"
        })),
        remote,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let j: Value = serde_json::from_str(&body).unwrap();
    j["authorize_url"].as_str().unwrap().split("state=").nth(1).unwrap().split('&').next().unwrap().to_string()
}

async fn complete(app: &Router, st: &str) -> String {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(format!("/oauth/callback?code=synthetic-code&state={st}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}

/// Answer the code exchange with `token`, then complete the callback.
async fn callback(app: &Router, http: &MockHttpClient, st: &str, token: &str) -> String {
    http.push_response(HttpResponse::json(200, json!({ "access_token": token, "refresh_token": "synthetic-refresh", "expires_in": 3600 })));
    complete(app, st).await
}

fn stored(store: &dyn Store) -> Option<String> {
    let c = store.get_connection(CONNECTION).unwrap()?;
    let s = store.get_secret(&c.secret_id).unwrap()?;
    Some(String::from_utf8(permaura_core::open(&s.sealed, vault_passphrase()).unwrap().to_vec()).unwrap())
}

fn secret_writes(store: &dyn Store) -> Vec<Value> {
    store
        .audit_events(None)
        .unwrap()
        .into_iter()
        .filter(|e| e.payload.action == SECRET_WRITE)
        .map(|e| serde_json::to_value(&e).unwrap())
        .collect()
}

fn token_exchanges(http: &MockHttpClient) -> usize {
    http.requests().iter().filter(|r| r.form.as_ref().is_some_and(|f| f.get("grant_type").is_some())).count()
}

/// The first reproduction: GitHub's pending authorization completed into a Stripe connection
/// made under the same id, whose invocations then carried the GitHub token to Stripe.
#[tokio::test]
async fn a_callback_for_a_connection_replaced_by_another_connector_is_refused() {
    let (state, app, http) = setup().await;
    let st = start(&app, false).await;
    delete(&app).await;
    create(&app, "stripe").await;
    assert_eq!(state.service.store().get_connection(CONNECTION).unwrap().unwrap().connector, "stripe");

    let page = callback(&app, &http, &st, "synthetic-github-access").await;
    assert!(page.contains(OUT_OF_DATE) && page.contains("removed and made again"), "{page}");
    assert_eq!(stored(state.service.store().as_ref()), None, "the Stripe connection holds no GitHub token");
    assert_eq!(token_exchanges(&http), 0, "the code is not exchanged for a connection it no longer names");
    assert!(secret_writes(state.service.store().as_ref()).is_empty());
}

/// The same reuse with the same connector: a removed connection is a new incarnation even where its
/// replacement looks the same.
#[tokio::test]
async fn a_callback_for_a_connection_removed_and_made_again_is_refused() {
    let (state, app, http) = setup().await;
    let st = start(&app, false).await;
    delete(&app).await;
    create(&app, "github").await;

    let page = callback(&app, &http, &st, "synthetic-older-access").await;
    assert!(page.contains(OUT_OF_DATE), "{page}");
    assert_eq!(stored(state.service.store().as_ref()), None);
    assert_eq!(token_exchanges(&http), 0);
}

/// A vault import writes a bundle's connection verbatim, so one exported, removed and imported again
/// keeps its creation stamp; the removal bumped the connection's watch, and that alone refuses the dance.
#[tokio::test]
async fn a_callback_for_a_connection_removed_and_imported_again_is_refused() {
    let (state, app, http) = setup().await;
    let store = state.service.store();
    let exported = store.get_connection(CONNECTION).unwrap().unwrap();
    let st = start(&app, false).await;
    delete(&app).await;
    let bundle = BundlePayload { connections: vec![exported.clone()], ..Default::default() };
    vault_bundle::apply(store.as_ref(), bundle, &ImportOptions::default(), |_, _, _| Ok(())).unwrap();
    assert_eq!(store.get_connection(CONNECTION).unwrap().unwrap().created_at, exported.created_at);

    let page = callback(&app, &http, &st, "synthetic-older-access").await;
    assert!(page.contains(OUT_OF_DATE) && page.contains("removed and made again"), "{page}");
    assert_eq!(stored(store.as_ref()), None);
    assert_eq!(token_exchanges(&http), 0);
}

/// A second connection bound to the same slot, as the seeded GitHub connection and `http.request` share one.
fn put_sibling(store: &dyn Store) {
    let mut sibling = store.get_connection(CONNECTION).unwrap().unwrap();
    sibling.id = "review-gh-sibling".into();
    sibling.capabilities = vec![];
    store.put_connection(sibling).unwrap();
}

/// Deleting another connection that shares the slot keeps the slot and its credential, so it does not
/// refuse a dance on the connection that remains.
#[tokio::test]
async fn deleting_a_sibling_sharing_the_slot_does_not_refuse_the_dance() {
    let (state, app, http) = setup().await;
    write_credential(&app, "synthetic-shared-key").await;
    let store = state.service.store();
    put_sibling(store.as_ref());
    let st = start(&app, false).await;
    let (status, body) = send(&app, "DELETE", "/v1/connections/review-gh-sibling", None, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(stored(store.as_ref()).as_deref(), Some("synthetic-shared-key"), "the shared slot is kept");

    assert!(callback(&app, &http, &st, "synthetic-survivor-access").await.contains("Connected"));
    assert!(stored(store.as_ref()).unwrap().contains("synthetic-survivor-access"));
}

/// The other way round: the dance's own connection removed while a sibling keeps the slot, then imported
/// again with its stamp, is refused on its removal alone.
#[tokio::test]
async fn a_connection_removed_while_its_slot_is_shared_and_imported_again_is_refused() {
    let (state, app, http) = setup().await;
    write_credential(&app, "synthetic-shared-key").await;
    let store = state.service.store();
    put_sibling(store.as_ref());
    let exported = store.get_connection(CONNECTION).unwrap().unwrap();
    let st = start(&app, false).await;
    delete(&app).await;
    let bundle = BundlePayload { connections: vec![exported], ..Default::default() };
    vault_bundle::apply(store.as_ref(), bundle, &ImportOptions::default(), |_, _, _| Ok(())).unwrap();
    assert_eq!(stored(store.as_ref()).as_deref(), Some("synthetic-shared-key"));

    let page = callback(&app, &http, &st, "synthetic-older-access").await;
    assert!(page.contains(OUT_OF_DATE) && page.contains("removed and made again"), "{page}");
    assert_eq!(stored(store.as_ref()).as_deref(), Some("synthetic-shared-key"));
    assert_eq!(token_exchanges(&http), 0);
}

/// The second reproduction: a credential written after the dance began was replaced by the
/// older tab's callback, with nothing in the chain.
#[tokio::test]
async fn a_callback_older_than_the_credential_is_refused_and_writes_nothing() {
    let (state, app, http) = setup().await;
    let st = start(&app, false).await;
    write_credential(&app, "synthetic-newer-credential").await;
    let store = state.service.store();
    let before = store.audit_len().unwrap();

    let page = callback(&app, &http, &st, "synthetic-older-oauth-access").await;
    assert!(page.contains(OUT_OF_DATE) && page.contains("credential changed"), "{page}");
    assert_eq!(stored(store.as_ref()).as_deref(), Some("synthetic-newer-credential"));
    assert_eq!(store.audit_len().unwrap(), before, "a refused callback writes nothing");
    assert_eq!(token_exchanges(&http), 0);
}

/// Of two dances the operator opened, the one completed second is the older one by then, and it does
/// not undo the first.
#[tokio::test]
async fn a_second_dance_completing_after_the_first_is_refused() {
    let (state, app, http) = setup().await;
    let older = start(&app, false).await;
    let newer = start(&app, false).await;
    assert!(callback(&app, &http, &newer, "synthetic-newer-access").await.contains("Connected"));

    let page = callback(&app, &http, &older, "synthetic-older-access").await;
    assert!(page.contains(OUT_OF_DATE), "{page}");
    assert!(stored(state.service.store().as_ref()).unwrap().contains("synthetic-newer-access"));
}

/// A write that reaches the slot without bumping the watch is still seen when it is anything but an
/// OAuth bundle for the same app, because the slot's contents are compared too.
#[tokio::test]
async fn a_credential_replaced_by_an_unwatched_write_is_still_seen() {
    let (state, app, http) = setup().await;
    write_credential(&app, "synthetic-original-key").await;
    let st = start(&app, false).await;
    let store = state.service.store();
    let sealed = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, vault_passphrase(), b"synthetic-replacement-key").unwrap();
    let metadata = store.get_secret(SLOT).unwrap().unwrap().metadata;
    store.put_secret(permaura_core::SecretRecord { id: SLOT.into(), sealed, metadata }).unwrap();

    let page = callback(&app, &http, &st, "synthetic-older-access").await;
    assert!(page.contains(OUT_OF_DATE), "{page}");
    assert_eq!(stored(store.as_ref()).as_deref(), Some("synthetic-replacement-key"));
}

fn oauth_bundle(access: &str, refresh: &str) -> OAuthCredential {
    OAuthCredential { token_auth: Default::default(),
        layer: OAuthLayer::ByoApp,
        provider: "github".into(),
        access_token: access.into(),
        refresh_token: Some(refresh.into()),
        expires_at: 0,
        scopes: vec![],
        token_url: "https://github.com/login/oauth/access_token".into(),
        client_id: Some("synthetic-client".into()),
        client_secret: Some(CLIENT_SECRET.into()),
    }
}

fn sealed_bundle(c: &OAuthCredential) -> permaura_core::SealedSecret {
    permaura_core::seal(permaura_core::Cipher::Aes256Gcm, vault_passphrase(), to_sealed_json(c).unwrap().as_bytes()).unwrap()
}

/// A reconnect over an OAuth credential that refreshed while the operator was at the provider is the
/// ordinary case, not a stale one: a rotation keeps the app and the reconnect still lands.
#[tokio::test]
async fn a_refresh_rotation_during_a_reconnect_does_not_refuse_it() {
    let (state, app, http) = setup().await;
    let store = state.service.store();
    let first = sealed_bundle(&oauth_bundle("synthetic-first-access", "synthetic-first-refresh"));
    store.put_secret(permaura_core::SecretRecord { id: SLOT.into(), sealed: first.clone(), metadata: Default::default() }).unwrap();
    let st = start(&app, false).await;
    let rotated = sealed_bundle(&oauth_bundle("synthetic-rotated-access", "synthetic-rotated-refresh"));
    assert!(store.put_secret_if_unchanged(SLOT, &first, rotated).unwrap(), "the rotation lands as a refresh writes it");

    let page = callback(&app, &http, &st, "synthetic-reconnected-access").await;
    assert!(page.contains("Connected"), "{page}");
    let now = from_sealed_bytes(stored(store.as_ref()).unwrap().as_bytes()).unwrap();
    assert_eq!(now.access_token, "synthetic-reconnected-access");
}

/// A deliberate write of a bundle for the same app looks like a refresh to the contents comparison, and
/// the watch its writer bumped is what refuses the older dance.
#[tokio::test]
async fn a_same_app_bundle_written_deliberately_during_a_dance_is_refused() {
    let (state, app, http) = setup().await;
    let first = to_sealed_json(&oauth_bundle("synthetic-first-access", "synthetic-first-refresh")).unwrap();
    write_credential(&app, first.expose()).await;
    let st = start(&app, false).await;
    let newer = to_sealed_json(&oauth_bundle("synthetic-newer-access", "synthetic-newer-refresh")).unwrap();
    write_credential(&app, newer.expose()).await;

    let page = callback(&app, &http, &st, "synthetic-older-access").await;
    assert!(page.contains(OUT_OF_DATE) && page.contains("credential changed"), "{page}");
    assert_eq!(stored(state.service.store().as_ref()).as_deref(), Some(newer.expose()));
}

/// The contents comparison's limit: a bundle for the same app that reaches the slot without bumping the
/// watch is admitted as a refresh would be, which is why every deliberate writer bumps it.
#[tokio::test]
async fn a_same_app_bundle_written_without_a_watch_bump_is_admitted() {
    let (state, app, http) = setup().await;
    let store = state.service.store();
    let first = sealed_bundle(&oauth_bundle("synthetic-first-access", "synthetic-first-refresh"));
    store.put_secret(permaura_core::SecretRecord { id: SLOT.into(), sealed: first, metadata: Default::default() }).unwrap();
    let st = start(&app, false).await;
    let other = sealed_bundle(&oauth_bundle("synthetic-other-access", "synthetic-other-refresh"));
    store.put_secret(permaura_core::SecretRecord { id: SLOT.into(), sealed: other, metadata: Default::default() }).unwrap();

    let page = callback(&app, &http, &st, "synthetic-reconnected-access").await;
    assert!(page.contains("Connected"), "{page}");
    let now = from_sealed_bytes(stored(store.as_ref()).unwrap().as_bytes()).unwrap();
    assert_eq!(now.access_token, "synthetic-reconnected-access");
}

/// An HTTP seam that holds the code exchange until the test releases it.
struct HeldExchange {
    entered: Notify,
    release: Semaphore,
    exchanged: AtomicBool,
}

#[async_trait]
impl HttpClient for HeldExchange {
    async fn send(&self, _r: HttpRequest) -> anyhow::Result<HttpResponse> {
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
        self.exchanged.store(true, Ordering::SeqCst);
        Ok(HttpResponse::json(200, json!({ "access_token": "synthetic-exchanged-access", "refresh_token": "synthetic-refresh", "expires_in": 3600 })))
    }
}

/// The exchange is an await: a credential written while it is in flight is seen by the check made
/// in the unit of work that writes, not only by the one made before the exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_written_during_the_code_exchange_is_kept() {
    common::isolate_from_the_real_install();
    let http = Arc::new(HeldExchange { entered: Notify::new(), release: Semaphore::new(0), exchanged: AtomicBool::new(false) });
    let state = AppState::in_memory_seeded_with_http(http.clone());
    let app = app_over(&state);
    create(&app, "github").await;
    let st = start(&app, false).await;

    let pending = tokio::spawn({
        let app = app.clone();
        async move { complete(&app, &st).await }
    });
    http.entered.notified().await;
    write_credential(&app, "synthetic-written-mid-exchange").await;
    let store = state.service.store();
    let before = store.audit_len().unwrap();
    http.release.add_permits(1);
    let page = pending.await.unwrap();

    assert!(http.exchanged.load(Ordering::SeqCst), "the refusal came after the exchange");
    assert!(page.contains(OUT_OF_DATE), "{page}");
    assert_eq!(stored(store.as_ref()).as_deref(), Some("synthetic-written-mid-exchange"));
    assert_eq!(store.audit_len().unwrap(), before);
}

/// The ordinary path, which still connects and still refuses a replay, writes
/// exactly one credential-write event, naming the session that started the dance and carrying no
/// token, code, state or client secret.
#[tokio::test]
async fn a_completed_callback_writes_one_event_naming_who_started_it() {
    let (state, app, http) = setup().await;
    let st = start(&app, false).await;
    let store = state.service.store();
    let operator = store.session_by_token(seed::DEMO_TOKEN).unwrap().unwrap();
    let before = store.audit_len().unwrap();

    let page = callback(&app, &http, &st, "synthetic-access").await;
    assert!(page.contains("Connected"), "{page}");
    assert!(stored(store.as_ref()).unwrap().contains("synthetic-access"));
    assert_eq!(store.audit_len().unwrap(), before + 1, "exactly one event");
    let events = secret_writes(store.as_ref());
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["payload"]["session_id"], json!(operator.id));
    assert_eq!(event["payload"]["decision"], json!("allow"));
    assert_eq!(event["payload"]["summary"]["connection_id"], json!(CONNECTION));
    assert_eq!(event["payload"]["summary"]["secret_id"], json!(SLOT));
    assert_eq!(event["payload"]["summary"]["provider"], json!("github"));
    assert_eq!(event["payload"]["summary"]["remote"], json!(false));
    let text = event.to_string();
    for secret in ["synthetic-access", "synthetic-refresh", "synthetic-code", st.as_str(), CLIENT_SECRET, seed::DEMO_TOKEN] {
        assert!(!text.contains(secret), "the audit event carries secret material: {text}");
    }

    let replay = callback(&app, &http, &st, "synthetic-replayed-access").await;
    assert!(replay.contains("This authorization has expired"), "{replay}");
    assert!(stored(store.as_ref()).unwrap().contains("synthetic-access"));
    assert_eq!(store.audit_len().unwrap(), before + 1);
}

/// A dance whose starting session was revoked before the callback still completes, as it did before
/// the fix (the corroborating probe, which reproduced no defect), and its record names that session.
#[tokio::test]
async fn a_callback_after_its_starting_session_is_revoked_names_that_session() {
    let (state, app, http) = setup().await;
    let st = start(&app, false).await;
    let store = state.service.store();
    let session = store.session_by_token(seed::DEMO_TOKEN).unwrap().unwrap();
    store.revoke_session(&session.id).unwrap();

    assert!(callback(&app, &http, &st, "synthetic-revoked-access").await.contains("Connected"));
    assert!(stored(store.as_ref()).unwrap().contains("synthetic-revoked-access"));
    let events = secret_writes(store.as_ref());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["payload"]["session_id"], json!(session.id));
}

/// The control: a remote start on a gateway with no device enrolled completes, and its
/// record says it came over the broker.
#[tokio::test]
async fn a_remote_start_without_devices_completes_and_says_so() {
    let (state, app, http) = setup().await;
    assert!(!state.service.any_device_enrolled());
    let st = start(&app, true).await;

    assert!(callback(&app, &http, &st, "synthetic-remote-access").await.contains("Connected"));
    assert!(stored(state.service.store().as_ref()).unwrap().contains("synthetic-remote-access"));
    let events = secret_writes(state.service.store().as_ref());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["payload"]["summary"]["remote"], json!(true));
}

fn pair_a_device(state: &AppState) {
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let pubkey = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key("device:owner", &pubkey));
}

/// `start` refuses a remote dance while a device is enrolled, so one started before the first
/// device enrolled is refused at its callback once that device would hold it, before its code is exchanged.
#[tokio::test]
async fn a_remote_dance_is_refused_once_a_device_enrolls_under_it() {
    let (state, app, http) = setup().await;
    let st = start(&app, true).await;
    pair_a_device(&state);
    assert!(state.service.control_plane_hold_required(true));

    let page = callback(&app, &http, &st, "synthetic-remote-access").await;
    assert!(page.contains(OUT_OF_DATE) && page.contains("device was enrolled"), "{page}");
    assert_eq!(stored(state.service.store().as_ref()), None);
    assert_eq!(token_exchanges(&http), 0);
    assert!(secret_writes(state.service.store().as_ref()).is_empty());
}

/// The callback refuses only when a device would now hold the write: with the floor opted down to Approve
/// on a self-run gateway, a remote dance whose first device enrolls during the window still completes.
#[tokio::test]
async fn a_remote_dance_completes_when_a_device_enrolls_under_an_opted_down_floor() {
    let (state, app, http) = setup().await;
    state.service.set_approval_floor(Some(permaura_gateway::service::ApprovalFloor::Approve)).unwrap();
    let st = start(&app, true).await;
    pair_a_device(&state);
    assert!(state.service.any_device_enrolled());
    assert!(!state.service.control_plane_hold_required(true));

    let page = callback(&app, &http, &st, "synthetic-opted-down-access").await;
    assert!(page.contains("Connected"), "{page}");
    assert!(stored(state.service.store().as_ref()).unwrap().contains("synthetic-opted-down-access"));
    assert_eq!(secret_writes(state.service.store().as_ref()).len(), 1);
}

/// The same, with the device enrolled while the code exchange is in flight: the check in the unit that writes sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remote_dance_is_refused_when_a_device_enrolls_during_the_code_exchange() {
    common::isolate_from_the_real_install();
    let http = Arc::new(HeldExchange { entered: Notify::new(), release: Semaphore::new(0), exchanged: AtomicBool::new(false) });
    let state = AppState::in_memory_seeded_with_http(http.clone());
    let app = app_over(&state);
    create(&app, "github").await;
    let st = start(&app, true).await;

    let pending = tokio::spawn({
        let app = app.clone();
        async move { complete(&app, &st).await }
    });
    http.entered.notified().await;
    pair_a_device(&state);
    http.release.add_permits(1);
    let page = pending.await.unwrap();

    assert!(http.exchanged.load(Ordering::SeqCst), "the refusal came after the exchange");
    assert!(page.contains(OUT_OF_DATE) && page.contains("device was enrolled"), "{page}");
    assert_eq!(stored(state.service.store().as_ref()), None);
    assert!(secret_writes(state.service.store().as_ref()).is_empty());
}

/// A device enrolled under a dance started from the gateway's own host holds nothing: that dance completes.
#[tokio::test]
async fn a_local_dance_completes_when_a_device_enrolls_under_it() {
    let (state, app, http) = setup().await;
    let st = start(&app, false).await;
    pair_a_device(&state);

    assert!(callback(&app, &http, &st, "synthetic-local-access").await.contains("Connected"));
    assert!(stored(state.service.store().as_ref()).unwrap().contains("synthetic-local-access"));
}

/// The credential and its event commit or roll back together, so a callback
/// whose event cannot be appended leaves the credential that was there.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_callback_whose_event_cannot_be_written_leaves_the_old_credential() {
    use permaura_gateway::service::EnforcementService;
    use permaura_gateway::store::sqlite::SqliteStore;

    common::isolate_from_the_real_install();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("permaura-oauth-audit-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("gateway.db");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&db.to_string_lossy()).unwrap());
    seed::seed(store.as_ref()).unwrap();
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::new(EnforcementService::new(store.clone(), http.clone()));
    let app = app_over(&state);
    create(&app, "github").await;
    write_credential(&app, "synthetic-old-credential").await;
    let st = start(&app, false).await;
    let before = store.audit_len().unwrap();

    let sql = rusqlite::Connection::open(&db).unwrap();
    sql.execute_batch("CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'synthetic: the audit write failed'); END;")
        .unwrap();
    let page = callback(&app, &http, &st, "synthetic-unrecorded-access").await;
    sql.execute_batch("DROP TRIGGER refuse_audit;").unwrap();

    assert!(page.contains("Could not store the credential"), "{page}");
    assert_eq!(stored(store.as_ref()).as_deref(), Some("synthetic-old-credential"), "the credential is put back");
    assert_eq!(store.audit_len().unwrap(), before);
}

async fn get_page(app: &Router, path: &str) -> String {
    let resp = app.clone().oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
    String::from_utf8(to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}

/// The callback is unauthenticated and served on the gateway's own hostname, so an error form with no live dance behind it shows a fixed sentence, never text the link's author chose.
#[tokio::test]
async fn an_error_callback_with_no_live_dance_shows_none_of_the_callers_text() {
    let (_state, app, _http) = setup().await;
    let spoof = "Your%20Permaura%20gateway%20must%20be%20re-verified%20at%20evil.example";
    for path in [
        format!("/oauth/callback?error=access_denied&error_description={spoof}"),
        format!("/oauth/callback?error=access_denied&error_description={spoof}&state=not-a-live-state"),
        format!("/oauth/callback?error={spoof}"),
    ] {
        let page = get_page(&app, &path).await;
        assert!(!page.contains("re-verified") && !page.contains("evil.example"), "{path} rendered the caller's text: {page}");
    }
}

/// A provider's refusal that names a live dance ends that dance, so its state cannot complete afterwards, and the provider's own words are shown.
#[tokio::test]
async fn an_error_callback_for_a_live_dance_ends_it_and_shows_the_providers_words() {
    let (_state, app, http) = setup().await;
    let st = start(&app, false).await;
    let page = get_page(&app, &format!("/oauth/callback?error=access_denied&error_description=The%20user%20declined&state={st}")).await;
    assert!(page.contains("The user declined"), "{page}");
    let after = callback(&app, &http, &st, "synthetic-token").await;
    assert!(after.contains("expired"), "the refused dance cannot complete: {after}");
    assert_eq!(token_exchanges(&http), 0, "no code was exchanged");
}
