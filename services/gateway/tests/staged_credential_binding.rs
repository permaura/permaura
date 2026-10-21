//! A held credential change promotes the bytes the device signed for and nothing else.
//!
//! A remote credential write is held by reference: the value is sealed under a staged row (`sec:staging:<32 hex>`,
//! outside the `sec_` namespace every connection's slot is derived in) and the device signs the hold's params. Two things make
//! that binding real. The staged row is writable by no route but the hold that parked it (the generic secret create,
//! rotate and delete, and a vault import, all refuse it), and the params carry a digest of the staged envelope, so a
//! row that was rewritten anyway is refused at promotion with a readable error and an audit row rather than promoted.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{seal, Cipher, SecretRecord};
use permaura_gateway::service::vault_passphrase;
use common::build_router;
use permaura_gateway::{seed, AppState};
use tower::ServiceExt;

mod common;

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    remote: bool,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri).header("authorization", format!("Bearer {token}"));
    if remote {
        builder = builder.header("cf-ray", "abc123");
    }
    let req = match body {
        Some(b) => builder.header("content-type", "application/json").body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

fn approver_key(seed: u8) -> (String, ed25519_dalek::SigningKey) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    (STANDARD.encode(sk.verifying_key().to_bytes()), sk)
}

fn gateway_with_device(seed_byte: u8) -> (axum::Router, AppState, ed25519_dalek::SigningKey) {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, sk) = approver_key(seed_byte);
    assert!(state.service.trust_approver_key_for("device:approver", &pubkey, Some("user_approver")).unwrap());
    (app, state, sk)
}

async fn device_sign(
    app: &axum::Router,
    token: &str,
    approval_id: &str,
    approver: &str,
    sk: &ed25519_dalek::SigningKey,
) -> (StatusCode, serde_json::Value) {
    device_decide(app, token, approval_id, approver, sk, true).await
}

async fn device_decide(
    app: &axum::Router,
    token: &str,
    approval_id: &str,
    approver: &str,
    sk: &ed25519_dalek::SigningKey,
    approve: bool,
) -> (StatusCode, serde_json::Value) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use permaura_relay::{approval_display_full_digest_of, approval_result_preimage_v3, sign};
    let (_s, appr) = send(app, "GET", &format!("/v1/approvals/{approval_id}"), token, false, None).await;
    let request_hash = appr["request_hash"].as_str().unwrap().to_string();
    let job_id = appr["job_id"].as_str().unwrap().to_string();
    let audience = appr["approval_audience"].as_str().expect("audience").to_string();
    let shown = approval_display_full_digest_of(&appr).expect("full rendering");
    let decided_at = now_ms();
    let preimage =
        approval_result_preimage_v3(&audience, &job_id, approval_id, approve, &request_hash, &shown, approver, decided_at);
    let device_sig = sign(sk, &preimage);
    send(
        app,
        "POST",
        "/v1/approvals",
        token,
        false,
        Some(serde_json::json!({
            "approval_id": approval_id, "approve": approve, "approver": approver,
            "request_hash": request_hash, "decided_at": decided_at, "job_id": job_id,
            "approver_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
            "audience": audience, "display_digest": shown, "device_sig": device_sig,
        })),
    )
    .await
}

fn plaintext(state: &AppState, id: &str) -> Option<String> {
    state
        .service
        .store()
        .get_secret(id)
        .unwrap()
        .map(|r| String::from_utf8(permaura_core::open(&r.sealed, vault_passphrase()).unwrap().to_vec()).unwrap())
}

fn audit_events(state: &AppState) -> Vec<permaura_core::AuditEvent> {
    state.service.store().audit_events_from(0, 100_000).unwrap()
}

const LIVE_BEFORE: &str = "bt_demo_private_key_value";
const APPROVED_VALUE: &str = "value_the_device_approves";

/// Hold a remote credential change for the seeded Braintree connection; returns (approval id, staging id, live id).
async fn held_change(app: &axum::Router, state: &AppState) -> (String, String, String) {
    let (hs, hresp) = send(
        app,
        "POST",
        "/v1/connections/braintree_production/credential",
        seed::DEMO_TOKEN,
        true,
        Some(serde_json::json!({ "value": APPROVED_VALUE })),
    )
    .await;
    assert_eq!(hs, StatusCode::ACCEPTED, "a remote credential set is held: {hresp}");
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();
    let held = state.service.store().get_approval(&approval_id).unwrap().unwrap();
    let params = held.params.to_value_unbounded();
    let staging_id = params["staging_secret_id"].as_str().unwrap().to_string();
    let live_id = params["secret_id"].as_str().unwrap().to_string();
    let digest = params["staged_sha256"].as_str().expect("the hold binds a digest of the staged envelope");
    assert_eq!(digest.len(), 64, "hex sha256: {digest}");
    assert_eq!(plaintext(state, &live_id).as_deref(), Some(LIVE_BEFORE));
    (approval_id, staging_id, live_id)
}

/// The first reproduction: a remote `POST /v1/secrets/<staging>/rotate` from a second caller.
#[tokio::test]
async fn a_remote_rotate_of_the_staged_row_is_refused_and_the_device_approved_value_lands() {
    let (app, state, sk) = gateway_with_device(41);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;
    let audit_before = audit_events(&state).len();

    let (rs, rresp) = send(
        &app,
        "POST",
        &format!("/v1/secrets/{staging_id}/rotate"),
        seed::DEMO_TOKEN,
        true,
        Some(serde_json::json!({ "value": "attacker_value" })),
    )
    .await;
    assert_eq!(rs, StatusCode::FORBIDDEN, "{rresp}");
    assert!(rresp["error"].as_str().unwrap_or_default().contains("parked for a device signature"), "{rresp}");
    assert_eq!(plaintext(&state, &staging_id).as_deref(), Some(APPROVED_VALUE), "the staged row is untouched");
    assert_eq!(audit_events(&state).len(), audit_before, "a refused write records nothing it did not do");

    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "{sresp}");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(APPROVED_VALUE));
    assert!(state.service.store().get_secret(&staging_id).unwrap().is_none(), "the staged row is consumed");
}

/// The second reproduction: a remote `POST /v1/secrets` naming the staging id, and a delete of it.
#[tokio::test]
async fn a_remote_create_or_delete_of_the_staged_row_is_refused() {
    let (app, state, sk) = gateway_with_device(42);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;

    let (cs, cresp) = send(
        &app,
        "POST",
        "/v1/secrets",
        seed::DEMO_TOKEN,
        true,
        Some(serde_json::json!({ "id": staging_id, "value": "attacker_value_via_create" })),
    )
    .await;
    assert_eq!(cs, StatusCode::FORBIDDEN, "{cresp}");
    let (ds, dresp) = send(&app, "DELETE", &format!("/v1/secrets/{staging_id}"), seed::DEMO_TOKEN, true, None).await;
    assert_eq!(ds, StatusCode::FORBIDDEN, "{dresp}");
    // Loopback too: the owner's own agents on the host are not the hold's author either.
    let (ls, lresp) = send(
        &app,
        "POST",
        &format!("/v1/secrets/{staging_id}/rotate"),
        seed::DEMO_TOKEN,
        false,
        Some(serde_json::json!({ "value": "local_agent_value" })),
    )
    .await;
    assert_eq!(ls, StatusCode::FORBIDDEN, "{lresp}");
    assert_eq!(plaintext(&state, &staging_id).as_deref(), Some(APPROVED_VALUE));

    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "{sresp}");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(APPROVED_VALUE));
}

/// A vault import may not name a staged row either, as a secret it writes or as the secret a connection or
/// capability it adds would bind.
#[tokio::test]
async fn a_vault_import_may_not_write_or_bind_a_staged_row() {
    let (app, state, _sk) = gateway_with_device(43);
    let (_approval_id, staging_id, _live_id) = held_change(&app, &state).await;
    let bundle_with = |secrets: serde_json::Value, connections: serde_json::Value| {
        let payload = serde_json::json!({
            "connections": connections, "policies": [], "grants": [], "capabilities": [], "secrets": secrets, "agents": [],
        });
        let bundle = permaura_core::seal_bundle(
            b"correct horse battery staple",
            payload,
            1_754_500_000_000,
            permaura_core::BundleSource { gateway_id: "gw_other".into(), mode: "self-run".into() },
        )
        .unwrap();
        serde_json::json!({ "bundle": serde_json::to_value(bundle).unwrap(), "passphrase": "correct horse battery staple", "on_conflict": "replace" })
    };
    let as_secret = bundle_with(
        serde_json::json!([{ "id": staging_id, "metadata": {}, "custody": "local_vault", "value": "YXR0YWNrZXJfdmFsdWVfdmlhX2ltcG9ydA==" }]),
        serde_json::json!([]),
    );
    let (s1, r1) = send(&app, "POST", "/v1/vault/import", seed::DEMO_TOKEN, false, Some(as_secret)).await;
    assert_eq!(s1, StatusCode::FORBIDDEN, "{r1}");
    assert!(r1["error"].as_str().unwrap_or_default().contains("parked for a device signature"), "{r1}");
    let as_binding = bundle_with(
        serde_json::json!([]),
        serde_json::json!([{ "id": "takeover", "connector": "github", "name": "Takeover", "secret_id": staging_id, "capabilities": [] }]),
    );
    let (s2, r2) = send(&app, "POST", "/v1/vault/import", seed::DEMO_TOKEN, false, Some(as_binding)).await;
    assert_ne!(s2, StatusCode::OK, "{r2}");
    assert!(state.service.store().get_connection("takeover").unwrap().is_none(), "nothing bound the staged row");
    assert_eq!(plaintext(&state, &staging_id).as_deref(), Some(APPROVED_VALUE));
}

/// The digest binding itself: a staged row rewritten by any means after the hold is refused at promotion, the
/// live credential is left as it was, the hold is closed as unresolved, and the chain says why.
#[tokio::test]
async fn a_staged_row_rewritten_after_the_hold_is_not_promoted() {
    let (app, state, sk) = gateway_with_device(44);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;

    // Straight through the store, which is what every route now refuses: the binding has to hold even then.
    let store = state.service.store();
    let staged = store.get_secret(&staging_id).unwrap().unwrap();
    let swapped = seal(Cipher::Aes256Gcm, vault_passphrase(), b"attacker_value_behind_the_routes").unwrap();
    store.put_secret(SecretRecord { id: staging_id.clone(), sealed: swapped, metadata: staged.metadata }).unwrap();

    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::CONFLICT, "{sresp}");
    let error = sresp["error"].as_str().unwrap_or_default();
    assert!(error.contains("not the one this approval was held for"), "{sresp}");
    assert!(error.contains("Ask for the credential change again"), "{sresp}");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(LIVE_BEFORE), "the live credential did not move");

    let approval = store.get_approval(&approval_id).unwrap().unwrap();
    assert_ne!(approval.status, "approved", "{}", approval.status);
    assert!(store.get_secret(&staging_id).unwrap().is_none(), "the refused hold's claim is spent, so its staged row is released");
    let refusal = audit_events(&state)
        .into_iter()
        .find(|e| e.payload.action == "permaura.secret.write" && e.payload.decision == "deny")
        .expect("the refusal is in the chain");
    assert_eq!(refusal.payload.summary["staging_secret_id"], staging_id);
    assert_eq!(refusal.payload.summary["connection_id"], "braintree_production");
    assert_eq!(refusal.payload.summary["expected_sha256"], approval.params.to_value_unbounded()["staged_sha256"]);
    assert_ne!(refusal.payload.summary["found_sha256"], approval.params.to_value_unbounded()["staged_sha256"]);
}

// ── the staged slot and the derived slot, by every other route ──────────────────────────────────────

/// Counts every request the gateway sends upstream and answers each with an empty list.
#[derive(Default)]
struct Counting(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl permaura_gateway::connectors::HttpClient for Counting {
    async fn send(
        &self,
        _request: permaura_gateway::connectors::HttpRequest,
    ) -> anyhow::Result<permaura_gateway::connectors::HttpResponse> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        anyhow::bail!("no upstream is reachable from this test")
    }
}

fn gateway_with_device_and_http(seed_byte: u8, http: std::sync::Arc<Counting>) -> (axum::Router, AppState) {
    common::isolate_from_the_real_install();
    let state = AppState::in_memory_seeded_with_http(http);
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, _sk) = approver_key(seed_byte);
    assert!(state.service.trust_approver_key_for("device:approver", &pubkey, Some("user_approver")).unwrap());
    (app, state)
}

/// A WordPress connection as a hand-built bundle carries it: no `secret_id`, and a source on a host the bundle chose.
fn wordpress_connection(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id, "connector": "wordpress", "name": "Site", "label": "WordPress", "secret_id": "", "capabilities": [],
        "source": {
            "kind": "wordpress", "url": "https://attacker.example", "rest_root": "https://attacker.example/wp-json/",
            "abilities": true, "synced_at": 0,
        },
    })
}

fn import_body(connections: serde_json::Value, secrets: serde_json::Value) -> serde_json::Value {
    let payload = serde_json::json!({
        "connections": connections, "policies": [], "grants": [], "capabilities": [], "secrets": secrets, "agents": [],
    });
    let bundle = permaura_core::seal_bundle(
        b"correct horse battery staple",
        payload,
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_other".into(), mode: "self-run".into() },
    )
    .unwrap();
    serde_json::json!({ "bundle": serde_json::to_value(bundle).unwrap(), "passphrase": "correct horse battery staple", "on_conflict": "skip" })
}

fn sealed(value: &[u8]) -> permaura_core::SealedSecret {
    seal(Cipher::Aes256Gcm, vault_passphrase(), value).unwrap()
}

/// No connection can derive a staged row's id: a parked change is minted under `sec:staging:`, which no `sec_<id>` slot can hold. A connection named after the staged id, in the shape gateway 1.3.46 parked changes under, is an ordinary connection with its own slot, and a bundle that binds the staged row by name is refused.
#[tokio::test]
async fn no_connection_reaches_a_staged_row_and_one_named_after_it_is_ordinary() {
    let (app, state, sk) = gateway_with_device(45);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;
    let minted = staging_id.strip_prefix(permaura_gateway::secret_inventory::STAGING_SECRET_PREFIX).expect("a staged id");
    assert!(!staging_id.starts_with("sec_"), "no derived slot can name it: {staging_id}");
    let named_after = format!("staging_{minted}");

    let binds_it = serde_json::json!({ "id": "binds_staged", "connector": "github", "name": "Binds", "label": "GitHub", "secret_id": staging_id, "capabilities": [] });
    let (s, r) = send(&app, "POST", "/v1/vault/import", seed::DEMO_TOKEN, false, Some(import_body(serde_json::json!([binds_it]), serde_json::json!([])))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{r}");
    assert!(r["error"].as_str().unwrap_or_default().contains("parked for a device signature"), "{r}");

    let ssh = serde_json::json!({ "id": named_after, "connector": "ssh", "name": "Named after it", "ssh": { "host": "box.example", "user": "deploy", "insecure": true, "sftp_root": "/srv" } });
    let (s, r) = send(&app, "POST", "/v1/connections", seed::DEMO_TOKEN, false, Some(ssh)).await;
    assert_eq!(s, StatusCode::CREATED, "nothing reserves it: {r}");
    let (s, r) = send(&app, "POST", &format!("/v1/connections/{named_after}/credential"), seed::DEMO_TOKEN, false, Some(serde_json::json!({ "value": "its own" }))).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let slot = state.service.store().get_connection(&named_after).unwrap().unwrap().secret_id;
    assert_eq!(slot, format!("sec_staging_{minted}"));
    assert_eq!(plaintext(&state, &slot).as_deref(), Some("its own"));
    assert_eq!(plaintext(&state, &staging_id).as_deref(), Some(APPROVED_VALUE), "the staged row is untouched");

    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "the owner's change still promotes: {sresp}");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(APPROVED_VALUE));
    assert_eq!(plaintext(&state, &slot).as_deref(), Some("its own"));
}

/// An imported connection with an empty `secret_id` cannot reach the unbound credential in its derived slot: the import counts it as reach, and a re-sync of one already stored sends nothing.
#[tokio::test]
async fn an_unbound_credential_is_not_reached_through_an_imported_connections_derived_slot() {
    let upstream = std::sync::Arc::new(Counting::default());
    let (app, state) = gateway_with_device_and_http(46, upstream.clone());
    let store = state.service.store();
    store.put_secret(SecretRecord { id: "sec_orphan_wp".into(), sealed: sealed(b"admin:unbound-application-password"), metadata: Default::default() }).unwrap();

    for remote in [true, false] {
        let (s, r) = send(&app, "POST", "/v1/vault/import", seed::DEMO_TOKEN, remote, Some(import_body(serde_json::json!([wordpress_connection("orphan_wp")]), serde_json::json!([])))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "remote={remote}: {r}");
        assert!(r["error"].as_str().unwrap_or_default().contains("connection orphan_wp using secret sec_orphan_wp"), "{r}");
    }
    assert!(store.get_connection("orphan_wp").unwrap().is_none());

    let planted: permaura_core::Connection = serde_json::from_value(wordpress_connection("orphan_wp")).unwrap();
    store.put_connection(planted).unwrap();
    for remote in [true, false] {
        let (s, r) = send(&app, "POST", "/v1/connections/orphan_wp/resync", seed::DEMO_TOKEN, remote, Some(serde_json::json!({ "sources": ["abilities"], "dry_run": true }))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "remote={remote}: {r}");
        assert!(r["error"].as_str().unwrap_or_default().contains("already holds a credential"), "{r}");
        let (s, r) = send(&app, "POST", "/v1/connections/orphan_wp/credential", seed::DEMO_TOKEN, remote, Some(serde_json::json!({ "value": "admin:replacement" }))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "remote={remote}: {r}");
    }
    assert_eq!(upstream.0.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing was sent to the bundle's host");
    assert_eq!(store.get_connection("orphan_wp").unwrap().unwrap().secret_id, "", "the slot was not bound");
    assert!(
        !audit_events(&state).iter().any(|e| e.payload.action == permaura_gateway::rest::ABILITIES_READ_ACTION),
        "no Abilities read happened"
    );
    assert_eq!(plaintext(&state, "sec_orphan_wp").as_deref(), Some("admin:unbound-application-password"));
}

/// A bundle the apply would refuse leaves no credential hold pending a device could still approve.
#[tokio::test]
async fn a_refused_import_parks_no_credential_hold() {
    let (app, state, _sk) = gateway_with_device(47);
    let ssh = serde_json::json!({ "id": "fill_target", "connector": "ssh", "name": "Fill", "ssh": { "host": "box.example", "user": "deploy", "insecure": true, "sftp_root": "/srv" } });
    let (s, r) = send(&app, "POST", "/v1/connections", seed::DEMO_TOKEN, false, Some(ssh)).await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    let fill = serde_json::json!([{ "id": "sec_fill_target", "metadata": {}, "custody": "local_vault", "value": "ZmlsbGVk" }]);

    let staged = permaura_gateway::secret_inventory::mint_staging_secret_id();
    for (refused, status) in [
        (serde_json::json!([{ "id": "binds_staged", "connector": "github", "name": "Binds", "label": "GitHub", "secret_id": staged, "capabilities": [] }]), StatusCode::FORBIDDEN),
        (serde_json::json!([{ "id": "permaura.policy.write", "connector": "github", "name": "Reserved", "label": "GitHub", "secret_id": "sec_x", "capabilities": [] }]), StatusCode::BAD_REQUEST),
    ] {
        let (s, r) = send(&app, "POST", "/v1/vault/import", seed::DEMO_TOKEN, true, Some(import_body(refused, fill.clone()))).await;
        assert_eq!(s, status, "{r}");
        let error = r["error"].as_str().unwrap_or_default();
        assert!(error.contains("parked for a device signature") || error.contains("is reserved"), "refused for what it binds or its id: {r}");
        let pending = state.service.store().list_approvals(Some("pending")).unwrap();
        assert!(pending.is_empty(), "a refused bundle parked a hold: {pending:?}");
        let staged = state.service.store().list_secret_ids().unwrap();
        assert!(!staged.iter().any(|id| permaura_gateway::secret_inventory::is_staging_secret_id(id)), "{staged:?}");
    }

    let (s, r) = send(&app, "POST", "/v1/vault/import", seed::DEMO_TOKEN, true, Some(import_body(serde_json::json!([]), fill))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "the same fill on its own is held as before: {r}");
}

// ── a hold an earlier build parked, and a staged row nothing can promote any more ───────────────────────

/// The probe in `held_before_digests.rs`, with the row moved where gateway 1.3.46 parked it: a change held with no digest and approved after the upgrade is refused with its own reason, the chain does not call it a rewrite, and its staged row does not outlive the claim the approval spent.
#[tokio::test]
async fn a_hold_from_before_digests_is_refused_without_a_tamper_record_and_leaves_nothing_behind() {
    let (app, state, sk) = gateway_with_device(61);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;
    let store = state.service.store();
    let legacy_id = as_parked_by_1_3_46(&state, &approval_id, &staging_id);

    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::CONFLICT, "a hold with no digest is never promoted: {sresp}");
    let error = sresp["error"].as_str().unwrap_or_default();
    assert!(error.contains("held before this version of the gateway") && error.contains("ask for it again"), "{sresp}");
    assert!(!error.contains("rewrote"), "nothing rewrote it: {sresp}");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(LIVE_BEFORE), "the live credential did not move");

    let refusal = audit_events(&state)
        .into_iter()
        .rev()
        .find(|e| e.payload.action == "permaura.secret.write" && e.payload.decision == "deny")
        .expect("the refusal is in the chain");
    let reason = refusal.payload.summary["reason"].as_str().unwrap_or_default().to_string();
    assert!(!reason.contains("changed after its hold was signed over"), "a pre-upgrade hold is recorded as a rewrite: {}", refusal.payload.summary);
    assert!(reason.contains("earlier gateway version"), "{}", refusal.payload.summary);
    assert!(refusal.payload.summary.get("expected_sha256").is_none(), "{}", refusal.payload.summary);
    assert_eq!(refusal.payload.summary["staging_secret_id"], legacy_id.as_str());

    assert!(store.get_secret(&legacy_id).unwrap().is_none(), "the sealed value parked for it does not outlive the hold");
    assert_eq!(store.get_approval(&approval_id).unwrap().unwrap().status, permaura_gateway::store::APPROVAL_UNRESOLVED);
}

/// Rewrite a fresh hold into what gateway 1.3.46 stored: its staged row under `sec_staging_` and no digest. Returns the legacy row's id.
fn as_parked_by_1_3_46(state: &AppState, approval_id: &str, staging_id: &str) -> String {
    let store = state.service.store();
    let legacy_id = format!("sec_staging_{}", staging_id.strip_prefix(permaura_gateway::secret_inventory::STAGING_SECRET_PREFIX).unwrap());
    let staged = store.get_secret(staging_id).unwrap().unwrap();
    store.put_secret(SecretRecord { id: legacy_id.clone(), ..staged }).unwrap();
    store.delete_secret(staging_id).unwrap();
    let mut held = store.get_approval(approval_id).unwrap().unwrap();
    let mut params = held.params.to_value_unbounded();
    let fields = params.as_object_mut().unwrap();
    fields.remove("staged_sha256");
    fields.insert("staging_secret_id".into(), legacy_id.clone().into());
    held.params = params.into();
    store.put_approval(held).unwrap();
    legacy_id
}

/// A 1.3.46 hold's row is an ordinary secret now: deleting it is held like any credential deletion rather than refused, and denying the hold releases it.
#[tokio::test]
async fn a_denied_hold_from_before_digests_releases_its_row_and_the_row_is_never_refused() {
    let (app, state, sk) = gateway_with_device(63);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;
    let legacy_id = as_parked_by_1_3_46(&state, &approval_id, &staging_id);

    let (ds, dresp) = send(&app, "DELETE", &format!("/v1/secrets/{legacy_id}"), seed::DEMO_TOKEN, false, None).await;
    assert_eq!(ds, StatusCode::ACCEPTED, "held for a device signature, not refused as parked: {dresp}");

    let (ss, sresp) = device_decide(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk, false).await;
    assert_eq!(ss, StatusCode::OK, "{sresp}");
    assert!(state.service.store().get_secret(&legacy_id).unwrap().is_none(), "the denial released the parked row");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(LIVE_BEFORE));
}

/// The refusal of a 1.3.46 hold releases its row only while nothing binds it: a connection named in that shape takes the row as its slot, and then the row is that connection's credential and stays.
#[tokio::test]
async fn a_refused_hold_from_before_digests_leaves_a_row_a_connection_has_since_bound() {
    let (app, state, sk) = gateway_with_device(64);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;
    let legacy_id = as_parked_by_1_3_46(&state, &approval_id, &staging_id);
    let mut bound: permaura_core::Connection = serde_json::from_value(wordpress_connection(&legacy_id["sec_".len()..])).unwrap();
    bound.secret_id = legacy_id.clone();
    state.service.store().put_connection(bound).unwrap();

    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::CONFLICT, "{sresp}");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(LIVE_BEFORE));
    assert_eq!(plaintext(&state, &legacy_id).as_deref(), Some(APPROVED_VALUE), "a bound credential is not released");
}

/// A staged row no pending hold names, which a promotion that failed before this build left behind, is the operator's to delete; one a pending hold names stays the hold's.
#[tokio::test]
async fn an_orphaned_staged_row_can_be_deleted_and_a_parked_one_cannot() {
    let (app, state, sk) = gateway_with_device(62);
    let (approval_id, staging_id, live_id) = held_change(&app, &state).await;
    let store = state.service.store();
    let orphan = permaura_gateway::secret_inventory::mint_staging_secret_id();
    store.put_secret(SecretRecord { id: orphan.clone(), sealed: sealed(b"left behind by a failed promotion"), metadata: Default::default() }).unwrap();

    let (ds, dresp) = send(&app, "DELETE", &format!("/v1/secrets/{staging_id}"), seed::DEMO_TOKEN, false, None).await;
    assert_eq!(ds, StatusCode::FORBIDDEN, "{dresp}");
    assert!(dresp["error"].as_str().unwrap_or_default().contains("parked for a device signature"), "{dresp}");
    // Held like any other credential deletion once a device is paired, and gone once the device signs it.
    let (os, oresp) = send(&app, "DELETE", &format!("/v1/secrets/{orphan}"), seed::DEMO_TOKEN, false, None).await;
    assert_eq!(os, StatusCode::ACCEPTED, "{oresp}");
    let delete_id = oresp["approval_id"].as_str().unwrap().to_string();
    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &delete_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "{sresp}");
    assert!(store.get_secret(&orphan).unwrap().is_none());
    // Still not writable: only deleting an orphan is the operator's.
    let (cs, cresp) = send(&app, "POST", "/v1/secrets", seed::DEMO_TOKEN, false, Some(serde_json::json!({ "id": orphan, "value": "planted" }))).await;
    assert_eq!(cs, StatusCode::FORBIDDEN, "{cresp}");

    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "{sresp}");
    assert_eq!(plaintext(&state, &live_id).as_deref(), Some(APPROVED_VALUE));
}
