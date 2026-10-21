//! A connector manifest decides where the credentials of every connection
//! made from it are sent, so installing or removing one goes through the control-plane funnel, the
//! held credential prompt names the host the credential goes to, a connection says where it is
//! pinned, and nothing may wear the id of a connector family the gateway builds itself while pinned
//! somewhere else.
//!
//! Every host and credential here is synthetic.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

/// permaura.com's console calling the gateway straight from the browser.
const PAGE: (&str, &str) = ("origin", "https://permaura.com");

/// A member's lookalike of a catalog connector the shipped catalog does not carry.
fn lookalike() -> Value {
    json!({
        "id": "paddle-billing",
        "name": "Paddle",
        "logo": "paddle",
        "vertical": "payments",
        "base_url": "https://api.paddle-billing.net",
        "capabilities": [
            { "id": "transactions.list", "method": "GET", "path": "/transactions", "description": "List transactions" }
        ]
    })
}

fn pair_a_device(state: &AppState) {
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let pubkey = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key("device:owner", &pubkey));
}

async fn send(state: &AppState, method: &str, uri: &str, body: Option<Value>, via: Option<(&str, &str)>) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    if let Some((name, value)) = via {
        request = request.header(name, value);
    }
    let body = match body {
        Some(b) => {
            request = request.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Sign the held approval as the device [`pair_a_device`] trusted, as the phone does, and resolve it.
async fn device_sign(state: &AppState, approval_id: &str) -> (StatusCode, Value) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use permaura_relay::{approval_display_full_digest_of, approval_result_preimage_v3, sign};
    let sk = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let (_, approval) = send(state, "GET", &format!("/v1/approvals/{approval_id}"), None, None).await;
    let request_hash = approval["request_hash"].as_str().unwrap().to_string();
    let job_id = approval["job_id"].as_str().unwrap().to_string();
    let audience = approval["approval_audience"].as_str().unwrap().to_string();
    let shown = approval_display_full_digest_of(&approval).expect("the approval serves its full rendering");
    let decided_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let preimage =
        approval_result_preimage_v3(&audience, &job_id, approval_id, true, &request_hash, &shown, "device:owner", decided_at);
    let body = json!({
        "approval_id": approval_id,
        "approve": true,
        "approver": "device:owner",
        "request_hash": request_hash,
        "decided_at": decided_at,
        "job_id": job_id,
        "approver_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
        "audience": audience,
        "display_digest": shown,
        "device_sig": sign(&sk, &preimage),
    });
    send(state, "POST", "/v1/approvals", Some(body), None).await
}

fn installed(state: &AppState, id: &str) -> bool {
    state.service.store().get_connector_manifest(id).unwrap().is_some()
}

async fn title_of(state: &AppState, approval_id: &str) -> String {
    let (_, approval) = send(state, "GET", &format!("/v1/approvals/{approval_id}"), None, None).await;
    approval["action_description"].as_str().unwrap_or_default().to_string()
}

/// Every control-plane audit row, oldest first.
async fn control_plane_audit(state: &AppState) -> Vec<Value> {
    let (_, audit) = send(state, "GET", "/v1/audit-events?limit=500", None, None).await;
    audit["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e["payload"]["action"] == "permaura.policy.write")
        .collect()
}

/// The member's lookalike, sent from off the host to a gateway with a device paired, is held for that
/// device, names what it installs and where it sends credentials, and installs only on its signature.
#[tokio::test]
async fn a_remote_lookalike_install_is_held_at_a_device_floor() {
    let state = common::seeded();
    pair_a_device(&state);
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike(), "version": 1 })), Some(PAGE)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["required_tier"], "device_signed", "{body}");
    assert!(!installed(&state, "paddle-billing"), "nothing installs before the device signs");
    let approval_id = body["approval_id"].as_str().unwrap().to_string();
    let title = title_of(&state, &approval_id).await;
    for part in ["paddle-billing", "unsigned", "api.paddle-billing.net"] {
        assert!(title.contains(part), "the prompt names {part}: {title}");
    }

    let (status, resp) = device_sign(&state, &approval_id).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(installed(&state, "paddle-billing"), "the signature installs it");
    let approved = control_plane_audit(&state)
        .await
        .into_iter()
        .find(|e| e["payload"]["decision"] == "approved" && e["payload"]["summary"]["approval_id"] == approval_id.as_str())
        .expect("the signed install is in the chain");
    let applied = &approved["payload"]["summary"]["mutation"];
    assert_eq!(applied["connector_id"], "paddle-billing", "{approved}");
    assert_eq!(applied["provenance"]["kind"], "user", "{approved}");
    assert_eq!(applied["host"], "api.paddle-billing.net", "{approved}");
}

/// On the gateway's own host the install applies at once, and the chain says what was installed.
#[tokio::test]
async fn a_local_install_applies_and_is_audited() {
    let state = common::seeded();
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike(), "version": 1 })), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["provenance"]["kind"], "user", "{body}");
    let row = control_plane_audit(&state).await.pop().expect("the install is in the chain");
    let summary = &row["payload"]["summary"];
    assert_eq!(summary["method"], "applied", "{row}");
    assert_eq!(summary["applied"]["connector_id"], "paddle-billing", "{row}");
    assert_eq!(summary["applied"]["provenance"]["kind"], "user", "{row}");
    assert_eq!(summary["applied"]["host"], "api.paddle-billing.net", "{row}");
    assert_eq!(summary["applied"]["base_url"], "https://api.paddle-billing.net", "{row}");
    let title = summary["title"].as_str().unwrap_or_default();
    assert!(title.contains("paddle-billing") && title.contains("api.paddle-billing.net"), "{title}");
}

/// From off the host with no device paired there is nothing to hold the install for.
#[tokio::test]
async fn a_remote_install_on_an_unpaired_self_run_gateway_is_refused() {
    let state = common::seeded();
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike(), "version": 1 })), Some(PAGE)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!installed(&state, "paddle-billing"));
}

/// Removing an installed connector goes through the same funnel: held from off the host at a device
/// floor, applied and audited on the host.
#[tokio::test]
async fn a_connector_delete_is_held_remotely_and_audited_locally() {
    let state = common::seeded();
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike(), "version": 1 })), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    pair_a_device(&state);

    let (status, body) = send(&state, "DELETE", "/v1/connectors/paddle-billing", None, Some(PAGE)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(installed(&state, "paddle-billing"), "nothing is removed before the device signs");
    let (status, resp) = device_sign(&state, body["approval_id"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(!installed(&state, "paddle-billing"), "the signature removes it");

    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike(), "version": 2 })), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = send(&state, "DELETE", "/v1/connectors/paddle-billing", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["removed"], true, "{body}");
    let row = control_plane_audit(&state).await.pop().expect("the removal is in the chain");
    assert_eq!(row["payload"]["summary"]["applied"]["connector_id"], "paddle-billing", "{row}");
}

/// The credential prompt the owner signs names the host the credential will be sent to, in the form
/// the console derives with `new URL(base_url).host`.
#[tokio::test]
async fn the_held_credential_prompt_names_the_pinned_host() {
    let state = common::seeded();
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike(), "version": 1 })), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = send(
        &state,
        "POST",
        "/v1/connections/from-preset",
        Some(json!({ "preset_id": "paddle-billing", "name": "Paddle", "id": "paddle" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    pair_a_device(&state);

    for (connection, host) in [("paddle", "api.paddle-billing.net"), ("braintree_production", "api.braintreegateway.com")] {
        let (status, body) = send(
            &state,
            "POST",
            &format!("/v1/connections/{connection}/credential"),
            Some(json!({ "value": "synthetic-live-key" })),
            Some(PAGE),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{connection}: {body}");
        let title = title_of(&state, body["approval_id"].as_str().unwrap()).await;
        assert!(title.starts_with("Save the new credential for"), "{title}");
        assert!(title.contains(host), "{connection}: the prompt names {host}: {title}");
    }
}

/// `GET /v1/connections` and `GET /v1/connections/:id` say where each connection's credential is sent.
#[tokio::test]
async fn a_connection_carries_its_pinned_base_url() {
    let state = common::seeded();
    let mut manifest = lookalike();
    manifest["id"] = json!("books");
    manifest["base_url"] = json!("https://API.B\u{fc}cher.example:8443/v1/");
    let (status, body) = send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": manifest, "version": 1 })), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) =
        send(&state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": "books", "name": "Books", "id": "books" })), None)
            .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (_, list) = send(&state, "GET", "/v1/connections", None, None).await;
    let by_id = |id: &str| list["connections"].as_array().unwrap().iter().find(|c| c["id"] == id).cloned().unwrap();
    let braintree = by_id("braintree_production");
    assert_eq!(braintree["base_url"], "https://api.braintreegateway.com", "{braintree}");
    assert_eq!(braintree["pinned_hosts"], json!(["api.braintreegateway.com"]), "{braintree}");
    let ssh = by_id("ssh_prod");
    assert_eq!(ssh["base_url"], Value::Null, "an SSH connection names its target in `ssh`: {ssh}");
    assert_eq!(ssh["pinned_hosts"], json!([]), "{ssh}");
    let books = by_id("books");
    assert_eq!(books["pinned_hosts"], json!(["api.xn--bcher-kva.example:8443"]), "lowercase, punycode, port kept: {books}");

    let (status, one) = send(&state, "GET", "/v1/connections/books", None, None).await;
    assert_eq!(status, StatusCode::OK, "{one}");
    assert_eq!(one["base_url"], books["base_url"], "{one}");
    assert_eq!(one["pinned_hosts"], books["pinned_hosts"], "{one}");
}

/// A connector family the gateway builds itself is pinned to that family's host. A lookalike under
/// its id, an override that moves it, or a hand-built connection naming a family whose capabilities
/// only its own route builds, is refused.
#[tokio::test]
async fn a_family_the_gateway_builds_cannot_be_pinned_elsewhere() {
    let state = common::seeded();
    for id in ["braintree", "fal", "wordpress", "openapi", "ssh", "generic-http"] {
        let mut manifest = lookalike();
        manifest["id"] = json!(id);
        manifest["base_url"] = json!("https://collector.attacker.example");
        let (status, body) =
            send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": manifest, "version": 1 })), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{id}: {body}");
        assert!(!installed(&state, id), "{id}");
    }

    let (status, body) = send(
        &state,
        "POST",
        "/v1/connections/from-preset",
        Some(json!({ "preset_id": "github", "name": "Elsewhere", "base_url": "https://collector.attacker.example" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("api.github.com"), "{body}");

    for connector in ["wordpress", "openapi", "stripe"] {
        let (status, body) =
            send(&state, "POST", "/v1/connections", Some(json!({ "connector": connector, "name": "Hand built" })), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{connector}: {body}");
    }

    let (status, body) =
        send(&state, "POST", "/v1/connections", Some(json!({ "connector": "braintree", "name": "Hand built", "id": "bt_hand" })), None)
            .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (_, one) = send(&state, "GET", "/v1/connections/bt_hand", None, None).await;
    assert_eq!(one["pinned_hosts"], json!(["api.braintreegateway.com"]), "{one}");
}

// ── The hosts an install names, and signed manifests ───────────────────────────────────────

/// The lookalike, connectable over OAuth with its authorization and token endpoints on hosts of their own.
fn lookalike_with_oauth() -> Value {
    let mut manifest = lookalike();
    manifest["oauth"] = json!({
        "authorize_url": "https://login.paddle-billing.net/oauth/authorize",
        "token_url": "https://tokens.paddle-billing.net/oauth/token",
        "scopes": ["read"]
    });
    manifest
}

fn stored(state: &AppState, id: &str) -> permaura_gateway::manifest::InstalledManifest {
    state.service.store().get_connector_manifest(id).unwrap().expect("installed")
}

/// The hold names every host the manifest sends something to, OAuth endpoints included, and the installed record keeps that set.
#[tokio::test]
async fn an_install_hold_names_every_endpoint_host_and_the_record_keeps_them() {
    let state = common::seeded();
    pair_a_device(&state);
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike_with_oauth(), "version": 1 })), Some(PAGE)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let approval_id = body["approval_id"].as_str().unwrap().to_string();
    let title = title_of(&state, &approval_id).await;
    for host in ["api.paddle-billing.net", "tokens.paddle-billing.net", "login.paddle-billing.net"] {
        assert!(title.contains(host), "the prompt names {host}: {title}");
    }
    assert!(title.contains("client secret"), "and says what goes to the token endpoint: {title}");

    let (status, resp) = device_sign(&state, &approval_id).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(
        stored(&state, "paddle-billing").endpoint_hosts,
        ["api.paddle-billing.net", "login.paddle-billing.net", "tokens.paddle-billing.net"]
    );
    let (_, list) = send(&state, "GET", "/v1/connectors/installed", None, None).await;
    assert_eq!(list["connectors"][0]["endpoint_hosts"].as_array().map(Vec::len), Some(3), "{list}");
}

async fn start_oauth(state: &AppState) -> (StatusCode, Value) {
    send(
        state,
        "POST",
        "/v1/connections/paddle/oauth/start",
        Some(json!({ "client_id": "synthetic-client", "client_secret": "synthetic-client-secret", "redirect_uri": "http://127.0.0.1:7376/oauth/callback" })),
        None,
    )
    .await
}

/// OAuth start sends the client secret only to a host the install named: a record edited after the install cannot redirect it, and a record kept before the set was recorded named the base URL's host alone.
#[tokio::test]
async fn oauth_start_refuses_an_endpoint_the_install_did_not_name() {
    let state = common::seeded();
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike_with_oauth(), "version": 1 })), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) =
        send(&state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": "paddle-billing", "name": "Paddle", "id": "paddle" })), None)
            .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = start_oauth(&state).await;
    assert_eq!(status, StatusCode::OK, "the named endpoints start: {body}");
    assert!(body["authorize_url"].as_str().unwrap().starts_with("https://login.paddle-billing.net/"), "{body}");

    let store = state.service.store();
    let mut record = stored(&state, "paddle-billing");
    record.manifest.oauth.as_mut().unwrap().token_url = "https://collector.attacker.example/token".into();
    store.put_connector_manifest(record).unwrap();
    let (status, body) = start_oauth(&state).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(error.contains("collector.attacker.example") && error.contains("did not name"), "{error}");

    let mut legacy = stored(&state, "paddle-billing");
    legacy.endpoint_hosts.clear();
    legacy.manifest.oauth = serde_json::from_value(json!({
        "authorize_url": "https://api.paddle-billing.net/oauth/authorize",
        "token_url": "https://api.paddle-billing.net/oauth/token"
    }))
    .unwrap();
    store.put_connector_manifest(legacy.clone()).unwrap();
    let (status, body) = start_oauth(&state).await;
    assert_eq!(status, StatusCode::OK, "a record from before named its base URL's host: {body}");
    legacy.manifest.oauth.as_mut().unwrap().token_url = "https://tokens.paddle-billing.net/oauth/token".into();
    store.put_connector_manifest(legacy).unwrap();
    let (status, body) = start_oauth(&state).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "and nothing else: {body}");
}

fn signed_record(id: &str, version: u32) -> permaura_gateway::manifest::InstalledManifest {
    let mut manifest = lookalike();
    manifest["id"] = json!(id);
    let manifest: permaura_gateway::presets::Preset = serde_json::from_value(manifest).unwrap();
    permaura_gateway::manifest::InstalledManifest {
        endpoint_hosts: manifest.endpoint_hosts(),
        manifest,
        version,
        provenance: permaura_gateway::manifest::Provenance::Signed { key_id: "pmconn-dev".into() },
        installed_at: 1,
    }
}

/// An unsigned manifest under the id of an installed Permaura-signed one is refused outright with a reason; once the signed one is removed, which is its own change, the id is free.
#[tokio::test]
async fn an_unsigned_manifest_cannot_replace_a_signed_one() {
    let state = common::seeded();
    state.service.store().put_connector_manifest(signed_record("paddle-billing", 3)).unwrap();
    let mut lookalike = lookalike();
    lookalike["base_url"] = json!("https://collector.attacker.example");
    for via in [None, Some(PAGE)] {
        let (status, body) =
            send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike.clone(), "version": 4 })), via).await;
        assert_eq!(status, StatusCode::CONFLICT, "{via:?}: {body}");
        let error = body["error"].as_str().unwrap_or_default();
        assert!(error.contains("Permaura-signed") && error.contains("Remove the installed connector first"), "{error}");
    }
    let kept = stored(&state, "paddle-billing");
    assert!(matches!(kept.provenance, permaura_gateway::manifest::Provenance::Signed { .. }));
    assert_eq!(kept.manifest.base_url, "https://api.paddle-billing.net");

    let (status, body) = send(&state, "DELETE", "/v1/connectors/paddle-billing", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike, "version": 4 })), None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// An unsigned install held before a signed one was installed under its id does not land over it when its device signs.
#[tokio::test]
async fn a_held_unsigned_install_does_not_land_over_a_signed_one_installed_since() {
    let state = common::seeded();
    pair_a_device(&state);
    let (status, body) =
        send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": lookalike(), "version": 9 })), Some(PAGE)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    state.service.store().put_connector_manifest(signed_record("paddle-billing", 2)).unwrap();
    let (status, resp) = device_sign(&state, body["approval_id"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{resp}");
    let kept = stored(&state, "paddle-billing");
    assert!(matches!(kept.provenance, permaura_gateway::manifest::Provenance::Signed { .. }), "{kept:?}");
    assert_eq!(kept.version, 2);
}
