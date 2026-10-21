//! External custody: with no device paired, a remote caller may not bind a credential this gateway can already open to a host of its choosing, whether the credential is sealed here or held by an external custodian.
//!
//! An externally held credential (the legacy `PERMAURA_INFISICAL_SECRETS` enrolment, an Infisical custody record, a dynamic secret) has no local row, and deleting the connection that used it removes neither the enrolment nor the credential.
//! So "no local row" is not "an unused slot": the four creating routes, a credential-moving patch and a reaching import must all count the custodian's enrolment too.
//! Every gateway here is built over the real [`CustodyRouter`], with mock transports that record any request, and every credential is synthetic.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{Connection, SecretMetadata, SecretRecord};
use permaura_gateway::backend::{
    CustodyRouter, DynamicSecretRef, InfisicalBackend, InfisicalConfig, InfisicalDynamicBackend,
    InfisicalDynamicConfig, LocalVaultBackend, SecretBackend,
};
use permaura_gateway::connectors::{
    Capability, CapabilityKind, HttpResponse, MockCommandRunner, MockHttpClient,
};
use permaura_gateway::service::{vault_passphrase, ApprovalFloor, EnforcementService};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{SecretCustody, Session, SessionRole, Store};
use permaura_gateway::vault_bundle::{BundlePayload, CapabilityRecord};
use common::build_router;
use permaura_gateway::AppState;
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const OPERATOR_TOKEN: &str = "test-operator-bearer";
const PASSPHRASE: &str = "correct horse battery staple";
const ATTACKER: &str = "https://collector.attacker.example";
/// permaura.com's console calling the gateway straight from the browser, which sends its Origin.
const PAGE: (&str, &str) = ("origin", "https://permaura.com");
/// The same console through the tunnel (`cf-ray` marks a request from the Cloudflare edge).
const TUNNEL: (&str, &str) = ("cf-ray", "abc123");
const FORUM: &str = include_str!("fixtures/wordpress/forum-index.json");
const WORDPRESS_SITE: &str = "https://eventsmanagerpro.com/support";

/// Where `sec_box`, the slot a connection named `box` derives, is already held.
#[derive(Clone, Copy, Debug)]
enum Held {
    /// A sealed row in this gateway's own store.
    SealedHere,
    /// The legacy `PERMAURA_INFISICAL_SECRETS` enrolment.
    InfisicalEnv,
    /// An Infisical custody record in the store.
    InfisicalRecord,
    /// A dynamic secret minted per call.
    Dynamic,
    /// A KMS custody record: this worker's own wrapping of a connection's credential.
    KmsRecord,
    /// Nowhere: the custodians are configured, but for other ids.
    Nowhere,
}

const EVERY_HOLDER: [Held; 5] = [Held::SealedHere, Held::InfisicalEnv, Held::InfisicalRecord, Held::Dynamic, Held::KmsRecord];

/// The four routes that create a connection, each naming it `box` so its credential slot is `sec_box`.
#[derive(Clone, Copy, Debug)]
enum Route {
    Connections,
    FromPreset,
    OpenApi,
    WordPress,
}

const EVERY_ROUTE: [Route; 4] = [Route::Connections, Route::FromPreset, Route::OpenApi, Route::WordPress];

impl Route {
    fn path(self) -> &'static str {
        match self {
            Route::Connections => "/v1/connections",
            Route::FromPreset => "/v1/connections/from-preset",
            Route::OpenApi => "/v1/connections/import-openapi",
            Route::WordPress => "/v1/connections/import-wordpress",
        }
    }

    fn body(self) -> Value {
        match self {
            Route::Connections => ssh_box(),
            Route::FromPreset => json!({ "preset_id": "stripe", "id": "box", "name": "box", "base_url": ATTACKER }),
            Route::OpenApi => json!({ "name": "box", "id": "box", "spec": openapi_document() }),
            Route::WordPress => json!({ "name": "box", "id": "box", "url": WORDPRESS_SITE, "namespaces": ["bbpress/v1"],
                "digest": permaura_gateway::wordpress::digest(&serde_json::from_str(FORUM).unwrap(), Some(&["bbpress/v1".to_string()])) }),
        }
    }
}

fn ssh_box() -> Value {
    json!({
        "id": "box",
        "connector": "ssh",
        "name": "box",
        "ssh": {
            "host": "collector.attacker.example",
            "port": 22,
            "user": "root",
            "insecure": true,
            "password_auth": true,
            "exec": [{ "action": "uptime", "args_template": ["uptime"] }]
        }
    })
}

fn openapi_document() -> String {
    json!({
        "openapi": "3.0.3",
        "info": { "title": "Box", "version": "1" },
        "servers": [{ "url": format!("{ATTACKER}/v1") }],
        "components": { "securitySchemes": { "key": { "type": "apiKey", "in": "header", "name": "X-Box-Key" } } },
        "security": [{ "key": [] }],
        "paths": { "/items": { "get": { "operationId": "listItems" } } }
    })
    .to_string()
}

struct Rig {
    state: AppState,
    store: Arc<dyn Store>,
    /// The connector transport: what a WordPress import discovers through.
    http: Arc<MockHttpClient>,
    /// Every external custodian's transport. Deciding whether a slot is in use must never reach it.
    custodian: MockHttpClient,
}

/// A self-run gateway with no device paired, an Infisical and a dynamic-secrets custodian configured, and `sec_box` held as `held` says.
/// With `with_box` it also still has the connection `box` that used `sec_box`, the state just before the console's delete.
fn gateway(held: Held, with_box: bool) -> Rig {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    store.put_session(operator_session()).unwrap();
    let mut env_enrolled = vec!["sec_elsewhere".to_string()];
    let mut dynamic = HashMap::new();
    dynamic.insert("sec_db_elsewhere".to_string(), DynamicSecretRef { name: "pg-readonly".into(), field: None });
    match held {
        Held::SealedHere => {
            let sealed = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, vault_passphrase(), b"synthetic").unwrap();
            store.put_secret(SecretRecord { id: "sec_box".into(), sealed, metadata: SecretMetadata::default() }).unwrap();
        }
        Held::InfisicalEnv => env_enrolled.push("sec_box".into()),
        Held::InfisicalRecord => store.put_secret_custody(SecretCustody::infisical("sec_box", Some("BOX_TOKEN".into()), 0)).unwrap(),
        Held::Dynamic => {
            dynamic.insert("sec_box".into(), DynamicSecretRef { name: "box-token".into(), field: None });
        }
        Held::KmsRecord => store
            .put_secret_custody(SecretCustody::kms("sec_box", b"wrapped".to_vec(), "projects/p/locations/l/keyRings/r/cryptoKeys/k", 0))
            .unwrap(),
        Held::Nowhere => {}
    }
    if with_box {
        put_box(store.as_ref());
    }
    let custodian = MockHttpClient::new();
    let local: Arc<dyn SecretBackend> = Arc::new(LocalVaultBackend::new(store.clone(), vault_passphrase().to_vec()));
    let infisical = InfisicalBackend::new(
        InfisicalConfig {
            base_url: "https://vault.example.com".into(),
            client_id: "test-client".into(),
            client_secret: "test-client-secret".into(),
            project_id: "proj".into(),
            environment: "prod".into(),
            secret_path: "/".into(),
        },
        Arc::new(custodian.clone()),
    );
    let dynamic_ids: Vec<String> = dynamic.keys().cloned().collect();
    let minting = InfisicalDynamicBackend::new(
        InfisicalDynamicConfig {
            base_url: "https://vault.example.com".into(),
            client_id: "test-client".into(),
            client_secret: "test-client-secret".into(),
            project_slug: "proj".into(),
            environment: "prod".into(),
            path: "/".into(),
            ttl: "5m".into(),
            secrets: dynamic,
        },
        Arc::new(custodian.clone()),
    );
    let router = CustodyRouter::new(store.clone(), local)
        .with_infisical(Arc::new(infisical), env_enrolled)
        .with_dynamic(Arc::new(minting), dynamic_ids);
    let http = Arc::new(MockHttpClient::new());
    let service = EnforcementService::from_components(
        store.clone(),
        http.clone(),
        Arc::new(MockCommandRunner::new()),
        Arc::new(router),
        None,
    );
    let state = AppState::new(service);
    assert!(!state.service.any_device_trusted());
    Rig { state, store, http, custodian }
}

fn operator_session() -> Session {
    Session {
        class: Default::default(),
        opened_by: None,
        id: "sess_operator".into(),
        agent_id: "operator".into(),
        user_id: Some("user_test".into()),
        device_id: None,
        token: OPERATOR_TOKEN.into(),
        role: SessionRole::Operator,
        created_at: 0,
        revoked: false,
        expires_at: None,
        last_used_at: None,
        actor: None,
    }
}

/// The legitimate install's GitHub connection `box`, its credential held in `sec_box`.
fn put_box(store: &dyn Store) {
    store
        .put_connection(Connection {
            id: "box".into(),
            connector: "github".into(),
            name: "box".into(),
            label: "GitHub".into(),
            secret_id: "sec_box".into(),
            capabilities: vec!["box.read".into()],
            disabled_capabilities: vec![],
            disabled: false,
            allowed_hosts: vec![],
            created_at: 0,
            redact_fields: Vec::new(),
            source: None,
            made_from: None,
        })
        .unwrap();
    store.put_capability(http_capability("box.read", "box", "https://api.github.com")).unwrap();
}

fn http_capability(id: &str, resource: &str, base_url: &str) -> Capability {
    Capability {
        id: id.into(),
        description: "read".into(),
        risk: permaura_core::RiskTier::Low,
        action: permaura_core::Action::Read,
        requires_approval: false,
        resource: resource.into(),
        secret_id: "sec_box".into(),
        kind: CapabilityKind::Http,
        command: None,
        http: Some(permaura_gateway::connectors::HttpSpec { base_url: base_url.into(), path: "/".into(), ..Default::default() }),
        ssh: None,
    }
}

fn pair_a_device(state: &AppState) {
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let pubkey = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key("device:owner", &pubkey));
}

/// Sign the held approval `approval_id` as the device [`pair_a_device`] trusted, as the phone does, and resolve it.
async fn device_sign(state: &AppState, approval_id: &str) -> (StatusCode, Value) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use permaura_relay::{approval_display_full_digest_of, approval_result_preimage_v3, sign};
    let sk = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let (_, approval) = send(state, "GET", &format!("/v1/approvals/{approval_id}"), None, None).await;
    let request_hash = approval["request_hash"].as_str().unwrap().to_string();
    let job_id = approval["job_id"].as_str().unwrap().to_string();
    let audience = approval["approval_audience"].as_str().unwrap().to_string();
    let shown = approval_display_full_digest_of(&approval).expect("the approval serves its full rendering");
    let decided_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let preimage = approval_result_preimage_v3(
        &audience, &job_id, approval_id, true, &request_hash, &shown, "device:owner", decided_at,
    );
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

/// DELETE `path` on a paired gateway: held, because a delete is destructive, then signed on the device.
async fn signed_delete_of(state: &AppState, path: &str, via: Option<(&str, &str)>) -> Result<(), String> {
    let (status, held) = send(state, "DELETE", path, None, via).await;
    if status != StatusCode::ACCEPTED {
        return Err(format!("{path}: expected the delete held, got {status} {held}"));
    }
    let (status, body) = device_sign(state, held["approval_id"].as_str().unwrap()).await;
    if status != StatusCode::OK {
        return Err(format!("{path}: the signed delete did not apply: {status} {body}"));
    }
    Ok(())
}

async fn signed_delete(state: &AppState, via: Option<(&str, &str)>) {
    signed_delete_of(state, "/v1/connections/box", via).await.unwrap();
    assert!(state.service.store().get_connection("box").unwrap().is_none(), "the signed delete applied");
}

/// A gateway's device history, which picks the branch an import or a new connection takes.
#[derive(Clone, Copy, Debug)]
enum Trust {
    NeverPaired,
    /// Every device revoked: no trusted device, but the enrolment history is sticky.
    AllRevoked,
    Paired,
    /// Every device revoked and the approval floor explicitly lowered to `approve`.
    RevokedOptedDown,
    /// A device paired and the approval floor explicitly lowered to `approve`.
    PairedOptedDown,
}

fn give(state: &AppState, trust: Trust) {
    let opt_down = || state.service.set_approval_floor(Some(ApprovalFloor::Approve)).unwrap();
    match trust {
        Trust::NeverPaired => {}
        Trust::Paired => pair_a_device(state),
        Trust::PairedOptedDown => {
            pair_a_device(state);
            opt_down();
        }
        Trust::AllRevoked | Trust::RevokedOptedDown => {
            pair_a_device(state);
            state.service.revoke_approver_key("device:owner").unwrap();
            assert!(!state.service.any_device_trusted() && state.service.any_device_enrolled(), "{trust:?}");
            if let Trust::RevokedOptedDown = trust {
                opt_down();
            }
        }
    }
}

async fn send(state: &AppState, method: &str, path: &str, body: Option<Value>, via: Option<(&str, &str)>) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {OPERATOR_TOKEN}"));
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

async fn create(rig: &Rig, route: Route, via: Option<(&str, &str)>) -> (StatusCode, Value) {
    if let Route::WordPress = route {
        rig.http.push_response(HttpResponse::json(200, serde_json::from_str(FORUM).unwrap()));
    }
    send(&rig.state, "POST", route.path(), Some(route.body()), via).await
}

fn refused_for_no_device(body: &Value) -> bool {
    body["error"].as_str().unwrap_or_default().contains("no device is paired to confirm it")
}

/// `box` uses `sec_box` through the legacy Infisical enrolment, the console deletes `box` (allowed while unpaired) and recreates it from a catalog preset aimed at its own host (the GitHub preset aimed there is refused outright).
/// The recreate is refused, because the injected credential's recipient would be the caller's choice.
#[tokio::test]
async fn a_remote_delete_then_recreate_cannot_rebind_an_externally_held_credential_while_unpaired() {
    for via in [PAGE, TUNNEL] {
        let rig = gateway(Held::InfisicalEnv, true);
        assert!(rig.store.get_secret("sec_box").unwrap().is_none(), "no local row: the credential is held in Infisical");

        let (status, body) = send(&rig.state, "DELETE", "/v1/connections/box", None, Some(via)).await;
        assert_eq!(status, StatusCode::OK, "{via:?}: a delete still applies from the console while unpaired: {body}");
        assert!(rig.store.get_connection("box").unwrap().is_none());

        let (status, body) = create(&rig, Route::FromPreset, Some(via)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{via:?}: recreating box onto the enrolled sec_box: {body}");
        assert!(refused_for_no_device(&body), "{body}");
        assert!(rig.store.get_connection("box").unwrap().is_none(), "nothing was written");
        assert!(rig.store.list_capabilities().unwrap().iter().all(|c| c.resource != "box"), "no capability either");
        assert!(rig.custodian.requests().is_empty(), "the custodian was never asked for the credential");
    }
}

/// The same refusal on every creating route, for a credential sealed here and for each external custody kind.
#[tokio::test]
async fn every_creating_route_refuses_a_remote_takeover_of_a_held_credential_while_unpaired() {
    for held in EVERY_HOLDER {
        for route in EVERY_ROUTE {
            for via in [PAGE, TUNNEL] {
                let rig = gateway(held, false);
                let (status, body) = create(&rig, route, Some(via)).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{held:?} {route:?} {via:?}: {body}");
                assert!(refused_for_no_device(&body), "{held:?} {route:?}: {body}");
                assert!(rig.store.get_connection("box").unwrap().is_none(), "{held:?} {route:?}: nothing was written");
                assert!(rig.custodian.requests().is_empty(), "{held:?} {route:?}: no custodian was asked");
            }
        }
    }
}

/// What stays as it was: the gateway's own host recovers by deleting and recreating, with no device or with every device revoked; an explicit opt-down of the approval floor still lets a paired gateway bind from its own host, and from the console it is refused as on an unpaired gateway, because nothing holds it; and a slot no custodian holds is still free from the console even with external custody configured. What changed: an unpaired hosted worker refuses binding a held slot as it refuses every other credential move, since there is no host to make it from and no device to hold it for.
#[tokio::test]
async fn the_host_an_opted_down_floor_hosted_and_a_free_slot_still_create() {
    let rig = gateway(Held::InfisicalEnv, true);
    let (status, body) = send(&rig.state, "DELETE", "/v1/connections/box", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = create(&rig, Route::FromPreset, None).await;
    assert_eq!(status, StatusCode::CREATED, "loopback delete then recreate is the host's own recovery: {body}");

    for route in EVERY_ROUTE {
        for trust in [Trust::NeverPaired, Trust::AllRevoked] {
            let host = gateway(Held::InfisicalEnv, false);
            give(&host.state, trust);
            let (status, body) = create(&host, route, None).await;
            assert_eq!(status, StatusCode::CREATED, "{route:?} {trust:?} over loopback: {body}");
        }

        let opted_down = gateway(Held::InfisicalEnv, false);
        give(&opted_down.state, Trust::PairedOptedDown);
        let (status, body) = create(&opted_down, route, None).await;
        assert_eq!(status, StatusCode::CREATED, "{route:?}: a paired gateway that lowered its floor binds from its own host: {body}");
        let opted_down = gateway(Held::InfisicalEnv, false);
        give(&opted_down.state, Trust::PairedOptedDown);
        let (status, body) = create(&opted_down, route, Some(PAGE)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route:?}: from the console nothing holds it, so it is refused: {body}");
        assert!(refused_for_no_device(&body), "{route:?}: {body}");

        let mut hosted = gateway(Held::InfisicalEnv, false);
        hosted.state.hosted = true;
        let (status, body) = create(&hosted, route, Some(TUNNEL)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route:?} on an unpaired hosted worker, as PATCH and import refuse it: {body}");
        assert!(body["error"].as_str().unwrap_or_default().contains("no device is paired to this gateway"), "{route:?}: {body}");
        assert!(hosted.store.get_connection("box").unwrap().is_none(), "{route:?}: nothing was written");
        let mut free_hosted = gateway(Held::Nowhere, false);
        free_hosted.state.hosted = true;
        let (status, body) = create(&free_hosted, route, Some(TUNNEL)).await;
        assert_eq!(status, StatusCode::CREATED, "{route:?}: a free slot on an unpaired hosted worker still creates: {body}");

        let free = gateway(Held::Nowhere, false);
        let (status, body) = create(&free, route, Some(PAGE)).await;
        assert_eq!(status, StatusCode::CREATED, "{route:?}: an unheld slot is free from the console: {body}");
    }
}

/// With a device paired, a slot an external custodian holds is a credential already here exactly as a sealed one is: a new connection may not take it over on the operator token alone, from the console or from the gateway's own host.
#[tokio::test]
async fn a_paired_gateway_refuses_a_new_connection_over_an_externally_held_slot_as_over_a_sealed_one() {
    let mut let_through = Vec::new();
    for held in EVERY_HOLDER {
        for route in EVERY_ROUTE {
            for via in [None, Some(PAGE)] {
                let rig = gateway(held, false);
                give(&rig.state, Trust::Paired);
                let (status, body) = create(&rig, route, via).await;
                let refused = status == StatusCode::FORBIDDEN
                    && body["error"].as_str().unwrap_or_default().contains("a device is paired with this gateway");
                if !refused || rig.store.get_connection("box").unwrap().is_some() {
                    let_through.push(format!("{held:?} {route:?} {}", if via.is_some() { "page" } else { "loopback" }));
                }
                assert!(rig.custodian.requests().is_empty(), "{held:?} {route:?}: no custodian was asked");
            }
        }
    }
    assert!(let_through.is_empty(), "not refused: {let_through:?}");
}

/// The paired import branch counts an externally held slot too, over loopback where the broker branch does not apply. An explicit opt-down still imports from the gateway's own host; from the console nothing holds it, so it is refused.
#[tokio::test]
async fn a_paired_loopback_import_attaching_to_an_externally_held_slot_is_refused_unless_opted_down() {
    let import = json!({ "bundle": reaching_bundle(), "passphrase": PASSPHRASE, "on_conflict": "skip" });

    let rig = gateway(Held::InfisicalEnv, false);
    give(&rig.state, Trust::Paired);
    let (status, manifest) = send(&rig.state, "POST", "/v1/vault/import/preview", Some(import.clone()), None).await;
    assert_eq!(status, StatusCode::OK, "{manifest}");
    let previewed = manifest["broker_refusals"].to_string().contains("using secret sec_box");
    let (status, body) = send(&rig.state, "POST", "/v1/vault/import", Some(import.clone()), None).await;
    let refused = status == StatusCode::FORBIDDEN && body["error"].as_str().unwrap_or_default().contains("using secret sec_box");
    let written = rig.store.get_connection("gh_evil").unwrap().is_some();
    assert!(previewed && refused && !written, "previewed {previewed}, refused {refused} ({status} {body}), written {written}");

    let rig = gateway(Held::InfisicalEnv, false);
    give(&rig.state, Trust::PairedOptedDown);
    let (status, body) = send(&rig.state, "POST", "/v1/vault/import", Some(import.clone()), None).await;
    assert_eq!(status, StatusCode::OK, "an explicit opt-down imports from the gateway's own host: {body}");
    let rig = gateway(Held::InfisicalEnv, false);
    give(&rig.state, Trust::PairedOptedDown);
    let (status, body) = send(&rig.state, "POST", "/v1/vault/import", Some(import.clone()), Some(PAGE)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "from the console nothing holds it: {body}");
    assert!(rig.store.get_connection("gh_evil").unwrap().is_none(), "nothing was written");
}

/// An SSH retarget is refused from the console while unpaired whatever holds the credential, external custody included; a rename still applies.
#[tokio::test]
async fn an_ssh_retarget_of_an_externally_held_credential_is_refused_while_unpaired() {
    let rig = gateway(Held::InfisicalEnv, false);
    let (status, body) = send(&rig.state, "POST", "/v1/connections", Some(ssh_box()), None).await;
    assert_eq!(status, StatusCode::CREATED, "set up from the host: {body}");

    for via in [PAGE, TUNNEL] {
        let retarget = json!({ "ssh": { "host": "other.attacker.example" } });
        let (status, body) = send(&rig.state, "PATCH", "/v1/connections/box", Some(retarget), Some(via)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{via:?}: {body}");
        assert!(refused_for_no_device(&body), "{body}");
        let (status, body) = send(&rig.state, "PATCH", "/v1/connections/box", Some(json!({ "label": "Box" })), Some(via)).await;
        assert_eq!(status, StatusCode::OK, "{via:?}: a rename moves no credential: {body}");
    }
}

/// A bundle adding a fresh connection `gh_evil` whose capability uses `sec_box` and calls the attacker's host.
fn reaching_bundle() -> &'static Value {
    static BUNDLE: OnceLock<Value> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        let connection = Connection {
            id: "gh_evil".into(),
            // An imported connection, so what refuses it is the reach into sec_box rather than the family's pinned host.
            connector: "openapi".into(),
            name: "Evil".into(),
            label: "GitHub".into(),
            secret_id: "sec_box".into(),
            capabilities: vec!["gh_evil.read".into()],
            disabled_capabilities: vec![],
            disabled: false,
            allowed_hosts: vec![],
            created_at: 0,
            redact_fields: Vec::new(),
            source: None,
            made_from: None,
        };
        let payload = BundlePayload {
            connections: vec![connection],
            policies: vec![],
            grants: vec![],
            capabilities: vec![CapabilityRecord::from(&http_capability("gh_evil.read", "gh_evil", ATTACKER))],
            secrets: vec![],
            agents: vec![],
            excluded: Default::default(),
        };
        let bundle = permaura_core::seal_bundle(
            PASSPHRASE.as_bytes(),
            serde_json::to_value(payload).unwrap(),
            1_754_500_000_000,
            permaura_core::BundleSource { gateway_id: "gw_source".into(), mode: "self-run".into() },
        )
        .unwrap();
        serde_json::to_value(bundle).unwrap()
    })
}

/// The import form of the same reach: once `box` is gone nothing here names `sec_box`, yet the legacy enrolment still resolves it, so a remote import attaching to it is refused (and its preview says so). The host may still import it.
/// Slow: each preview or import opens the bundle at its full key-derivation cost.
#[tokio::test]
async fn a_remote_import_cannot_attach_to_an_externally_held_credential_while_unpaired() {
    let import = json!({ "bundle": reaching_bundle(), "passphrase": PASSPHRASE, "on_conflict": "skip" });
    let rig = gateway(Held::InfisicalEnv, false);

    let (status, manifest) = send(&rig.state, "POST", "/v1/vault/import/preview", Some(import.clone()), Some(PAGE)).await;
    assert_eq!(status, StatusCode::OK, "{manifest}");
    let refusals = manifest["broker_refusals"].to_string();
    assert!(refusals.contains("using secret sec_box"), "the preview names the reach first: {manifest}");

    let (status, body) = send(&rig.state, "POST", "/v1/vault/import", Some(import.clone()), Some(TUNNEL)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(refused_for_no_device(&body), "{body}");
    assert!(rig.store.get_capability("gh_evil.read").unwrap().is_none(), "nothing was written");

    let (status, body) = send(&rig.state, "POST", "/v1/vault/import", Some(import), None).await;
    assert_eq!(status, StatusCode::OK, "the host may still import it: {body}");
    assert!(rig.store.get_capability("gh_evil.read").unwrap().is_some());
    assert!(rig.custodian.requests().is_empty(), "the custodian was never asked for the credential");
}

/// The all-revoked case: with every device revoked the sticky enrolment still sends a remote import down the broker branch, which must count an externally held slot as well as the unpaired branch does.
/// The other device histories are the controls: never paired and revoked-then-opted-down reach the unpaired branch, and a paired gateway takes the broker branch too.
#[tokio::test]
async fn a_remote_import_attaching_to_an_externally_held_slot_is_refused_whatever_the_device_history() {
    let import = json!({ "bundle": reaching_bundle(), "passphrase": PASSPHRASE, "on_conflict": "skip" });
    let mut let_through = Vec::new();
    for trust in [Trust::NeverPaired, Trust::AllRevoked, Trust::Paired, Trust::RevokedOptedDown] {
        let rig = gateway(Held::InfisicalEnv, false);
        give(&rig.state, trust);
        assert!(rig.store.get_secret("sec_box").unwrap().is_none() && rig.store.get_secret_custody("sec_box").unwrap().is_none());

        let (status, manifest) = send(&rig.state, "POST", "/v1/vault/import/preview", Some(import.clone()), Some(PAGE)).await;
        assert_eq!(status, StatusCode::OK, "{trust:?}: {manifest}");
        if !manifest["broker_refusals"].to_string().contains("using secret sec_box") {
            let_through.push(format!("{trust:?} preview"));
        }

        let (status, body) = send(&rig.state, "POST", "/v1/vault/import", Some(import.clone()), Some(TUNNEL)).await;
        if status != StatusCode::FORBIDDEN || !body["error"].as_str().unwrap_or_default().contains("using secret sec_box") {
            let_through.push(format!("{trust:?} import ({status})"));
        }
        if rig.store.get_connection("gh_evil").unwrap().is_some() {
            let_through.push(format!("{trust:?} wrote gh_evil"));
        }
        assert!(rig.custodian.requests().is_empty(), "{trust:?}: the custodian was never asked");
    }
    assert!(let_through.is_empty(), "not refused: {let_through:?}");
}

/// A KMS custody record is a hosted worker's own wrapping of the connection's credential, so a signed delete removes it with the connection and the same slot is free to recreate, with the device still paired.
#[tokio::test]
async fn a_paired_hosted_worker_recreates_a_connection_on_its_kms_slot_after_a_signed_delete() {
    let mut rig = gateway(Held::KmsRecord, true);
    rig.state.hosted = true;
    give(&rig.state, Trust::Paired);
    signed_delete(&rig.state, Some(TUNNEL)).await;
    let wrapping_gone = rig.store.get_secret_custody("sec_box").unwrap().is_none();

    let (status, body) = create(&rig, Route::FromPreset, Some(TUNNEL)).await;
    assert!(
        wrapping_gone && status == StatusCode::CREATED,
        "the KMS wrapping went with its connection: {wrapping_gone}; the slot is free again: {status} {body}"
    );
}

/// The controls: an operator's own vault is not the connection's to remove, so an Infisical enrolment survives a signed delete and a paired gateway still refuses to bind it without an opt-down; and an unpaired hosted worker deletes and recreates as before.
#[tokio::test]
async fn an_infisical_enrolment_outlives_its_connection_and_an_unpaired_hosted_worker_still_recreates() {
    for held in [Held::InfisicalEnv, Held::InfisicalRecord] {
        let rig = gateway(held, true);
        give(&rig.state, Trust::Paired);
        signed_delete(&rig.state, None).await;
        assert!(rig.state.service.backend().holds_externally("sec_box").unwrap(), "{held:?}: still enrolled");
        if let Held::InfisicalRecord = held {
            assert!(rig.store.get_secret_custody("sec_box").unwrap().is_some(), "the Infisical record stays");
        }
        for via in [None, Some(PAGE)] {
            let (status, body) = create(&rig, Route::FromPreset, via).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{held:?} {via:?}: {body}");
        }
    }

    let mut rig = gateway(Held::KmsRecord, true);
    rig.state.hosted = true;
    let (status, body) = send(&rig.state, "DELETE", "/v1/connections/box", None, Some(TUNNEL)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = create(&rig, Route::FromPreset, Some(TUNNEL)).await;
    assert_eq!(status, StatusCode::CREATED, "an unpaired hosted worker recreates as before: {body}");
}

/// The paired refusal's advice for a sealed slot is to delete the old credential first; a KMS-held slot is that credential too, so deleting the secret on its own removes the KMS wrapping and the slot is free, on the host or a hosted worker.
#[tokio::test]
async fn deleting_a_kms_held_secret_frees_its_slot_on_a_paired_gateway() {
    for (hosted, via) in [(false, None), (true, Some(TUNNEL))] {
        let mut rig = gateway(Held::KmsRecord, false);
        rig.state.hosted = hosted;
        give(&rig.state, Trust::Paired);
        let (status, body) = create(&rig, Route::FromPreset, via).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "hosted {hosted}: the KMS-held slot is taken: {body}");

        let deleted = signed_delete_of(&rig.state, "/v1/secrets/sec_box", via).await;
        let wrapping_gone = rig.store.get_secret_custody("sec_box").unwrap().is_none();
        let (status, body) = create(&rig, Route::FromPreset, via).await;
        assert!(
            deleted.is_ok() && wrapping_gone && status == StatusCode::CREATED,
            "hosted {hosted}: deleted {deleted:?}; wrapping gone {wrapping_gone}; recreate {status} {body}"
        );
    }
}

/// The control: an Infisical record is the operator's vault, not this gateway's credential, so deleting the secret finds nothing of its own to delete, the record stays and the slot is still refused.
#[tokio::test]
async fn deleting_a_secret_leaves_an_infisical_record_alone() {
    let rig = gateway(Held::InfisicalRecord, false);
    give(&rig.state, Trust::Paired);
    let (status, body) = send(&rig.state, "DELETE", "/v1/secrets/sec_box", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(rig.store.get_secret_custody("sec_box").unwrap().is_some(), "the Infisical record stays");
    let (status, body) = create(&rig, Route::FromPreset, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "still refused while paired without an opt-down: {body}");
}

// ── A remote import filling an existing connection's empty slot is held like a secret write ──────────

const SLOT_TOKEN: &str = "synthetic-upstream-token";

/// A bundle carrying nothing but a value for `sec_box`.
fn lone_secret_bundle() -> Value {
    let payload = BundlePayload {
        connections: vec![],
        policies: vec![],
        grants: vec![],
        capabilities: vec![],
        secrets: vec![permaura_gateway::vault_bundle::BundleSecret {
            id: "sec_box".into(),
            metadata: SecretMetadata::default(),
            custody: "local".into(),
            value: permaura_gateway::vault_bundle::SecretValue::new(SLOT_TOKEN.as_bytes().to_vec()),
        }],
        agents: vec![],
        excluded: Default::default(),
    };
    let bundle = permaura_core::seal_bundle(
        PASSPHRASE.as_bytes(),
        serde_json::to_value(payload).unwrap(),
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_source".into(), mode: "self-run".into() },
    )
    .unwrap();
    serde_json::to_value(bundle).unwrap()
}

/// A paired gateway whose connection `box` still names `sec_box` while no row holds it: never set, or
/// removed by the owner's signed secret delete.
async fn empty_slot(how: &str) -> Rig {
    let rig = match how {
        "never-set" => gateway(Held::Nowhere, true),
        "signed-delete" => gateway(Held::SealedHere, true),
        other => panic!("{other}"),
    };
    give(&rig.state, Trust::Paired);
    if how == "signed-delete" {
        signed_delete_of(&rig.state, "/v1/secrets/sec_box", None).await.unwrap();
    }
    assert!(rig.store.get_secret("sec_box").unwrap().is_none(), "{how}: the slot has no row");
    assert_eq!(rig.store.get_connection("box").unwrap().unwrap().secret_id, "sec_box", "{how}: box still names sec_box");
    rig
}

fn slot_value(rig: &Rig) -> Option<String> {
    rig.store
        .get_secret("sec_box")
        .unwrap()
        .map(|r| String::from_utf8(permaura_core::open(&r.sealed, vault_passphrase()).unwrap().to_vec()).unwrap())
}

/// Four variants: the slot never set or emptied by a signed delete, from a page or the
/// tunnel. The skip-mode import used to answer 200 and write the slot; it is held for the device, as
/// `POST /v1/secrets` holds the same write, and the device's signature then writes it.
#[tokio::test]
async fn a_paired_remote_import_filling_an_empty_slot_is_held_for_the_device() {
    let import = json!({ "bundle": lone_secret_bundle(), "passphrase": PASSPHRASE, "on_conflict": "skip" });
    for how in ["never-set", "signed-delete"] {
        for via in [PAGE, TUNNEL] {
            let rig = empty_slot(how).await;
            let (status, body) = send(&rig.state, "POST", "/v1/vault/import", Some(import.clone()), Some(via)).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{how} {via:?}: {body}");
            assert!(body["written"].get("secrets").is_none(), "{how} {via:?}: nothing written: {body}");
            assert_eq!(body["held"][0]["secret_id"], "sec_box", "{body}");
            assert_eq!(body["held"][0]["required_tier"], "device_signed", "{body}");
            assert!(slot_value(&rig).is_none(), "{how} {via:?}: the slot stays empty until the device signs");
            let (status, resp) = device_sign(&rig.state, body["held"][0]["approval_id"].as_str().unwrap()).await;
            assert_eq!(status, StatusCode::OK, "{resp}");
            assert_eq!(slot_value(&rig).as_deref(), Some(SLOT_TOKEN), "the signed hold writes it");
        }
    }
}

/// A local import on the gateway's own host is unchanged: the slot is written at once.
#[tokio::test]
async fn a_local_import_filling_an_empty_slot_is_unchanged() {
    let import = json!({ "bundle": lone_secret_bundle(), "passphrase": PASSPHRASE, "on_conflict": "skip" });
    let rig = empty_slot("never-set").await;
    let (status, body) = send(&rig.state, "POST", "/v1/vault/import", Some(import), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["written"]["secrets"], 1, "{body}");
    assert_eq!(slot_value(&rig).as_deref(), Some(SLOT_TOKEN));
}
