//! The ways a catalog connector takes its credential, end to end through the ordinary routes: a pasted pair split across two slots, a token in the URL path, a client id and secret that mint a token, and the help the console shows beside the box. Every credential here is synthetic and every upstream is a mock.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::manifest::{InstalledManifest, Provenance};
use permaura_gateway::oauth_connect::from_sealed_bytes;
use permaura_gateway::oauth_credential::RefreshGrant;
use permaura_gateway::service::vault_passphrase;
use permaura_gateway::{build_router, presets, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

async fn call(app: &axum::Router, method: &str, uri: &str, token: Option<&str>, value: Option<Value>) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let body = match value {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let response = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn op(app: &axum::Router, uri: &str, value: Value) -> Value {
    let (status, value) = call(app, "POST", uri, Some(seed::DEMO_TOKEN), Some(value)).await;
    assert!(status.is_success(), "{uri}: {status}: {value}");
    value
}

struct Rig {
    app: axum::Router,
    http: Arc<MockHttpClient>,
    token: String,
}

impl Rig {
    fn bare() -> (axum::Router, AppState, Arc<MockHttpClient>) {
        common::isolate_from_the_real_install();
        let http = Arc::new(MockHttpClient::new());
        let state = AppState::in_memory_seeded_with_http(http.clone());
        let app = build_router(state.clone(), "127.0.0.1:0".parse().unwrap());
        (app, state, http)
    }

    /// A connection called `probe` from the preset, sealed with `credential`, a policy allowing `allowed`, and one approved agent.
    async fn new(preset: &str, base_url: Option<&str>, credential: &str, allowed: &[&str]) -> Rig {
        let (app, _state, http) = Rig::bare();
        let mut input = json!({ "preset_id": preset, "name": "Synthetic", "id": "probe" });
        if let Some(base) = base_url {
            input["base_url"] = json!(base);
        }
        op(&app, "/v1/connections/from-preset", input).await;
        op(&app, "/v1/connections/probe/credential", json!({ "value": credential })).await;
        let policy = op(&app, "/v1/policies", json!({ "connection_id": "probe", "name": "Narrow", "allow": allowed })).await;
        op(&app, "/v1/grants", json!({ "policy_id": policy["policy_id"], "target": "all_agents" })).await;
        let enroll = op(&app, "/v1/agents/enroll", json!({ "label": "Catalog agent" })).await;
        let enrolled = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "permaura_enroll",
            "arguments": { "code": enroll["code"], "agent_id": "catalog-agent", "name": "Catalog agent" } } });
        let (status, enrolled) = call(&app, "POST", "/mcp", None, Some(enrolled)).await;
        assert_eq!(status, StatusCode::OK, "{enrolled}");
        let token = enrolled["result"]["structuredContent"]["token"].as_str().expect("an agent session").to_string();
        op(&app, "/v1/agents/catalog-agent/approve", json!({})).await;
        Rig { app, http, token }
    }

    async fn invoke(&self, capability: &str, params: Value) -> Value {
        let (status, value) = call(&self.app, "POST", "/v1/invoke", Some(&self.token), Some(json!({ "capability": capability, "params": params }))).await;
        assert_eq!(status, StatusCode::OK, "{capability}: {value}");
        value
    }
}

#[tokio::test]
async fn a_pair_reaches_the_upstream_in_its_two_headers_and_neither_half_comes_back() {
    let rig = Rig::new("datadog", None, "synthetic-api-half:synthetic-app-half", &["monitors.list"]).await;
    rig.http.push_response(HttpResponse::json(200, json!({ "echoed": "synthetic-api-half and synthetic-app-half" })));
    let answer = rig.invoke("probe.monitors.list", json!({})).await;
    let sent = rig.http.last_request().unwrap();
    assert_eq!(sent.headers.get("DD-API-KEY").map(String::as_str), Some("synthetic-api-half"));
    assert_eq!(sent.headers.get("DD-APPLICATION-KEY").map(String::as_str), Some("synthetic-app-half"));
    assert!(!sent.headers.contains_key("Authorization"));
    let text = answer.to_string();
    assert!(!text.contains("synthetic-api-half") && !text.contains("synthetic-app-half"), "each half is scrubbed alone: {text}");
}

#[tokio::test]
async fn a_pair_can_travel_in_the_query_after_anything_an_agent_sent() {
    let rig = Rig::new("trello", None, "synthetic-trello-key:synthetic-trello-token", &["members.read"]).await;
    rig.http.push_response(HttpResponse::json(200, json!({ "id": "m1" })));
    rig.invoke("probe.members.read", json!({ "id": "me" })).await;
    let sent = rig.http.last_request().unwrap();
    assert!(sent.url.contains("key=synthetic-trello-key") && sent.url.ends_with("token=synthetic-trello-token"), "{}", sent.url);
}

#[tokio::test]
async fn a_path_token_is_sent_in_the_path_and_scrubbed_from_what_comes_back() {
    let bot = ["123456", "synthetic-bot"].join(":");
    let bot = bot.as_str();
    let rig = Rig::new("telegram", None, bot, &["bot.read"]).await;
    rig.http.push_response(HttpResponse::json(200, json!({ "ok": true, "note": format!("called /bot{bot}/getMe") })));
    let answer = rig.invoke("probe.bot.read", json!({})).await;
    let sent = rig.http.last_request().unwrap();
    assert_eq!(sent.url, format!("https://api.telegram.org/bot{bot}/getMe"));
    assert!(!answer.to_string().contains(bot), "{answer}");
}

#[tokio::test]
async fn a_client_id_and_secret_mint_a_token_the_call_then_sends() {
    let (app, state, http) = Rig::bare();
    op(&app, "/v1/connections/from-preset", json!({ "preset_id": "paypal", "name": "Synthetic", "id": "probe" })).await;
    http.push_response(HttpResponse::json(200, json!({ "access_token": "minted-synthetic", "token_type": "Bearer", "expires_in": 32400 })));
    op(&app, "/v1/connections/probe/credential", json!({ "value": "synthetic-client:synthetic-secret" })).await;
    let mint = http.last_request().unwrap();
    assert_eq!(mint.url, "https://api-m.paypal.com/v1/oauth2/token");
    assert_eq!(mint.form.clone().unwrap_or_default().get("grant_type").map(String::as_str), Some("client_credentials"));

    let store = state.service.store();
    let connection = store.get_connection("probe").unwrap().unwrap();
    let sealed = store.get_secret(&connection.secret_id).unwrap().unwrap();
    let plain = permaura_core::open(&sealed.sealed, vault_passphrase()).unwrap();
    let cred = from_sealed_bytes(&plain).expect("sealed as a bundle, not the pasted pair");
    assert_eq!(cred.refresh_grant, RefreshGrant::ClientCredentials);
    assert_eq!(cred.access_token, "minted-synthetic");
    assert_eq!(cred.client_id.as_deref(), Some("synthetic-client"));

    let (status, body) = call(&app, "POST", "/v1/connections/probe/oauth/start", Some(seed::DEMO_TOKEN), Some(json!({ "client_id": "c", "client_secret": "s", "redirect_uri": "http://127.0.0.1:7376/oauth/callback" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no consent screen to start: {body}");
}

#[tokio::test]
async fn a_rejected_client_id_and_secret_seal_nothing() {
    let (app, state, http) = Rig::bare();
    op(&app, "/v1/connections/from-preset", json!({ "preset_id": "paypal", "name": "Synthetic", "id": "probe" })).await;
    http.push_response(HttpResponse::json(401, json!({ "error": "invalid_client" })));
    let (status, body) = call(&app, "POST", "/v1/connections/probe/credential", Some(seed::DEMO_TOKEN), Some(json!({ "value": "synthetic-client:wrong-secret" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(!body.to_string().contains("wrong-secret"), "{body}");
    let store = state.service.store();
    let connection = store.get_connection("probe").unwrap().unwrap();
    assert!(store.get_secret(&connection.secret_id).unwrap().is_none());
}

#[tokio::test]
async fn the_marketplace_shows_credential_help_for_the_catalog_and_never_for_an_unsigned_install() {
    let (app, state, _http) = Rig::bare();
    let (status, body) = call(&app, "GET", "/v1/presets", Some(seed::DEMO_TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    let list = body["presets"].as_array().or(body.as_array()).expect("a list of presets").clone();
    let find = |id: &str| list.iter().find(|p| p["id"] == id).unwrap_or_else(|| panic!("{id} is listed")).clone();
    let notion = find("notion");
    assert_eq!(notion["credential"]["url"].as_str().map(|u| u.starts_with("https://")), Some(true), "{notion}");
    assert!(notion["credential"]["hint"].as_str().is_some_and(|h| !h.is_empty()));
    assert_eq!(find("paypal")["oauth_supported"], false, "no consent screen to send anyone to");
    assert_eq!(find("gmail")["oauth_supported"], true);
    assert_eq!(find("google-sheets")["credential"]["oauth_only"], true, "nothing to paste");

    let mut manifest = presets::catalog().get("notion").unwrap().clone();
    manifest.id = "lookalike".into();
    let endpoint_hosts = manifest.endpoint_hosts();
    state.service.store().put_connector_manifest(InstalledManifest { manifest, version: 1, provenance: Provenance::User, installed_at: 0, endpoint_hosts }).unwrap();
    let (_, body) = call(&app, "GET", "/v1/presets", Some(seed::DEMO_TOKEN), None).await;
    let list = body["presets"].as_array().or(body.as_array()).unwrap().clone();
    let lookalike = list.iter().find(|p| p["id"] == "lookalike").expect("the install is listed");
    assert!(lookalike["credential"].is_null(), "a link in an unsigned definition is its author's: {lookalike}");
}

#[tokio::test]
async fn a_scope_naming_the_connections_host_is_filled_in_when_the_dance_starts() {
    let (app, _state, _http) = Rig::bare();
    let input = json!({ "preset_id": "microsoft-dynamics", "name": "Synthetic", "id": "probe", "base_url": "https://acme.crm4.dynamics.com/api/data/v9.2" });
    op(&app, "/v1/connections/from-preset", input).await;
    let body = op(&app, "/v1/connections/probe/oauth/start", json!({ "client_id": "c", "client_secret": "s", "redirect_uri": "http://127.0.0.1:7376/oauth/callback" })).await;
    let url = body["authorize_url"].as_str().unwrap();
    assert!(url.contains("scope=https%3A%2F%2Facme.crm4.dynamics.com%2Fuser_impersonation"), "{url}");
    assert!(!url.contains("host"), "{url}");
}

#[tokio::test]
async fn shopify_mints_on_the_shops_own_host_and_still_takes_an_older_apps_lasting_token() {
    let (app, state, http) = Rig::bare();
    let input = json!({ "preset_id": "shopify", "name": "Synthetic", "id": "probe", "base_url": "https://acme.myshopify.com/admin/api/2026-10" });
    op(&app, "/v1/connections/from-preset", input).await;
    http.push_response(HttpResponse::json(200, json!({ "access_token": "minted-synthetic", "expires_in": 86399 })));
    op(&app, "/v1/connections/probe/credential", json!({ "value": "synthetic-client:synthetic-secret" })).await;
    let mint = http.last_request().unwrap();
    assert_eq!(mint.url, "https://acme.myshopify.com/admin/oauth/access_token", "the token endpoint follows the connection's pinned host");
    let form = mint.form.clone().unwrap_or_default();
    assert_eq!(form.get("client_id").map(String::as_str), Some("synthetic-client"));

    let requests = http.requests().len();
    op(&app, "/v1/connections/probe/credential", json!({ "value": "shpat_lasting_synthetic" })).await;
    assert_eq!(http.requests().len(), requests, "a token is sealed as it is, with nothing to mint");
    let store = state.service.store();
    let connection = store.get_connection("probe").unwrap().unwrap();
    let sealed = store.get_secret(&connection.secret_id).unwrap().unwrap();
    assert_eq!(&*permaura_core::open(&sealed.sealed, vault_passphrase()).unwrap(), b"shpat_lasting_synthetic");
}
