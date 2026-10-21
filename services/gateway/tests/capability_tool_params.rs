//! A capability's own tool, and every route that calls a capability, against the parameters the capability pins.
//!
//! - Every tool's input schema uses only property keys the Claude API accepts (`^[a-zA-Z0-9_.-]{1,64}$`): Claude clients send every MCP tool with every request, so one tool with a key such as Microsoft Graph's `$top` fails every turn of the session. A tool whose parameters cannot be declared gets an open schema that names them instead.
//! - A capability with a pinned shape (an imported HTTP spec, an SSH operation) refuses a parameter it does not read, by name, on `/v1/invoke`, `permaura_invoke`, `permaura_explain_denial` and its own tool, where the connector used to drop it and the call answered 2xx.
//! - A capability's own `reason` parameter reaches the upstream through its tool, and the call's stated reason is still recorded: from `permaura_reason` when given, otherwise from that `reason`.
//! - An SSH command's placeholders are the ones its template uses, once each.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

/// The audit-reason argument of a capability tool whose capability has a `reason` of its own.
const AUDIT_REASON: &str = "permaura_reason";

/// The seeded estate over a mock HTTP client the test keeps, so it can read what an executed call sent.
fn seeded_with_http() -> (AppState, Arc<MockHttpClient>) {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = Arc::new(MockHttpClient::new());
    (AppState::new(EnforcementService::new(store, http.clone())), http)
}

async fn send(state: &AppState, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
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

async fn rpc(state: &AppState, method: &str, params: Value) -> Value {
    let (status, answer) = send(state, "POST", "/mcp", Some(json!({ "jsonrpc": "2.0", "id": 3, "method": method, "params": params }))).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    answer
}

async fn tools(state: &AppState) -> Vec<Value> {
    rpc(state, "tools/list", json!({})).await["result"]["tools"].as_array().expect("a tool list").clone()
}

fn tool<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("{name} is listed"))
}

/// The Claude API's rule for an input schema's property keys.
fn claude_key(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Every property key in `schema`, at any depth.
fn property_keys(schema: &Value, out: &mut Vec<String>) {
    match schema {
        Value::Object(map) => {
            if let Some(Value::Object(props)) = map.get("properties") {
                out.extend(props.keys().cloned());
            }
            map.values().for_each(|v| property_keys(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| property_keys(v, out)),
        _ => {}
    }
}

/// A connection made from the bundled preset `preset` under `id`, its credential set, every capability on, and a policy allowing `actions` granted to the demo agent.
async fn connect(state: &AppState, preset: &str, id: &str, actions: &[&str]) {
    let (status, body) = send(state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": preset, "name": id, "id": id }))).await;
    assert!(status.is_success(), "{preset}: {status} {body}");
    let (status, body) = send(state, "POST", &format!("/v1/connections/{id}/credential"), Some(json!({ "value": "test-credential" }))).await;
    assert!(status.is_success(), "{status} {body}");
    for action in actions {
        let (status, body) = send(
            state,
            "POST",
            &format!("/v1/connections/{id}/capabilities"),
            Some(json!({ "capability": format!("{id}.{action}"), "enabled": true })),
        )
        .await;
        assert!(status.is_success(), "{status} {body}");
    }
    let (status, policy) = send(state, "POST", "/v1/policies", Some(json!({ "connection_id": id, "name": id, "allow": actions }))).await;
    assert!(status.is_success(), "{status} {policy}");
    let policy_id = policy["policy_id"].as_str().unwrap().to_string();
    let (status, body) = send(state, "POST", "/v1/grants", Some(json!({ "name": id, "policy_ids": [policy_id], "agents": ["codex-cli"] }))).await;
    assert!(status.is_success(), "{status} {body}");
}

/// A manifest shaped like the marketplace's Paddle `adjustments.create`, whose body needs a `reason` of its own.
fn paddle_like() -> Value {
    json!({
        "id": "paddle-test",
        "name": "Paddle test",
        "vertical": "payments",
        "base_url": "https://api.paddle-test.example",
        "capabilities": [{
            "id": "adjustments.create", "method": "POST", "path": "/adjustments",
            "body_params": ["action", "transaction_id", "reason", "type", "items"], "description": "Create an adjustment"
        }]
    })
}

// ── property keys ─────────────────────────────────────────────────────────────

/// Every tool every bundled preset makes, the fixed tools and the seed's, uses only property keys the Claude API takes; Microsoft Graph's `$top` and `$filter` tools get an open schema that names them.
#[tokio::test]
async fn every_tool_uses_only_property_keys_the_claude_api_accepts() {
    let (state, _) = seeded_with_http();
    let store = state.service.store();
    for preset in permaura_gateway::presets::catalog().list() {
        let connection = format!("p_{}", preset.id.replace('-', "_"));
        for cap in preset.instantiate(&connection, "sec_p").capabilities {
            store.put_capability(cap).unwrap();
        }
    }
    let listed = tools(&state).await;
    let mut bad = Vec::new();
    for t in &listed {
        let mut keys = Vec::new();
        property_keys(&t["inputSchema"], &mut keys);
        bad.extend(keys.into_iter().filter(|k| !claude_key(k)).map(|k| format!("{}: {k}", t["name"])));
    }
    assert!(bad.is_empty(), "property keys the Claude API refuses: {bad:?}");
    let graph = tool(&listed, "p_microsoft_graph.messages.list");
    let schema = &graph["inputSchema"];
    assert_ne!(schema["additionalProperties"], json!(false), "{schema}");
    let said = schema["description"].as_str().unwrap_or_default();
    assert!(said.contains("$top") && said.contains("$filter"), "the open schema names what the tool takes: {schema}");
}

/// An imported OData-style parameter is not made a property key either.
#[tokio::test]
async fn an_imported_parameter_the_claude_api_refuses_is_named_in_an_open_schema() {
    let (state, _) = seeded_with_http();
    let spec = "openapi: 3.0.0\ninfo: { title: Odata, version: \"1\" }\nservers: [ { url: \"https://api.odata.example\" } ]\npaths:\n  /things:\n    get:\n      operationId: listThings\n      parameters:\n        - { name: \"$filter\", in: query, schema: { type: string } }\n        - { name: top, in: query, schema: { type: integer } }\n      responses: { \"200\": { description: ok } }\n";
    let (status, body) = send(&state, "POST", "/v1/connections/import-openapi", Some(json!({ "name": "odata", "id": "odata", "spec": spec }))).await;
    assert!(status.is_success(), "{status} {body}");
    let listed = tools(&state).await;
    let schema = &tool(&listed, "odata.listThings")["inputSchema"];
    let mut keys = Vec::new();
    property_keys(schema, &mut keys);
    assert!(keys.iter().all(|k| claude_key(k)), "{schema}");
    assert!(schema["description"].as_str().unwrap_or_default().contains("$filter"), "{schema}");
}

// ── a capability's own `reason` ───────────────────────────────────────────────

/// Stripe's refund body carries a `reason` of its own. Its tool forwards it, records `permaura_reason` as the stated reason, and falls back to the refund's own reason when none is given.
#[tokio::test]
async fn a_capability_reason_parameter_reaches_the_upstream_and_a_reason_is_still_recorded() {
    let (state, http) = seeded_with_http();
    connect(&state, "stripe", "s", &["refunds.create"]).await;
    let listed = tools(&state).await;
    let schema = &tool(&listed, "s.refunds.create")["inputSchema"];
    assert!(schema["properties"].get("reason").is_some(), "the refund's own reason is offered: {schema}");
    assert_eq!(schema["properties"][AUDIT_REASON]["type"], "string", "and the stated reason under its own name: {schema}");

    for (args, intent) in [
        (json!({ "charge": "ch_1", "amount": 500, "reason": "fraudulent", AUDIT_REASON: "the customer disputed it" }), "the customer disputed it"),
        (json!({ "charge": "ch_1", "amount": 500, "reason": "fraudulent" }), "fraudulent"),
    ] {
        let answer = rpc(&state, "tools/call", json!({ "name": "s.refunds.create", "arguments": args })).await;
        let approval_id = answer["result"]["structuredContent"]["approval_id"].as_str().unwrap_or_else(|| panic!("a refund is held: {answer}")).to_string();
        let held = state.service.store().get_approval(&approval_id).unwrap().expect("the hold is stored");
        assert_eq!(held.params.to_value_unbounded()["reason"], "fraudulent", "the refund's reason is kept for the upstream");
        assert!(held.params.to_value_unbounded().get(AUDIT_REASON).is_none(), "the stated reason is not sent upstream");
        assert_eq!(held.intent.as_deref(), Some(intent));
        let (status, resolved) = send(&state, "POST", "/v1/approvals", Some(json!({ "approval_id": approval_id, "approve": true }))).await;
        assert_eq!(status, StatusCode::OK, "{resolved}");
        let sent = http.last_request().expect("the approved refund ran");
        let form = sent.form_encoded.as_deref().unwrap_or_default();
        assert!(form.contains("reason=fraudulent"), "Stripe receives the reason: {form}");
    }
}

/// A manifest's own `reason` (Paddle's adjustments need one) is forwarded the same way.
#[tokio::test]
async fn an_installed_capability_keeps_its_own_reason_too() {
    let (state, _) = seeded_with_http();
    let (status, body) = send(&state, "POST", "/v1/connectors/install", Some(json!({ "manifest": paddle_like(), "version": 1 }))).await;
    assert!(status.is_success(), "{status} {body}");
    connect(&state, "paddle-test", "pd", &["adjustments.create"]).await;
    let args = json!({ "action": "refund", "transaction_id": "txn_1", "reason": "customer requested refund", "type": "full" });
    let answer = rpc(&state, "tools/call", json!({ "name": "pd.adjustments.create", "arguments": args })).await;
    let outcome = &answer["result"]["structuredContent"];
    let params = match outcome["approval_id"].as_str() {
        Some(id) => state.service.store().get_approval(id).unwrap().unwrap().params.to_value_unbounded(),
        None => panic!("an adjustment is held: {answer}"),
    };
    assert_eq!(params["reason"], "customer requested refund", "{answer}");
}

// ── a pinned capability refuses what it would drop ────────────────────────────

/// A parameter a pinned capability does not read is refused by name on every route that calls it, where it used to be dropped while the call answered 2xx; an unpinned built-in still takes what it is given.
#[tokio::test]
async fn a_pinned_capability_refuses_a_parameter_it_does_not_read() {
    let (state, _) = seeded_with_http();
    connect(&state, "stripe", "s", &["refunds.create"]).await;
    let extra = json!({ "charge": "ch_1", "amount_cents": 500 });

    let (status, answer) = send(&state, "POST", "/v1/invoke", Some(json!({ "capability": "s.refunds.create", "params": extra }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(answer["error"].as_str().unwrap_or_default().contains("amount_cents"), "{answer}");

    let answer = rpc(&state, "tools/call", json!({ "name": "s.refunds.create", "arguments": extra })).await;
    assert_eq!(answer["error"]["code"], json!(-32602), "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap_or_default().contains("amount_cents"), "{answer}");

    for (name, args) in [
        ("permaura_invoke", json!({ "capability": "s.refunds.create", "params": extra })),
        ("permaura_explain_denial", json!({ "capability": "s.refunds.create", "params": extra })),
    ] {
        let answer = rpc(&state, "tools/call", json!({ "name": name, "arguments": args })).await;
        assert!(answer["error"]["message"].as_str().unwrap_or_default().contains("amount_cents"), "{name}: {answer}");
    }

    // An SSH operation reads only its own parameters.
    let (status, answer) = send(&state, "POST", "/v1/invoke", Some(json!({ "capability": "ssh.sftp.list", "params": { "pth": "logs" } }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(answer["error"].as_str().unwrap_or_default().contains("pth"), "{answer}");

    // Parameters that are not an object at all.
    let (status, answer) = send(&state, "POST", "/v1/invoke", Some(json!({ "capability": "s.refunds.create", "params": "ch_1" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");

    // The capability's own parameters, its `reason` among them, are not refused.
    let (status, answer) = send(
        &state,
        "POST",
        "/v1/invoke",
        Some(json!({ "capability": "s.refunds.create", "params": { "charge": "ch_1", "amount": 500, "reason": "duplicate" } })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");

    // A built-in connector with no pinned shape takes its params as they come.
    let answer = rpc(&state, "tools/call", json!({ "name": "github.pull_requests.list", "arguments": { "repo": "acme/app", "zz_unknown": 1 } })).await;
    let refused = answer["error"]["message"].as_str().is_some_and(|m| m.contains("zz_unknown"));
    assert!(!refused, "{answer}");
}

// ── SSH placeholders ──────────────────────────────────────────────────────────

/// The tools of the SSH connection made from `exec`, by capability id.
async fn ssh_tools(state: &AppState, id: &str, exec: Value) -> (StatusCode, Value, Vec<Value>) {
    let body = json!({ "connector": "ssh", "id": id, "name": id, "ssh": { "host": "box.example", "user": "deploy", "insecure": true, "exec": [exec] } });
    let (status, answer) = send(state, "POST", "/v1/connections", Some(body)).await;
    (status, answer, tools(state).await)
}

/// An SSH command declares each placeholder its template uses, once, and refuses a template slot that is not allow-listed or an allow-listed name the template never uses; a placeholder named `reason` is the command's own, and one the Claude API cannot take as a key is named in an open schema.
#[tokio::test]
async fn an_ssh_command_declares_the_placeholders_its_template_uses() {
    let (state, _) = seeded_with_http();
    let (status, answer, listed) =
        ssh_tools(&state, "box_a", json!({ "action": "cmpfiles", "args_template": ["cmp", "{f}", "{f}"], "allowed_placeholders": ["f", "f"] })).await;
    assert!(status.is_success(), "{status} {answer}");
    let schema = &tool(&listed, "box_a.cmpfiles")["inputSchema"];
    assert_eq!(schema["required"], json!(["f"]), "{schema}");

    for (exec, said) in [
        (json!({ "action": "echoslot", "args_template": ["echo", "{x}"], "allowed_placeholders": [] }), "{x}"),
        (json!({ "action": "unused", "args_template": ["uptime"], "allowed_placeholders": ["x"] }), "'x'"),
    ] {
        let (status, answer, _) = ssh_tools(&state, "box_b", exec.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{exec}: {answer}");
        assert!(answer["error"].as_str().unwrap_or_default().contains(said), "{exec}: {answer}");
    }

    let (status, answer, listed) =
        ssh_tools(&state, "box_c", json!({ "action": "echoreason", "args_template": ["echo", "{reason}"], "allowed_placeholders": ["reason"] })).await;
    assert!(status.is_success(), "{status} {answer}");
    let schema = &tool(&listed, "box_c.echoreason")["inputSchema"];
    assert_eq!(schema["properties"]["reason"]["type"], "string", "{schema}");
    assert_eq!(schema["properties"][AUDIT_REASON]["type"], "string", "{schema}");
    assert_eq!(schema["required"], json!(["reason"]), "{schema}");

    let (status, answer, listed) =
        ssh_tools(&state, "box_d", json!({ "action": "dollar", "args_template": ["echo", "{$x}"], "allowed_placeholders": ["$x"] })).await;
    assert!(status.is_success(), "{status} {answer}");
    let schema = &tool(&listed, "box_d.dollar")["inputSchema"];
    let mut keys = Vec::new();
    property_keys(schema, &mut keys);
    assert!(keys.iter().all(|k| claude_key(k)), "{schema}");
    assert!(schema["description"].as_str().unwrap_or_default().contains("$x"), "{schema}");
}
