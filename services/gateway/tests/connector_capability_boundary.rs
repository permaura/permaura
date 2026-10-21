//! A grant names a capability, and the request that capability sends upstream has to stay inside
//! what the name promises: a Linear read capability may not carry a mutation, and a built-in path
//! identifier may not carry URL syntax that moves the call to another endpoint or query. Every
//! connection is made through the ordinary REST routes and every upstream is a mock.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

async fn post(app: &axum::Router, uri: &str, token: Option<&str>, value: Value) -> (StatusCode, Value) {
    let mut b = Request::builder().method("POST").uri(uri).header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let response = app.clone().oneshot(b.body(Body::from(value.to_string())).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn op(app: &axum::Router, uri: &str, value: Value) -> Value {
    let (status, value) = post(app, uri, Some(seed::DEMO_TOKEN), value).await;
    assert!(status.is_success(), "{uri}: {status}: {value}");
    value
}

struct Rig {
    app: axum::Router,
    state: AppState,
    http: Arc<MockHttpClient>,
    token: String,
}

impl Rig {
    /// A connection called `probe`, made from a marketplace preset or a built-in family, with a
    /// synthetic credential, a policy allowing exactly `allowed`, and one approved enrolled agent.
    async fn new(kind: &str, preset: bool, allowed: &[&str], enable: &[&str]) -> Rig {
        common::isolate_from_the_real_install();
        let http = Arc::new(MockHttpClient::new());
        let state = AppState::in_memory_seeded_with_http(http.clone());
        let app = build_router(state.clone(), "127.0.0.1:0".parse().unwrap());
        Rig::build(app, state, http, kind, preset, allowed, enable).await
    }

    /// A rig on an existing gateway, for a preset installed on it first.
    async fn from_parts(
        app: axum::Router,
        state: AppState,
        http: Arc<MockHttpClient>,
        preset: &str,
        allowed: &[&str],
    ) -> Rig {
        Rig::build(app, state, http, preset, true, allowed, &[]).await
    }

    async fn build(
        app: axum::Router,
        state: AppState,
        http: Arc<MockHttpClient>,
        kind: &str,
        preset: bool,
        allowed: &[&str],
        enable: &[&str],
    ) -> Rig {
        let (uri, mut input) = if preset {
            ("/v1/connections/from-preset", json!({ "preset_id": kind, "name": "Synthetic", "id": "probe" }))
        } else {
            ("/v1/connections", json!({ "connector": kind, "name": "Synthetic", "id": "probe" }))
        };
        if kind == "generic-http" {
            input["allowed_hosts"] = json!(["api.probe.test"]);
        }
        op(&app, uri, input).await;
        for action in enable {
            let toggle = json!({ "capability": format!("probe.{action}"), "enabled": true });
            op(&app, "/v1/connections/probe/capabilities", toggle).await;
        }
        op(&app, "/v1/connections/probe/credential", json!({ "value": "synthetic-not-a-real-key" })).await;
        let policy = op(&app, "/v1/policies", json!({ "connection_id": "probe", "name": "Narrow", "allow": allowed })).await;
        op(&app, "/v1/grants", json!({ "policy_id": policy["policy_id"], "target": "all_agents" })).await;
        let enroll = op(&app, "/v1/agents/enroll", json!({ "label": "Boundary agent" })).await;
        let call = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "permaura_enroll",
            "arguments": { "code": enroll["code"], "agent_id": "boundary-agent", "name": "Boundary agent" } } });
        let (status, enrolled) = post(&app, "/mcp", None, call).await;
        assert_eq!(status, StatusCode::OK, "{enrolled}");
        let token = enrolled["result"]["structuredContent"]["token"].as_str().expect("an agent session").to_string();
        op(&app, "/v1/agents/boundary-agent/approve", json!({})).await;
        Rig { app, state, http, token }
    }

    async fn invoke(&self, capability: &str, params: Value) -> (StatusCode, Value) {
        post(&self.app, "/v1/invoke", Some(&self.token), json!({ "capability": capability, "params": params })).await
    }

    /// Invoke and require a refusal that sent nothing upstream and left a `deny` in the audit chain.
    async fn refused(&self, capability: &str, params: Value) -> String {
        let before = self.http.requests().len();
        let (status, value) = self.invoke(capability, params.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{capability} {params}: {value}");
        assert_eq!(value["decision"]["decision"], "deny", "{value}");
        assert_eq!(self.http.requests().len(), before, "a refused call must not reach the upstream: {params}");
        let events = self.state.service.store().audit_events(Some(1)).unwrap();
        let last = events.last().expect("the refusal is audited");
        assert_eq!(last.payload.action, capability);
        assert_eq!(last.payload.decision, "deny");
        let summary = &last.payload.summary;
        assert!(
            summary["request_refused"].is_string() || summary["egress_blocked"] == true,
            "refused by the request-shape or the egress gate: {summary:?}"
        );
        value["decision"]["reason"].as_str().unwrap_or_default().to_string()
    }

    async fn allowed(&self, capability: &str, params: Value) -> Value {
        let (status, value) = self.invoke(capability, params.clone()).await;
        assert_eq!(status, StatusCode::OK, "{capability} {params}: {value}");
        value
    }

    /// A High-risk capability is escalated to a human; passing the request-shape gate means a hold.
    async fn held(&self, capability: &str, params: Value) {
        let (status, value) = self.invoke(capability, params.clone()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{capability} {params}: {value}");
        assert_eq!(value["decision"]["decision"], "requires_approval", "{value}");
    }
}

const ARCHIVE: &str = r#"mutation { issueArchive(id: "synthetic-issue-id") { success } }"#;

#[tokio::test]
async fn a_linear_read_capability_refuses_a_mutation_before_dispatch() {
    let rig = Rig::new("linear", true, &["issues.list", "issue.read", "projects.list"], &[]).await;
    let reason = rig.refused("probe.issues.list", json!({ "query": ARCHIVE })).await;
    assert!(reason.contains("mutation"), "the refusal names what was refused: {reason}");
    rig.refused("probe.issue.read", json!({ "query": ARCHIVE })).await;
    rig.refused("probe.projects.list", json!({ "query": ARCHIVE, "variables": {} })).await;
}

#[tokio::test]
async fn a_linear_read_capability_still_runs_a_query() {
    let rig = Rig::new("linear", true, &["issues.list", "issue.read"], &[]).await;
    for query in [
        "query { issues { nodes { id title } } }",
        "query Issues($first: Int) { issues(first: $first) { nodes { id } } }",
        "{ issues { nodes { id } } }",
        "query { ...Q } fragment Q on Query { issues { nodes { id } } }",
        "# mutation { issueArchive }\nquery { issue(id: \"mutation { x }\") { title } }",
        "query { issues(filter: { title: { contains: \"\"\"mutation\"\"\" } }) { nodes { id } } }",
    ] {
        rig.allowed("probe.issues.list", json!({ "query": query, "variables": { "first": 5 } })).await;
        let sent = rig.http.last_request().expect("the query reached the upstream");
        assert_eq!(sent.json().unwrap()["query"], query, "forwarded unchanged");
        assert!(sent.headers.contains_key("Authorization"));
    }
}

#[tokio::test]
async fn a_linear_read_capability_refuses_documents_that_smuggle_a_write() {
    let rig = Rig::new("linear", true, &["issues.list"], &[]).await;
    for query in [
        // A second operation beside a harmless one: which runs is the upstream's choice, not ours.
        "query A { issues { nodes { id } } } mutation B { issueArchive(id: \"x\") { success } }",
        "query A { issues { nodes { id } } } query B { viewer { id } }",
        // A mutation after a fragment, and after a string and a comment that contain braces.
        "fragment F on Issue { id } mutation { issueArchive(id: \"x\") { success } }",
        "query { issue(id: \"}\") { id } } mutation { issueArchive(id: \"x\") { success } }",
        "# {\nmutation { issueArchive(id: \"x\") { success } }",
        // A block string whose escaped quotes must not end it early.
        "query { issues(filter: \"\"\" \\\"\"\" } mutation { a } \"\"\") { nodes { id } } } mutation { issueArchive(id: \"x\") { success } }",
        "subscription { issueUpdates { id } }",
        "  MUTATION { issueArchive(id: \"x\") { success } }",
        "query { issues { nodes { id } } ",
        "query { issue(id: \"unterminated) { id } }",
        "type Mutation { x: Int }",
        "",
    ] {
        rig.refused("probe.issues.list", json!({ "query": query })).await;
    }
    rig.refused("probe.issues.list", json!({ "variables": {} })).await;
    rig.refused("probe.issues.list", json!({ "query": { "mutation": "issueArchive" } })).await;
}

#[tokio::test]
async fn a_linear_write_capability_sends_only_its_own_mutation() {
    let rig = Rig::new("linear", true, &["issue.create"], &["issue.create"]).await;
    let create = r#"mutation Create($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id } } }"#;
    // Refused before a human is asked, so nobody is shown an approval for a write it does not name.
    rig.held("probe.issue.create", json!({ "query": create, "variables": { "input": { "title": "t", "teamId": "x" } } })).await;
    rig.held("probe.issue.create", json!({ "query": "mutation { made: issueCreate(input: { title: \"t\", teamId: \"x\" }) { success } }" })).await;
    rig.refused("probe.issue.create", json!({ "query": ARCHIVE })).await;
    rig.refused("probe.issue.create", json!({ "query": "mutation { issueCreate(input: {}) { success } issueDelete(id: \"x\") { success } }" })).await;
    rig.refused("probe.issue.create", json!({ "query": "mutation { ...M } fragment M on Mutation { issueDelete(id: \"x\") { success } }" })).await;
    rig.refused("probe.issue.create", json!({ "query": "query { issues { nodes { id } } }" })).await;
}

/// A Linear connection made before capabilities carried a GraphQL rule, and one made from an installed
/// manifest that has none (the signed catalog's Linear entry predates them), are still held to their
/// action: the endpoint names GraphQL and the capability forwards `query`.
#[tokio::test]
async fn a_linear_read_capability_without_a_declared_rule_still_refuses_a_mutation() {
    let rig = Rig::new("linear", true, &["issues.list"], &[]).await;
    let store = rig.state.service.store();
    let mut cap = store.get_capability("probe.issues.list").unwrap().unwrap();
    assert!(cap.http.as_ref().unwrap().graphql.is_some(), "a new connection carries its rule");
    cap.http.as_mut().unwrap().graphql = None;
    store.put_capability(cap).unwrap();
    rig.refused("probe.issues.list", json!({ "query": ARCHIVE })).await;
    rig.allowed("probe.issues.list", json!({ "query": "{ issues { nodes { id } } }" })).await;

    common::isolate_from_the_real_install();
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::in_memory_seeded_with_http(http.clone());
    let app = build_router(state.clone(), "127.0.0.1:0".parse().unwrap());
    let mut manifest = serde_json::to_value(permaura_gateway::presets::catalog().get("linear").unwrap()).unwrap();
    manifest["id"] = json!("linear-installed");
    for cap in manifest["capabilities"].as_array_mut().unwrap() {
        cap.as_object_mut().unwrap().remove("graphql");
    }
    vouch_for(&state, manifest);
    let installed = Rig::from_parts(app, state, http, "linear-installed", &["issues.list"]).await;
    installed.refused("probe.issues.list", json!({ "query": ARCHIVE })).await;
    installed.allowed("probe.issues.list", json!({ "query": "{ issues { nodes { id } } }" })).await;
}

/// An installed manifest for a GraphQL API whose URL does not say so, with no declared rules: monday.com
/// serves GraphQL at `/v2`. Its capabilities forward `variables` beside `query`, which is what marks them.
async fn rule_less_graphql_rig(allowed: &[&str]) -> Rig {
    common::isolate_from_the_real_install();
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::in_memory_seeded_with_http(http.clone());
    let app = build_router(state.clone(), "127.0.0.1:0".parse().unwrap());
    let manifest = json!({
        "id": "boards", "name": "Boards", "vertical": "devtools", "base_url": "https://api.monday.com",
        "auth": { "scheme": "bearer" },
        "capabilities": [
            { "id": "boards.list", "method": "POST", "path": "/v2", "body_params": ["query", "variables"],
              "action": "list", "risk": "low", "description": "Query boards" },
            { "id": "items.create", "method": "POST", "path": "/v2", "body_params": ["query", "variables"],
              "action": "create", "risk": "low", "disabled": false, "requires_approval": false, "description": "Create an item" }
        ]
    });
    // Permaura-signed, so its declared read stands: an unsigned manifest's POST is held to the write its method gives it.
    vouch_for(&state, manifest);
    Rig::from_parts(app, state, http, "boards", allowed).await
}

/// Store `manifest` as a Permaura-signed install, whose posture lines apply as written.
fn vouch_for(state: &AppState, manifest: Value) {
    let manifest: permaura_gateway::presets::Preset = serde_json::from_value(manifest).unwrap();
    state
        .service
        .store()
        .put_connector_manifest(permaura_gateway::manifest::InstalledManifest {
            endpoint_hosts: manifest.endpoint_hosts(),
            manifest,
            version: 1,
            provenance: permaura_gateway::manifest::Provenance::Signed { key_id: "pmconn-dev".into() },
            installed_at: 1,
        })
        .unwrap();
}

#[tokio::test]
async fn a_read_capability_on_a_graphql_endpoint_its_url_does_not_name_refuses_a_mutation() {
    let rig = rule_less_graphql_rig(&["boards.list", "items.create"]).await;
    let cap = rig.state.service.store().get_capability("probe.boards.list").unwrap().unwrap();
    assert!(cap.http.as_ref().unwrap().graphql.is_none(), "nothing declared");
    assert!(!cap.http.as_ref().unwrap().base_url.contains("graphql"), "nothing in the URL either");

    let mutation = r#"mutation { create_item(board_id: 1, item_name: "x") { id } }"#;
    let reason = rig.refused("probe.boards.list", json!({ "query": mutation })).await;
    assert!(reason.contains("mutation"), "{reason}");
    rig.refused("probe.boards.list", json!({ "query": "query A { boards { id } } mutation B { delete_board(board_id: 1) { id } }" })).await;
    // A read must not forward a document the gateway cannot read.
    rig.refused("probe.boards.list", json!({ "query": "\"desc\" { boards { id } }" })).await;
    rig.refused("probe.boards.list", json!({ "query": "boards" })).await;

    let query = "query ($limit: Int) { boards(limit: $limit) { id name } }";
    rig.allowed("probe.boards.list", json!({ "query": query, "variables": { "limit": 5 } })).await;
    let sent = rig.http.last_request().unwrap();
    assert_eq!(sent.url, "https://api.monday.com/v2");
    assert_eq!(sent.json().unwrap()["query"], query);
    rig.allowed("probe.boards.list", json!({ "query": "{ boards { id } }" })).await;

    // A write capability with no rule is held to its action, which already allows a mutation.
    rig.allowed("probe.items.create", json!({ "query": mutation })).await;
    assert_eq!(rig.http.last_request().unwrap().json().unwrap()["query"], mutation);
}

#[tokio::test]
async fn a_rest_capability_with_a_query_search_term_is_untouched() {
    let rig = Rig::new("hubspot", true, &["contacts.search"], &[]).await;
    for term in ["jane", "jane doe", "mutation testing", "{"] {
        rig.allowed("probe.contacts.search", json!({ "query": term, "limit": 5 })).await;
        let sent = rig.http.last_request().unwrap();
        assert_eq!(sent.url, "https://api.hubapi.com/crm/v3/objects/contacts/search");
        assert_eq!(sent.json().unwrap()["query"], term, "forwarded exactly as given");
    }
    // A value that is a GraphQL write is still a write, whatever the endpoint.
    rig.refused("probe.contacts.search", json!({ "query": ARCHIVE })).await;
}

const INJECTED_IDS: &[&str] = &[
    "synthetic-project/env?decrypt=true#",
    "../../v10/projects/synthetic-project/env?decrypt=true#",
    "synthetic-project?decrypt=true",
    "synthetic-project#",
    "..",
    ".",
    "prj%2Fenv",
    "synthetic project",
    "synthetic\\project",
    "",
];

#[tokio::test]
async fn a_builtin_vercel_identifier_with_url_syntax_is_refused() {
    let rig = Rig::new("vercel", false, &["env.read", "projects.read", "deployments.read"], &[]).await;
    rig.allowed("probe.env.read", json!({ "project_id": "synthetic-project" })).await;
    assert_eq!(rig.http.last_request().unwrap().url, "https://api.vercel.com/v9/projects/synthetic-project/env");
    rig.allowed("probe.env.read", json!({ "project_id": "prj_AbC123" })).await;
    assert_eq!(rig.http.last_request().unwrap().url, "https://api.vercel.com/v9/projects/prj_AbC123/env");
    for id in INJECTED_IDS {
        let reason = rig.refused("probe.env.read", json!({ "project_id": id })).await;
        assert!(reason.contains("project"), "{reason}");
    }
    rig.refused("probe.env.read", json!({ "project_id": 42 })).await;
    rig.refused("probe.env.read", json!({})).await;
}

/// The same for the other built-in Vercel paths that take an identifier. A rig per family keeps each
/// test under one caller's execution burst.
#[tokio::test]
async fn every_builtin_vercel_identifier_path_is_held_to_the_grammar() {
    let rig = Rig::new("vercel", false, &["projects.read", "deployments.read"], &[]).await;
    rig.allowed("probe.deployments.read", json!({ "deployment_id": "my-app-abc123.vercel.app" })).await;
    assert_eq!(rig.http.last_request().unwrap().url, "https://api.vercel.com/v13/deployments/my-app-abc123.vercel.app");
    for id in INJECTED_IDS {
        rig.refused("probe.projects.read", json!({ "id": id })).await;
        rig.refused("probe.deployments.read", json!({ "deployment_id": id })).await;
    }
}

/// A Vercel env listing with every shape of value the endpoint can return: a plain-type value that
/// Vercel sends in clear without `decrypt`, an encrypted one, and the fields a decrypted read adds.
fn env_listing() -> Value {
    json!({
        "envs": [
            { "id": "env_1", "key": "SYNTHETIC_PLAIN", "type": "plain", "target": ["production"],
              "value": "synthetic-plain-value", "createdAt": 1, "updatedAt": 2 },
            { "id": "env_2", "key": "SYNTHETIC_SERVICE_CREDENTIAL", "type": "encrypted", "target": ["preview"],
              "value": "synthetic-decrypted-value", "decrypted": true, "vsmValue": "synthetic-vsm-value",
              "gitBranch": "main", "comment": "synthetic" }
        ],
        "pagination": { "count": 2, "next": null, "prev": null }
    })
}

fn assert_metadata_only(value: &Value) {
    let text = value.to_string();
    for leaked in ["synthetic-plain-value", "synthetic-decrypted-value", "synthetic-vsm-value", "\"value\"", "vsmValue", "decrypted"] {
        assert!(!text.contains(leaked), "{leaked} reached the agent: {text}");
    }
    let envs = value["result"]["envs"].as_array().expect("the listing keeps its envs");
    assert_eq!(envs.len(), 2);
    assert_eq!(envs[0]["key"], "SYNTHETIC_PLAIN");
    assert_eq!(envs[1]["key"], "SYNTHETIC_SERVICE_CREDENTIAL");
    assert_eq!(envs[1]["type"], "encrypted");
    assert_eq!(envs[1]["target"], json!(["preview"]));
    assert_eq!(value["result"]["pagination"]["count"], 2);
}

#[tokio::test]
async fn builtin_vercel_env_responses_carry_no_values() {
    let rig = Rig::new("vercel", false, &["env.read", "projects.read"], &[]).await;
    rig.http.push_response(HttpResponse::json(200, env_listing()));
    let value = rig.allowed("probe.env.read", json!({ "project_id": "synthetic-project" })).await;
    assert_metadata_only(&value);

    // A project read embeds the same records; they get the same projection.
    let mut project = json!({ "id": "prj_1", "name": "synthetic-project" });
    project["env"] = env_listing()["envs"].clone();
    rig.http.push_response(HttpResponse::json(200, project));
    let value = rig.allowed("probe.projects.read", json!({ "id": "synthetic-project" })).await;
    let text = value.to_string();
    assert!(!text.contains("synthetic-plain-value") && !text.contains("synthetic-decrypted-value"), "{text}");
    assert_eq!(value["result"]["env"][1]["key"], "SYNTHETIC_SERVICE_CREDENTIAL");
    assert_eq!(value["result"]["name"], "synthetic-project");
}

#[tokio::test]
async fn marketplace_vercel_env_responses_carry_no_values() {
    let rig = Rig::new("vercel", true, &["env.read", "projects.read"], &[]).await;
    rig.http.push_response(HttpResponse::json(200, env_listing()));
    let value = rig.allowed("probe.env.read", json!({ "id": "synthetic-project" })).await;
    assert_metadata_only(&value);
    assert_eq!(rig.http.last_request().unwrap().url, "https://api.vercel.com/v9/projects/synthetic-project/env");
    // The marketplace shape encodes URL syntax as data, and a separator or a dot segment, which encoding cannot
    // neutralize for an upstream that decodes the segment, is refused.
    rig.allowed("probe.env.read", json!({ "id": "synthetic-project?decrypt=true#" })).await;
    let sent = rig.http.last_request().unwrap().url.clone();
    assert!(sent.ends_with("/v9/projects/synthetic-project%3Fdecrypt%3Dtrue%23/env"), "{sent}");
    rig.refused("probe.env.read", json!({ "id": "synthetic-project/env?decrypt=true#" })).await;
    rig.refused("probe.env.read", json!({ "id": "prj%2Fenv" })).await;
    rig.refused("probe.env.read", json!({ "id": ".." })).await;
    rig.refused("probe.projects.read", json!({ "id": "." })).await;
}

/// The id of the fixture's deploy hook, which Vercel also makes the last segment of the hook's URL.
const HOOK_ID: &str = "synthetic-hook-secret";

/// A Vercel project as `GET /v9/projects/{id}` returns it with two deploy hooks and two Protection Bypass entries, whose map keys are the secrets. A hook's URL is `https://api.vercel.com/v1/integrations/deploy/<projectId>/<hookId>`, so the project id and the hook id together are the trigger.
fn project_with_standing_credentials() -> Value {
    json!({
        "id": "prj_1",
        "name": "synthetic-project",
        "link": {
            "type": "github",
            "repo": "synthetic-repo",
            "deployHooks": [{
                "id": HOOK_ID,
                "name": "nightly",
                "ref": "main",
                "createdAt": 1,
                "url": format!("https://api.vercel.com/v1/integrations/deploy/prj_1/{HOOK_ID}")
            }, {
                "id": "synthetic-second-hook-secret",
                "name": "preview",
                "ref": "preview",
                "createdAt": 2,
                "url": "https://api.vercel.com/v1/integrations/deploy/prj_1/synthetic-second-hook-secret"
            }]
        },
        "protectionBypass": {
            "synthetic-automation-bypass-secret": { "createdAt": 1, "createdBy": "user_1", "scope": "automation-bypass" },
            "synthetic-shareable-link-secret": { "createdAt": 2, "createdBy": "user_1", "scope": "shareable-link" }
        }
    })
}

/// Every string anywhere in `value`, object keys included.
fn every_string(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| every_string(v, out)),
        Value::Object(map) => map.iter().for_each(|(k, v)| {
            out.push(k.clone());
            every_string(v, out);
        }),
        _ => {}
    }
}

fn assert_no_standing_credentials(result: &Value) {
    let mut strings = Vec::new();
    every_string(result, &mut strings);
    for leaked in [HOOK_ID, "synthetic-second-hook-secret", "synthetic-automation-bypass-secret", "synthetic-shareable-link-secret"] {
        assert!(!strings.iter().any(|s| s.contains(leaked)), "{leaked} reached the agent: {result}");
    }
}

/// A Low-risk project read hands the agent no standing Vercel credential. The deploy hook list is replaced whole, since a hook's id and the project id rebuild its trigger URL; each Protection Bypass keeps its scope with its secret key redacted.
#[tokio::test]
async fn vercel_project_reads_carry_no_deploy_hooks_or_bypass_secrets() {
    for preset in [false, true] {
        let rig = Rig::new("vercel", preset, &["projects.read", "projects.list"], &[]).await;
        rig.http.push_response(HttpResponse::json(200, project_with_standing_credentials()));
        let value = rig.allowed("probe.projects.read", json!({ "id": "synthetic-project" })).await;
        let project = &value["result"];
        assert_no_standing_credentials(project);
        assert_eq!(project["link"]["deployHooks"], permaura_core::REDACTED, "preset={preset}: {project}");
        assert_eq!(project["link"]["repo"], "synthetic-repo", "the rest of the link is kept");
        assert_eq!(project["id"], "prj_1");
        let bypass = project["protectionBypass"].as_object().expect("the bypass list keeps its shape");
        assert_eq!(bypass.len(), 2, "{project}");
        let mut scopes: Vec<&str> = bypass.values().filter_map(|v| v["scope"].as_str()).collect();
        scopes.sort();
        assert_eq!(scopes, ["automation-bypass", "shareable-link"]);
        assert!(bypass.keys().all(|k| k.starts_with(permaura_core::REDACTED)), "{project}");

        rig.http.push_response(HttpResponse::json(200, json!({ "projects": [project_with_standing_credentials()] })));
        let value = rig.allowed("probe.projects.list", json!({})).await;
        assert_no_standing_credentials(&value["result"]);
        assert_eq!(value["result"]["projects"][0]["link"]["deployHooks"], permaura_core::REDACTED);
    }
}

/// A deployment a deploy hook created, as Vercel returns it: the hook named in `meta`.
fn deployment_from_a_hook(id: &str) -> Value {
    json!({
        "uid": id,
        "name": "synthetic-project",
        "url": format!("{id}.vercel.app"),
        "state": "READY",
        "source": "deploy-hook",
        "meta": {
            "deployHookId": HOOK_ID,
            "deployHookName": "nightly",
            "deployHookRef": "main",
            "githubCommitRef": "main"
        }
    })
}

/// A deployment a hook created carries the hook's id in `meta.deployHookId`, and with the project id that rebuilds the trigger. It is dropped, with the hook's name and ref, from a deployment list, a deployment read and a project's `latestDeployments`; the rest of `meta` is kept. The marketplace preset has no deployment read, so it is checked on the built-in family.
#[tokio::test]
async fn vercel_deployments_carry_no_deploy_hook_id() {
    for preset in [false, true] {
        let actions: &[&str] = if preset { &["deployments.list", "projects.read"] } else { &["deployments.list", "deployments.read", "projects.read"] };
        let rig = Rig::new("vercel", preset, actions, &[]).await;
        rig.http.push_response(HttpResponse::json(200, json!({ "deployments": [deployment_from_a_hook("dpl_1"), deployment_from_a_hook("dpl_2")] })));
        let listed = rig.allowed("probe.deployments.list", json!({})).await;
        let mut project = project_with_standing_credentials();
        project["latestDeployments"] = json!([deployment_from_a_hook("dpl_4")]);
        rig.http.push_response(HttpResponse::json(200, project));
        let latest = rig.allowed("probe.projects.read", json!({ "id": "synthetic-project" })).await;
        let mut shapes = vec![
            ("deployments.list", listed["result"].clone(), listed["result"]["deployments"][0]["meta"].clone()),
            ("latestDeployments", latest["result"].clone(), latest["result"]["latestDeployments"][0]["meta"].clone()),
        ];
        if !preset {
            rig.http.push_response(HttpResponse::json(200, deployment_from_a_hook("dpl_3")));
            let read = rig.allowed("probe.deployments.read", json!({ "id": "dpl_3" })).await;
            shapes.push(("deployments.read", read["result"].clone(), read["result"]["meta"].clone()));
        }
        for (shape, result, meta) in &shapes {
            assert_no_standing_credentials(result);
            let mut strings = Vec::new();
            every_string(result, &mut strings);
            assert!(!strings.iter().any(|s| s.starts_with("deployHook") && s != "deployHooks"), "preset={preset} {shape}: {result}");
            assert!(meta.get("deployHookName").is_none() && meta.get("deployHookRef").is_none(), "preset={preset} {shape}: {result}");
            assert_eq!(meta["githubCommitRef"], "main", "preset={preset} {shape}: the rest of meta is kept: {result}");
        }
    }
}

#[tokio::test]
async fn a_builtin_github_repository_with_url_syntax_is_refused() {
    let rig = Rig::new("github", false, &["repos.read", "pull_requests.list", "pull_requests.create"], &[]).await;
    rig.allowed("probe.pull_requests.list", json!({ "repo": "synthetic/app" })).await;
    assert_eq!(rig.http.last_request().unwrap().url, "https://api.github.com/repos/synthetic/app/pulls");
    rig.allowed("probe.repos.read", json!({ "owner": "synthetic", "repo": ".github" })).await;
    assert_eq!(rig.http.last_request().unwrap().url, "https://api.github.com/repos/synthetic/.github");
    for repo in [
        "synthetic/app/../../orgs/synthetic/repos#",
        "../user/emails#",
        "synthetic/app?per_page=100",
        "synthetic/..",
        "synthetic",
        "synthetic/app/extra",
        "-synthetic/app",
    ] {
        rig.refused("probe.pull_requests.list", json!({ "repo": repo })).await;
        rig.refused("probe.pull_requests.create", json!({ "repo": repo, "title": "t", "head": "h", "base": "b" })).await;
    }
    rig.refused("probe.repos.read", json!({ "owner": "synthetic/x", "repo": "app" })).await;
}

#[tokio::test]
async fn a_builtin_braintree_identifier_with_url_syntax_is_refused() {
    let rig = Rig::new("braintree", false, &["transactions.read", "customers.read"], &[]).await;
    rig.allowed("probe.transactions.read", json!({ "transaction_id": "txn_123" })).await;
    assert_eq!(rig.http.last_request().unwrap().url, "https://api.braintreegateway.com/transactions/txn_123");
    for id in ["txn_123/refund", "../customers/x", "txn?x=1", "..", "txn#"] {
        rig.refused("probe.transactions.read", json!({ "transaction_id": id })).await;
        rig.refused("probe.customers.read", json!({ "customer_id": id })).await;
    }
}

/// The generic proxy's request leaves with the host the allowlist judged and the vault's
/// credential alone. A header that would move either is refused before policy, as a recorded denial,
/// where an ordinary request on this High-risk capability goes to a human.
#[tokio::test]
async fn the_generic_proxy_refuses_headers_that_move_the_host_or_the_credential() {
    let rig = Rig::new("generic-http", false, &["request"], &[]).await;
    let url = "https://api.probe.test/v1/items";
    rig.held("probe.request", json!({ "url": url, "headers": { "Accept": "application/json" } })).await;
    for (name, value) in [
        ("Host", "internal.probe.test"),
        ("Authorization", "Bearer attacker"),
        ("authorization", "Bearer attacker"),
        ("Cookie", "session=stolen"),
        ("Proxy-Authorization", "Basic x"),
        ("Metadata-Flavor", "Google"),
        ("Transfer-Encoding", "chunked"),
    ] {
        let reason = rig.refused("probe.request", json!({ "url": url, "headers": { name: value } })).await;
        assert!(reason.contains(name), "the refusal names the header: {reason}");
    }
}

/// A credentialed request to an allowlisted host still goes nowhere over plain http: the egress gate
/// refuses it before policy, as a recorded denial, while the same URL over https goes to a human.
#[tokio::test]
async fn the_generic_proxy_sends_a_credential_over_https_only() {
    let rig = Rig::new("generic-http", false, &["request"], &[]).await;
    let reason = rig.refused("probe.request", json!({ "url": "http://api.probe.test/v1/items" })).await;
    assert!(reason.contains("https only"), "the refusal names the rule: {reason}");
    assert!(reason.contains("'http'"), "and the scheme that was given: {reason}");
    rig.refused("probe.request", json!({ "url": "HTTP://api.probe.test/v1/items" })).await;
    rig.held("probe.request", json!({ "url": "https://api.probe.test/v1/items" })).await;
}

/// A path dot segment, literal or percent-encoded, is refused before policy. The parser the client dispatches with resolves it, so a held write would execute on a path the approver never read.
#[tokio::test]
async fn the_generic_proxy_refuses_a_dot_segment_in_the_path() {
    let rig = Rig::new("generic-http", false, &["request"], &[]).await;
    for url in [
        "https://api.probe.test/orders/123/note/../../orders/999/cancel",
        "https://api.probe.test/orders/123/note/%2e%2e/%2e%2e/orders/999/cancel",
        "https://api.probe.test/a/.%2E/b",
        "https://api.probe.test/a/%2E./b",
        "https://api.probe.test/a/./b",
        "https://api.probe.test/a/%2e/b",
        "https://api.probe.test/a\\..\\b",
        "https://api.probe.test/a/.\t./b",
        "https://api.probe.test/a/..",
    ] {
        let reason = rig.refused("probe.request", json!({ "method": "POST", "url": url })).await;
        assert!(reason.contains("dot segment"), "{url}: {reason}");
    }
    // A dot inside a segment, or anywhere in the query, is ordinary text.
    rig.held("probe.request", json!({ "method": "POST", "url": "https://api.probe.test/v1..2/.well-known/x?path=../y" })).await;
}

/// Userinfo in the agent's URL is refused before policy. The client would have sent it as an
/// `Authorization: Basic` ahead of the vault's credential, so the upstream could run the call as whoever
/// the agent named while the audit recorded the connection's identity.
#[tokio::test]
async fn the_generic_proxy_refuses_userinfo_in_the_url() {
    let rig = Rig::new("generic-http", false, &["request"], &[]).await;
    for url in [
        "https://agent:pw@api.probe.test/v1/me",
        "https://agent@api.probe.test/v1/me",
        "https://:pw@api.probe.test/v1/me",
        "https://agent:pw@API.probe.test:443/v1/me",
    ] {
        let reason = rig.refused("probe.request", json!({ "url": url })).await;
        assert!(reason.contains("user name or password"), "{url}: {reason}");
        assert!(!reason.contains("pw"), "the refusal does not repeat the password: {reason}");
    }
    rig.held("probe.request", json!({ "url": "https://api.probe.test/v1/me" })).await;
}

/// A held generic-proxy write stores, shows and signs its URL in the form the client sends, so what executes on approval is byte for byte what the approver read.
#[tokio::test]
async fn a_held_generic_proxy_write_holds_the_url_it_sends() {
    let rig = Rig::new("generic-http", false, &["request"], &[]).await;
    let (status, value) =
        rig.invoke("probe.request", json!({ "method": "POST", "url": "https://API.Probe.test:443/v1/items/a b?q=x y" })).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{value}");
    let id = value["approval_id"].as_str().expect("a hold").to_string();
    let held = rig.state.service.store().get_approval(&id).unwrap().expect("stored");
    let shown = held.params.to_value_unbounded()["url"].as_str().unwrap().to_string();
    assert_eq!(shown, "https://api.probe.test/v1/items/a%20b?q=x%20y");
    let read = Request::builder()
        .uri(format!("/v1/approvals/{id}"))
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::empty())
        .unwrap();
    let response = rig.app.clone().oneshot(read).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let listed: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["request_hash"], listed["request_hash"], "the agent is told the hash a device signs: {listed}");
    rig.state.service.resolve_approval(&id, true, "bearer", None).await.unwrap();
    let sent = rig.http.last_request().expect("the approved call ran");
    assert_eq!(sent.url, shown);
}

/// An alias renames a response key, so key-name redaction would be the agent's to switch off on every capability that forwards its GraphQL document. Each alias is resolved to the field it renames, defaults and an operator's dotted entry alike, through nested selections and fragments.
#[tokio::test]
async fn a_graphql_alias_does_not_unredact_a_field() {
    let rig = Rig::new("linear", true, &["issues.list"], &[]).await;
    let store = rig.state.service.store();
    let mut connection = store.get_connection("probe").unwrap().expect("the probe connection");
    connection.redact_fields.push("creator.email".into());
    store.put_connection(connection).unwrap();

    let cases = [
        (
            "query { w: webhooks { nodes { id s: secret } } }",
            json!({ "data": { "w": { "nodes": [{ "id": "wh_1", "s": "synthetic-signing-secret" }] } } }),
        ),
        (
            "query { w: webhooks { nodes { ...F } } } fragment F on Webhook { id s: secret }",
            json!({ "data": { "w": { "nodes": [{ "id": "wh_1", "s": "synthetic-signing-secret" }] } } }),
        ),
        (
            "query { w: webhooks { nodes { id ... on Webhook { s: secret } } } }",
            json!({ "data": { "w": { "nodes": [{ "id": "wh_1", "s": "synthetic-signing-secret" }] } } }),
        ),
        (
            "query { i: issues { nodes { id c: creator { e: email } } } }",
            json!({ "data": { "i": { "nodes": [{ "id": "iss_1", "c": { "e": "synthetic@example.test" } }] } } }),
        ),
    ];
    for (query, answer) in cases {
        rig.http.push_response(HttpResponse::json(200, answer));
        let value = rig.allowed("probe.issues.list", json!({ "query": query })).await;
        let text = value["result"].to_string();
        assert!(!text.contains("synthetic-signing-secret") && !text.contains("synthetic@example.test"), "{query}: {text}");
        let node = &value["result"]["data"].as_object().unwrap().values().next().unwrap()["nodes"][0];
        assert_eq!(node["id"].as_str().map(|id| id.ends_with("_1")), Some(true), "{query}: {text}");
    }
}

/// The Slack connector's docs promise contact details are stripped on the way back. A `users.list` page as Slack returns it (with `users:read.email`) comes back with every member's email, phone and Skype handle redacted, at the depth Slack puts them, and names and message text untouched.
#[tokio::test]
async fn slack_users_list_comes_back_without_contact_details() {
    let rig = Rig::new("slack", true, &["users.list"], &[]).await;
    rig.http.push_response(HttpResponse::json(
        200,
        json!({
            "ok": true,
            "members": [{
                "id": "U0SYNTH1",
                "name": "synthetic.one",
                "real_name": "Synthetic One",
                "tz": "Australia/Perth",
                "profile": {
                    "real_name": "Synthetic One",
                    "display_name": "synth",
                    "title": "Engineer",
                    "email": "synthetic.one@example.test",
                    "phone": "+61 400 000 001",
                    "skype": "synthetic.one.skype",
                    "status_text": "Shipping"
                }
            }, {
                "id": "U0SYNTH2",
                "name": "synthetic.two",
                "profile": { "display_name": "two", "email": "synthetic.two@example.test", "phone": "", "skype": "" }
            }],
            "response_metadata": { "next_cursor": "" }
        }),
    ));
    let value = rig.allowed("probe.users.list", json!({ "limit": 2 })).await;
    let text = value["result"].to_string();
    for leaked in ["synthetic.one@example.test", "synthetic.two@example.test", "+61 400 000 001", "synthetic.one.skype"] {
        assert!(!text.contains(leaked), "{leaked} reached the agent: {text}");
    }
    let first = &value["result"]["members"][0]["profile"];
    for field in ["email", "phone", "skype"] {
        assert_eq!(first[field], permaura_core::REDACTED, "{field}: {text}");
    }
    assert_eq!(first["display_name"], "synth");
    assert_eq!(first["real_name"], "Synthetic One");
    assert_eq!(first["status_text"], "Shipping");
    assert_eq!(value["result"]["members"][1]["profile"]["display_name"], "two");
}
