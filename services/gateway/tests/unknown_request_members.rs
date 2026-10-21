//! A request member the gateway does not read is refused, never dropped.
//!
//! Every mutating REST route is in [`rows`], with a body the route accepts. Each one is sent that body plus `"zz_unknown": 1`, or followed by a second JSON value, and must answer 400 naming what was wrong; sent the body alone it must not be refused for its body.
//! The table is held to the router: [`every_mutating_route_is_in_the_table`] reads `build_router` and fails for a route with no row or one mounted in a way the scan cannot read, and [`every_request_type_is_read_strictly_all_the_way_down`] fails for a handler that reads its body any other way than the strict extractors, or for any request type, nested type or mirror reachable from one that does not deny unknown fields.
//! The fixed MCP tools are held the same way from their own advertised catalog, and the capability tools in `capability_tool_params.rs`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::vault_bundle::BundlePayload;
use common::build_router;
use permaura_gateway::AppState;
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const LIB_RS: &str = include_str!("../src/lib.rs");
const REST_RS: &str = include_str!("../src/rest.rs");
const REQUEST_BODY_RS: &str = include_str!("../src/request_body.rs");
const MCP_RS: &str = include_str!("../src/mcp.rs");

const PASSPHRASE: &str = "correct horse battery staple";
const UNKNOWN: &str = "zz_unknown";
const INVALID_BODY: &str = "invalid request body";

/// What a route reads from its body.
enum Reads {
    /// A required JSON object, valid as given.
    Json(Value),
    /// A JSON object that may be left out entirely, valid as given.
    Optional(Value),
    /// Nothing: an empty body, `{}` or `null`.
    Nothing,
}

/// One mutating route: its method, its pattern as `build_router` writes it, a concrete path, and what
/// it reads. `control_as_operator` sends the valid body with the operator bearer, for the routes whose
/// caller is decided before the body is read (where a bearer-less control would prove nothing).
struct Row {
    method: &'static str,
    route: &'static str,
    path: &'static str,
    reads: Reads,
    control_as_operator: bool,
}

fn row(method: &'static str, route: &'static str, path: &'static str, reads: Reads) -> Row {
    Row { method, route, path, reads, control_as_operator: false }
}

fn openapi_spec() -> String {
    "openapi: 3.0.0\ninfo: { title: Mini, version: \"1\" }\nservers: [ { url: \"https://api.mini.example\" } ]\npaths:\n  /things:\n    get:\n      operationId: listThings\n      responses: { \"200\": { description: ok } }\n".to_string()
}

fn empty_bundle() -> Value {
    let bundle = permaura_core::seal_bundle(
        PASSPHRASE.as_bytes(),
        serde_json::to_value(BundlePayload::default()).unwrap(),
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_source".into(), mode: "self-run".into() },
    )
    .unwrap();
    serde_json::to_value(bundle).unwrap()
}

fn manifest() -> Value {
    json!({
        "id": "paddle-billing",
        "name": "Paddle",
        "vertical": "payments",
        "base_url": "https://api.paddle-billing.net",
        "capabilities": [
            { "id": "transactions.list", "method": "GET", "path": "/transactions", "description": "List transactions" }
        ]
    })
}

/// Every mutating route the gateway serves, except `/mcp`, whose JSON-RPC envelope is free-form and
/// whose tool arguments are held by the MCP tests below.
fn rows(bundle: &Value) -> Vec<Row> {
    use Reads::{Json as J, Nothing as N, Optional as O};
    let policy = json!({
        "connection_id": "github_acme", "name": "PRs", "allow": ["pull_requests.list"], "deny": [],
        "requires_approval": [], "notify": [], "device_signed": [], "device_signed_quorum": 1, "grant_ids": []
    });
    let grant = json!({
        "name": "Billing", "enabled": true, "is_default": false, "policy_ids": ["pol_github_prs"], "all_agents": false,
        "agents": ["codex-cli", { "agent_id": "claude-code", "per_agent_limit": 5 }], "period": "day",
        "overall_limit": 50, "default_per_agent_limit": 10, "expires_at": null
    });
    vec![
        row("POST", "/v1/connections/:id/capability-posture", "/v1/connections/github_acme/capability-posture", J(json!({ "capability": "github.pull_requests.list", "risk": "low", "requires_approval": false }))),
        row("POST", "/v1/sessions", "/v1/sessions", J(json!({ "agent_id": "codex-cli" }))),
        row("POST", "/v1/sessions/:id/revoke", "/v1/sessions/sess_x/revoke", N),
        row("DELETE", "/v1/agents/:id", "/v1/agents/agent_x", N),
        row("PUT", "/v1/agents/:id", "/v1/agents/agent_x", J(json!({ "name": "Renamed" }))),
        row("POST", "/v1/grants", "/v1/grants", J(grant.clone())),
        row("PUT", "/v1/grants/:id", "/v1/grants/gr_x", J(grant)),
        row("PATCH", "/v1/grants/:id", "/v1/grants/gr_x", J(json!({ "enabled": false, "is_default": false }))),
        row("DELETE", "/v1/grants/:id", "/v1/grants/gr_x", N),
        row("POST", "/v1/grants/rebuild-usage", "/v1/grants/rebuild-usage", N),
        row("POST", "/v1/secrets", "/v1/secrets", J(json!({ "id": "sec_x", "value": "v", "labels": ["a"] }))),
        row("DELETE", "/v1/secrets/:id", "/v1/secrets/sec_x", N),
        row("POST", "/v1/connections", "/v1/connections", J(json!({ "connector": "github", "name": "GitHub", "label": "GitHub" }))),
        row("POST", "/v1/connections/from-preset", "/v1/connections/from-preset", J(json!({ "preset_id": "github", "name": "gh2", "label": "GH" }))),
        row("POST", "/v1/connections/discover", "/v1/connections/discover", J(json!({ "url": "https://wp.example.com" }))),
        row(
            "POST",
            "/v1/connections/import-wordpress",
            "/v1/connections/import-wordpress",
            J(json!({ "name": "wp", "url": "https://wp.example.com", "namespaces": ["wp/v2"], "dry_run": true })),
        ),
        row("POST", "/v1/connections/:id/resync", "/v1/connections/conn_x/resync", J(json!({ "dry_run": true, "sources": ["abilities"] }))),
        row(
            "POST",
            "/v1/connections/:id/oauth/start",
            "/v1/connections/conn_x/oauth/start",
            J(json!({ "client_id": "c", "client_secret": "s", "redirect_uri": "http://127.0.0.1:7376/oauth/callback", "scopes": ["read"] })),
        ),
        row("DELETE", "/v1/connectors/:id", "/v1/connectors/paddle-billing", N),
        row("PATCH", "/v1/connections/:id", "/v1/connections/conn_x", J(json!({ "label": "L", "disabled": false, "ssh": { "port": 2222 } }))),
        row("DELETE", "/v1/connections/:id", "/v1/connections/conn_x", N),
        row("POST", "/v1/connections/:id/credential", "/v1/connections/conn_x/credential", J(json!({ "value": "v" }))),
        row(
            "POST",
            "/v1/connections/:id/capabilities",
            "/v1/connections/conn_x/capabilities",
            J(json!({ "capability": "github.pull_requests.list", "enabled": true })),
        ),
        row("POST", "/v1/policies", "/v1/policies", J(policy.clone())),
        row("PUT", "/v1/policies/:id", "/v1/policies/pol_x", J(policy)),
        row("DELETE", "/v1/policies/:id", "/v1/policies/pol_x", N),
        row("POST", "/v1/broker/pause", "/v1/broker/pause", J(json!({ "paused": false }))),
        row("POST", "/v1/broker/require-approval", "/v1/broker/require-approval", J(json!({ "require_agent_approval": true }))),
        row("POST", "/v1/shutdown", "/v1/shutdown", N),
        row("POST", "/v1/remote/disable", "/v1/remote/disable", N),
        row("POST", "/v1/approvals", "/v1/approvals", J(json!({ "approval_id": "appr_x", "approve": false }))),
        row("DELETE", "/v1/audit/diagnostics", "/v1/audit/diagnostics", N),
        row("POST", "/v1/secrets/:id/rotate", "/v1/secrets/sec_x/rotate", J(json!({ "value": "v2" }))),
        row("POST", "/v1/devices/enroll", "/v1/devices/enroll", J(json!({ "name": "Phone", "platform": "ios", "push_token": "t" }))),
        row("DELETE", "/v1/devices/:id", "/v1/devices/dev_x", N),
        row("POST", "/v1/devices/push-token", "/v1/devices/push-token", J(json!({ "token": "t", "platform": "ios" }))),
        row(
            "POST",
            "/v1/approver-keys/pair",
            "/v1/approver-keys/pair",
            J(json!({ "approver_id": "phone_x", "approver_pubkey": "k", "issued_at": 1, "sig": "s", "person": "user_x" })),
        ),
        row("DELETE", "/v1/approver-keys/:approver_id", "/v1/approver-keys/phone_x", N),
        row("PUT", "/v1/approval-floor", "/v1/approval-floor", J(json!({ "floor": "approve" }))),
        row("PUT", "/v1/announce", "/v1/announce", J(json!({ "gateway_id": "gw_1", "announce_secret": "gwa_x" }))),
        row("DELETE", "/v1/announce", "/v1/announce", O(json!({ "gateway_id": "gw_1" }))),
        row("POST", "/v1/recovery/reconciliation/confirm", "/v1/recovery/reconciliation/confirm", J(json!({ "kind": "agent", "id": "x" }))),
        row("POST", "/v1/recovery/reconciliation/remove", "/v1/recovery/reconciliation/remove", J(json!({ "kind": "agent", "id": "x" }))),
        row("POST", "/v1/recovery/reconciliation/confirm-all", "/v1/recovery/reconciliation/confirm-all", N),
        row("POST", "/v1/recovery/reconciliation/close", "/v1/recovery/reconciliation/close", N),
        row(
            "POST",
            "/v1/recovery-codes",
            "/v1/recovery-codes",
            O(json!({ "approver_id": "phone_x", "issued_at": 1, "sig": "s", "audience": "aud_x" })),
        ),
        row("POST", "/v1/agents/register", "/v1/agents/register", J(json!({ "name": "Agent", "id": "agent_x" }))),
        row("POST", "/v1/agents/enroll", "/v1/agents/enroll", J(json!({ "label": "claude-code" }))),
        row("POST", "/v1/agents/:id/approve", "/v1/agents/agent_x/approve", N),
        // The bulk group decides who the caller is before reading the body, so these controls carry the bearer.
        row("POST", "/v1/vault/export", "/v1/vault/export", J(json!({ "passphrase": PASSPHRASE }))),
        Row {
            control_as_operator: true,
            ..row(
                "POST",
                "/v1/vault/import/preview",
                "/v1/vault/import/preview",
                J(json!({ "bundle": bundle, "passphrase": PASSPHRASE, "on_conflict": "skip", "allow_command_capabilities": false })),
            )
        },
        row(
            "POST",
            "/v1/vault/import",
            "/v1/vault/import",
            J(json!({ "bundle": bundle, "passphrase": PASSPHRASE, "on_conflict": "skip", "allow_command_capabilities": false })),
        ),
        Row {
            control_as_operator: true,
            ..row(
                "POST",
                "/v1/connections/import-openapi",
                "/v1/connections/import-openapi",
                J(json!({ "name": "Mini", "spec": openapi_spec(), "base_url": "https://api.mini.example", "dry_run": true })),
            )
        },
        Row {
            control_as_operator: true,
            ..row("POST", "/v1/connectors/install", "/v1/connectors/install", J(json!({ "manifest": manifest(), "version": 1 })))
        },
        Row {
            control_as_operator: true,
            ..row(
                "POST",
                "/v1/invoke",
                "/v1/invoke",
                J(json!({
                    "capability": "github.pull_requests.list", "params": {}, "reason": "check",
                    "execution_location": "local_only", "explain_only": true
                })),
            )
        },
    ]
}

/// Routes the REST table leaves to another test: `/mcp` carries a JSON-RPC envelope, and the MCP tests below hold its tool arguments.
const NOT_IN_THE_TABLE: [(&str, &str); 1] = [("POST", "/mcp")];

async fn send(state: &AppState, method: &str, path: &str, body: Option<String>, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let body = match body {
        Some(text) => {
            request = request.header("content-type", "application/json");
            Body::from(text)
        }
        None => Body::empty(),
    };
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(format!("(not JSON) {}", String::from_utf8_lossy(&bytes))));
    (status, value)
}

fn with_unknown(body: &Value) -> Value {
    let mut body = body.clone();
    body.as_object_mut().expect("every row's body is an object").insert(UNKNOWN.into(), json!(1));
    body
}

/// The refusal the strict extractors write: a 400 whose `error` is a body refusal naming `member`.
fn names_refusal(status: StatusCode, answer: &Value, member: &str) -> Result<(), String> {
    let error = answer["error"].as_str().unwrap_or_default();
    if status == StatusCode::BAD_REQUEST && error.starts_with("bad request: invalid request body") && error.contains(member) {
        Ok(())
    } else {
        Err(format!("{status} {answer}"))
    }
}

fn is_body_refusal(answer: &Value) -> bool {
    answer["error"].as_str().is_some_and(|e| e.contains("invalid request body"))
        || answer.as_str().is_some_and(|e| e.contains("deserialize") || e.contains("parse the request body"))
}

#[tokio::test]
async fn every_mutating_route_refuses_an_unknown_member_and_names_it() {
    let bundle = empty_bundle();
    let mut failures = Vec::new();
    for row in rows(&bundle) {
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        let label = format!("{} {}", row.method, row.route);

        let refused = match &row.reads {
            Reads::Json(body) | Reads::Optional(body) => with_unknown(body),
            Reads::Nothing => json!({ UNKNOWN: 1 }),
        };
        let (status, answer) = send(&state, row.method, row.path, Some(refused.to_string()), Some(&operator)).await;
        if let Err(got) = names_refusal(status, &answer, UNKNOWN) {
            failures.push(format!("{label}: a body carrying `{UNKNOWN}` answered {got}"));
        }
        // A second value after the first was read as the first alone, while the web proxy's own parse refuses it.
        let first = match &row.reads {
            Reads::Json(body) | Reads::Optional(body) => body.to_string(),
            Reads::Nothing => "{}".to_string(),
        };
        for trailing in [format!("{first}{{\"{UNKNOWN}\":1}}"), format!("{first} x")] {
            let (status, answer) = send(&state, row.method, row.path, Some(trailing.clone()), Some(&operator)).await;
            if let Err(got) = names_refusal(status, &answer, "trailing") {
                failures.push(format!("{label}: a body with something after it answered {got}"));
            }
        }

        let bearer = row.control_as_operator.then_some(operator.as_str());
        let controls: Vec<Option<String>> = match &row.reads {
            Reads::Json(body) => vec![Some(body.to_string())],
            Reads::Optional(body) => vec![Some(body.to_string()), None],
            Reads::Nothing => vec![Some("{}".into()), Some("null".into()), None],
        };
        for control in controls {
            let (status, answer) = send(&state, row.method, row.path, control.clone(), bearer).await;
            if is_body_refusal(&answer) {
                failures.push(format!("{label}: the accepted body {control:?} was refused for its body: {status} {answer}"));
            }
        }
    }
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}

/// A member nested inside a request-only object is refused too, named by its path.
#[tokio::test]
async fn an_unknown_member_inside_a_request_object_is_refused_by_its_path() {
    let cases = [
        ("POST", "/v1/grants", json!({ "policy_ids": ["pol_github_prs"], "agents": [{ "agent_id": "codex-cli", "per_agent_limt": 5 }] }), "per_agent_limt"),
        (
            "POST",
            "/v1/connections",
            json!({ "connector": "ssh", "name": "Box", "ssh": { "host": "h.example", "user": "u", "insecure": true, "sftp_rot": "/srv" } }),
            "sftp_rot",
        ),
        (
            "POST",
            "/v1/connections",
            json!({ "connector": "ssh", "name": "Box", "ssh": { "host": "h.example", "user": "u", "insecure": true,
                "exec": [{ "action": "uptime", "args_template": ["uptime"], "requires_aproval": true }] } }),
            "requires_aproval",
        ),
        ("PATCH", "/v1/connections/conn_x", json!({ "ssh": { "hots": "h.example" } }), "hots"),
    ];
    let mut failures = Vec::new();
    for (method, path, body, member) in cases {
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        let (status, answer) = send(&state, method, path, Some(body.to_string()), Some(&operator)).await;
        if let Err(got) = names_refusal(status, &answer, member) {
            failures.push(format!("{method} {path}: `{member}` answered {got}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The grant `docs/policy-language.md` used to teach: every condition in it is one the engine does not
/// have, so the gateway refuses the grant rather than storing it without them.
#[tokio::test]
async fn a_grant_or_policy_carrying_conditions_the_engine_lacks_is_refused_and_not_stored() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let grant = json!({
        "grant_id": "gr_documented",
        "policy_ids": ["pol_braintree_readonly"],
        "agents": ["codex-cli"],
        "denied_actions": ["transactions.refund"],
        "conditions": { "requires_two_person_approval": true, "business_hours_only": true, "max_amount": 50, "allowed_environments": ["staging"] }
    });
    let (status, answer) = send(&state, "POST", "/v1/grants", Some(grant.to_string()), Some(&operator)).await;
    assert!(names_refusal(status, &answer, "conditions").is_ok(), "{status} {answer}");
    assert!(state.service.store().get_grant("gr_documented").unwrap().is_none(), "nothing is stored");

    let policy = json!({ "id": "pol_documented", "connection_id": "github_acme", "allow": ["pull_requests.create"], "max_amount": 50 });
    let (status, answer) = send(&state, "POST", "/v1/policies", Some(policy.to_string()), Some(&operator)).await;
    assert!(names_refusal(status, &answer, "max_amount").is_ok(), "{status} {answer}");
    assert!(state.service.store().get_policy("pol_documented").unwrap().is_none(), "nothing is stored");

    for flag in ["requires_two_person_approval", "requires_touch_id"] {
        let mut policy = json!({ "id": "pol_flagged", "connection_id": "github_acme", "allow": ["pull_requests.create"] });
        policy[flag] = json!(true);
        let (status, answer) = send(&state, "POST", "/v1/policies", Some(policy.to_string()), Some(&operator)).await;
        assert!(names_refusal(status, &answer, flag).is_ok(), "{flag}: {status} {answer}");
    }
}

/// A request member typed with a shared type that stored rows are also read with (an auth scheme, an intermediate certificate, a vault bundle) is read through a strict request-only mirror, so a member inside it is refused by its path too.
#[tokio::test]
async fn an_unknown_member_inside_a_shared_request_type_is_refused_by_its_path() {
    let bundle = empty_bundle();
    let with = |path: &[&str], member: &str| {
        let mut b = bundle.clone();
        let mut at = &mut b;
        for key in path {
            at = &mut at[*key];
        }
        at[member] = json!(1);
        b
    };
    let cert = json!({ "key_id": "k", "pubkey": "p", "issued_at": 1, "expires_at": 2, "root_key_id": "r", "root_sig": "s", "zz_cert": 1 });
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "/v1/connections/import-openapi",
            json!({ "name": "Mini", "spec": openapi_spec(), "dry_run": true, "auth": { "scheme": "basic", "key_as_usrname": true } }),
            "key_as_usrname",
        ),
        (
            "/v1/connections/import-openapi",
            json!({ "name": "Mini", "spec": openapi_spec(), "dry_run": true, "auth": { "scheme": "raw", "header": "Authorization", "prefx": "Token " } }),
            "prefx",
        ),
        (
            "/v1/connections/import-openapi",
            json!({ "name": "Mini", "spec": openapi_spec(), "dry_run": true, "auth": { "scheme": "bearer", "zz_auth": 1 } }),
            "zz_auth",
        ),
        ("/v1/connectors/install", json!({ "manifest": manifest(), "version": 1, "signature": "s", "key_id": "k", "cert": cert, "envelope_version": 2 }), "zz_cert"),
        ("/v1/vault/import/preview", json!({ "bundle": with(&[], "zz_bundle"), "passphrase": PASSPHRASE }), "zz_bundle"),
        ("/v1/vault/import/preview", json!({ "bundle": with(&["source"], "zz_source"), "passphrase": PASSPHRASE }), "zz_source"),
        ("/v1/vault/import/preview", json!({ "bundle": with(&["sealed"], "zz_sealed"), "passphrase": PASSPHRASE }), "zz_sealed"),
        ("/v1/vault/import/preview", json!({ "bundle": with(&["sealed", "kdf_params"], "zz_kdf"), "passphrase": PASSPHRASE }), "zz_kdf"),
        ("/v1/grants", json!({ "policy_id": "pol_github_prs", "target": { "agent": "codex-cli", "zz_target": 1 } }), "zz_target"),
    ];
    let mut failures = Vec::new();
    for (path, body, member) in cases {
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        let (status, answer) = send(&state, "POST", path, Some(body.to_string()), Some(&operator)).await;
        let error = answer["error"].as_str().unwrap_or_default();
        if status != StatusCode::BAD_REQUEST || !error.contains(member) {
            failures.push(format!("{path} `{member}`: {status} {answer}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // The same shared values with nothing extra still read: an auth the dry run itself reports, and a bundle as exported.
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    for auth in [json!({ "scheme": "basic", "key_as_username": true }), json!({ "scheme": "raw", "header": "Authorization", "prefix": "Token " }), json!({ "scheme": "bearer" })] {
        let body = json!({ "name": "Mini", "spec": openapi_spec(), "dry_run": true, "auth": auth });
        let (status, answer) = send(&state, "POST", "/v1/connections/import-openapi", Some(body.to_string()), Some(&operator)).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["auth"], auth, "the dry run reports the scheme it was given");
    }
    let (status, answer) = send(&state, "POST", "/v1/vault/import/preview", Some(json!({ "bundle": bundle, "passphrase": PASSPHRASE }).to_string()), Some(&operator)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
}

/// A capability tool with a pinned shape, an SSH operation or an HTTP spec, says it takes no argument beyond what it reads, and declares the `reason` every capability tool reads for the audit trail.
#[tokio::test]
async fn a_pinned_capability_tool_advertises_a_closed_schema_with_reason() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let (status, created) = send(
        &state,
        "POST",
        "/v1/connections/from-preset",
        Some(json!({ "preset_id": "github", "name": "gh_preset", "id": "gh_preset" }).to_string()),
        Some(&operator),
    )
    .await;
    assert!(status.is_success(), "{status} {created}");
    let listed = rpc(&state, &operator, "tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().expect("a tool list").clone();
    let pinned: Vec<String> = state
        .service
        .store()
        .list_capabilities()
        .unwrap()
        .into_iter()
        .filter(|c| c.ssh.is_some() || c.http.is_some())
        .map(|c| c.id)
        .collect();
    assert!(pinned.iter().any(|id| id.starts_with("ssh.")), "the seed has SSH capabilities: {pinned:?}");
    assert!(pinned.iter().any(|id| id.starts_with("gh_preset.")), "the preset connection has HTTP capabilities: {pinned:?}");
    let mut failures = Vec::new();
    for id in pinned {
        let Some(tool) = tools.iter().find(|t| t["name"] == id.as_str()) else {
            failures.push(format!("{id} is not listed"));
            continue;
        };
        let schema = &tool["inputSchema"];
        if schema["additionalProperties"] != json!(false) || schema["properties"]["reason"]["type"] != "string" {
            failures.push(format!("{id}: {schema}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A member the request type knows but a route would not read on this request is refused too, naming it: the same request that answered 2xx with the member dropped.
#[tokio::test]
async fn a_known_member_a_route_would_not_read_is_refused_by_name() {
    let cases: Vec<(&str, &str, Value, &str)> = vec![
        // On a bearer resolution every device-signature member was dropped, so an `approver` naming a second person was recorded as the operator.
        ("POST", "/v1/approvals", json!({ "approval_id": "appr_x", "approve": true, "approver": "alice" }), "'approver'"),
        ("POST", "/v1/approvals", json!({ "approval_id": "appr_x", "approve": true, "display_digest": "d" }), "'display_digest'"),
        // A PUT's path decides which record it writes, so a different id in the body was dropped.
        ("PUT", "/v1/grants/gr_x", json!({ "grant_id": "gr_other", "policy_ids": ["pol_github_prs"], "all_agents": true }), "gr_other"),
        ("PUT", "/v1/policies/pol_x", json!({ "id": "pol_other", "connection_id": "github_acme", "allow": ["pull_requests.list"] }), "pol_other"),
        // One thing said twice: only one spelling was read.
        ("POST", "/v1/grants", json!({ "policy_ids": ["pol_github_prs"], "policy_id": "pol_vercel", "all_agents": true }), "'policy_id'"),
        ("POST", "/v1/grants", json!({ "policy_ids": ["pol_github_prs"], "all_agents": true, "agents": ["codex-cli"] }), "'agents'"),
        ("POST", "/v1/grants", json!({ "policy_ids": ["pol_github_prs"], "agents": ["codex-cli"], "default_per_agent_limit": 5, "max_calls": 50 }), "'max_calls'"),
        ("POST", "/v1/grants", json!({ "policy_id": "pol_github_prs", "target": "all_agents", "target_agent": "codex-cli" }), "'target_agent'"),
        // A zero quorum was read as absent and kept the stored one.
        ("POST", "/v1/policies", json!({ "connection_id": "github_acme", "device_signed": ["pull_requests.create"], "device_signed_quorum": 0 }), "device_signed_quorum"),
        // SSH configuration on another connector was dropped.
        ("POST", "/v1/connections", json!({ "connector": "github", "name": "GitHub", "ssh": { "host": "h.example", "user": "u", "insecure": true } }), "'ssh'"),
        // A blank link id dropped every link, as no id does.
        ("DELETE", "/v1/announce", json!({ "gateway_id": "  " }), "gateway_id"),
        // The platform was documented as recorded and never read.
        ("POST", "/v1/devices/push-token", json!({ "token": "t", "platform": "windows" }), "platform"),
        // Already refused before this class: a resume secret with nothing to resume.
        ("POST", "/v1/vault/export", json!({ "passphrase": PASSPHRASE, "resume_secret": "x" }), "no export to collect"),
    ];
    let mut failures = Vec::new();
    for (method, path, body, said) in cases {
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        let (status, answer) = send(&state, method, path, Some(body.to_string()), Some(&operator)).await;
        let error = answer["error"].as_str().unwrap_or_default();
        if status != StatusCode::BAD_REQUEST || !error.contains(said) {
            failures.push(format!("{method} {path} {body}: {status} {answer}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // The legacy spellings alone, as `permaura grant` sends them, still make a grant.
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let legacy = json!({ "policy_id": "pol_github_prs", "target_agent": "codex-cli", "max_calls": 5, "expires_at": null });
    let (status, answer) = send(&state, "POST", "/v1/grants", Some(legacy.to_string()), Some(&operator)).await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
}

/// A reviewed OpenAPI digest is checked on a dry run too, as the WordPress import already did, rather than dropped there.
#[tokio::test]
async fn an_openapi_dry_run_checks_the_digest_it_is_given() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let body = json!({ "name": "Mini", "spec": openapi_spec(), "base_url": "https://api.mini.example", "dry_run": true, "digest": "sha256:stale" });
    let (status, answer) = send(&state, "POST", "/v1/connections/import-openapi", Some(body.to_string()), Some(&operator)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
}

/// `envelope_version` is a member the signing service writes, so it is read and checked against the envelope rather than refused or ignored; the envelope members are read only with a signature, and a `key_id` beside a certificate must be the certificate's.
#[tokio::test]
async fn an_install_envelope_is_checked_member_by_member() {
    let cert = json!({ "key_id": "k", "pubkey": "p", "issued_at": 1, "expires_at": 2, "root_key_id": "r", "root_sig": "s" });
    let cases = [
        (json!({ "manifest": manifest(), "version": 1, "signature": "s", "envelope_version": 3 }), "not one this gateway reads"),
        (json!({ "manifest": manifest(), "version": 1, "signature": "s", "envelope_version": 2 }), "does not describe this envelope"),
        (json!({ "manifest": manifest(), "version": 1, "signature": "s", "envelope_version": 1, "cert": cert }), "does not describe this envelope"),
        // Without a signature these were dropped and the manifest installed as user-provided.
        (json!({ "manifest": manifest(), "version": 1, "envelope_version": 1 }), "'envelope_version'"),
        (json!({ "manifest": manifest(), "version": 1, "key_id": "k" }), "'key_id'"),
        (json!({ "manifest": manifest(), "version": 1, "cert": cert, "envelope_version": 2 }), "'cert'"),
        // The certificate decides the key; a different key_id beside it was dropped.
        (json!({ "manifest": manifest(), "version": 1, "signature": "s", "key_id": "other", "cert": cert, "envelope_version": 2 }), "'other'"),
    ];
    for (body, said) in cases {
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        let (status, answer) = send(&state, "POST", "/v1/connectors/install", Some(body.to_string()), Some(&operator)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert!(answer["error"].as_str().is_some_and(|e| e.contains(said)), "{body}: {answer}");
    }
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let body = json!({ "manifest": manifest(), "version": 1, "signature": "not-a-signature", "key_id": "pmconn-dev", "envelope_version": 1 });
    let (status, answer) = send(&state, "POST", "/v1/connectors/install", Some(body.to_string()), Some(&operator)).await;
    let error = answer["error"].as_str().unwrap_or_default();
    assert!(!error.contains("envelope_version") && !error.contains(INVALID_BODY), "a flat envelope that says so reaches the signature check: {status} {answer}");
}

/// A body refused for some other reason than its members keeps its own status, in the gateway's shape.
#[tokio::test]
async fn a_body_without_a_json_content_type_is_refused_in_the_gateway_shape() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/broker/pause")
                .header("authorization", format!("Bearer {operator}"))
                .body(Body::from("{\"paused\":false}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let answer: Value = serde_json::from_slice(&bytes).expect("a JSON body");
    assert!(answer["error"].as_str().is_some_and(|e| e.contains("Content-Type")), "{answer}");
}

/// An SSH host-key posture said two ways kept one of them and dropped the other; each such request is refused.
#[tokio::test]
async fn an_ssh_host_key_posture_said_two_ways_is_refused() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let create = |extra: Value| {
        let mut ssh = json!({ "host": "box.example", "user": "deploy", "exec": [{ "action": "posture", "args_template": ["uptime"] }] });
        ssh.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        json!({ "connector": "ssh", "id": "box_posture", "name": "Box", "ssh": ssh })
    };
    let (status, answer) =
        send(&state, "POST", "/v1/connections", Some(create(json!({ "insecure": true, "host_key_sha256": "SHA256:abc" })).to_string()), Some(&operator)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(answer["error"].as_str().unwrap_or_default().contains("host_key_sha256"), "{answer}");

    let (status, answer) = send(&state, "POST", "/v1/connections", Some(create(json!({ "insecure": true })).to_string()), Some(&operator)).await;
    assert!(status.is_success(), "{status} {answer}");
    for (patch, said) in [
        (json!({ "ssh": { "insecure": true, "host_key_sha256": "SHA256:abc" } }), "host_key_sha256"),
        // On an unverified target this changed nothing and answered 200.
        (json!({ "ssh": { "insecure": false } }), "host_key_sha256"),
    ] {
        let (status, answer) = send(&state, "PATCH", "/v1/connections/box_posture", Some(patch.to_string()), Some(&operator)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{patch}: {answer}");
        assert!(answer["error"].as_str().unwrap_or_default().contains(said), "{patch}: {answer}");
    }
}

/// The last members a route took and did not read: signature members beside a recovery code, `sftp_max_bytes` without an `sftp_root`, and `allow_command_capabilities` on an import preview, which now reports what the import would refuse with it.
#[tokio::test]
async fn the_last_unread_members_are_refused_or_read() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/recovery-codes")
                .header("authorization", format!("Bearer {operator}"))
                .header("content-type", "application/json")
                .header("x-permaura-recovery-code", "abcd-efgh")
                .body(Body::from(json!({ "approver_id": "phone_x", "issued_at": 1, "sig": "s" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(answer["error"].as_str().unwrap_or_default().contains("not both"), "{answer}");

    let body = json!({ "connector": "ssh", "id": "box_sftp", "name": "Box", "ssh": {
        "host": "box.example", "user": "deploy", "insecure": true, "sftp_max_bytes": 1024,
        "exec": [{ "action": "sftpcap", "args_template": ["uptime"] }] } });
    let (status, answer) = send(&state, "POST", "/v1/connections", Some(body.to_string()), Some(&operator)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(answer["error"].as_str().unwrap_or_default().contains("sftp_max_bytes"), "{answer}");

    // A bundle carrying a capability that runs a local program: the import refuses it without the opt-in, and the preview says so.
    let mut cap = state.service.store().list_capabilities().unwrap().into_iter().next().unwrap();
    cap.id = "cmd.run".into();
    cap.kind = permaura_gateway::connectors::CapabilityKind::Command;
    // The store lists capabilities in no fixed order, so the one taken may be an SSH one: clear every transport spec, not only HTTP.
    cap.http = None;
    cap.ssh = None;
    cap.command = Some(permaura_gateway::connectors::CommandSpec {
        program: "echo".into(),
        args_template: vec!["hello".into()],
        secret_env: "TOKEN".into(),
        allowed_placeholders: vec![],
    });
    let payload = BundlePayload { capabilities: vec![permaura_gateway::vault_bundle::CapabilityRecord::from(&cap)], ..Default::default() };
    let bundle = permaura_core::seal_bundle(
        PASSPHRASE.as_bytes(),
        serde_json::to_value(payload).unwrap(),
        1_754_500_000_000,
        permaura_core::BundleSource { gateway_id: "gw_source".into(), mode: "self-run".into() },
    )
    .unwrap();
    for (allow, refused) in [(false, true), (true, false)] {
        let body = json!({ "bundle": bundle, "passphrase": PASSPHRASE, "allow_command_capabilities": allow });
        let (status, answer) = send(&state, "POST", "/v1/vault/import/preview", Some(body.to_string()), Some(&operator)).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let said = answer["broker_refusals"].as_array().into_iter().flatten().any(|r| r.as_str().is_some_and(|r| r.contains("local program")));
        assert_eq!(said, refused, "allow_command_capabilities {allow}: {answer}");
    }
}

/// The extractors agree at their edges: an optional body of `null` is no body, and a body over the route's limit is refused in the gateway's shape.
#[tokio::test]
async fn the_extractors_agree_at_their_edges() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let (status, answer) = send(&state, "DELETE", "/v1/announce", Some("null".into()), Some(&operator)).await;
    assert!(!is_body_refusal(&answer), "{status} {answer}");
    let huge = format!("{{\"pad\":\"{}\"}}", "x".repeat(300 * 1024));
    for (method, path) in [("DELETE", "/v1/grants/gr_x"), ("DELETE", "/v1/announce")] {
        let (status, answer) = send(&state, method, path, Some(huge.clone()), Some(&operator)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{method} {path}: {answer}");
        assert!(answer["error"].is_string(), "{method} {path}: refused in the gateway's shape: {answer}");
    }
}

/// A bundle from a later gateway is refused with the upgrade message, not as an unknown member, even when it carries a member this gateway does not know.
#[tokio::test]
async fn a_newer_bundle_is_refused_with_the_upgrade_message() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let mut bundle = empty_bundle();
    bundle["version"] = json!(2);
    bundle["source"]["label"] = json!("a later member");
    bundle["sealed"]["kdf_params"]["algorithm"] = json!("argon2id-v2");
    let (status, answer) = send(&state, "POST", "/v1/vault/import/preview", Some(json!({ "bundle": bundle, "passphrase": PASSPHRASE }).to_string()), Some(&operator)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    let error = answer["error"].as_str().unwrap_or_default();
    assert!(error.contains("newer") && !error.contains("unknown field"), "{answer}");
}

/// A bundle sealed by the export code released gateways run (`bundle.rs`, `crypto.rs` and `vault_bundle.rs` are unchanged since gateway-v1.3.55, and the envelope's shape since v1.1.1) still reads through the strict mirror.
#[tokio::test]
async fn a_released_gateways_bundle_still_imports() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let bundle: Value = serde_json::from_str(include_str!("fixtures/vault-bundle-v1.json")).unwrap();
    let body = json!({ "bundle": bundle, "passphrase": "golden fixture passphrase" });
    let (status, answer) = send(&state, "POST", "/v1/vault/import/preview", Some(body.to_string()), Some(&operator)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["counts"]["connections"], 1, "{answer}");
}

/// The envelope's members are pinned to `BUNDLE_VERSION`: a change to them is a new version, which an older gateway refuses with the upgrade message rather than as an unknown member.
#[test]
fn the_bundle_envelope_is_pinned_to_its_version() {
    common::isolate_from_the_real_install();
    let bundle = empty_bundle();
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(permaura_core::BUNDLE_VERSION, 1, "a new bundle version: update the members below with it");
    assert_eq!(keys(&bundle), ["created_at_ms", "format", "sealed", "source", "version"]);
    assert_eq!(keys(&bundle["source"]), ["gateway_id", "mode"]);
    assert_eq!(keys(&bundle["sealed"]), ["cipher", "ciphertext", "dek_nonce", "kdf_params", "nonce", "wrapped_dek"]);
    assert_eq!(keys(&bundle["sealed"]["kdf_params"]), ["mem_cost_kib", "parallelism", "salt", "time_cost"]);
}

/// The production intermediate certificate reads through the strict mirror, so a Permaura-signed install carrying it is not refused for its shape.
#[test]
fn the_production_certificate_reads_strictly() {
    let text = include_str!("fixtures/pmconn-int-2026b-cert.json");
    let cert = permaura_gateway::request_body::strict_cert(&mut serde_json::Deserializer::from_str(text)).expect("the committed certificate reads strictly");
    assert!(cert.is_some());
    let mut extra: Value = serde_json::from_str(text).unwrap();
    extra["note"] = json!("hand-edited");
    assert!(permaura_gateway::request_body::strict_cert(&mut serde_json::Deserializer::from_str(&extra.to_string())).is_err());
}

// ── the table and the types, held to the source ──────────────────────────────

/// The text of the call starting just after an opening parenthesis, up to its matching close.
fn balanced(text: &str) -> &str {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, c) in text.char_indices() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &text[..i];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced call: {text}")
}

/// The byte offsets just inside each call `name(` in `text`, as a name of its own and not the tail of a longer one; a method (`.name(`) or a free function (not after a `.`), as `method` says.
fn calls_of(text: &str, name: &str, method: bool) -> Vec<usize> {
    let token = format!("{name}(");
    text.match_indices(&token)
        .filter(|(i, _)| {
            let before = text[..*i].chars().next_back();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '_') && (before == Some('.')) == method
        })
        .map(|(i, _)| i + token.len())
        .collect()
}

/// [`calls_of`] either way: a method router is `post(h)` on its own or `.post(h)` chained onto another.
fn calls(text: &str, name: &str) -> Vec<usize> {
    let mut at = calls_of(text, name, false);
    at.extend(calls_of(text, name, true));
    at
}

/// Every `(METHOD, route, handler)` `build_router` in `lib` serves for POST, PUT, PATCH and DELETE, and every way it mounts a route that this scan could not read, which fails the pin rather than hiding a route from it.
fn scan_router(lib: &str) -> (Vec<(String, String, String)>, Vec<String>) {
    let start = lib.find("pub fn build_router").expect("lib.rs has build_router");
    let body = &lib[start..];
    let body = &body[..body.find("\n}\n").expect("build_router ends")];
    let mut unreadable = Vec::new();
    for (name, method) in [("nest", true), ("nest_service", true), ("route_service", true), ("fallback_service", true), ("on", false), ("on", true), ("any", false)] {
        if !calls_of(body, name, method).is_empty() {
            unreadable.push(format!("build_router calls `{name}(`, which mounts what this scan cannot read"));
        }
    }
    for at in calls_of(body, "merge", true) {
        let merged = balanced(&body[at..]).trim();
        if !["bulk", "execution"].contains(&merged) {
            unreadable.push(format!("build_router merges `{merged}`, a router this scan does not read"));
        }
    }
    let mut found = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find(".route(") {
        let after = &rest[at + ".route(".len()..];
        let call = balanced(after);
        let open = call.find('"').expect("a route names its path");
        let close = open + 1 + call[open + 1..].find('"').expect("the path literal closes");
        let route = &call[open + 1..close];
        let mut methods = 0;
        for method in ["get", "head", "options", "post", "put", "patch", "delete"] {
            for at in calls(call, method) {
                methods += 1;
                if ["get", "head", "options"].contains(&method) {
                    continue;
                }
                let handler = balanced(&call[at..]).trim();
                let handler = handler.rsplit("::").next().unwrap_or(handler).to_string();
                found.push((method.to_uppercase(), route.to_string(), handler));
            }
        }
        if methods == 0 {
            unreadable.push(format!("route {route} names no method this scan reads"));
        }
        rest = &after[call.len()..];
    }
    (found, unreadable)
}

fn mutating_routes() -> Vec<(String, String, String)> {
    scan_router(LIB_RS).0
}

#[test]
fn every_mutating_route_is_in_the_table() {
    let (served, unreadable) = scan_router(LIB_RS);
    assert!(unreadable.is_empty(), "{}", unreadable.join("\n"));
    assert!(served.len() > 40, "the scan found the router: {served:?}");
    let bundle = json!({});
    let table: Vec<(String, String)> = rows(&bundle).iter().map(|r| (r.method.to_string(), r.route.to_string())).collect();
    let exempt: Vec<(String, String)> = NOT_IN_THE_TABLE.iter().map(|(m, r)| (m.to_string(), r.to_string())).collect();
    let missing: Vec<_> = served
        .iter()
        .filter(|(m, r, _)| !table.contains(&(m.clone(), r.clone())) && !exempt.contains(&(m.clone(), r.clone())))
        .collect();
    assert!(missing.is_empty(), "mutating routes with no row in this test's table: add one for each: {missing:?}");
    let stale: Vec<_> = table.iter().filter(|(m, r)| !served.iter().any(|(sm, sr, _)| sm == m && sr == r)).collect();
    assert!(stale.is_empty(), "rows for routes the router no longer serves: {stale:?}");
}

/// The signature of `handler` in `src`, up to its return type.
fn signature<'a>(src: &'a str, handler: &str) -> Option<&'a str> {
    let key = format!("pub async fn {handler}(");
    let start = src.find(&key)?;
    let sig = &src[start..];
    Some(&sig[..sig.find(") ->")?])
}

/// The line index of the item `struct name` or `enum name` in `src`, whatever its visibility.
fn item_line(src: &str, name: &str) -> Option<usize> {
    src.lines().position(|l| {
        let l = l.trim_start_matches("pub(crate) ").trim_start_matches("pub ");
        ["struct", "enum"].iter().any(|kind| l.starts_with(&format!("{kind} {name} ")) || l.starts_with(&format!("{kind} {name}<")))
    })
}

/// Whether the struct or enum `name` in `src` carries `#[serde(deny_unknown_fields)]` in its attributes, not in a doc comment.
fn denies_unknown_fields(src: &str, name: &str) -> bool {
    let lines: Vec<&str> = src.lines().collect();
    let Some(at) = item_line(src, name) else { return false };
    lines[..at]
        .iter()
        .rev()
        .take_while(|l| {
            let l = l.trim_start();
            l.starts_with("#[") || l.starts_with("///")
        })
        .any(|l| l.trim_start().starts_with("#[") && l.contains("deny_unknown_fields"))
}

/// The type parameter of `extractor<...>` in `sig`.
fn body_type<'a>(sig: &'a str, extractor: &str) -> Option<&'a str> {
    let open = sig.find(&format!(": {extractor}<"))? + extractor.len() + 3;
    let close = open + sig[open..].find('>')?;
    Some(sig[open..close].rsplit("::").next().unwrap_or(&sig[open..close]))
}

/// The handlers in `rest` that read a body through a strict extractor; each must serve a route the router scan read.
fn strict_handlers(rest: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (at, _) in rest.match_indices("pub async fn ") {
        let name_start = at + "pub async fn ".len();
        let name: String = rest[name_start..].chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        if let Some(sig) = signature(rest, &name) {
            if ["JsonBody<", "OptionalJsonBody<", "NoBody"].iter().any(|e| sig.contains(e)) {
                found.push(name);
            }
        }
    }
    found
}

/// One field of a struct as the scan reads it.
struct Field {
    name: String,
    ty: String,
    attrs: String,
}

/// The fields of `struct name` in `src`, every line of its body accounted for: a field written over several lines is joined up to its comma, and a line that is neither an attribute, a comment nor part of a field is a failure, so no field can hide from the walk.
fn struct_fields(src: &str, name: &str) -> Result<Vec<Field>, String> {
    let lines: Vec<&str> = src.lines().collect();
    let at = item_line(src, name).ok_or_else(|| format!("no struct {name}"))?;
    if !lines[at].contains("struct ") || !lines[at].trim_end().ends_with('{') {
        return Err(format!("{name} is not a struct with named fields"));
    }
    let mut fields = Vec::new();
    let (mut attrs, mut pending) = (String::new(), String::new());
    for line in &lines[at + 1..] {
        if *line == "}" {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if pending.is_empty() && line.starts_with("#[") {
            if !line.ends_with(']') {
                return Err(format!("{name}: an attribute over several lines: {line}"));
            }
            attrs.push_str(line);
            continue;
        }
        pending.push_str(line);
        pending.push(' ');
        let depth = pending.chars().fold(0i32, |d, c| match c {
            '<' | '(' | '[' | '{' => d + 1,
            '>' | ')' | ']' | '}' => d - 1,
            _ => d,
        });
        if depth == 0 && pending.trim_end().ends_with(',') {
            let field = pending.trim().trim_end_matches(',');
            let field = field.trim_start_matches("pub(crate) ").trim_start_matches("pub ");
            let (fname, ty) = field.split_once(':').ok_or_else(|| format!("{name}: a line the scan cannot read: {field}"))?;
            fields.push(Field { name: fname.trim().to_string(), ty: ty.trim().to_string(), attrs: std::mem::take(&mut attrs) });
            pending.clear();
        }
    }
    if !pending.trim().is_empty() {
        return Err(format!("{name}: a field without a closing comma: {}", pending.trim()));
    }
    Ok(fields)
}

const STD_FIELD_TYPES: [&str; 11] = ["Option", "Vec", "String", "bool", "u8", "u16", "u32", "u64", "i64", "BTreeMap", "std"];
/// Shared enums whose every variant is a unit variant, so an unknown value is refused already.
const UNIT_ENUMS: [&str; 5] = ["RiskTier", "ExecutionLocation", "OnConflict", "GrantPeriod", "Cipher"];
/// The two fields free-form by design, each for its reason, keyed by struct and field so the exemption covers nothing else.
const FREE_FORM_FIELDS: [(&str, &str, &str); 2] = [
    ("InstallConnectorReq", "manifest", "a connector manifest, a document verified over its bytes as sent"),
    ("InvokeReq", "params", "an agent's capability params, checked against a pinned capability's own parameters by the service"),
];
/// The marker after which request_body.rs declares its strict mirrors of shared types.
const MIRRORS_MARKER: &str = "// ── Strict readings of shared types";

/// Check every field of `ty` (in `src`) and, through them, every request type reachable from it.
fn walk_fields(src: &str, body_src: &str, ty: &str, seen: &mut Vec<String>, failures: &mut Vec<String>) {
    if seen.iter().any(|s| s == ty) {
        return;
    }
    seen.push(ty.to_string());
    if !denies_unknown_fields(src, ty) {
        failures.push(format!("{ty} does not deny unknown fields"));
    }
    let fields = match struct_fields(src, ty) {
        Ok(fields) => fields,
        Err(why) => return failures.push(why),
    };
    for field in fields {
        if let Some(at) = field.attrs.find("deserialize_with = \"") {
            let path = &field.attrs[at + "deserialize_with = \"".len()..];
            let path = &path[..path.find('"').unwrap_or(path.len())];
            let reader = path.strip_prefix("crate::request_body::").unwrap_or("");
            if !reader.starts_with("strict_") || !body_src.contains(&format!("pub fn {reader}<")) {
                failures.push(format!("{ty}.{}: deserialize_with names `{path}`, which is not one of request_body's strict readers", field.name));
            }
            continue;
        }
        for word in field.ty.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':')).filter(|w| !w.is_empty()) {
            let last = word.rsplit("::").next().unwrap_or(word);
            if STD_FIELD_TYPES.contains(&last) || UNIT_ENUMS.contains(&last) {
                continue;
            }
            if ["Value", "MeteredValue"].contains(&last) && FREE_FORM_FIELDS.iter().any(|(t, f, _)| *t == ty && *f == field.name) {
                continue;
            }
            if last == "AgentSel" {
                walk_fields(src, body_src, "AgentOverride", seen, failures);
                continue;
            }
            if item_line(src, last).is_some() {
                walk_fields(src, body_src, last, seen, failures);
                continue;
            }
            failures.push(format!(
                "{ty}.{} is typed `{}`: `{last}` is a type this scan cannot see refuse a member it does not know; read it through a strict mirror",
                field.name, field.ty
            ));
        }
    }
}

/// The strict mirrors request_body.rs declares, read from the source rather than listed by hand: every struct or enum after the marker that derives `Deserialize`. One read by hand (the bundle, whose version is read first) refuses unknown members in its own visitor, which the behavior tests hold.
fn strict_mirrors(body_src: &str) -> Vec<String> {
    let start = body_src.find(MIRRORS_MARKER).expect("request_body.rs marks its strict mirrors");
    let lines: Vec<&str> = body_src[start..].lines().collect();
    lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let l = l.trim_start_matches("pub(crate) ").trim_start_matches("pub ");
            let rest = l.strip_prefix("struct ").or_else(|| l.strip_prefix("enum "))?;
            let derives = lines[..i].iter().rev().take_while(|p| p.trim_start().starts_with("#[") || p.trim_start().starts_with("///")).any(|p| p.contains("Deserialize"));
            derives.then(|| rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect())
        })
        .collect()
}

/// The unit variants of `enum name` in `src`: under `tag = ...` a unit variant reads a map and drops every member in it whatever `deny_unknown_fields` says, so a strict mirror writes each variant with braces.
fn unit_variants(src: &str, name: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let Some(at) = item_line(src, name) else { return Vec::new() };
    let mut depth = 0i32;
    let mut found = Vec::new();
    for line in &lines[at..] {
        let trimmed = line.trim();
        if depth == 1 && !trimmed.starts_with('#') && !trimmed.starts_with("//") {
            let variant = trimmed.trim_end_matches(',');
            if !variant.is_empty() && variant.chars().all(|c| c.is_alphanumeric() || c == '_') {
                found.push(variant.to_string());
            }
        }
        depth += trimmed.matches('{').count() as i32 - trimmed.matches('}').count() as i32;
        if depth == 0 && line.contains('}') {
            break;
        }
    }
    found
}

/// Every failure the type scan finds in `rest` and `body_src` (request_body.rs), given the router's mutating routes.
fn scan_types(rest: &str, body_src: &str, routes: &[(String, String, String)]) -> Vec<String> {
    let mut failures = Vec::new();
    let mut roots = vec!["InvokeReq".to_string()];
    for (method, route, handler) in routes {
        if (method.as_str(), route.as_str()) == ("POST", "/mcp") {
            continue;
        }
        let Some(sig) = signature(rest, handler) else {
            failures.push(format!("{method} {route}: no `pub async fn {handler}(` in rest.rs"));
            continue;
        };
        for bare in [": Json<", "Option<Json<", "Bytes", ": String", ": Form<"] {
            if sig.contains(bare) {
                failures.push(format!("{method} {route}: {handler} reads its body as `{bare}`, which ignores unknown members"));
            }
        }
        match body_type(sig, "JsonBody").or_else(|| body_type(sig, "OptionalJsonBody")) {
            Some(ty) => roots.push(ty.to_string()),
            None if sig.contains("NoBody") => {}
            // `/v1/invoke` resolves its caller before reading the body, so it reads it itself, through the metered parse, into `InvokeReq`.
            None if handler == "invoke" && sig.contains("request: Request") => {}
            None => failures.push(format!("{method} {route}: {handler} reads no body through JsonBody, OptionalJsonBody or NoBody")),
        }
    }
    for handler in strict_handlers(rest) {
        if !routes.iter().any(|(_, _, h)| *h == handler) {
            failures.push(format!("{handler} reads a strict body but serves no route the router scan read"));
        }
    }
    let mut seen = Vec::new();
    for ty in roots {
        walk_fields(rest, body_src, &ty, &mut seen, &mut failures);
    }
    let mirrors = strict_mirrors(body_src);
    if mirrors.len() < 4 {
        failures.push(format!("request_body.rs declares too few strict mirrors for the scan to have read them: {mirrors:?}"));
    }
    for mirror in mirrors {
        if !denies_unknown_fields(body_src, &mirror) {
            failures.push(format!("{mirror} does not deny unknown fields"));
        }
        if struct_fields(body_src, &mirror).is_ok() {
            let mut seen_here = Vec::new();
            walk_fields(body_src, body_src, &mirror, &mut seen_here, &mut failures);
        } else {
            for variant in unit_variants(body_src, &mirror) {
                failures.push(format!("{mirror}::{variant} is a unit variant, which reads a map and drops every member in it; write it `{variant} {{}}`"));
            }
        }
    }
    failures
}

#[test]
fn every_request_type_is_read_strictly_all_the_way_down() {
    let failures = scan_types(REST_RS, REQUEST_BODY_RS, &mutating_routes());
    assert!(MCP_RS.contains("pub async fn handle("), "the MCP entry point is where this test looks for it");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The scans fail on each way a route or a field could otherwise slip past them: a router mounted another way, a free-form field outside its two named exemptions, a field written over two lines or not `pub`, a reader that is not strict, a nested type without the attribute, and a unit variant in a mirror.
#[test]
fn the_scans_catch_what_they_would_otherwise_miss() {
    let routes = mutating_routes();
    let into_push_token = |extra: &str| REST_RS.replacen("pub struct PushTokenReq {\n", &format!("pub struct PushTokenReq {{\n{extra}"), 1);
    let field_cases = [
        ("a free-form field", into_push_token("    pub metadata: Option<serde_json::Value>,\n")),
        ("a type on the next line", into_push_token("    pub scheme:\n        Option<crate::connectors::AuthScheme>,\n")),
        ("a field that is not pub", into_push_token("    pub(crate) hidden: Option<crate::connectors::AuthScheme>,\n")),
        ("a lenient reader", into_push_token("    #[serde(default, deserialize_with = \"lenient\")]\n    pub other: Option<crate::connectors::AuthScheme>,\n")),
        (
            "a nested type without the attribute",
            into_push_token("    pub nested: Nested,\n") + "\n#[derive(Deserialize)]\npub struct Nested {\n    pub a: String,\n}\n",
        ),
    ];
    for (what, mutated) in field_cases {
        assert!(!scan_types(&mutated, REQUEST_BODY_RS, &routes).is_empty(), "the type scan misses {what}");
    }
    let unit = REQUEST_BODY_RS.replacen("    Bearer {},", "    Bearer,", 1);
    assert_ne!(unit, REQUEST_BODY_RS, "the auth mirror writes its bearer variant with braces");
    assert!(!scan_types(REST_RS, &unit, &routes).is_empty(), "the type scan misses a unit variant in a mirror");
    let in_router = |extra: &str| LIB_RS.replacen("        .merge(bulk)\n", &format!("        .merge(bulk)\n{extra}"), 1);
    for (what, extra) in [
        ("a merged helper router", "        .merge(extra_routes())\n"),
        ("a method filter", "        .route(\"/v1/filtered\", on(MethodFilter::POST, rest::filtered))\n"),
        ("a route for any method", "        .route(\"/v1/any\", any(rest::anything))\n"),
        ("a method router bound elsewhere", "        .route(\"/v1/bound\", bound_router)\n"),
    ] {
        let mutated = in_router(extra);
        assert_ne!(mutated, LIB_RS, "the router has `.merge(bulk)` to anchor the mutation");
        assert!(!scan_router(&mutated).1.is_empty(), "the router scan misses {what}");
    }
}

// ── MCP ───────────────────────────────────────────────────────────────────────

async fn rpc(state: &AppState, bearer: &str, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params });
    let (status, answer) = send(state, "POST", "/mcp", Some(body.to_string()), Some(bearer)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    answer
}

/// Arguments that satisfy `schema`'s required members, with placeholder values of the declared type.
fn required_arguments(schema: &Value) -> Value {
    let mut args = serde_json::Map::new();
    for name in schema["required"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let value = match schema["properties"][name]["type"].as_str() {
            Some("object") => json!({}),
            Some("array") => json!([]),
            Some("integer") | Some("number") => json!(1),
            Some("boolean") => json!(false),
            _ => json!("placeholder"),
        };
        args.insert(name.to_string(), value);
    }
    Value::Object(args)
}

/// A value of the wrong type for `schema`, or `None` where the schema states no type.
fn mistyped(schema: &Value) -> Option<Value> {
    match schema["type"].as_str()? {
        "string" => Some(json!(123)),
        "object" => Some(json!("not an object")),
        "array" => Some(json!([5])),
        _ => Some(json!("not a number")),
    }
}

/// Every fixed tool that reads arguments refuses one it does not declare and a value of the wrong type for one it does, naming it; arguments that are not an object are refused; an omitted or null `arguments` is read as none.
#[tokio::test]
async fn every_fixed_mcp_tool_refuses_an_argument_it_does_not_declare() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let listed = rpc(&state, &operator, "tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().expect("a tool list").clone();
    let fixed: Vec<&Value> = tools.iter().filter(|t| t["name"].as_str().is_some_and(|n| n.starts_with("permaura_"))).collect();
    assert!(fixed.len() >= 7, "the fixed tools are listed: {listed}");

    let mut failures = Vec::new();
    for tool in fixed {
        // Each tool gets its own session, or the calls below pass the per-session execution rate.
        let state = common::seeded();
        let operator = common::operator_token(state.clone()).await;
        let name = tool["name"].as_str().unwrap();
        let schema = &tool["inputSchema"];
        let declared = schema["properties"].as_object().cloned().unwrap_or_default();
        let refuses = |answer: &Value, what: &str| {
            answer["error"]["code"] == json!(-32602) && answer["error"]["message"].as_str().is_some_and(|m| m.contains(what))
        };
        // Omitted or null arguments mean none: a client may send either for a tool with nothing required.
        for params in [json!({ "name": name }), json!({ "name": name, "arguments": null })] {
            let answer = rpc(&state, &operator, "tools/call", params.clone()).await;
            if answer["error"]["code"] == json!(-32602) && answer["error"]["message"].as_str().is_some_and(|m| m.contains("argument")) {
                failures.push(format!("{name}: {params} was refused for its arguments: {answer}"));
            }
        }
        if declared.is_empty() {
            // A tool that reads nothing cannot drop anything that changes its answer, and some clients add a placeholder argument to such a tool, so it takes whatever it is sent and does not advertise a refusal it does not make.
            if schema["additionalProperties"] == json!(false) {
                failures.push(format!("{name}: it reads no argument but advertises refusing them: {schema}"));
            }
            let answer = rpc(&state, &operator, "tools/call", json!({ "name": name, "arguments": { "random_string": "x" } })).await;
            if answer["error"].is_object() {
                failures.push(format!("{name}: an argument it does not read was refused: {answer}"));
            }
            continue;
        }
        if schema["additionalProperties"] != json!(false) {
            failures.push(format!("{name}: its input schema does not say it takes no other argument: {schema}"));
        }
        let mut args = required_arguments(schema);
        args[UNKNOWN] = json!(1);
        let answer = rpc(&state, &operator, "tools/call", json!({ "name": name, "arguments": args })).await;
        if !refuses(&answer, UNKNOWN) {
            failures.push(format!("{name}: an undeclared argument answered {answer}"));
        }
        let answer = rpc(&state, &operator, "tools/call", json!({ "name": name, "arguments": "not an object" })).await;
        if answer["error"]["code"] != json!(-32602) {
            failures.push(format!("{name}: arguments that are not an object answered {answer}"));
        }
        // A mistyped value used to read as absent: `session_id: 123` revoked the caller's own session.
        for (property, property_schema) in &declared {
            let Some(wrong) = mistyped(property_schema) else { continue };
            let mut args = required_arguments(schema);
            args[property.as_str()] = wrong;
            let answer = rpc(&state, &operator, "tools/call", json!({ "name": name, "arguments": args })).await;
            if !refuses(&answer, property) {
                failures.push(format!("{name}: a mistyped '{property}' answered {answer}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `scope` was advertised and never read; the tool now reads no argument and ignores any it is sent, including the placeholder some clients add to an argument-less tool.
#[tokio::test]
async fn list_capabilities_reads_no_argument_and_ignores_any_it_is_sent() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    for args in [json!({ "scope": "all" }), json!({ "random_string": "x" }), json!({})] {
        let answer = rpc(&state, &operator, "tools/call", json!({ "name": "permaura_list_capabilities", "arguments": args })).await;
        assert!(answer["result"].is_object(), "{args}: {answer}");
    }
    let listed = rpc(&state, &operator, "tools/list", json!({})).await;
    let tool = listed["result"]["tools"].as_array().unwrap().iter().find(|t| t["name"] == "permaura_list_capabilities").unwrap().clone();
    assert!(tool["inputSchema"]["properties"].get("scope").is_none(), "{tool}");
}

/// An HTTP capability's tool advertises the parameters its connector forwards, not a guess keyed on its id.
#[tokio::test]
async fn an_http_capability_tool_advertises_the_parameters_its_connector_forwards() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let (status, connection) = send(
        &state,
        "POST",
        "/v1/connections/from-preset",
        Some(json!({ "preset_id": "github", "name": "gh_preset", "id": "gh_preset" }).to_string()),
        Some(&operator),
    )
    .await;
    assert!(status.is_success(), "{status} {connection}");
    let listed = rpc(&state, &operator, "tools/list", json!({})).await;
    let tool = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "gh_preset.pull_requests.create")
        .unwrap_or_else(|| panic!("the preset connection's tool is listed: {listed}"))
        .clone();
    let schema = &tool["inputSchema"];
    for name in ["owner", "repo", "title", "head", "base", "body", "reason"] {
        assert!(schema["properties"].get(name).is_some(), "{name} is advertised: {schema}");
    }
    assert_eq!(schema["required"], json!(["owner", "repo"]), "{schema}");
    assert_eq!(schema["additionalProperties"], json!(false), "{schema}");
}

/// The argument names each tool in the STDIO bridge's static advertisement (`packages/mcp-stdio/src/tools.ts`) declares, read from its source.
fn stdio_static_arguments() -> Vec<(String, Vec<String>, Vec<String>)> {
    let src = include_str!("../../../packages/mcp-stdio/src/tools.ts");
    let list = &src[src.find("export const PERMAURA_TOOLS").expect("the static list")..];
    let mut tools = Vec::new();
    let mut rest = list;
    while let Some(at) = rest.find("name: \"permaura_") {
        let after = &rest[at + "name: \"".len()..];
        let name = after[..after.find('"').unwrap()].to_string();
        let props_at = after.find("properties: {").expect("each tool declares its properties") + "properties: {".len();
        let mut keys = Vec::new();
        let (mut depth, mut in_string, mut escaped, mut token) = (1usize, false, false, String::new());
        for c in after[props_at..].chars() {
            if in_string {
                match (escaped, c) {
                    (true, _) => escaped = false,
                    (false, '\\') => escaped = true,
                    (false, '"') => in_string = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => in_string = true,
                '{' | '[' => depth += 1,
                '}' | ']' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                ':' if depth == 1 && !token.trim().is_empty() => {
                    keys.push(token.trim().to_string());
                    token.clear();
                    continue;
                }
                ',' if depth == 1 => token.clear(),
                _ if depth == 1 => token.push(c),
                _ => {}
            }
        }
        let block_end = after[props_at..].find("name: \"permaura_").map_or(after.len(), |i| props_at + i);
        let block = &after[props_at..block_end];
        let required = block
            .find("required: [")
            .map(|at| {
                let list = &block[at + "required: [".len()..];
                list[..list.find(']').unwrap()].split(',').map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect()
            })
            .unwrap_or_default();
        tools.push((name, keys, required));
        rest = &after[props_at..];
    }
    tools
}

/// The static list's only deliberate omission: some gateway versions answer explain_denial by attempting the call, so the list a bridge serves when it cannot reach the gateway offers no parameters for it to run with.
const STDIO_LEAVES_OUT: &[(&str, &str)] = &[("permaura_explain_denial", "params")];

/// The bridge serves its static list only when the gateway cannot be reached, and an agent may keep it, so nothing in it may name an argument the gateway's own tool refuses, require what the gateway does not, or leave out what the gateway reads unless it is listed in STDIO_LEAVES_OUT.
#[tokio::test]
async fn the_stdio_bridge_advertises_no_argument_the_gateway_refuses() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let listed = rpc(&state, &operator, "tools/list", json!({})).await;
    let gateway = listed["result"]["tools"].as_array().expect("a tool list").clone();
    let advertised = stdio_static_arguments();
    assert!(advertised.len() >= 7, "the static list was read: {advertised:?}");
    let mut failures = Vec::new();
    for (name, keys, required) in advertised {
        let Some(tool) = gateway.iter().find(|t| t["name"] == name.as_str()) else {
            failures.push(format!("{name} is not one of the gateway's tools"));
            continue;
        };
        for key in &keys {
            if tool["inputSchema"]["properties"].get(key).is_none() {
                failures.push(format!("{name} advertises '{key}', which the gateway's tool does not declare"));
            }
        }
        for key in tool["inputSchema"]["properties"].as_object().into_iter().flat_map(|p| p.keys()) {
            let left_out_on_purpose = STDIO_LEAVES_OUT.contains(&(name.as_str(), key.as_str()));
            if keys.contains(key) && left_out_on_purpose {
                failures.push(format!("{name} now advertises '{key}', so its entry in STDIO_LEAVES_OUT is stale"));
            } else if !keys.contains(key) && !left_out_on_purpose {
                failures.push(format!("{name} leaves out '{key}', which the gateway's tool reads"));
            }
        }
        let gateway_required: Vec<String> =
            tool["inputSchema"]["required"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
        if required != gateway_required {
            failures.push(format!("{name} requires {required:?} and the gateway's tool requires {gateway_required:?}"));
        }
    }
    // permaura_request_grant writes no row, event or announce, so neither side may tell an agent the operator was asked.
    let gateway_grant = gateway.iter().find(|t| t["name"] == "permaura_request_grant").expect("request_grant is listed");
    let stdio_src = include_str!("../../../packages/mcp-stdio/src/tools.ts");
    let stdio_grant = &stdio_src[stdio_src.find("name: \"permaura_request_grant\"").expect("stdio lists request_grant")..];
    let stdio_grant = &stdio_grant[..stdio_grant.find("inputSchema").expect("its schema follows its description")];
    for (side, description) in [("gateway", gateway_grant["description"].as_str().unwrap_or_default()), ("stdio", stdio_grant)] {
        if !description.contains("records nothing") {
            failures.push(format!("the {side} request_grant description does not say it records nothing: {description}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
