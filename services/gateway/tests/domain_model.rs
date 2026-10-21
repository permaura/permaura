//! Integration tests for the redesigned domain model: the capability master-switch,
//! the agent connect→approve gate, and the connection → policy → grant flow through
//! the REST surface.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::store::{Agent, AgentStatus, PendingApproval};
use permaura_gateway::service::ApprovalFloor;
use common::build_router;
use permaura_gateway::{seed, AppState};
use tower::ServiceExt;

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

mod common;

fn app() -> axum::Router {
    build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap())
}

/// POST `uri` with an optional bearer token and JSON body; return (status, json).
async fn post(
    app: &axum::Router,
    uri: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// GET `uri` with a bearer token; return (status, json).
async fn get(app: &axum::Router, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// Disabling a capability on its connection denies it for every grant, above the policy.
#[tokio::test]
async fn disabled_capability_is_denied_above_policy() {
    let app = app();
    // Sanity: it is allowed before the toggle.
    let (status, _) = post(
        &app,
        "/v1/invoke",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": "braintree.transactions.search", "params": {} }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Switch the capability off on its connection.
    let (status, _) = post(
        &app,
        "/v1/connections/braintree_production/capabilities",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": "braintree.transactions.search", "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Now the same call is denied with the master-switch reason.
    let (status, json) = post(
        &app,
        "/v1/invoke",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": "braintree.transactions.search", "params": {} }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(json["decision"]["reason"]
        .as_str()
        .unwrap()
        .contains("switched off"));
}

/// The full connect→approve flow: a connection + policy + all-agents grant is created, an
/// agent self-enrols over MCP (landing Pending), is denied while Pending, then allowed once
/// an operator approves it.
#[tokio::test]
async fn agent_must_be_approved_before_it_can_invoke() {
    let app = app();

    // 1. Operator builds a connection + credential + policy + all-agents grant.
    let (status, conn) = post(
        &app,
        "/v1/connections",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": "Second GitHub" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let connection_id = conn["connection_id"].as_str().unwrap().to_string();

    let (status, _) = post(
        &app,
        &format!("/v1/connections/{connection_id}/credential"),
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "value": "ghp_second_account_token" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, pol) = post(
        &app,
        "/v1/policies",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({
            "connection_id": connection_id,
            "name": "Read-only PRs",
            "allow": ["pull_requests.list"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let policy_id = pol["policy_id"].as_str().unwrap().to_string();

    let (status, _grant) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "policy_id": policy_id, "target": "all_agents" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // The capability id is namespaced by connection (so two GitHub accounts don't collide).
    let capability = format!("{connection_id}.pull_requests.list");

    // 2. Operator mints an enrolment code; the agent redeems it over MCP → Pending + token.
    let (status, enroll) = post(
        &app,
        "/v1/agents/enroll",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "label": "Cursor" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let code = enroll["code"].as_str().unwrap().to_string();

    let (status, mcp) = post(
        &app,
        "/mcp",
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "name": "Cursor", "agent_id": "cursor" } }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let result = &mcp["result"]["structuredContent"];
    assert_eq!(result["status"], "pending");
    let agent_token = result["token"].as_str().unwrap().to_string();

    // 3. While Pending, the agent is denied even though an all-agents grant covers the cap.
    let (status, json) = post(
        &app,
        "/v1/invoke",
        Some(&agent_token),
        serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(json["decision"]["reason"]
        .as_str()
        .unwrap()
        .contains("not approved"));

    // 4. Operator approves the agent (one click).
    let (status, _) = post(
        &app,
        "/v1/agents/cursor/approve",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 5. Now the same call is allowed.
    let (status, json) = post(
        &app,
        "/v1/invoke",
        Some(&agent_token),
        serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approved agent should be allowed: {json}");
    assert_eq!(json["decision"]["decision"], "allow");
}

/// Security regression: an agent-role token (minted by MCP self-enrolment)
/// must never be able to drive the console: it cannot approve itself, self-grant, or create
/// connections. This is the gate that stops a self-enrolled agent escalating to Approved-with-
/// grants on its own.
#[tokio::test]
async fn agent_token_cannot_drive_the_console() {
    let app = app();
    // Enrol an agent → get its agent-role token.
    let (_s, enroll) = post(
        &app,
        "/v1/agents/enroll",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({}),
    )
    .await;
    let code = enroll["code"].as_str().unwrap().to_string();
    let (_s, mcp) = post(
        &app,
        "/mcp",
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "evil" } }
        }),
    )
    .await;
    let agent_token = mcp["result"]["structuredContent"]["token"].as_str().unwrap().to_string();

    // The agent token is rejected (403) on every control-plane mutation it might use to escalate.
    for (uri, body) in [
        ("/v1/agents/evil/approve", serde_json::json!({})),
        ("/v1/grants", serde_json::json!({ "policy_id": "pol_github_prs", "target": "all_agents" })),
        ("/v1/connections", serde_json::json!({ "connector": "github", "name": "X" })),
        ("/v1/policies", serde_json::json!({ "connection_id": "github_acme", "name": "x", "allow": [] })),
    ] {
        let (status, _) = post(&app, uri, Some(&agent_token), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "agent token must be forbidden on {uri}");
    }
}

/// Security regression: the credential-/authorization-root mutations reject an *unauthenticated*
/// caller (they previously had no auth at all).
#[tokio::test]
async fn unauthenticated_mutations_are_rejected() {
    let app = app();
    for (uri, body) in [
        ("/v1/grants", serde_json::json!({ "policy_id": "pol_github_prs", "target": "all_agents" })),
        ("/v1/approvals", serde_json::json!({ "approval_id": "x", "approve": true })),
        ("/v1/secrets", serde_json::json!({ "value": "hunter2" })),
    ] {
        let (status, _) = post(&app, uri, None, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri} without a token must be 401");
    }
}

/// Security regression: MCP self-enrolment cannot hijack an existing agent id (which would
/// overwrite/downgrade the approved operator or seeded agent).
#[tokio::test]
async fn enrolment_cannot_hijack_an_existing_agent_id() {
    let app = app();
    let (_s, enroll) = post(
        &app,
        "/v1/agents/enroll",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({}),
    )
    .await;
    let code = enroll["code"].as_str().unwrap().to_string();
    let (status, mcp) = post(
        &app,
        "/mcp",
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "codex-cli" } }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The JSON-RPC call returns an error (id collision), not a token, so codex-cli is untouched.
    assert!(mcp["error"].is_object(), "enrol onto existing id must error: {mcp}");
}

/// An enrolment code used directly as the `Authorization: Bearer` (the Claude-Desktop /
/// mcp-remote path) bootstraps a Pending agent, is denied until approved, then works, all
/// with the code as the only credential the client ever holds.
#[tokio::test]
async fn enrolment_code_as_bearer_bootstraps_then_works_after_approval() {
    let app = app();
    // Operator builds a connection + credential + policy + all-agents grant.
    let (_s, conn) = post(&app, "/v1/connections", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": "P1" })).await;
    let cid = conn["connection_id"].as_str().unwrap().to_string();
    post(&app, &format!("/v1/connections/{cid}/credential"), Some(seed::DEMO_TOKEN),
        serde_json::json!({ "value": "ghp_p1" })).await;
    let (_s, pol) = post(&app, "/v1/policies", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connection_id": cid, "name": "ro", "allow": ["pull_requests.list"] })).await;
    let pid = pol["policy_id"].as_str().unwrap().to_string();
    post(&app, "/v1/grants", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "policy_id": pid, "target": "all_agents" })).await;
    let capability = format!("{cid}.pull_requests.list");

    // Operator mints an enrolment code.
    let (_s, enroll) = post(&app, "/v1/agents/enroll", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "label": "Claude Desktop" })).await;
    let code = enroll["code"].as_str().unwrap().to_string();

    // 1. The agent's client uses the CODE itself as the bearer. First call bootstraps a Pending
    //    agent and is denied "not approved", NOT "unauthorized".
    let (status, json) = post(&app, "/v1/invoke", Some(&code),
        serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(json["decision"]["reason"].as_str().unwrap().contains("not approved"),
        "expected agent-not-approved, got: {json}");

    // The bootstrapped agent now shows up as Pending.
    let (_s, agents) = get(&app, "/v1/agents", seed::DEMO_TOKEN).await;
    let pending = agents["agents"].as_array().unwrap().iter()
        .find(|a| a["status"] == "pending").expect("a pending agent exists");
    let agent_id = pending["id"].as_str().unwrap().to_string();
    assert!(agent_id.starts_with("claude-desktop-"), "id derived from label: {agent_id}");

    // 2. Operator approves it.
    let (status, _) = post(&app, &format!("/v1/agents/{agent_id}/approve"), Some(seed::DEMO_TOKEN),
        serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);

    // 3. Same code bearer now works.
    let (status, json) = post(&app, "/v1/invoke", Some(&code),
        serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } })).await;
    assert_eq!(status, StatusCode::OK, "approved agent should be allowed: {json}");
    assert_eq!(json["decision"]["decision"], "allow");
}

/// A grant's per-period call budget denies once exhausted (counted from the audit log).
#[tokio::test]
async fn grant_call_budget_is_enforced() {
    let app = app();
    // The seeded read-only Braintree grant caps total calls at 100. Build a tiny-budget
    // connection of our own to exercise exhaustion without 100 calls.
    let (_s, conn) = post(
        &app,
        "/v1/connections",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": "Budget GitHub" }),
    )
    .await;
    let connection_id = conn["connection_id"].as_str().unwrap().to_string();
    post(
        &app,
        &format!("/v1/connections/{connection_id}/credential"),
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "value": "ghp_budget" }),
    )
    .await;
    let (_s, pol) = post(
        &app,
        "/v1/policies",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connection_id": connection_id, "name": "ro", "allow": ["pull_requests.list"] }),
    )
    .await;
    let policy_id = pol["policy_id"].as_str().unwrap().to_string();
    post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "policy_id": policy_id, "target_agent": "codex-cli", "max_calls": 1, "period": "total" }),
    )
    .await;

    let capability = format!("{connection_id}.pull_requests.list");
    // First call: allowed (0 of 1 used).
    let (s1, _) = post(
        &app,
        "/v1/invoke",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } }),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    // Second call: budget exhausted → denied.
    let (s2, json) = post(
        &app,
        "/v1/invoke",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } }),
    )
    .await;
    assert_eq!(s2, StatusCode::FORBIDDEN, "{json}");
    assert!(json["decision"]["reason"]
        .as_str()
        .unwrap()
        .contains("budget exhausted"));
}

/// An upstream slow enough that every concurrent call is past the policy engine before the first one
/// has appended the terminal event that charges its grant.
struct SlowUpstream;

#[async_trait::async_trait]
impl permaura_gateway::connectors::HttpClient for SlowUpstream {
    async fn send(
        &self,
        _request: permaura_gateway::connectors::HttpRequest,
    ) -> anyhow::Result<permaura_gateway::connectors::HttpResponse> {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        Ok(permaura_gateway::connectors::HttpResponse::json(200, serde_json::json!({ "ok": true })))
    }
}

/// The budget was measured before execution and charged only by the terminal event after it,
/// so N concurrent invokes against a grant with one call left all measured zero used and all ran.
#[tokio::test]
async fn concurrent_invokes_cannot_overrun_a_grant_budget() {
    common::isolate_from_the_real_install();
    let state = permaura_gateway::AppState::in_memory_seeded_with_http(std::sync::Arc::new(SlowUpstream));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    let (_s, conn) = post(&app, "/v1/connections", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": "Race GitHub" })).await;
    let connection_id = conn["connection_id"].as_str().unwrap().to_string();
    post(&app, &format!("/v1/connections/{connection_id}/credential"), Some(seed::DEMO_TOKEN),
        serde_json::json!({ "value": "ghp_race" })).await;
    let (_s, pol) = post(&app, "/v1/policies", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connection_id": connection_id, "name": "ro", "allow": ["pull_requests.list"] })).await;
    let (s, _) = post(&app, "/v1/grants", Some(seed::DEMO_TOKEN), serde_json::json!({
        "policy_id": pol["policy_id"], "target_agent": "codex-cli", "max_calls": 1, "period": "total"
    })).await;
    assert_eq!(s, StatusCode::CREATED);

    let capability = format!("{connection_id}.pull_requests.list");
    let calls = (0..5).map(|_| {
        let app = app.clone();
        let capability = capability.clone();
        async move {
            post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
                serde_json::json!({ "capability": capability, "params": { "repo": "a/b" } })).await
        }
    });
    let results = futures_util::future::join_all(calls).await;
    let ran = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    assert_eq!(ran, 1, "exactly one call fits a one-call budget: {results:?}");
    assert!(
        results.iter().filter(|(s, _)| *s != StatusCode::OK).all(|(s, j)| *s == StatusCode::FORBIDDEN
            && j["decision"]["reason"].as_str().unwrap_or_default().contains("budget exhausted")),
        "{results:?}"
    );
}

// ── Grant model v2 (M2M bundles, Default grant, two-tier budgets, usage) ──

/// Generic request helper for the verbs the v2 suite needs (PATCH / DELETE) beyond post/get.
async fn req(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// Stand up a fresh connection + credential + read-only policy + grant; return (connection_id,
/// policy_id, grant_id, capability). The grant is created from the supplied JSON body.
/// Three ways a control-plane write used to accept input that named nothing, all of which
/// produced a success and an estate entry that could never match a caller.
///
/// The empty policy id was recorded as already fixed, on the reasoning that `get_policy("")` finds
/// no row. It was not: `resolve_policy_ids` filtered empties out before validation ever ran, so the
/// request returned 201 and created a grant with no policies at all. That is the same defect as the
/// other two, one step further along, because the caller is told it worked.
#[tokio::test]
async fn a_grant_cannot_name_a_policy_or_an_agent_that_does_not_exist() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    let (status, body) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "name": "empty policy id", "policy_ids": [""] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an empty policy id names nothing: {body}");

    // The legacy singular keeps its old tolerance: a pre-v2 caller sending "" there meant "no
    // policy", and breaking that would be a regression rather than a fix.
    let (status, body) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "name": "legacy blank singular", "policy_id": "" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the legacy shape still means no policy: {body}");

    let (status, body) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "name": "absent policy", "policy_ids": ["pol_does_not_exist"] }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // The one this item is actually about: the agent was never checked at all, so a typo minted a
    // grant that looks like authorization and targets nobody.
    let (status, body) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "name": "absent agent", "target_agent": "codex-clii" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an unknown agent id must 404: {body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("codex-clii"),
        "and the error must name it: {body}"
    );

    // An unscoped grant names no agent and must stay legal, in both of its shapes.
    for (label, extra) in [
        ("all agents", serde_json::json!({ "all_agents": true })),
        ("nobody yet", serde_json::json!({})),
    ] {
        let mut b = serde_json::json!({ "name": format!("unscoped {label}") });
        b.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let (status, body) = post(&app, "/v1/grants", Some(seed::DEMO_TOKEN), b).await;
        assert_eq!(status, StatusCode::CREATED, "an unscoped grant is legitimate ({label}): {body}");
    }

    // A real agent still works, or the check has simply broken grant creation.
    let (status, body) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "name": "real agent", "target_agent": "codex-cli" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// The capability master switch stored whatever string it was handed and echoed it back, so a
/// typo returned 200 and an operator believed they had switched something off.
#[tokio::test]
async fn the_capability_master_switch_refuses_a_capability_the_connection_does_not_expose() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    for enabled in [false, true] {
        let (status, body) = post(
            &app,
            "/v1/connections/braintree_production/capabilities",
            Some(seed::DEMO_TOKEN),
            serde_json::json!({ "capability": "braintree.transactions.refundd", "enabled": enabled }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown capability, enabled={enabled}: {body}");
    }

    // A capability this connection really exposes still toggles, and the response echoes the id as
    // stored rather than as sent.
    let (status, body) = post(
        &app,
        "/v1/connections/braintree_production/capabilities",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": "braintree.transactions.refund", "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["capability"], "braintree.transactions.refund", "{body}");
    assert_eq!(body["enabled"], false, "{body}");

    // And a capability that exists but belongs to a DIFFERENT connection is still refused, so the
    // check is per connection rather than a global catalogue lookup.
    let (status, body) = post(
        &app,
        "/v1/connections/braintree_production/capabilities",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": "github.pull_requests.list", "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another connection's capability: {body}");
}

async fn scaffold_grant(
    app: &axum::Router,
    name: &str,
    grant_extra: serde_json::Value,
) -> (String, String, String, String) {
    let (_s, conn) = post(
        app,
        "/v1/connections",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": name }),
    )
    .await;
    let connection_id = conn["connection_id"].as_str().unwrap().to_string();
    post(
        app,
        &format!("/v1/connections/{connection_id}/credential"),
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "value": "ghp_test" }),
    )
    .await;
    let (_s, pol) = post(
        app,
        "/v1/policies",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connection_id": connection_id, "name": "ro", "allow": ["pull_requests.list"] }),
    )
    .await;
    let policy_id = pol["policy_id"].as_str().unwrap().to_string();
    let mut body = serde_json::json!({ "policy_ids": [policy_id] });
    for (k, v) in grant_extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let (_s, gr) = post(app, "/v1/grants", Some(seed::DEMO_TOKEN), body).await;
    let grant_id = gr["grant_id"].as_str().unwrap().to_string();
    let capability = format!("{connection_id}.pull_requests.list");
    (connection_id, policy_id, grant_id, capability)
}

async fn invoke(app: &axum::Router, capability: &str) -> StatusCode {
    post(
        app,
        "/v1/invoke",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } }),
    )
    .await
    .0
}

#[tokio::test]
async fn default_grant_is_auto_created_protected_and_reassignable() {
    let app = app();
    let (_s, grants) = get(&app, "/v1/grants", seed::DEMO_TOKEN).await;
    let default = grants["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["is_default"] == true)
        .expect("a Default grant exists on a seeded gateway");
    let default_id = default["grant_id"].as_str().unwrap().to_string();

    // The Default cannot be deleted while it holds is_default.
    let (s, _) = req(&app, "DELETE", &format!("/v1/grants/{default_id}"), seed::DEMO_TOKEN, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Reassign Default to a new grant; the old one loses the flag and becomes deletable.
    let (_s, gr) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "name": "New baseline", "all_agents": true, "is_default": true }),
    )
    .await;
    let new_id = gr["grant_id"].as_str().unwrap().to_string();
    let (_s, grants) = get(&app, "/v1/grants", seed::DEMO_TOKEN).await;
    let defaults: Vec<_> = grants["grants"].as_array().unwrap().iter().filter(|g| g["is_default"] == true).collect();
    assert_eq!(defaults.len(), 1, "exactly one default at a time");
    assert_eq!(defaults[0]["grant_id"], new_id);
    let (s, _) = req(&app, "DELETE", &format!("/v1/grants/{default_id}"), seed::DEMO_TOKEN, None).await;
    assert_eq!(s, StatusCode::OK, "the old default is now deletable");
}

#[tokio::test]
async fn patch_pause_makes_a_grant_inert() {
    let app = app();
    let (_c, _p, grant_id, capability) =
        scaffold_grant(&app, "Pause Test", serde_json::json!({ "target_agent": "codex-cli" })).await;
    assert_eq!(invoke(&app, &capability).await, StatusCode::OK);

    // Pause → the grant is inert → deny by default.
    let (s, _) = req(&app, "PATCH", &format!("/v1/grants/{grant_id}"), seed::DEMO_TOKEN, Some(serde_json::json!({ "enabled": false }))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(invoke(&app, &capability).await, StatusCode::FORBIDDEN);

    // Re-enable → restored unchanged.
    req(&app, "PATCH", &format!("/v1/grants/{grant_id}"), seed::DEMO_TOKEN, Some(serde_json::json!({ "enabled": true }))).await;
    assert_eq!(invoke(&app, &capability).await, StatusCode::OK);
}

#[tokio::test]
async fn overall_limit_is_the_hard_ceiling() {
    let app = app();
    let (_c, _p, _g, capability) = scaffold_grant(
        &app,
        "Overall Cap",
        serde_json::json!({ "all_agents": true, "overall_limit": 1, "period": "total" }),
    )
    .await;
    assert_eq!(invoke(&app, &capability).await, StatusCode::OK);
    let (s2, json) = post(
        &app,
        "/v1/invoke",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } }),
    )
    .await;
    assert_eq!(s2, StatusCode::FORBIDDEN);
    assert!(json["decision"]["reason"].as_str().unwrap().contains("overall budget"));
}

#[tokio::test]
async fn grant_usage_endpoint_reports_two_tier_stats() {
    let app = app();
    let (_c, _p, grant_id, capability) = scaffold_grant(
        &app,
        "Usage Stats",
        serde_json::json!({ "all_agents": true, "default_per_agent_limit": 10, "period": "month" }),
    )
    .await;
    invoke(&app, &capability).await;
    invoke(&app, &capability).await;

    let (s, usage) = get(&app, &format!("/v1/grants/{grant_id}/usage"), seed::DEMO_TOKEN).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(usage["overall_used"], 2);
    let agents = usage["agents"].as_array().unwrap();
    let codex = agents.iter().find(|a| a["agent_id"] == "codex-cli").expect("codex-cli usage row");
    assert_eq!(codex["used"], 2);
    assert_eq!(codex["limit"], 10);
    // A bounded period yields a sparkline series.
    assert!(!usage["series"].as_array().unwrap().is_empty());
}

/// Grant usage is a console view: it names every agent charged against a grant and how much
/// each has spent, and an agent has no console to render it. An agent token is refused, and the
/// operator still gets the view.
#[tokio::test]
async fn grant_usage_refuses_an_agent_token() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_c, _p, grant_id, _capability) = scaffold_grant(
        &app,
        "Usage Is The Operator's",
        serde_json::json!({ "all_agents": true, "period": "day" }),
    )
    .await;
    state
        .service
        .store()
        .put_session(permaura_gateway::store::Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_usage_agent".into(),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: "usage-agent-token".into(),
            role: permaura_gateway::store::SessionRole::Agent,
            created_at: now_ms(),
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();

    let uri = format!("/v1/grants/{grant_id}/usage");
    let (agent, body) = get(&app, &uri, "usage-agent-token").await;
    assert_eq!(agent, StatusCode::FORBIDDEN, "an agent token is refused: {body}");
    let (operator, _) = get(&app, &uri, seed::DEMO_TOKEN).await;
    assert_eq!(operator, StatusCode::OK, "the operator still gets the view");
}

#[tokio::test]
async fn policy_create_and_edit_sync_grant_membership() {
    let app = app();
    // An empty named grant to attach into.
    let (_s, gr) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "name": "Attach target", "all_agents": true }),
    )
    .await;
    let grant_id = gr["grant_id"].as_str().unwrap().to_string();

    let (_s, conn) = post(
        &app,
        "/v1/connections",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": "Attach Conn" }),
    )
    .await;
    let connection_id = conn["connection_id"].as_str().unwrap().to_string();

    // Create a policy attached to the grant in the same call.
    let (_s, pol) = post(
        &app,
        "/v1/policies",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connection_id": connection_id, "name": "ro", "allow": ["pull_requests.list"], "grant_ids": [grant_id] }),
    )
    .await;
    let policy_id = pol["policy_id"].as_str().unwrap().to_string();

    let grant_holds = |grants: &serde_json::Value, gid: &str, pid: &str| -> bool {
        grants["grants"].as_array().unwrap().iter().any(|g| {
            g["grant_id"] == gid
                && g["policy_ids"].as_array().map_or(false, |ps| ps.iter().any(|p| p == pid))
        })
    };

    let (_s, grants) = get(&app, "/v1/grants", seed::DEMO_TOKEN).await;
    assert!(grant_holds(&grants, &grant_id, &policy_id), "policy attached on create");

    // Editing with an empty grant_ids detaches it.
    req(
        &app,
        "PUT",
        &format!("/v1/policies/{policy_id}"),
        seed::DEMO_TOKEN,
        Some(serde_json::json!({ "connection_id": connection_id, "name": "ro", "allow": ["pull_requests.list"], "grant_ids": [] })),
    )
    .await;
    let (_s, grants) = get(&app, "/v1/grants", seed::DEMO_TOKEN).await;
    assert!(!grant_holds(&grants, &grant_id, &policy_id), "policy detached on edit");
}

/// An edit that never mentions the quorum must not silently take a two-person policy apart.
///
/// Every console and CLI shipped before the two-person rule PUTs the five rung lists and nothing
/// else, so `device_signed_quorum` arrives absent on a plain rename, and reading absent as "one
/// signature" turned each of those edits into a 2-of-2 → 1-of-1 downgrade that answered `200` and
/// reported success. Only an explicit quorum may move it.
#[tokio::test]
async fn an_edit_that_omits_the_quorum_leaves_the_two_person_rule_intact() {
    let app = app();
    let quorum_of = |policies: &serde_json::Value, id: &str| -> u64 {
        policies["policies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .and_then(|p| p["device_signed_quorum"].as_u64())
            .expect("the policy list carries the quorum")
    };

    let (status, pol) = post(
        &app,
        "/v1/policies",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({
            "connection_id": "braintree_production",
            "name": "Refunds need two people",
            "device_signed": ["transactions.refund"],
            "device_signed_quorum": 2,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{pol:?}");
    let policy_id = pol["policy_id"].as_str().unwrap().to_string();

    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert_eq!(quorum_of(&policies, &policy_id), 2, "created as a 2-of-2");

    // The pre-quorum shape: same rungs, new name, no quorum field at all.
    let (status, _) = req(
        &app,
        "PUT",
        &format!("/v1/policies/{policy_id}"),
        seed::DEMO_TOKEN,
        Some(serde_json::json!({
            "connection_id": "braintree_production",
            "name": "Refunds need two people (renamed)",
            "device_signed": ["transactions.refund"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    let stored = policies["policies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == policy_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(
        stored["name"], "Refunds need two people (renamed)",
        "the edit landed, so the quorum survived a real write rather than a no-op"
    );
    assert_eq!(quorum_of(&policies, &policy_id), 2, "still a 2-of-2 after the rename");

    // Explicit is still explicit: an operator who means one signature says one, and gets it.
    let (status, _) = req(
        &app,
        "PUT",
        &format!("/v1/policies/{policy_id}"),
        seed::DEMO_TOKEN,
        Some(serde_json::json!({
            "connection_id": "braintree_production",
            "name": "Refunds need two people (renamed)",
            "device_signed": ["transactions.refund"],
            "device_signed_quorum": 1,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert_eq!(quorum_of(&policies, &policy_id), 1, "an explicit downgrade is honoured");
}

/// From the moment an approver device is enrolled, a bearer-only (unsigned) approval
/// resolution is refused, and revoking the device does not reopen the fallback, since revocation
/// is broker-reachable and reopening would be a downgrade attack.
#[tokio::test]
async fn enrolled_device_locks_out_unsigned_approval_resolution() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let body = serde_json::json!({ "approval_id": "appr_missing", "approve": true });

    // Before any device is enrolled the bearer-only path is still open: an unknown id gets past
    // the signing gate and 404s on lookup.
    let (status, _) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN), body.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "bearer-only resolution must reach lookup pre-enrolment");

    // Pair a device signing key, exactly as the worker-local pairing endpoint does.
    let pubkey = STANDARD.encode(SigningKey::from_bytes(&[42u8; 32]).verifying_key().to_bytes());
    assert!(state.service.trust_approver_key("device:phone", &pubkey));

    // Enrolment alone no longer closes it: the policy's per-action rung decides, and this approval
    // sits at the tier a bearer may resolve. Pairing makes the device_signed rung RESOLVABLE; it is
    // not itself an answer about every other action.
    let (status, _) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN), body.clone()).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "pairing a device must not silently override the rung a policy chose",
    );

    // Raising the floor is the explicit choice that closes it, and it is offered at first pairing.
    state.service.set_approval_floor(Some(ApprovalFloor::DeviceSigned)).unwrap();
    let (status, resp) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN), body.clone()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "with the floor raised, no bearer resolves anything: {resp}"
    );

    // Revoking the only device must NOT reopen the unsigned path. The raised floor is a stored
    // decision, not something derived from the keyring, so emptying the keyring cannot undo it.
    state.service.revoke_approver_key("device:phone").unwrap();
    let (status, resp) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN), body).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "revoking every device must not restore bearer-only approvals: {resp}"
    );
}

// ── Approval ladder: per-approval tier + the worker-local approval floor ──────────────

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// POST with an explicit extra header (used to simulate a broker/tunnelled request via `cf-ray`).
async fn post_hdr(
    app: &axum::Router,
    uri: &str,
    token: &str,
    header: (&str, &str),
    body: serde_json::Value,
) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header(header.0, header.1)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

/// PUT helper (the approval-floor endpoint), optionally with an extra header.
async fn put_floor(app: &axum::Router, token: &str, floor: &str, extra: Option<(&str, &str)>) -> StatusCode {
    let mut builder = Request::builder()
        .method("PUT")
        .uri("/v1/approval-floor")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    if let Some((k, v)) = extra {
        builder = builder.header(k, v);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(serde_json::json!({ "floor": floor }).to_string())).unwrap())
        .await
        .unwrap();
    resp.status()
}

/// Seed a `device_signed`-tier pending approval directly (the bearer gate short-circuits on the
/// tier before it ever looks the session up, so a bare record is enough to exercise the gate).
fn seed_device_signed_approval(state: &AppState, id: &str) {
    state
        .service
        .store()
        .put_approval(PendingApproval {
            id: id.into(),
            session_id: "sess_ds".into(),
            capability: "vercel.deployments.create".into(),
            resource: "vercel_acme".into(),
            message: "Approve the held call?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({}).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: now_ms(),
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "device_signed".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
}

/// A `device_signed`-tier approval refuses a bearer resolution EVEN when the floor is `approve`
/// (no device enrolled): the per-approval tier is stricter than the global floor.
#[tokio::test]
async fn device_signed_tier_refuses_bearer_even_at_approve_floor() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    seed_device_signed_approval(&state, "appr_ds");
    let (status, resp) = post(
        &app,
        "/v1/approvals",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": "appr_ds", "approve": true }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a device_signed-tier approval must refuse a bearer resolution at any floor: {resp}"
    );
}

/// The full floor lifecycle end-to-end: an `approve`-tier hold resolves on a bearer while the
/// floor is `approve`; enrolling a device raises the floor to `device_signed` and the next bearer
/// resolution is refused; a loopback opt-down to `approve` re-opens bearer resolution.
#[tokio::test]
async fn approve_tier_bearer_tracks_the_floor() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    // vercel.deployments.create is High-risk → an `approve`-tier hold (it is not device_signed).
    let invoke = serde_json::json!({
        "capability": "vercel.deployments.create",
        "params": { "name": "acme-web", "target": "production" }
    });
    let (s1, j1) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN), invoke.clone()).await;
    assert_eq!(s1, StatusCode::ACCEPTED, "high-risk create should hold: {j1}");
    let appr1 = j1["approval_id"].as_str().unwrap().to_string();

    // Floor is `approve` (nothing enrolled) → a bearer resolution runs the held call.
    let (s2, j2) = post(
        &app,
        "/v1/approvals",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": appr1, "approve": true }),
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "bearer approve must work at the approve floor: {j2}");
    assert_eq!(j2["status"], "approved");

    // Enrol + trust a device, then raise the floor. Pairing alone leaves this approval resolvable
    // by a bearer, because its rung says so; the raise is what makes the floor track above it.
    let (_sk, codes) = pair_first_device(&app, 9, "device:test").await;

    let (s3, j3) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN), invoke.clone()).await;
    assert_eq!(s3, StatusCode::ACCEPTED, "second high-risk create should hold: {j3}");
    let appr2 = j3["approval_id"].as_str().unwrap().to_string();
    let (s4, _) = post(
        &app,
        "/v1/approvals",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": appr2, "approve": true }),
    )
    .await;
    assert_eq!(s4, StatusCode::FORBIDDEN, "bearer approve must be refused once a device is enrolled");

    // A loopback opt-down to `approve` re-enables bearer resolution for approve-tier holds. With a
    // device trusted it takes a recovery authority; here, one of the codes that pairing issued.
    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[("x-permaura-recovery-code", codes[0].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (s5, j5) = post(
        &app,
        "/v1/approvals",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": appr2, "approve": true }),
    )
    .await;
    assert_eq!(s5, StatusCode::OK, "after opting the floor down, bearer approve works again: {j5}");
    assert_eq!(j5["status"], "approved");
}

/// LOWERING the floor is refused over the broker, applies on loopback while no device is trusted,
/// and once one is trusted needs a recovery authority the operator bearer does not carry; RAISING it
/// is fail-safe and allowed from anywhere.
#[tokio::test]
async fn approval_floor_lowering_needs_recovery_authority() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    // Raising to device_signed is allowed even over the broker (cf-ray present → treated remote).
    assert_eq!(
        put_floor(&app, seed::DEMO_TOKEN, "device_signed", Some(("cf-ray", "abc123"))).await,
        StatusCode::OK,
        "raising the floor must be allowed from anywhere"
    );
    // Lowering to approve over the broker is refused …
    assert_eq!(
        put_floor(&app, seed::DEMO_TOKEN, "approve", Some(("cf-ray", "abc123"))).await,
        StatusCode::FORBIDDEN,
        "lowering the floor must be refused over the broker"
    );
    // … and with no device trusted it still applies on loopback: nothing is held in that state, so
    // there is nothing for a second factor to protect.
    assert_eq!(
        put_floor(&app, seed::DEMO_TOKEN, "approve", None).await,
        StatusCode::OK,
        "lowering the floor must work on the loopback host while no device is trusted"
    );
    assert!(
        !state.service.require_device_signed_approval(),
        "the floor is now Approve, so bearer resolution is no longer globally required"
    );

    // Trust a device. The floor goes back up, and from here the bearer alone lowers nothing.
    let (_sk, codes) = pair_first_device(&app, 61, "device:owner").await;
    assert_eq!(
        put_floor(&app, seed::DEMO_TOKEN, "device_signed", None).await,
        StatusCode::OK
    );
    let (status, body) = send_with(&app, "PUT", "/v1/approval-floor", Some(serde_json::json!({ "floor": "approve" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the bearer alone must not lower the floor: {body}");
    assert_eq!(body["status"], "requires_approval");
    assert!(
        state.service.require_device_signed_approval(),
        "the floor must not move while the hold is outstanding"
    );

    // A recovery code is the authority the bearer does not carry.
    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[("x-permaura-recovery-code", codes[0].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a recovery code lowers the floor at once: {body}");
    assert!(!state.service.require_device_signed_approval());
}

/// A `notify`-rung action executes immediately (200 allow) and its audit event records
/// `notified: true`, the after-the-fact awareness marker.
#[tokio::test]
async fn notify_rung_allows_and_audits_notified() {
    let app = app();
    // pol_vercel lists `deployments.list` on the notify rung in the seed.
    let (status, j) = post(
        &app,
        "/v1/invoke",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": "vercel.deployments.list", "params": {} }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "notify action executes immediately: {j}");
    assert_eq!(j["decision"]["decision"], "allow");

    let (_s, audit) = get(&app, "/v1/audit-events?limit=50", seed::DEMO_TOKEN).await;
    let events = audit["events"].as_array().unwrap();
    let notified = events.iter().any(|e| {
        e["payload"]["decision"] == "allow"
            && e["payload"]["summary"]["notified"] == serde_json::Value::Bool(true)
    });
    assert!(notified, "a notify-rung allow must record notified:true in the audit chain");
}

/// The signed-vs-bearer resolution method is recorded in the audit chain (was invisible before).
#[tokio::test]
async fn bearer_resolution_records_method_in_audit() {
    let app = app();
    let (s1, j1) = post(
        &app,
        "/v1/invoke",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": "vercel.deployments.create", "params": { "name": "x", "target": "production" } }),
    )
    .await;
    assert_eq!(s1, StatusCode::ACCEPTED, "{j1}");
    let appr = j1["approval_id"].as_str().unwrap().to_string();
    let (s2, _) = post(
        &app,
        "/v1/approvals",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": appr, "approve": true }),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    let (_s, audit) = get(&app, "/v1/audit-events?limit=50", seed::DEMO_TOKEN).await;
    let events = audit["events"].as_array().unwrap();
    let has_method = events.iter().any(|e| {
        e["payload"]["decision"] == "approved" && e["payload"]["summary"]["method"] == "bearer"
    });
    assert!(has_method, "an approved event must record its resolution method");
}

// ── Approval ladder: the broker policy-mutation guard ─────────────────────────────────

/// Sign a held approval as a trusted device and POST it to `/v1/approvals`. Fetches the signing
/// inputs (request_hash, job_id) the gateway exposes, exactly as the phone/desktop approver does.
async fn device_sign(
    app: &axum::Router,
    token: &str,
    approval_id: &str,
    approver: &str,
    sk: &ed25519_dalek::SigningKey,
) -> (StatusCode, serde_json::Value) {
    device_sign_decision(app, token, approval_id, approver, sk, true).await
}

/// Like [`device_sign`] but signs an explicit approve/deny decision.
async fn device_sign_decision(
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
    let (_s, appr) = get(app, &format!("/v1/approvals/{approval_id}"), token).await;
    let request_hash = appr["request_hash"].as_str().unwrap().to_string();
    let job_id = appr["job_id"].as_str().unwrap().to_string();
    let audience = appr["approval_audience"].as_str().expect("the approval serves its audience").to_string();
    let shown = approval_display_full_digest_of(&appr).expect("the approval serves its full rendering");
    let decided_at = now_ms();
    let preimage = approval_result_preimage_v3(
        &audience, &job_id, approval_id, approve, &request_hash, &shown, approver, decided_at,
    );
    let device_sig = sign(sk, &preimage);
    post(
        app,
        "/v1/approvals",
        Some(token),
        serde_json::json!({
            "approval_id": approval_id,
            "approve": approve,
            "approver": approver,
            "request_hash": request_hash,
            "decided_at": decided_at,
            "job_id": job_id,
            "approver_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
            "audience": audience,
            "display_digest": shown,
            "device_sig": device_sig,
        }),
    )
    .await
}

/// POST a JSON body with a `cf-ray` header (simulating arrival over the Cloudflare tunnel / broker).
async fn post_remote(
    app: &axum::Router,
    uri: &str,
    token: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("cf-ray", "abc123")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

fn approver_key(seed: u8) -> (String, ed25519_dalek::SigningKey) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    (STANDARD.encode(sk.verifying_key().to_bytes()), sk)
}

fn has_policy_named(policies: &serde_json::Value, name: &str) -> bool {
    policies["policies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == name)
}

/// A LOOSENING policy write arriving over the broker (cf-ray) once a device is enrolled is HELD as
/// a device_signed approval, NOT applied, and applies only after a valid device signature.
#[tokio::test]
async fn remote_loosening_policy_write_is_held_then_applied_on_signature() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, sk) = approver_key(7);
    assert!(state.service.trust_approver_key("device:approver", &pubkey));

    // A new policy permitting a currently-unpermitted action (deny-by-default → auto is a genuine
    // loosening) over the broker. NB: permitting an action the seed already DENIES would not loosen
    // (deny-wins keeps it denied), so use a fresh action id.
    let body = serde_json::json!({
        // `http.request` is a real registered capability the seed deliberately leaves ungoverned,
        // so allowing it is a genuine deny-by-default → permitted loosening.
        "connection_id": "generic_http",
        "name": "evil-widen",
        "allow": ["request"],
    });
    let (status, resp) = post_remote(&app, "/v1/policies", seed::DEMO_TOKEN, body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "a loosening remote write must be held: {resp}");
    assert_eq!(resp["required_tier"], "device_signed");
    let approval_id = resp["approval_id"].as_str().unwrap().to_string();

    // Not applied yet.
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert!(!has_policy_named(&policies, "evil-widen"), "the held policy must not be live yet");

    // A bearer resolution is refused (it is device_signed-tier).
    let (bs, _) = post(
        &app,
        "/v1/approvals",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": approval_id, "approve": true }),
    )
    .await;
    assert_eq!(bs, StatusCode::FORBIDDEN, "a bearer cannot resolve a held mutation");

    // A valid device signature applies it.
    let (ss, sresp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "the device signature resolves the hold: {sresp}");
    assert_eq!(sresp["status"], "approved");
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert!(has_policy_named(&policies, "evil-widen"), "the signed mutation is now applied");
}

/// A TIGHTENING policy write over the broker applies immediately (no hold) even with a device
/// enrolled: only loosening needs a signature.
#[tokio::test]
async fn remote_tightening_policy_write_applies_immediately() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, _sk) = approver_key(8);
    assert!(state.service.trust_approver_key("device:approver", &pubkey));

    // A brand-new policy that only DENIES an action tightens (adds no permit) → applies now.
    let body = serde_json::json!({
        "connection_id": "braintree_production",
        "name": "tighten-deny",
        "deny": ["transactions.refund"],
    });
    let (status, resp) = post_remote(&app, "/v1/policies", seed::DEMO_TOKEN, body).await;
    assert_eq!(status, StatusCode::CREATED, "a tightening remote write applies immediately: {resp}");
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert!(has_policy_named(&policies, "tighten-deny"));
}

/// Over the broker: taking a two-person policy down to one signature is a loosening, so the
/// semi-trusted control plane cannot do it unsigned, while an edit that never mentions the quorum
/// still applies at once. Both halves matter: the guard has to catch the downgrade without turning
/// every ordinary edit of a two-person policy into signing friction.
#[tokio::test]
async fn remote_quorum_downgrade_is_held_but_an_unrelated_edit_still_applies() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, _sk) = approver_key(11);
    assert!(state.service.trust_approver_key("device:approver", &pubkey));

    let quorum_of = |policies: &serde_json::Value| -> u64 {
        policies["policies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "pol_two_person")
            .and_then(|p| p["device_signed_quorum"].as_u64())
            .expect("the policy exists and reports its quorum")
    };
    // `http.request` on `generic_http` is the seed's one deliberately ungoverned capability. It has to
    // be: every action the seed governs at all is already force-denied somewhere on its connection, and
    // deny-wins pins its ceiling to "no access" on both sides of any edit, so a quorum change there
    // genuinely loosens nothing and the guard is right to let it through.
    let two_person = |name: &str, quorum: Option<u8>| {
        let mut body = serde_json::json!({
            "id": "pol_two_person",
            "connection_id": "generic_http",
            "name": name,
            "device_signed": ["request"],
        });
        if let Some(q) = quorum {
            body["device_signed_quorum"] = serde_json::json!(q);
        }
        body
    };

    // Established on the loopback host, where the guard does not engage.
    let (status, resp) = post(
        &app,
        "/v1/policies",
        Some(seed::DEMO_TOKEN),
        two_person("Refunds need two people", Some(2)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert_eq!(quorum_of(&policies), 2);

    // The attack: same policy, same rungs, one fewer signature, over the broker.
    let (status, resp) = post_remote(
        &app,
        "/v1/policies",
        seed::DEMO_TOKEN,
        two_person("Refunds need two people", Some(1)),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "a quorum downgrade must be held: {resp}");
    assert_eq!(resp["required_tier"], "device_signed");
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert_eq!(quorum_of(&policies), 2, "held, so the rule is still in force");

    // The ordinary case: a rename that says nothing about the quorum keeps it, which is what makes
    // this a tightening (nothing moved) rather than a hold the operator has to sign every time.
    let (status, resp) = post_remote(
        &app,
        "/v1/policies",
        seed::DEMO_TOKEN,
        two_person("Refunds need two people (renamed)", None),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "an edit that keeps the quorum applies: {resp}");
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert_eq!(quorum_of(&policies), 2);
}

/// A loosening write on the LOOPBACK host (no cf-ray) applies immediately even with a device
/// enrolled: the guard only engages for broker-originated writes.
#[tokio::test]
async fn loopback_loosening_write_applies_even_with_device_enrolled() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, _sk) = approver_key(9);
    assert!(state.service.trust_approver_key("device:approver", &pubkey));

    let body = serde_json::json!({
        // `http.request` is a real registered capability that the seed deliberately leaves ungoverned
        // (no policy, no grant), so allowing it is a genuine deny-by-default → permitted loosening.
        "connection_id": "generic_http",
        "name": "loopback-widen",
        "allow": ["request"],
    });
    // post() sends no cf-ray → loopback.
    let (status, resp) = post(&app, "/v1/policies", Some(seed::DEMO_TOKEN), body).await;
    assert_eq!(status, StatusCode::CREATED, "loopback writes apply immediately: {resp}");
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    assert!(has_policy_named(&policies, "loopback-widen"));
}

// ── Approval ladder: the other operator-plane loosening endpoints ─────────────────────────

/// Send a request with any method, optionally over the broker (`cf-ray`), with an optional body.
async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    remote: bool,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    if remote {
        builder = builder.header("cf-ray", "abc123");
    }
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// Enrol + trust a device key on a fresh seeded gateway; returns the app, state and signing key.
fn gateway_with_device(seed_byte: u8) -> (axum::Router, AppState, ed25519_dalek::SigningKey) {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, sk) = approver_key(seed_byte);
    assert!(state.service.trust_approver_key_for("device:approver", &pubkey, Some("user_approver")).unwrap());
    (app, state, sk)
}

/// An unbound deny on the connection used to mask the next edit from the classifier, because its
/// deny-wins counted a deny no grant binds. Two broker calls then dropped a bound agent's `device_signed`
/// rung to auto with no device signature.
#[tokio::test]
async fn an_unbound_deny_cannot_launder_a_rung_drop_over_the_broker() {
    let (app, _state, _sk) = gateway_with_device(12);
    // The owner's setup, from the gateway's host: `request` on the seed's ungoverned generic-HTTP
    // connection needs a device signature, and the grant binds that to codex-cli.
    let (status, resp) = send(&app, "POST", "/v1/policies", seed::DEMO_TOKEN, false, Some(serde_json::json!({
        "id": "p_strict", "connection_id": "generic_http", "name": "strict", "device_signed": ["request"],
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    let (status, resp) = send(&app, "POST", "/v1/grants", seed::DEMO_TOKEN, false, Some(serde_json::json!({
        "policy_id": "p_strict", "target_agent": "codex-cli",
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");

    // Step one over the broker: a deny nobody is bound to. Inert, so it may apply.
    let (status, resp) = send(&app, "POST", "/v1/policies", seed::DEMO_TOKEN, true, Some(serde_json::json!({
        "id": "p_decoy", "connection_id": "generic_http", "name": "decoy", "deny": ["request"],
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");

    // Step two: the rung drop itself. It must wait for the device.
    let (status, resp) = send(&app, "PUT", "/v1/policies/p_strict", seed::DEMO_TOKEN, true, Some(serde_json::json!({
        "connection_id": "generic_http", "name": "strict", "allow": ["request"],
    }))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the rung drop must be held: {resp}");
    assert_eq!(resp["required_tier"], "device_signed");
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    let strict = policies["policies"].as_array().unwrap().iter().find(|p| p["id"] == "p_strict").unwrap().clone();
    assert!(strict["device_signed"].as_array().unwrap().iter().any(|a| a == "request"), "still signed: {strict}");
}

/// Two grants reach codex-cli for `request` on the seed's ungoverned generic-HTTP connection: one lax
/// (auto), one strict (two devices). The engine holds the call for two signatures. Set up on loopback.
async fn strict_beside_lax_over(app: &axum::Router) {
    for (policy, grant) in [
        (serde_json::json!({ "id": "p_lax", "connection_id": "generic_http", "name": "lax", "allow": ["request"] }), "g_lax"),
        (
            serde_json::json!({
                "id": "p_strict", "connection_id": "generic_http", "name": "strict",
                "device_signed": ["request"], "device_signed_quorum": 2,
            }),
            "g_strict",
        ),
    ] {
        let id = policy["id"].as_str().unwrap().to_string();
        let (status, resp) = send(app, "POST", "/v1/policies", seed::DEMO_TOKEN, false, Some(policy)).await;
        assert_eq!(status, StatusCode::CREATED, "{resp}");
        let (status, resp) = send(app, "POST", "/v1/grants", seed::DEMO_TOKEN, false, Some(serde_json::json!({
            "grant_id": grant, "policy_id": id, "target_agent": "codex-cli",
        }))).await;
        assert_eq!(status, StatusCode::CREATED, "{resp}");
    }
}

fn grant_enabled(grants: &serde_json::Value, id: &str) -> Option<bool> {
    grants["grants"].as_array().unwrap().iter().find(|g| g["grant_id"] == id).map(|g| g["enabled"] == true)
}

/// The exploit over the broker: the guard read the laxest bound policy as the one in force, so
/// pausing the grant that carries the two-person rule, or editing that rule away, looked like no change
/// and applied with no device, and the call then ran with no signature at all.
#[tokio::test]
async fn pausing_or_editing_away_a_two_person_rule_beside_a_lax_grant_is_held() {
    let (app, _state, _sk) = gateway_with_device(13);
    strict_beside_lax_over(&app).await;

    let (status, resp) =
        send(&app, "PATCH", "/v1/grants/g_strict", seed::DEMO_TOKEN, true, Some(serde_json::json!({ "enabled": false }))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "pausing the strict grant must be held: {resp}");
    let (_s, grants) = get(&app, "/v1/grants", seed::DEMO_TOKEN).await;
    assert_eq!(grant_enabled(&grants, "g_strict"), Some(true), "held, so the rule is still in force");

    for weaker in [
        serde_json::json!({ "connection_id": "generic_http", "name": "strict" }),
        serde_json::json!({ "connection_id": "generic_http", "name": "strict", "device_signed": ["request"], "device_signed_quorum": 1 }),
    ] {
        let (status, resp) = send(&app, "PUT", "/v1/policies/p_strict", seed::DEMO_TOKEN, true, Some(weaker)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "weakening the strict policy must be held: {resp}");
    }
    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    let strict = policies["policies"].as_array().unwrap().iter().find(|p| p["id"] == "p_strict").unwrap().clone();
    assert_eq!(strict["device_signed_quorum"], 2, "still two people: {strict}");

    // Pausing the LAX grant only leaves the strict rule in force, so it applies at once.
    let (status, resp) =
        send(&app, "PATCH", "/v1/grants/g_lax", seed::DEMO_TOKEN, true, Some(serde_json::json!({ "enabled": false }))).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
}

/// `DELETE /v1/grants/:id` called the store directly, so it skipped the device hold, the destructive hold
/// and the audit chain every other delete goes through. Deleting the grant that carries a device_signed
/// rule, or a deny, is now held once a device is paired, from the broker and from loopback alike.
#[tokio::test]
async fn deleting_a_grant_that_carries_a_device_signed_or_deny_rule_is_held() {
    let (app, state, sk) = gateway_with_device(14);
    strict_beside_lax_over(&app).await;
    let (status, resp) = send(&app, "POST", "/v1/policies", seed::DEMO_TOKEN, false, Some(serde_json::json!({
        "id": "p_guard", "connection_id": "generic_http", "name": "guard", "deny": ["request"],
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");
    let (status, resp) = send(&app, "POST", "/v1/grants", seed::DEMO_TOKEN, false, Some(serde_json::json!({
        "grant_id": "g_guard", "policy_id": "p_guard", "target_agent": "codex-cli",
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "{resp}");

    for (grant, remote) in [("g_strict", true), ("g_strict", false), ("g_guard", true), ("g_guard", false)] {
        let (status, resp) = send(&app, "DELETE", &format!("/v1/grants/{grant}"), seed::DEMO_TOKEN, remote, None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "deleting {grant} (remote {remote}) must be held: {resp}");
        assert_eq!(resp["required_tier"], "device_signed");
        assert!(state.service.store().get_grant(grant).unwrap().is_some(), "{grant} is still there");
    }

    // The signed hold deletes it, and the chain records the change.
    let held = state
        .service
        .store()
        .list_approvals(Some("pending"))
        .unwrap()
        .into_iter()
        .find(|a| a.params.to_value_unbounded()["kind"] == "grant_delete" && a.params.to_value_unbounded()["grant_id"] == "g_strict")
        .expect("the delete is held");
    let (status, resp) = device_sign(&app, seed::DEMO_TOKEN, &held.id, "device:approver", &sk).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(state.service.store().get_grant("g_strict").unwrap().is_none(), "the signed delete applied");
}

/// A control-plane change that applied at once left nothing in the audit chain: only held changes were
/// recorded. Each one now appends a `permaura.policy.write` event naming the change and who made it,
/// whether it applied over loopback or as a tightening over the broker.
#[tokio::test]
async fn a_control_plane_change_applied_at_once_is_in_the_audit_chain() {
    let (app, _state, _sk) = gateway_with_device(15);
    let (status, resp) = send(&app, "POST", "/v1/policies", seed::DEMO_TOKEN, false, Some(serde_json::json!({
        "id": "p_audited", "connection_id": "generic_http", "name": "audited", "allow": ["request"],
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "loopback applies at once: {resp}");
    let (status, resp) = send(&app, "PUT", "/v1/policies/p_audited", seed::DEMO_TOKEN, true, Some(serde_json::json!({
        "connection_id": "generic_http", "name": "audited", "deny": ["request"],
    }))).await;
    assert_eq!(status, StatusCode::OK, "a tightening applies at once over the broker: {resp}");

    let (_s, audit) = get(&app, "/v1/audit-events?limit=50", seed::DEMO_TOKEN).await;
    let applied: Vec<&serde_json::Value> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["payload"])
        .filter(|p| p["action"] == "permaura.policy.write" && p["summary"]["mutation"]["policy"]["id"] == "p_audited")
        .collect();
    assert_eq!(applied.len(), 2, "both applied changes are recorded: {audit}");
    for (remote, list) in [(false, "allow"), (true, "deny")] {
        let event = applied.iter().find(|e| e["summary"]["remote"] == remote).expect("one per route");
        assert_eq!(event["decision"], "allow", "{event}");
        assert_eq!(event["summary"]["method"], "applied", "{event}");
        assert_eq!(event["summary"]["mutation"]["kind"], "policy_upsert", "{event}");
        assert_eq!(event["summary"]["mutation"]["policy"][list][0], "request", "{event}");
        assert_eq!(event["session_id"], "sess_demo", "the actor is named: {event}");
    }
}

fn strict_quorum(state: &AppState) -> u8 {
    state.service.store().get_policy("p_strict").unwrap().expect("p_strict exists").device_signed_quorum
}

/// One device could sign away a two-device rule: every held change needed exactly one signature, and a
/// control-plane hold has no requesting session for the self-approval check to compare with, so the
/// member who asked for the change could approve it alone and then run the action alone. The two
/// devices belong to two people; one person's two devices are covered in `two_person.rs`.
#[tokio::test]
async fn lowering_a_two_person_rule_needs_two_devices_to_sign() {
    let (app, state, sk) = gateway_with_device(16);
    let (pk2, sk2) = approver_key(17);
    assert!(state.service.trust_approver_key_for("device:second", &pk2, Some("user_second")).unwrap());
    strict_beside_lax_over(&app).await;

    let (status, resp) = send(&app, "PUT", "/v1/policies/p_strict", seed::DEMO_TOKEN, true, Some(serde_json::json!({
        "connection_id": "generic_http", "name": "strict", "device_signed": ["request"], "device_signed_quorum": 1,
    }))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{resp}");
    assert_eq!(resp["required_signatures"], 2, "the hold asks for the quorum the rule demands: {resp}");
    let approval_id = resp["approval_id"].as_str().unwrap().to_string();

    let (status, resp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(status, StatusCode::ACCEPTED, "one device is not enough: {resp}");
    assert_eq!(strict_quorum(&state), 2, "not applied on one signature");

    let (status, resp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:second", &sk2).await;
    assert_eq!(status, StatusCode::OK, "the second device completes it: {resp}");
    assert_eq!(resp["status"], "approved");
    assert_eq!(strict_quorum(&state), 1);
}

/// The quorum is the one the rule demands when the change is applied, not when it was held: a rule
/// raised while the change waited is not lowered on the signatures the old one needed.
#[tokio::test]
async fn a_held_change_needs_the_quorum_the_rule_demands_when_it_applies() {
    let (app, state, sk) = gateway_with_device(18);
    let (pk2, sk2) = approver_key(19);
    assert!(state.service.trust_approver_key_for("device:second", &pk2, Some("user_second")).unwrap());
    strict_beside_lax_over(&app).await;
    let set_quorum = |q: u8| serde_json::json!({
        "connection_id": "generic_http", "name": "strict", "device_signed": ["request"], "device_signed_quorum": q,
    });
    let (status, resp) = send(&app, "PUT", "/v1/policies/p_strict", seed::DEMO_TOKEN, false, Some(set_quorum(1))).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let (status, resp) = send(&app, "PUT", "/v1/policies/p_strict", seed::DEMO_TOKEN, true, Some(serde_json::json!({
        "connection_id": "generic_http", "name": "strict", "allow": ["request"],
    }))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{resp}");
    // The rule took two before the host lowered it, and an unsigned lowering leaves that mark behind.
    assert_eq!(resp["required_signatures"], 2, "{resp}");
    let approval_id = resp["approval_id"].as_str().unwrap().to_string();

    // The owner raises the rule on the host while the change waits.
    let (status, resp) = send(&app, "PUT", "/v1/policies/p_strict", seed::DEMO_TOKEN, false, Some(set_quorum(3))).await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    let (status, resp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{resp}");
    let (status, resp) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:second", &sk2).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "two signatures cannot lower a rule that now takes three: {resp}");
    let row = state.service.store().get_approval(&approval_id).unwrap().unwrap();
    assert_eq!((row.status.as_str(), row.required_signatures), ("pending", 3), "raised and still pending");
    assert_eq!(strict_quorum(&state), 3);
}

/// Hold the seed's High-risk `github.pull_requests.create` for the demo session, at whatever rung its
/// policy puts it on now, and hand back the approval id.
async fn held_pull_request(state: &AppState) -> String {
    let session = state.service.store().get_session("sess_demo").unwrap().expect("seeded session");
    let outcome = state
        .service
        .invoke(&session, "github.pull_requests.create", &serde_json::json!({ "owner": "o", "repo": "r" }), None, Default::default())
        .await
        .unwrap();
    match outcome {
        permaura_gateway::service::InvokeOutcome::RequiresApproval { approval, .. } => approval.id,
        _ => panic!("a High-risk capability is held for a human"),
    }
}

/// Put `pull_requests.create` on the device_signed rung behind `quorum` devices, from the host.
fn sign_pull_requests_with(state: &AppState, quorum: u8) {
    let store = state.service.store();
    let mut policy = store.get_policy("pol_github_prs").unwrap().expect("seeded policy");
    policy.device_signed = vec!["pull_requests.create".into()];
    policy.device_signed_quorum = quorum;
    store.put_policy(policy).unwrap();
}

fn approval_row(state: &AppState, id: &str) -> PendingApproval {
    state.service.store().get_approval(id).unwrap().expect("the approval exists")
}

/// Approving a held call re-checked only for a deny, so it ignored the global pause: a call held before
/// every agent was paused could still be approved and run while they were.
#[tokio::test]
async fn a_held_call_cannot_be_approved_while_every_agent_is_paused() {
    let state = common::seeded();
    let id = held_pull_request(&state).await;
    state.service.set_paused(true).unwrap();
    let refused = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await;
    assert!(matches!(refused, Err(permaura_gateway::error::GatewayError::Denied(_))), "{refused:?}");
    assert_eq!(approval_row(&state, &id).status, "pending", "it waits for the pause to lift");
    // A denial runs nothing, so it is still taken.
    let id_two = {
        state.service.set_paused(false).unwrap();
        let id_two = held_pull_request(&state).await;
        state.service.set_paused(true).unwrap();
        id_two
    };
    let denied = state.service.resolve_approval(&id_two, false, "bearer", Some("operator")).await.unwrap();
    assert_eq!(denied.status, "denied");
    state.service.set_paused(false).unwrap();
    let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(approved.status, "approved", "resumed, it runs");
}

/// It also read the tier and quorum captured when the call was held. Raising the action to
/// device_signed afterwards left a bearer able to approve the older hold, and raising the quorum left
/// one signature enough.
#[tokio::test]
async fn approving_a_held_call_needs_what_its_action_demands_now() {
    let (app, state, sk) = gateway_with_device(19);
    let id = held_pull_request(&state).await;
    assert_eq!(approval_row(&state, &id).required_tier, "approve");

    sign_pull_requests_with(&state, 1);
    let (status, resp) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN), serde_json::json!({ "approval_id": id, "approve": true })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a bearer cannot approve what now needs a device: {resp}");
    let row = approval_row(&state, &id);
    assert_eq!((row.status.as_str(), row.required_tier.as_str()), ("pending", "device_signed"), "raised, still pending");

    sign_pull_requests_with(&state, 2);
    let (status, resp) = device_sign(&app, seed::DEMO_TOKEN, &id, "device:approver", &sk).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "one signature cannot release a two-person action: {resp}");
    let row = approval_row(&state, &id);
    assert_eq!((row.status.as_str(), row.required_signatures), ("pending", 2), "raised, still pending");

    let (pk2, sk2) = approver_key(20);
    assert!(state.service.trust_approver_key_for("device:second", &pk2, Some("user_second")).unwrap());
    let (status, resp) = device_sign(&app, seed::DEMO_TOKEN, &id, "device:second", &sk2).await;
    assert_eq!(status, StatusCode::OK, "two people's devices release it: {resp}");
    assert_eq!(resp["status"], "approved");
}

/// The seed's pull-request grant with its budget replaced through `update_grant`, because `put_grant` appends and would leave the uncapped original standing beside it.
fn cap_pull_requests(state: &AppState, overall: Option<u64>, per_agent: Option<u64>) -> permaura_core::Grant {
    let store = state.service.store();
    let mut grant = store.get_grant("gr_github_prs").unwrap().expect("seeded grant");
    grant.overall_limit = overall;
    grant.default_per_agent_limit = per_agent;
    assert!(store.update_grant(grant.clone()).unwrap());
    grant
}

/// A new grant over the same policy and agents as `like`, under its own id.
fn add_grant_like(state: &AppState, like: &permaura_core::Grant, id: &str) -> permaura_core::Grant {
    let mut grant = like.clone();
    grant.grant_id = id.into();
    state.service.store().put_grant(grant.clone()).unwrap();
    grant
}

async fn hold_pull_requests(state: &AppState, n: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for _ in 0..n {
        ids.push(held_pull_request(state).await);
    }
    ids
}

fn audit_summary(state: &AppState, decision: &str, approval_id: &str) -> Option<serde_json::Value> {
    state
        .service
        .store()
        .audit_events_from(0, 10_000)
        .unwrap()
        .into_iter()
        .find(|e| e.payload.decision == decision && e.payload.summary["approval_id"] == approval_id)
        .map(|e| e.payload.summary)
}

/// Approve each hold in turn and count the ones that ran, checking that each one's attempt names the grant its `approved` event charged.
async fn approve_each(state: &AppState, ids: &[String]) -> usize {
    let mut ran = 0;
    for id in ids {
        let row = state.service.resolve_approval(id, true, "bearer", Some("operator")).await.unwrap();
        if row.status == "approved" {
            ran += 1;
            let attempt = audit_summary(state, "attempt", id).expect("an attempt precedes the run");
            let approved = audit_summary(state, "approved", id).expect("the run was recorded");
            assert_eq!(attempt["grant_id"], approved["grant_id"], "{id}: {attempt} / {approved}");
        }
    }
    ran
}

/// The `approved` events charged to `grant`, which is what its budget is measured from.
fn charged_to(state: &AppState, grant: &str) -> usize {
    state
        .service
        .store()
        .audit_events_from(0, 10_000)
        .unwrap()
        .iter()
        .filter(|e| e.payload.decision == "approved" && e.payload.summary["grant_id"] == grant)
        .count()
}

/// Approving a hold re-resolved it against today's grants but reserved and charged the grant the hold recorded, so a second grant added while holds waited authorized every one of them while the exhausted first grant took the charges.
#[tokio::test]
async fn a_grant_added_while_holds_wait_adds_its_own_budget_and_no_more() {
    let state = common::seeded();
    let a = cap_pull_requests(&state, Some(1), None);
    let ids = hold_pull_requests(&state, 4).await;
    add_grant_like(&state, &a, "gr_spare");

    assert_eq!(approve_each(&state, &ids).await, 2, "one call from each one-call grant");
    assert_eq!((charged_to(&state, "gr_github_prs"), charged_to(&state, "gr_spare")), (1, 1));

    // Every hold recorded gr_github_prs; an attempt the recheck moved to the other grant keeps it as `held_grant_id`, and one it did not move is unchanged.
    let mut attempts: Vec<(String, Option<String>)> = ids
        .iter()
        .filter_map(|id| audit_summary(&state, "attempt", id))
        .map(|a| {
            let held = a.get("held_grant_id").map(|v| v.as_str().unwrap().to_string());
            (a["grant_id"].as_str().unwrap().to_string(), held)
        })
        .collect();
    attempts.sort();
    assert_eq!(
        attempts,
        vec![("gr_github_prs".to_string(), None), ("gr_spare".to_string(), Some("gr_github_prs".to_string()))]
    );
}

/// The same with no change at all: two overlapping one-call grants from the start, and the holds recorded whichever one the engine picked first.
#[tokio::test]
async fn overlapping_one_call_grants_release_one_held_call_each() {
    let state = common::seeded();
    let a = cap_pull_requests(&state, Some(1), None);
    add_grant_like(&state, &a, "gr_spare");
    let ids = hold_pull_requests(&state, 4).await;

    assert_eq!(approve_each(&state, &ids).await, 2);
    assert_eq!((charged_to(&state, "gr_github_prs"), charged_to(&state, "gr_spare")), (1, 1));
}

#[tokio::test]
async fn per_agent_limits_bind_held_calls_across_overlapping_grants() {
    for added_while_waiting in [true, false] {
        let state = common::seeded();
        let a = cap_pull_requests(&state, None, Some(1));
        if !added_while_waiting {
            add_grant_like(&state, &a, "gr_spare");
        }
        let ids = hold_pull_requests(&state, 4).await;
        if added_while_waiting {
            add_grant_like(&state, &a, "gr_spare");
        }

        assert_eq!(approve_each(&state, &ids).await, 2, "added while waiting: {added_while_waiting}");
        assert_eq!((charged_to(&state, "gr_github_prs"), charged_to(&state, "gr_spare")), (1, 1));
    }
}

/// The holds recorded an unlimited grant; once it is disabled the one-call grant beside it is the only ceiling left, and the disabled grant is charged nothing.
#[tokio::test]
async fn disabling_the_grant_a_hold_recorded_leaves_the_remaining_grant_as_the_ceiling() {
    let state = common::seeded();
    let store = state.service.store();
    let a = cap_pull_requests(&state, Some(1), None);
    let mut broad = a.clone();
    broad.grant_id = "gr_broad".into();
    broad.overall_limit = None;
    store.put_grant(broad.clone()).unwrap();
    let ids = hold_pull_requests(&state, 4).await;
    assert_eq!(approval_row(&state, &ids[0]).grant_id.as_deref(), Some("gr_broad"));
    broad.enabled = false;
    assert!(store.update_grant(broad).unwrap());

    assert_eq!(approve_each(&state, &ids).await, 1);
    assert_eq!((charged_to(&state, "gr_github_prs"), charged_to(&state, "gr_broad")), (1, 0));
}

/// Controls: with a single grant and nothing to fall back on, held calls stop exactly as they did.
#[tokio::test]
async fn a_single_grant_still_bounds_its_held_calls_when_unchanged_lowered_disabled_or_deleted() {
    let state = common::seeded();
    cap_pull_requests(&state, Some(1), None);
    let ids = hold_pull_requests(&state, 4).await;
    assert_eq!(approve_each(&state, &ids).await, 1, "unchanged");
    assert_eq!(charged_to(&state, "gr_github_prs"), 1);

    let state = common::seeded();
    let mut a = cap_pull_requests(&state, Some(5), None);
    let ids = hold_pull_requests(&state, 4).await;
    a.overall_limit = Some(1);
    assert!(state.service.store().update_grant(a).unwrap());
    assert_eq!(approve_each(&state, &ids).await, 1, "lowered from five to one");
    assert_eq!(charged_to(&state, "gr_github_prs"), 1);

    let state = common::seeded();
    let mut a = cap_pull_requests(&state, Some(5), None);
    let ids = hold_pull_requests(&state, 2).await;
    a.enabled = false;
    assert!(state.service.store().update_grant(a).unwrap());
    assert_eq!(approve_each(&state, &ids).await, 0, "disabled");
    assert!(ids.iter().all(|id| approval_row(&state, id).status == "denied"));

    let state = common::seeded();
    let ids = hold_pull_requests(&state, 2).await;
    assert!(state.service.store().delete_grant("gr_github_prs").unwrap());
    assert_eq!(approve_each(&state, &ids).await, 0, "deleted");
    assert!(ids.iter().all(|id| approval_row(&state, id).status == "denied"));
    assert_eq!(charged_to(&state, "gr_github_prs"), 0);
}

/// A capability id is its connection's id and an action, so a WordPress site imported under the
/// connection id `permaura`, with a POST route in a `policy` namespace, derived `permaura.policy.write`:
/// the id every held control-plane change is filed under. The namespace is now the gateway's own.
#[tokio::test]
async fn no_connection_can_take_the_gateways_own_namespace() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let attempts = [
        ("/v1/connections", serde_json::json!({ "id": "permaura", "connector": "github", "name": "Mine" })),
        ("/v1/connections", serde_json::json!({ "id": "permaura.policy", "connector": "github", "name": "Mine" })),
        ("/v1/connections/from-preset", serde_json::json!({ "id": "permaura", "preset_id": "github", "name": "Mine" })),
        (
            "/v1/connections/import-wordpress",
            serde_json::json!({ "id": "permaura", "name": "Site", "url": "https://example.com", "namespaces": ["policy"] }),
        ),
    ];
    for (uri, body) in attempts {
        let (status, resp) = post(&app, uri, Some(seed::DEMO_TOKEN), body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} {body}: {resp}");
        assert!(resp.to_string().contains("reserved"), "{uri}: {resp}");
    }
    assert!(state.service.store().get_connection("permaura").unwrap().is_none());
}

/// A held agent call carries its connection's id as its `resource`, and every client reads a hold on
/// `control-plane` as a settings change and one on `vault` as an export, so no create path may give a connection
/// either id.
#[tokio::test]
async fn no_connection_can_take_a_reserved_hold_resource() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    for id in ["control-plane", "vault"] {
        let attempts = [
            ("/v1/connections", serde_json::json!({ "id": id, "connector": "github", "name": "Mine" })),
            ("/v1/connections/from-preset", serde_json::json!({ "id": id, "preset_id": "github", "name": "Mine" })),
            (
                "/v1/connections/import-wordpress",
                serde_json::json!({ "id": id, "name": "Site", "url": "https://example.com", "namespaces": ["wp/v2"] }),
            ),
            (
                "/v1/connections/import-openapi",
                serde_json::json!({ "id": id, "name": "Pets", "url": "https://api.example.com/v1", "spec": "{}" }),
            ),
        ];
        for (uri, body) in attempts {
            let (status, resp) = post(&app, uri, Some(seed::DEMO_TOKEN), body.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} {body}: {resp}");
            assert!(resp.to_string().contains(&format!("connection id '{id}' is reserved")), "{uri}: {resp}");
        }
        assert!(state.service.store().get_connection(id).unwrap().is_none());
    }
}

/// Any approval filed under `permaura.policy.write` was applied as a stored control-plane change, even
/// one an agent call raised. Only the gateway's own control-plane path, which holds with no requesting
/// session, may now reach that branch.
#[tokio::test]
async fn an_agent_raised_approval_never_applies_as_a_control_plane_change() {
    let state = common::seeded();
    let store = state.service.store();
    store.put_agent(Agent { id: "agent-x".into(), name: "X".into(), status: AgentStatus::Pending, enrolled_at: 0 }).unwrap();
    let mutation = serde_json::json!({ "kind": "agent_approve", "agent_id": "agent-x" });
    let now = permaura_gateway::service::now_ms();
    store
        .put_approval(PendingApproval {
            id: "appr_from_agent".into(),
            session_id: "sess_demo".into(),
            capability: "permaura.policy.write".into(),
            resource: "permaura".into(),
            message: "Approve 'permaura.policy.write'?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: mutation.into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: now,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
    let resolved = state.service.resolve_approval("appr_from_agent", true, "device_signed", Some("device:approver")).await;
    let resolved = resolved.expect("the hold is settled rather than left claimed and pending");
    assert_eq!(resolved.status, "denied", "there is no such connector capability to run");
    let agent = store.get_agent("agent-x").unwrap().unwrap();
    assert_eq!(agent.status, AgentStatus::Pending, "and the stored change was not applied");
}

/// Re-enabling a killed capability over the broker is held; disabling one applies immediately; a
/// device signature applies the re-enable (verified end-to-end by whether the action then invokes).
#[tokio::test]
async fn remote_capability_reenable_is_held_then_applied() {
    let (app, _state, sk) = gateway_with_device(11);
    let cap = "braintree.transactions.search";
    let uri = "/v1/connections/braintree_production/capabilities";

    // Disabling over the broker is strictly tightening → applies immediately.
    let (ds, _) = send(&app, "POST", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "capability": cap, "enabled": false }))).await;
    assert_eq!(ds, StatusCode::OK, "disable is tightening → applies over the broker");
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::FORBIDDEN, "disabled capability is denied");

    // Re-enabling over the broker is loosening → held.
    let (es, eresp) = send(&app, "POST", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "capability": cap, "enabled": true }))).await;
    assert_eq!(es, StatusCode::ACCEPTED, "re-enable is held: {eresp}");
    assert_eq!(eresp["required_tier"], "device_signed");
    let approval_id = eresp["approval_id"].as_str().unwrap().to_string();

    // Still disabled until signed.
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::FORBIDDEN, "re-enable is not applied before signing");

    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "signature applies the re-enable");
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::OK, "the re-enabled capability invokes again");
}

/// Un-pausing a killed connection over the broker is held; pausing it applies immediately.
#[tokio::test]
async fn remote_connection_unpause_is_held_pause_is_immediate() {
    let (app, _state, sk) = gateway_with_device(12);
    let uri = "/v1/connections/braintree_production";
    let cap = "braintree.transactions.search";

    // Pause over the broker (tightening) applies immediately.
    let (ps, _) = send(&app, "PATCH", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "disabled": true }))).await;
    assert_eq!(ps, StatusCode::OK, "pausing a connection is tightening → immediate");
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::FORBIDDEN, "paused connection denies all capabilities");

    // Un-pause over the broker is loosening → held.
    let (us, uresp) = send(&app, "PATCH", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "disabled": false }))).await;
    assert_eq!(us, StatusCode::ACCEPTED, "un-pause is held: {uresp}");
    assert_eq!(uresp["required_tier"], "device_signed");
    let approval_id = uresp["approval_id"].as_str().unwrap().to_string();

    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::FORBIDDEN, "still paused before signing");

    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "signature applies the un-pause");
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::OK, "the un-paused connection invokes again");
}

/// An SSH target repoint over the broker is held (any SSH edit is potentially insecurity-increasing);
/// renaming (label only) applies immediately.
#[tokio::test]
async fn remote_ssh_repoint_is_held_rename_is_immediate() {
    let (app, _state, sk) = gateway_with_device(13);
    let uri = "/v1/connections/ssh_prod";

    // A pure rename is neutral → applies immediately even over the broker.
    let (rs, _) = send(&app, "PATCH", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "label": "Prod SSH (renamed)" }))).await;
    assert_eq!(rs, StatusCode::OK, "a rename is neutral → immediate");

    // Repointing the SSH host is held.
    let (hs, hresp) = send(&app, "PATCH", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "ssh": { "host": "evil.example.com" } }))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "an SSH repoint is held: {hresp}");
    assert_eq!(hresp["required_tier"], "device_signed");
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();

    // Not repointed yet.
    let (_s, before) = get(&app, uri, seed::DEMO_TOKEN).await;
    assert!(!before.to_string().contains("evil.example.com"), "repoint not applied before signing");

    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "signature applies the repoint");
    let (_s, after) = get(&app, uri, seed::DEMO_TOKEN).await;
    assert!(after.to_string().contains("evil.example.com"), "the signed repoint is now live");
}

/// Approving a pending agent over the broker is held; a device signature approves it.
#[tokio::test]
async fn remote_agent_approve_is_held_then_applied() {
    let (app, state, sk) = gateway_with_device(14);
    state
        .service
        .store()
        .put_agent(Agent { id: "bot".into(), name: "Bot".into(), status: AgentStatus::Pending, enrolled_at: now_ms() })
        .unwrap();

    let (hs, hresp) = send(&app, "POST", "/v1/agents/bot/approve", seed::DEMO_TOKEN, true, None).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "approving a pending agent over the broker is held: {hresp}");
    assert_eq!(hresp["required_tier"], "device_signed");
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();

    assert!(
        !state.service.store().get_agent("bot").unwrap().unwrap().is_approved(),
        "not approved before signing"
    );
    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "signature approves the agent");
    assert!(
        state.service.store().get_agent("bot").unwrap().unwrap().is_approved(),
        "the signed approval promoted the agent"
    );
}

/// A phone that gave up on a slow 202 and sent the same approve again got a second hold for the
/// same agent. The same change while its hold is waiting answers with that hold; a different change is
/// still a hold of its own, and signing the one hold leaves nothing pending behind it.
#[tokio::test]
async fn a_retried_remote_agent_approve_answers_with_the_hold_already_waiting() {
    let (app, state, sk) = gateway_with_device(41);
    let store = state.service.store();
    for id in ["bot", "other"] {
        store
            .put_agent(Agent { id: id.into(), name: id.into(), status: AgentStatus::Pending, enrolled_at: now_ms() })
            .unwrap();
    }
    let pending = || store.list_approvals(Some("pending")).unwrap().len();

    let (s1, first) = send(&app, "POST", "/v1/agents/bot/approve", seed::DEMO_TOKEN, true, None).await;
    assert_eq!(s1, StatusCode::ACCEPTED, "{first}");
    let held = pending();

    let (s2, again) = send(&app, "POST", "/v1/agents/bot/approve", seed::DEMO_TOKEN, true, None).await;
    assert_eq!(s2, StatusCode::ACCEPTED, "the retry is answered the way the first call was: {again}");
    assert_eq!(again["approval_id"], first["approval_id"], "with the hold that is already waiting");
    assert_eq!(pending(), held, "and no second hold");

    let (s3, other) = send(&app, "POST", "/v1/agents/other/approve", seed::DEMO_TOKEN, true, None).await;
    assert_eq!(s3, StatusCode::ACCEPTED);
    assert_ne!(other["approval_id"], first["approval_id"], "another agent is another change");
    assert_eq!(pending(), held + 1);

    let approval_id = first["approval_id"].as_str().unwrap();
    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK);
    assert!(store.get_agent("bot").unwrap().unwrap().is_approved());
    assert_eq!(pending(), held, "only the other agent's hold is left waiting");
}

/// The same on the hosted store: the duplicate is found after the hold has been through SQLite and
/// back, and answering it costs no snapshot upload.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_hold_on_the_hosted_store_is_found_and_uploads_nothing() {
    use permaura_gateway::backend::{AuditKeyWrap, KmsClient};
    use permaura_gateway::error::GatewayError;
    use permaura_gateway::objectstore::MemoryObjectStore;
    use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
    use permaura_gateway::store::Store;

    struct XorKms;
    #[async_trait::async_trait]
    impl KmsClient for XorKms {
        async fn decrypt(&self, _: &str, b: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, GatewayError> {
            Ok(zeroize::Zeroizing::new(b.iter().map(|x| x ^ 0x5a).collect()))
        }
        async fn encrypt(&self, _: &str, b: &[u8]) -> Result<Vec<u8>, GatewayError> {
            Ok(b.iter().map(|x| x ^ 0x5a).collect())
        }
    }

    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!("permaura-dedupe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let objects = std::sync::Arc::new(MemoryObjectStore::new());
    let persisted = PersistedSqliteStore::open(
        &dir.join("store.db").to_string_lossy(),
        objects.clone(),
        DEFAULT_OBJECT,
        Some(AuditKeyWrap { kms: std::sync::Arc::new(XorKms), key_id: "synthetic".into(), adopt_plaintext: false }),
    )
    .unwrap()
    .with_fresh_read_window(std::time::Duration::ZERO)
    .with_on_stale(Box::new(|m| panic!("a single instance is never stale: {m}")));
    let store: std::sync::Arc<dyn Store> = std::sync::Arc::new(persisted);
    seed::seed(store.as_ref()).unwrap();
    store
        .put_agent(Agent { id: "bot".into(), name: "Bot".into(), status: AgentStatus::Pending, enrolled_at: now_ms() })
        .unwrap();
    let http = std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let state = AppState::new(permaura_gateway::service::EnforcementService::new(store.clone(), http));
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (pubkey, _sk) = approver_key(42);
    assert!(state.service.trust_approver_key("device:approver", &pubkey));

    let (s1, first) = send(&app, "POST", "/v1/agents/bot/approve", seed::DEMO_TOKEN, true, None).await;
    assert_eq!(s1, StatusCode::ACCEPTED, "{first}");
    let uploads = objects.put_count();

    let (s2, again) = send(&app, "POST", "/v1/agents/bot/approve", seed::DEMO_TOKEN, true, None).await;
    assert_eq!(s2, StatusCode::ACCEPTED, "{again}");
    assert_eq!(again["approval_id"], first["approval_id"]);
    assert_eq!(objects.put_count(), uploads, "answering with the waiting hold writes nothing");
    let holds = store
        .list_approvals(Some("pending"))
        .unwrap()
        .into_iter()
        .filter(|a| a.params.to_value_unbounded()["agent_id"] == "bot")
        .count();
    assert_eq!(holds, 1);
}

/// Registering a new (pre-approved) agent over the broker is held; renaming an existing approved
/// agent applies immediately.
#[tokio::test]
async fn remote_register_agent_is_held_rename_is_immediate() {
    let (app, state, sk) = gateway_with_device(15);

    // register creates an Approved agent → held over the broker.
    let (hs, hresp) = send(&app, "POST", "/v1/agents/register", seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "id": "newbot", "name": "New Bot" }))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "registering a pre-approved agent is held: {hresp}");
    assert!(state.service.store().get_agent("newbot").unwrap().is_none(), "not created before signing");
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();
    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK);
    assert!(
        state.service.store().get_agent("newbot").unwrap().is_some_and(|a| a.is_approved()),
        "the signed register created the approved agent"
    );

    // Renaming the existing (already-approved) codex-cli agent is neutral → immediate.
    let (rs, _) = send(&app, "PUT", "/v1/agents/codex-cli", seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "name": "Codex CLI renamed" }))).await;
    assert_eq!(rs, StatusCode::OK, "renaming an approved agent applies immediately");
}

/// A credential set over the broker is held BY REFERENCE: the plaintext never lands in the approval
/// params (only the two secret ids do), and a device signature promotes the staged blob into the
/// live secret.
#[tokio::test]
async fn remote_credential_set_is_held_by_reference() {
    let (app, state, sk) = gateway_with_device(16);
    let uri = "/v1/connections/braintree_production/credential";
    let secret_value = "sk_live_SUPER_SECRET_VALUE";

    let (hs, hresp) = send(&app, "POST", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "value": secret_value }))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "a remote credential set is held: {hresp}");
    assert_eq!(hresp["required_tier"], "device_signed");
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();

    // The held approval carries a credential_promote (ids only), NEVER the plaintext at rest.
    let held = state.service.store().get_approval(&approval_id).unwrap().unwrap();
    assert_eq!(held.params.to_value_unbounded()["kind"], "credential_promote", "held by reference, not by value");
    assert!(
        !held.params.to_string().contains(secret_value),
        "the plaintext credential must never appear in the approval params"
    );
    let staging_id = held.params.to_value_unbounded()["staging_secret_id"].as_str().unwrap().to_string();
    let live_id = held.params.to_value_unbounded()["secret_id"].as_str().unwrap().to_string();
    // The sealed staged blob exists; the live secret is not yet written.
    assert!(state.service.store().get_secret(&staging_id).unwrap().is_some(), "staged blob sealed at rest");

    // A bearer cannot resolve it (device_signed tier).
    let (bs, _) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": approval_id, "approve": true })).await;
    assert_eq!(bs, StatusCode::FORBIDDEN);

    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "the signature promotes the staged credential");
    assert!(state.service.store().get_secret(&staging_id).unwrap().is_none(), "staging blob removed on promote");
    assert!(state.service.store().get_secret(&live_id).unwrap().is_some(), "live secret now set");
}

/// Denying a held credential change cleans up the staged secret (no orphaned blob).
#[tokio::test]
async fn denied_credential_hold_cleans_up_the_staging_secret() {
    let (app, state, sk) = gateway_with_device(17);
    let uri = "/v1/connections/braintree_production/credential";
    let (hs, hresp) = send(&app, "POST", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "value": "rotate_me" }))).await;
    assert_eq!(hs, StatusCode::ACCEPTED);
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();
    let staging_id = state.service.store().get_approval(&approval_id).unwrap().unwrap()
        .params.to_value_unbounded()["staging_secret_id"].as_str().unwrap().to_string();

    // A device-signed DENY resolves the hold negatively and must release the staged blob.
    let (ds, _) = device_sign_decision(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk, false).await;
    assert_eq!(ds, StatusCode::OK, "a signed denial resolves the hold");
    assert!(
        state.service.store().get_secret(&staging_id).unwrap().is_none(),
        "the denied credential's staged blob is cleaned up"
    );
}

/// A loopback credential set (no cf-ray) applies immediately even with a device enrolled.
#[tokio::test]
async fn loopback_credential_set_applies_immediately() {
    let (app, _state, _sk) = gateway_with_device(18);
    let (s, resp) = send(&app, "POST", "/v1/connections/braintree_production/credential",
        seed::DEMO_TOKEN, false, Some(serde_json::json!({ "value": "loopback_rotate" }))).await;
    assert_eq!(s, StatusCode::OK, "loopback credential set applies immediately: {resp}");
    assert_eq!(resp["rotated"], true);
}

/// The generic secrets API must not be a bypass of the credential hold: rotating a secret that
/// BACKS a connection over the broker is held by reference, exactly like `set_connection_credential`.
#[tokio::test]
async fn remote_secret_rotate_of_a_backing_secret_is_held() {
    let (app, state, sk) = gateway_with_device(19);
    let secret_id = "sec_braintree_prod"; // the braintree_production connection's live credential

    let (hs, hresp) = send(&app, "POST", &format!("/v1/secrets/{secret_id}/rotate"), seed::DEMO_TOKEN,
        true, Some(serde_json::json!({ "value": "attacker_key" }))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "rotating a connection-backing secret over the broker is held: {hresp}");
    assert_eq!(hresp["required_tier"], "device_signed");
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();

    let held = state.service.store().get_approval(&approval_id).unwrap().unwrap();
    assert_eq!(held.params.to_value_unbounded()["kind"], "credential_promote", "held by reference");
    assert!(!held.params.to_string().contains("attacker_key"), "no plaintext credential in params");
    let staging_id = held.params.to_value_unbounded()["staging_secret_id"].as_str().unwrap().to_string();

    // A bearer cannot resolve it; a device signature promotes the staged blob.
    let (bs, _) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": approval_id, "approve": true })).await;
    assert_eq!(bs, StatusCode::FORBIDDEN);
    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK);
    assert!(state.service.store().get_secret(&staging_id).unwrap().is_none(), "staged blob promoted");
    assert!(state.service.store().get_secret(secret_id).unwrap().is_some(), "live secret still present");
}

/// `POST /v1/secrets` is an upsert with a client-chosen id, so it must NOT be usable to overwrite a
/// connection's live credential over the broker; a brand-new unreferenced id still applies at once.
#[tokio::test]
async fn remote_secret_create_cannot_overwrite_a_backing_secret() {
    let (app, _state, _sk) = gateway_with_device(20);
    let (hs, hresp) = send(&app, "POST", "/v1/secrets", seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "id": "sec_braintree_prod", "value": "attacker_key" }))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "overwriting a backing secret via create is held: {hresp}");
    assert_eq!(hresp["required_tier"], "device_signed");

    let (cs, _) = send(&app, "POST", "/v1/secrets", seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "id": "sec_unreferenced_new", "value": "harmless" }))).await;
    assert_eq!(cs, StatusCode::CREATED, "an unreferenced new secret applies immediately");
}

/// A loopback secret rotate (no cf-ray) applies immediately even with a device enrolled.
#[tokio::test]
async fn loopback_secret_rotate_applies_immediately() {
    let (app, _state, _sk) = gateway_with_device(21);
    let (s, resp) = send(&app, "POST", "/v1/secrets/sec_braintree_prod/rotate", seed::DEMO_TOKEN, false,
        Some(serde_json::json!({ "value": "loopback_rotate" }))).await;
    assert_eq!(s, StatusCode::OK, "loopback rotate applies immediately: {resp}");
    assert_eq!(resp["rotated"], true);
}

// ── The two runtime broker toggles (pause kill switch, new-agent approval gate) ───────────────────

/// Pausing over the broker (tightening) applies immediately; UN-pausing over the broker is held for
/// a device signature, and only the signature lifts the global kill switch back to policy control.
#[tokio::test]
async fn remote_broker_unpause_is_held_pause_is_immediate() {
    let (app, _state, sk) = gateway_with_device(22);
    let uri = "/v1/broker/pause";
    let cap = "braintree.transactions.search";

    // Pause over the broker (tightening) applies immediately → every invoke denied above policy.
    let (ps, presp) = send(&app, "POST", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "paused": true }))).await;
    assert_eq!(ps, StatusCode::OK, "pausing the broker is tightening → immediate: {presp}");
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::FORBIDDEN, "a paused broker denies every invoke");

    // Un-pausing over the broker is loosening → held.
    let (us, uresp) = send(&app, "POST", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "paused": false }))).await;
    assert_eq!(us, StatusCode::ACCEPTED, "un-pausing over the broker is held: {uresp}");
    assert_eq!(uresp["required_tier"], "device_signed");
    let approval_id = uresp["approval_id"].as_str().unwrap().to_string();

    // Still paused until signed.
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::FORBIDDEN, "still paused before signing");

    // A bearer cannot resolve it (device_signed tier).
    let (bs, _) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": approval_id, "approve": true })).await;
    assert_eq!(bs, StatusCode::FORBIDDEN, "a bearer cannot lift the kill switch");

    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "the signature lifts the pause");
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::OK, "the un-paused broker invokes again");
}

/// Enabling the new-agent approval gate over the broker (tightening) applies immediately; DISABLING
/// it over the broker is held for a device signature, and only the signature turns the gate off.
#[tokio::test]
async fn remote_require_approval_off_is_held_on_is_immediate() {
    let (app, _state, sk) = gateway_with_device(23);
    let uri = "/v1/broker/require-approval";

    // Enabling the gate over the broker (tightening) applies immediately.
    let (es, eresp) = send(&app, "POST", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "require_agent_approval": true }))).await;
    assert_eq!(es, StatusCode::OK, "enabling the gate is tightening → immediate: {eresp}");
    let (_s, broker) = get(&app, "/v1/broker", seed::DEMO_TOKEN).await;
    assert_eq!(broker["require_agent_approval"], true, "the gate is now on");

    // Disabling it over the broker is loosening → held.
    let (hs, hresp) = send(&app, "POST", uri, seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "require_agent_approval": false }))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "disabling the new-agent gate over the broker is held: {hresp}");
    assert_eq!(hresp["required_tier"], "device_signed");
    let approval_id = hresp["approval_id"].as_str().unwrap().to_string();

    // Still on until signed.
    let (_s, broker) = get(&app, "/v1/broker", seed::DEMO_TOKEN).await;
    assert_eq!(broker["require_agent_approval"], true, "the gate stays on before signing");

    // A bearer cannot resolve it (device_signed tier).
    let (bs, _) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": approval_id, "approve": true })).await;
    assert_eq!(bs, StatusCode::FORBIDDEN, "a bearer cannot disable the new-agent gate");

    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "the signature disables the gate");
    let (_s, broker) = get(&app, "/v1/broker", seed::DEMO_TOKEN).await;
    assert_eq!(broker["require_agent_approval"], false, "the signed change turned the gate off");
}

/// The pause and the new-agent gate are store rows, so a restart (a new service and
/// router over the same store) keeps both, and lifting the pause remotely afterwards still waits for
/// the device. Both used to live in memory only, so any cold start lifted them with no signature.
#[tokio::test]
async fn a_restart_keeps_the_pause_and_the_gate_and_resuming_still_needs_the_device() {
    let (app, state, sk) = gateway_with_device(26);
    let cap = "braintree.transactions.search";
    let (ps, presp) = send(&app, "POST", "/v1/broker/pause", seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "paused": true }))).await;
    assert_eq!(ps, StatusCode::OK, "{presp}");
    let (gs, gresp) = send(&app, "POST", "/v1/broker/require-approval", seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "require_agent_approval": true }))).await;
    assert_eq!(gs, StatusCode::OK, "{gresp}");

    let restarted = restart(&state);
    let app = build_router(restarted.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_s, broker) = get(&app, "/v1/broker", seed::DEMO_TOKEN).await;
    assert_eq!(broker["paused"], true, "the pause survived the restart");
    assert_eq!(broker["require_agent_approval"], true, "and so did the new-agent gate");
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::FORBIDDEN, "every invoke is still denied");

    let (us, uresp) = send(&app, "POST", "/v1/broker/pause", seed::DEMO_TOKEN, true,
        Some(serde_json::json!({ "paused": false }))).await;
    assert_eq!(us, StatusCode::ACCEPTED, "resuming over the broker after the restart is still held: {uresp}");
    let approval_id = uresp["approval_id"].as_str().unwrap().to_string();
    let (bs, _) = post(&app, "/v1/approvals", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "approval_id": approval_id, "approve": true })).await;
    assert_eq!(bs, StatusCode::FORBIDDEN, "a bearer cannot lift it");
    let (ss, _) = device_sign(&app, seed::DEMO_TOKEN, &approval_id, "device:approver", &sk).await;
    assert_eq!(ss, StatusCode::OK, "the signature lifts it");
    let (inv, _) = post(&app, "/v1/invoke", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "capability": cap, "params": {} })).await;
    assert_eq!(inv, StatusCode::OK, "resumed, agents invoke again");

    let again = restart(&restarted);
    assert!(!again.service.is_paused(), "the signed resume is what the next start reads");
    assert!(again.service.require_agent_approval(), "the gate was never lifted");
}

/// A restart: a new service over the same store, as the next process would open it.
fn restart(state: &AppState) -> AppState {
    AppState::new(permaura_gateway::service::EnforcementService::new(
        state.service.store().clone(),
        std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new()),
    ))
}

/// A loopback broker release (no cf-ray) applies immediately even with a device enrolled: the guard
/// engages only for broker-originated toggles.
#[tokio::test]
async fn loopback_broker_release_applies_immediately() {
    let (app, _state, _sk) = gateway_with_device(24);
    // Enable the gate (tightening, immediate), then disable it over loopback (applies at once).
    let _ = send(&app, "POST", "/v1/broker/require-approval", seed::DEMO_TOKEN, false,
        Some(serde_json::json!({ "require_agent_approval": true }))).await;
    let (s, resp) = send(&app, "POST", "/v1/broker/require-approval", seed::DEMO_TOKEN, false,
        Some(serde_json::json!({ "require_agent_approval": false }))).await;
    assert_eq!(s, StatusCode::OK, "a loopback release applies immediately: {resp}");
    assert_eq!(resp["require_agent_approval"], false);
}

/// The engine matches a policy rung against the *bare* action id, while the connections list,
/// the capability listing, the invoke call and the capability toggle all hand out the *qualified*
/// one. A policy written from what the API returns used to be accepted, attach to its grant, read
/// back correctly, and match nothing, including on `deny`. A deny that silently enforces nothing is
/// the worst possible outcome, so the write is refused rather than normalised.
#[tokio::test]
async fn a_qualified_action_id_is_refused_on_every_rung_rather_than_silently_matching_nothing() {
    let app = app();

    for rung in ["allow", "deny", "requires_approval", "notify", "device_signed"] {
        let (status, body) = post(
            &app,
            "/v1/policies",
            Some(seed::DEMO_TOKEN),
            serde_json::json!({
                "connection_id": "github_acme",
                "name": "qualified",
                rung: ["github.pull_requests.list"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "rung {rung} must refuse a qualified id");
        let err = body["error"].as_str().unwrap_or_default();
        assert!(err.contains(rung), "the error must name the offending rung: {err}");
        assert!(
            err.contains("pull_requests.list"),
            "the error must name the id the engine would actually match: {err}"
        );
    }

    // The same action, in the form the engine matches, still works: this is a rejection of the
    // wrong *spelling*, not of the action.
    let (status, _) = post(
        &app,
        "/v1/policies",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({
            "connection_id": "github_acme",
            "name": "bare",
            "deny": ["pull_requests.list"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// An id that is simply wrong gets the valid set rather than a misleading "did you mean".
#[tokio::test]
async fn an_unknown_action_id_is_refused_and_the_error_names_the_valid_ones() {
    let app = app();
    let (status, body) = post(
        &app,
        "/v1/policies",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({
            "connection_id": "github_acme",
            "name": "typo",
            "allow": ["pull_requests.lsit"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err = body["error"].as_str().unwrap_or_default();
    assert!(err.contains("valid ids"), "must name the valid ids: {err}");
    assert!(!err.contains("Did you mean"), "nothing to suggest for a plain typo: {err}");
}

/// The four listing endpoints called `authed()` where their four siblings
/// (`/v1/audit-events`, `/v1/connectors/installed`, `/v1/devices`, `/v1/approvals`) correctly called
/// `operator_authed()`. An enrolled agent token got a 200 and read the whole security map: every
/// connection, every policy's allow/deny/approval rungs, every grant's budget and coverage, and the
/// inventory of secret ids with risk ratings and last-used times. No values leaked; the
/// reconnaissance did, and the agent is the untrusted party in this product's own threat model.
#[tokio::test]
async fn an_agent_token_cannot_read_the_security_configuration() {
    let app = app();
    let (_s, enroll) = post(&app, "/v1/agents/enroll", Some(seed::DEMO_TOKEN), serde_json::json!({})).await;
    let code = enroll["code"].as_str().unwrap().to_string();
    let (_s, mcp) = post(
        &app,
        "/mcp",
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "snoop" } }
        }),
    )
    .await;
    let agent_token = mcp["result"]["structuredContent"]["token"].as_str().unwrap().to_string();

    for uri in ["/v1/secrets", "/v1/connections", "/v1/grants", "/v1/policies"] {
        let (status, _) = get(&app, uri, &agent_token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "an agent token must not read {uri}");
        let (status, _) = get(&app, uri, seed::DEMO_TOKEN).await;
        assert_eq!(status, StatusCode::OK, "an operator token must still read {uri}");
    }
}

/// The capability listing describes itself as what this session may attempt, so it has to be that.
/// A freshly enrolled agent is Pending and can invoke nothing; handing it the full catalogue made
/// the endpoint a map of the estate for a session that could not call a single entry on it.
#[tokio::test]
async fn a_pending_agent_is_not_handed_the_whole_capability_catalogue() {
    let app = app();
    let (_s, enroll) = post(&app, "/v1/agents/enroll", Some(seed::DEMO_TOKEN), serde_json::json!({})).await;
    let code = enroll["code"].as_str().unwrap().to_string();
    let (_s, mcp) = post(
        &app,
        "/mcp",
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "pending-one" } }
        }),
    )
    .await;
    let agent_token = mcp["result"]["structuredContent"]["token"].as_str().unwrap().to_string();

    let (status, body) = get(&app, "/v1/capabilities", &agent_token).await;
    assert_eq!(status, StatusCode::OK, "listing stays readable; it just tells the truth");
    let caps = body["capabilities"].as_array().expect("capabilities array");
    assert!(caps.is_empty(), "a Pending agent can invoke nothing, so it may attempt nothing: {caps:?}");

    // The operator still sees the whole catalogue.
    let (status, body) = get(&app, "/v1/capabilities", seed::DEMO_TOKEN).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body["capabilities"].as_array().unwrap().is_empty(),
        "an operator drives the console and needs the full catalogue"
    );
}

/// The inverse, and the one that stops this becoming an over-restriction: an agent a grant actually
/// points at still sees what it can call. Scoping the listing must hide reconnaissance, not the
/// agent's own tools.
#[tokio::test]
async fn an_approved_agent_named_by_a_grant_still_sees_its_own_capabilities() {
    let app = app();
    let (_s, enroll) = post(&app, "/v1/agents/enroll", Some(seed::DEMO_TOKEN), serde_json::json!({})).await;
    let code = enroll["code"].as_str().unwrap().to_string();
    let (_s, mcp) = post(
        &app,
        "/mcp",
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "field-agent" } }
        }),
    )
    .await;
    let agent_token = mcp["result"]["structuredContent"]["token"].as_str().unwrap().to_string();

    // Pending and ungranted: nothing to attempt.
    let (_s, body) = get(&app, "/v1/capabilities", &agent_token).await;
    assert!(body["capabilities"].as_array().unwrap().is_empty());

    // Approve it and point a grant at every agent: now it can genuinely reach GitHub.
    let (status, _) = post(&app, "/v1/agents/field-agent/approve", Some(seed::DEMO_TOKEN), serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK, "approve must succeed");
    let (status, _) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "policy_id": "pol_github_prs", "target": "all_agents" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "grant must be created");

    let (status, body) = get(&app, "/v1/capabilities", &agent_token).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = body["capabilities"].as_array().unwrap().iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(
        ids.iter().any(|i| i.starts_with("github.")),
        "an agent a grant points at must see its own tools: {ids:?}"
    );
    // Still a strict subset: a capability no grant activates stays hidden.
    assert!(!ids.contains(&"http.request"), "an ungoverned capability must not be listed: {ids:?}");
    assert!(!ids.iter().any(|i| i.starts_with("braintree.")), "a connection this grant does not reach stays hidden: {ids:?}");
}

/// `permaura_http_request` maps onto the `http.request` capability, which only the demo estate
/// registers: a clean bootstrap registers none. Advertising it on a real install handed the agent a
/// tool that answers "not found: capability 'http.request'", which reads like a transient failure and
/// gets retried. Every advertised tool must resolve.
#[tokio::test]
async fn the_mcp_tool_list_advertises_no_tool_the_gateway_cannot_serve() {
    use permaura_gateway::store::Store;

    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    let names = |body: &serde_json::Value| -> Vec<String> {
        body["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|t| t["name"].as_str().map(String::from))
            .collect()
    };
    let list = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });

    // The seeded estate registers http.request, so offering the tool is honest here.
    let (_s, body) = post(&app, "/mcp", Some(seed::DEMO_TOKEN), list.clone()).await;
    assert!(
        names(&body).iter().any(|n| n == "permaura_http_request"),
        "the demo estate registers http.request, so the tool belongs"
    );

    // Remove the capability, as a clean bootstrap leaves it: the tool must stop being advertised.
    assert!(state.service.store().delete_capability("http.request").unwrap());
    let (_s, body) = post(&app, "/mcp", Some(seed::DEMO_TOKEN), list).await;
    let after = names(&body);
    assert!(
        !after.iter().any(|n| n == "permaura_http_request"),
        "a gateway with no http.request capability must not advertise the tool: {after:?}"
    );
    assert!(!after.is_empty(), "the rest of the catalogue is untouched");
}

/// The MCP tool list is a description of what this session may call, so it has to be one. Handing the
/// whole catalogue to a session that can call none of it is a map of the estate, the same defect already
/// fixed on the REST capability listing, on a surface with its own auth model.
#[tokio::test]
async fn the_mcp_tool_list_is_scoped_to_what_the_session_could_call() {
    let app = app();
    let list = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let names = |b: &serde_json::Value| -> Vec<String> {
        b["result"]["tools"].as_array().expect("tools").iter()
            .filter_map(|t| t["name"].as_str().map(String::from)).collect()
    };

    // An operator drives the console and needs the whole catalogue.
    let (_s, body) = post(&app, "/mcp", Some(seed::DEMO_TOKEN), list.clone()).await;
    let op = names(&body);
    assert!(op.iter().any(|n| n.starts_with("braintree.")), "operator sees the catalogue: {op:?}");

    // A freshly enrolled agent is Pending and can invoke nothing, so it may attempt nothing.
    let (_s, enroll) = post(&app, "/v1/agents/enroll", Some(seed::DEMO_TOKEN), serde_json::json!({})).await;
    let code = enroll["code"].as_str().unwrap().to_string();
    let (_s, mcp) = post(
        &app,
        "/mcp",
        None,
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "snoop" } } }),
    )
    .await;
    let agent_token = mcp["result"]["structuredContent"]["token"].as_str().unwrap().to_string();
    let (_s, body) = post(&app, "/mcp", Some(&agent_token), list.clone()).await;
    let pending = names(&body);
    assert!(
        !pending.iter().any(|n| n.starts_with("braintree.")),
        "a Pending agent must not be handed the estate: {pending:?}"
    );
    assert!(
        pending.iter().any(|n| n == "permaura_enroll"),
        "the fixed permaura_* tools stay, or an agent cannot enrol: {pending:?}"
    );

    // Unauthenticated: possible only on a local gateway, where open discovery is deliberate. It
    // keeps the fixed tools it needs to enrol and gets no inventory.
    let (_s, body) = post(&app, "/mcp", None, list).await;
    let anon = names(&body);
    assert!(!anon.iter().any(|n| n.starts_with("braintree.")), "no inventory unauthenticated: {anon:?}");
    assert!(anon.iter().any(|n| n == "permaura_enroll"), "enrolment stays reachable: {anon:?}");
}

/// The listing tool answered any caller with the whole catalogue, so a Pending agent, or on a hosted
/// worker anyone holding a live enrolment code, could map every connection and capability before a
/// human had approved anything. It is scoped exactly as tools/list is, and an unauthenticated call is
/// refused the way every other tool's is.
#[tokio::test]
async fn the_capability_listing_tool_is_scoped_to_what_the_session_could_call() {
    let app = app();
    let call = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "permaura_list_capabilities", "arguments": {} } });
    let ids = |b: &serde_json::Value| -> Vec<String> {
        b["result"]["structuredContent"]["capabilities"].as_array().expect("capabilities").iter()
            .filter_map(|c| c["id"].as_str().map(String::from)).collect()
    };

    // An operator drives the console and needs the whole catalogue.
    let (_s, body) = post(&app, "/mcp", Some(seed::DEMO_TOKEN), call.clone()).await;
    let op = ids(&body);
    assert!(op.iter().any(|n| n.starts_with("braintree.")), "operator sees the catalogue: {op:?}");

    // A freshly enrolled agent is Pending and can invoke nothing, so it is told about nothing.
    let (_s, enroll) = post(&app, "/v1/agents/enroll", Some(seed::DEMO_TOKEN), serde_json::json!({})).await;
    let code = enroll["code"].as_str().unwrap().to_string();
    let (_s, mcp) = post(
        &app,
        "/mcp",
        None,
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "mapper" } } }),
    )
    .await;
    let agent_token = mcp["result"]["structuredContent"]["token"].as_str().unwrap().to_string();
    let (_s, body) = post(&app, "/mcp", Some(&agent_token), call.clone()).await;
    assert!(ids(&body).is_empty(), "a Pending agent must not be handed the estate: {body}");

    // Unauthenticated is a refusal, not an empty answer that reads as an enrolled agent with no grants.
    let (_s, body) = post(&app, "/mcp", None, call).await;
    assert_eq!(body["error"]["code"], -32001, "unauthenticated is refused: {body}");
}


// ── Deleting a connection ────────────────────────────────────────────────────────────────────────

/// The cascade, asserted after it moved out of the handler into `apply_mutation`.
///
/// That move was the prerequisite for holding this delete: a held mutation is replayed through
/// `apply_mutation` when the device signs, so anything left behind in the handler would simply not
/// happen on the approved path. Nothing covered this cascade before, so the move was unprotected.
#[tokio::test]
async fn deleting_a_connection_takes_its_policies_and_capabilities_with_it() {
    let app = app();

    let before = get(&app, "/v1/policies", seed::DEMO_TOKEN).await.1;
    let named = |v: &serde_json::Value| {
        v["policies"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["connection_id"] == "github_acme")
            .count()
    };
    assert!(named(&before) > 0, "the fixture needs at least one policy on this connection");

    let (status, body) =
        req(&app, "DELETE", "/v1/connections/github_acme", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], true);

    assert_eq!(
        named(&get(&app, "/v1/policies", seed::DEMO_TOKEN).await.1),
        0,
        "every policy naming the connection must go with it"
    );
    let (status, _) = get(&app, "/v1/connections/github_acme", seed::DEMO_TOKEN).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "and the connection itself");
}

/// A typo must not become a notification asking someone to approve deleting something that never
/// existed, so existence is checked before the hold.
#[tokio::test]
async fn deleting_a_connection_that_does_not_exist_is_a_404_not_a_hold() {
    let app = app();
    let (status, _) = req(&app, "DELETE", "/v1/connections/nope", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Held over loopback with a device paired, and (the part that matters) NOTHING is deleted while it
/// waits. A hold that destroyed first and asked afterwards would be worse than no hold.
#[tokio::test]
async fn a_held_connection_delete_changes_nothing_until_it_is_signed() {
    let state = common::seeded();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let pubkey = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        sk.verifying_key().to_bytes(),
    );
    assert!(state.service.trust_approver_key("device:alice", &pubkey));
    let service = state.service.clone();
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    let (status, body) =
        req(&app, "DELETE", "/v1/connections/github_acme", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "requires_approval");

    let (status, _) = get(&app, "/v1/connections/github_acme", seed::DEMO_TOKEN).await;
    assert_eq!(status, StatusCode::OK, "the connection must still be there while the hold waits");

    // And the signature applies the whole cascade, not merely the last line of it.
    let approval_id = body["approval_id"].as_str().unwrap();
    service
        .resolve_approval(approval_id, true, "device_signed", Some("device:alice"))
        .await
        .expect("the device signs it");

    let (status, _) = get(&app, "/v1/connections/github_acme", seed::DEMO_TOKEN).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "approving must actually delete it");
    assert_eq!(
        get(&app, "/v1/policies", seed::DEMO_TOKEN)
            .await
            .1["policies"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["connection_id"] == "github_acme")
            .count(),
        0,
        "and cascade, which only works because the cascade moved into apply_mutation"
    );
}


// ── The two deletes that an export hold does not cover ───────────────────────────────────────────

/// Holding the export stops a credential being TAKEN and says nothing about it being destroyed.
/// `DELETE /v1/secrets/:id` removed one outright on an operator token, which is a 0600 file every
/// process running as the owner can read.
#[tokio::test]
async fn deleting_a_credential_holds_for_a_device_signature() {
    let state = common::seeded();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
    let pubkey = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        sk.verifying_key().to_bytes(),
    );
    assert!(state.service.trust_approver_key("device:alice", &pubkey));
    let service = state.service.clone();
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    let (status, body) =
        req(&app, "DELETE", "/v1/secrets/sec_github_acme", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "requires_approval");

    // Still there while the hold waits. A hold that destroyed first would be worse than none.
    let (status, _) = get(&app, "/v1/connections/github_acme", seed::DEMO_TOKEN).await;
    assert_eq!(status, StatusCode::OK);

    service
        .resolve_approval(body["approval_id"].as_str().unwrap(), true, "device_signed", Some("device:alice"))
        .await
        .expect("the device signs it");
    let (status, _) = req(&app, "DELETE", "/v1/secrets/sec_github_acme", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "approving must actually have deleted it");
}

/// Deleting an agent also strips it from every grant, so the whole cascade has to run on the approved
/// path rather than only the immediate path.
#[tokio::test]
async fn deleting_an_agent_holds_and_its_cascade_runs_on_approval() {
    let state = common::seeded();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[37u8; 32]);
    let pubkey = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        sk.verifying_key().to_bytes(),
    );
    assert!(state.service.trust_approver_key("device:alice", &pubkey));
    let service = state.service.clone();
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    let (status, body) = req(&app, "DELETE", "/v1/agents/codex-cli", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    // There is no GET /v1/agents/:id, so membership of the list is the check.
    let listed = |v: &serde_json::Value| serde_json::to_string(v).unwrap().contains("codex-cli");
    assert!(
        listed(&get(&app, "/v1/agents", seed::DEMO_TOKEN).await.1),
        "nothing may be destroyed while the hold waits"
    );

    service
        .resolve_approval(body["approval_id"].as_str().unwrap(), true, "device_signed", Some("device:alice"))
        .await
        .expect("the device signs it");

    assert!(
        !listed(&get(&app, "/v1/agents", seed::DEMO_TOKEN).await.1),
        "approving must actually delete it"
    );
    assert!(
        !listed(&get(&app, "/v1/grants", seed::DEMO_TOKEN).await.1),
        "the cascade must run on the approved path, not only the immediate one"
    );
}

/// With no device registered these proceed, same rule as everywhere else in the ladder.
#[tokio::test]
async fn the_new_deletes_are_not_held_when_no_device_is_registered() {
    let app = app();
    let (status, _) = req(&app, "DELETE", "/v1/secrets/sec_github_acme", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = req(&app, "DELETE", "/v1/agents/codex-cli", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::OK);
}

/// Enrol an agent through the real handshake (operator mints a code, the agent redeems it over MCP)
/// and leave it waiting. Returns the agent's bearer token.
async fn enrol_pending_agent(app: &axum::Router, agent_id: &str) -> String {
    let (status, enroll) =
        post(app, "/v1/agents/enroll", Some(seed::DEMO_TOKEN), serde_json::json!({ "label": "Cursor" })).await;
    assert_eq!(status, StatusCode::CREATED, "{enroll}");
    let code = enroll["code"].as_str().unwrap().to_string();
    let (status, mcp) = post(
        app,
        "/mcp",
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "name": "Cursor", "agent_id": agent_id } }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{mcp}");
    let result = &mcp["result"]["structuredContent"];
    assert_eq!(result["status"], "pending", "{mcp}");
    result["token"].as_str().unwrap().to_string()
}

/// `DELETE` as it arrives through the tunnel: `cf-ray` marks the request remote.
async fn delete_remote(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .header("cf-ray", "abc123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// A waiting agent holds no authority and names no grant, so removing it is the Deny button: it
/// applies at once, over the broker and with a device trusted, while removing an approved agent on the
/// same gateway over the same route is still held. The phone used to open the hold's card, whose own
/// Deny cancelled the removal and brought the agent back.
#[tokio::test]
async fn deleting_a_pending_agent_applies_at_once_while_an_approved_one_is_held() {
    let state = common::seeded();
    let (pubkey, _sk) = approver_key(41);
    assert!(state.service.trust_approver_key("device:alice", &pubkey));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    let agent_token = enrol_pending_agent(&app, "cursor").await;
    let listed = |v: &serde_json::Value, id: &str| serde_json::to_string(v).unwrap().contains(id);

    let (status, body) = delete_remote(&app, "/v1/agents/cursor").await;
    assert_eq!(status, StatusCode::OK, "a pending agent's removal is not held: {body}");
    assert_eq!(body["deleted"], serde_json::Value::Bool(true), "{body}");
    assert!(!listed(&get(&app, "/v1/agents", seed::DEMO_TOKEN).await.1, "cursor"), "it is gone at once");
    let (status, _) = get(&app, "/v1/capabilities", &agent_token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the cascade revoked its session on the immediate path too");
    let (_s, approvals) = get(&app, "/v1/approvals", seed::DEMO_TOKEN).await;
    assert!(!listed(&approvals, "cursor"), "nothing was queued for a device: {approvals}");

    // The removal is still a recorded decision.
    let (_s, audit) = get(&app, "/v1/audit-events?limit=50", seed::DEMO_TOKEN).await;
    let recorded = audit["events"].as_array().unwrap().iter().any(|e| {
        let summary = &e["payload"]["summary"];
        e["payload"]["action"] == "permaura.policy.write"
            && summary["method"] == "applied"
            && summary["remote"] == serde_json::Value::Bool(true)
            && summary["mutation"]["kind"] == "agent_delete"
            && summary["mutation"]["agent_id"] == "cursor"
    });
    assert!(recorded, "an applied removal writes the same audit event a held one does: {audit}");

    // Same device, same route: an approved agent's removal still waits for a signature.
    let (status, body) = delete_remote(&app, "/v1/agents/codex-cli").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["required_tier"], "device_signed", "{body}");
    assert!(listed(&get(&app, "/v1/agents", seed::DEMO_TOKEN).await.1, "codex-cli"), "held, so still there");
}

/// The applied event for a delete names what was deleted, the way the hold card for the same change
/// does. The title used to be resolved after the row was gone, so an immediate removal of "Cursor" was
/// recorded as the id while the card a device is shown for the held one read the name.
#[tokio::test]
async fn an_applied_delete_is_audited_by_name_not_id() {
    let app = app();
    let _agent_token = enrol_pending_agent(&app, "cursor").await;
    let (status, body) = req(&app, "DELETE", "/v1/agents/cursor", seed::DEMO_TOKEN, None).await;
    assert_eq!(status, StatusCode::OK, "no device is trusted, so it applies at once: {body}");

    let (_s, audit) = get(&app, "/v1/audit-events?limit=50", seed::DEMO_TOKEN).await;
    let title = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["payload"]["summary"])
        .find(|s| s["method"] == "applied" && s["mutation"]["kind"] == "agent_delete")
        .map(|s| s["title"].as_str().unwrap().to_string())
        .expect("the applied removal is audited");
    assert_eq!(title, "Remove the agent \u{201c}Cursor\u{201d}", "the name, read before the row went");
}

/// A grant that names the waiting agent is configuration the delete would cascade away, so that one
/// is still held: the exemption is for the row that is nothing but a row.
#[tokio::test]
async fn deleting_a_pending_agent_a_grant_names_is_still_held() {
    let state = common::seeded();
    let (pubkey, _sk) = approver_key(42);
    assert!(state.service.trust_approver_key("device:alice", &pubkey));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    let _agent_token = enrol_pending_agent(&app, "cursor").await;

    let (_s, policies) = get(&app, "/v1/policies", seed::DEMO_TOKEN).await;
    let policy_id = policies["policies"][0]["id"].as_str().expect("the seed has a policy").to_string();
    let (status, grant) = post(
        &app,
        "/v1/grants",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({ "name": "cursor only", "policy_ids": [policy_id], "agents": ["cursor"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{grant}");

    let (status, body) = delete_remote(&app, "/v1/agents/cursor").await;
    assert_eq!(status, StatusCode::ACCEPTED, "the cascade would edit the grant, so a device signs: {body}");
    let listed = |v: &serde_json::Value| serde_json::to_string(v).unwrap().contains("cursor");
    assert!(listed(&get(&app, "/v1/agents", seed::DEMO_TOKEN).await.1), "held, so still there");
}


// ── The trust root ───────────────────────────────────────────────────────────────────────────────

/// Adding a SECOND approver device over loopback must wait for one already trusted.
///
/// This was the softest thing in the system. Every hold worth having rests on a device signature, and
/// enrolling the device that produces those signatures took nothing but the operator token, a 0600
/// file every agent the owner runs can read. One loopback call added a key of the caller's own,
/// silently, alongside the owner's real device; from there it signed its own approvals and the export
/// hold, the delete holds and the rest were worth nothing.
#[tokio::test]
async fn enrolling_a_second_device_over_loopback_waits_for_the_first() {
    let state = common::seeded();
    let first = ed25519_dalek::SigningKey::from_bytes(&[51u8; 32]);
    let first_pk = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        first.verifying_key().to_bytes(),
    );
    assert!(state.service.trust_approver_key("device:owner", &first_pk));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    // A key of the attacker's own, with a valid possession proof, which it can always produce, since
    // it generated the key. The proof is not the control; the co-signature is.
    let theirs = ed25519_dalek::SigningKey::from_bytes(&[52u8; 32]);
    let theirs_pk = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        theirs.verifying_key().to_bytes(),
    );
    let issued_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let preimage =
        permaura_relay::approver_pairing_preimage("device:agent", &theirs_pk, issued_at);
    let sig = permaura_relay::sign(&theirs, &preimage);

    let (status, body) = post(
        &app,
        "/v1/approver-keys/pair",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({
            "approver_id": "device:agent",
            "approver_pubkey": theirs_pk,
            "issued_at": issued_at,
            "sig": sig,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::ACCEPTED, "a second device must not enrol itself: {body}");
    assert_eq!(body["status"], "requires_approval");

    // And it is not trusted while the hold waits, or the hold would be decoration.
    let keys = get(&app, "/v1/approver-keys", seed::DEMO_TOKEN).await.1;
    let trusted_agent = keys["keys"]
        .as_array()
        .map(|a| a.iter().any(|k| k["approver_id"] == "device:agent" && k["trusted"] == true))
        .unwrap_or(false);
    assert!(!trusted_agent, "nothing may be trusted before the co-signature: {keys}");
}

/// The first device still enrols with no ceremony. Holding that would mean a gateway that can never
/// have a device at all, which is the state the whole ladder is trying to leave.
#[tokio::test]
async fn the_first_device_still_enrols_without_a_co_signature() {
    let app = app();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[53u8; 32]);
    let pk = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        sk.verifying_key().to_bytes(),
    );
    let issued_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let sig = permaura_relay::sign(
        &sk,
        &permaura_relay::approver_pairing_preimage("device:first", &pk, issued_at),
    );

    let (status, body) = post(
        &app,
        "/v1/approver-keys/pair",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({
            "approver_id": "device:first", "approver_pubkey": pk,
            "issued_at": issued_at, "sig": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the first device pairs on trust-on-first-use: {body}");
    assert_eq!(body["trusted"], true);
}

// ── Recovery authority: the two doors that switch the device hold off ────────────────

/// Any method, any body, any extra headers, as the demo operator. Returns (status, json).
async fn send_with(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
    extra: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
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

/// Pair the FIRST device over loopback through the real endpoint, so the recovery codes are issued
/// the way they are for a user. Returns the device's signing key and the eight codes.
async fn pair_first_device(
    app: &axum::Router,
    seed_byte: u8,
    approver_id: &str,
) -> (ed25519_dalek::SigningKey, Vec<String>) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
    let pk = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        sk.verifying_key().to_bytes(),
    );
    let issued_at = now_ms();
    let sig = permaura_relay::sign(
        &sk,
        &permaura_relay::approver_pairing_preimage(approver_id, &pk, issued_at),
    );
    let (status, body) = post(
        app,
        "/v1/approver-keys/pair",
        Some(seed::DEMO_TOKEN),
        serde_json::json!({
            "approver_id": approver_id, "approver_pubkey": pk,
            "issued_at": issued_at, "sig": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "setup: the first device pairs on trust-on-first-use: {body}");
    let codes: Vec<String> = body["recovery_codes"]
        .as_array()
        .expect("the first pairing returns recovery codes")
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(codes.len(), 8, "eight codes are issued: {body}");
    // Raise the floor, which pairing no longer does by itself. Every caller of this helper is
    // setting up "a gateway that requires device-signed approvals" and used to get that free from
    // enrolment; making it a step here keeps those tests testing what they are named for, and keeps
    // the fact that it IS a separate decision visible at the one place they all pass through.
    let (floor_status, floor_body) = send_with(
        app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "device_signed" })),
        &[],
    )
    .await;
    assert_eq!(
        floor_status, StatusCode::OK,
        "setup: raising the floor is a call now, not a side effect of pairing: {floor_body}",
    );
    (sk, codes)
}

/// What an agent holding `operator.token` gets from `POST /v1/vault/export`.
async fn export_status(app: &axum::Router) -> (StatusCode, serde_json::Value) {
    send_with(app, "POST", "/v1/vault/export", Some(serde_json::json!({ "passphrase": "correct horse" })), &[])
        .await
}

fn pubkey_of(sk: &ed25519_dalek::SigningKey) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.verifying_key().to_bytes())
}

/// A paired device signs a decision on a held approval.
async fn device_decides(
    app: &axum::Router,
    approval_id: &str,
    approver: &str,
    sk: &ed25519_dalek::SigningKey,
    approve: bool,
) -> (StatusCode, serde_json::Value) {
    let (_s, appr) = send_with(app, "GET", &format!("/v1/approvals/{approval_id}"), None, &[]).await;
    let request_hash = appr["request_hash"].as_str().expect("held approval exposes request_hash");
    let job_id = appr["job_id"].as_str().expect("held approval exposes job_id");
    let decided_at = now_ms();
    let preimage = permaura_relay::approval_result_preimage(
        job_id,
        approval_id,
        approve,
        request_hash,
        approver,
        decided_at,
    );
    let body = serde_json::json!({
        "approval_id": approval_id,
        "approve": approve,
        "approver": approver,
        "request_hash": request_hash,
        "decided_at": decided_at,
        "job_id": job_id,
        "approver_pubkey": pubkey_of(sk),
        "device_sig": permaura_relay::sign(sk, &preimage),
    });
    send_with(app, "POST", "/v1/approvals", Some(body), &[]).await
}

fn key_is_trusted(state: &AppState, approver_id: &str) -> bool {
    state.service.approver_keyring_snapshot().trusted_key(approver_id).is_some()
}

/// The first attack chain: read `operator.token`, lower the floor, export. The lowering is held, so
/// the export stays held.
#[tokio::test]
async fn reading_the_operator_token_and_lowering_the_floor_does_not_reach_the_vault() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    pair_first_device(&app, 62, "device:owner").await;
    let (status, body) = export_status(&app).await;
    assert_eq!(status, StatusCode::ACCEPTED, "baseline: with a device trusted the export is held: {body}");

    let (status, body) = send_with(&app, "PUT", "/v1/approval-floor", Some(serde_json::json!({ "floor": "approve" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the bearer alone may not lower the floor: {body}");
    let (status, body) = send_with(&app, "PUT", "/v1/approval-floor", Some(serde_json::json!({ "floor": "default" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "clearing the override is a lowering too: {body}");
    assert!(state.service.require_device_signed_approval(), "the floor did not move");

    let (status, body) = export_status(&app).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the export is still held: {body}");
    assert_ne!(body["status"], "ok");
}

/// The second attack chain: read `operator.token`, revoke every key, export. The revocation that
/// would empty the keyring is held, so the key stays trusted and the export stays held.
#[tokio::test]
async fn reading_the_operator_token_and_revoking_the_last_key_does_not_reach_the_vault() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    pair_first_device(&app, 63, "device:owner").await;

    let (status, body) = send_with(&app, "DELETE", "/v1/approver-keys/device:owner", None, &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "revoking the last key on the bearer alone is held: {body}");
    assert_eq!(body["status"], "requires_approval");
    assert!(key_is_trusted(&state, "device:owner"), "the key stays trusted while the hold waits");
    assert!(state.service.any_device_trusted());

    let (status, body) = export_status(&app).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the export is still held: {body}");
}

/// Revoking a key while ANOTHER usable key remains stays fail-safe and applies on the bearer alone:
/// a co-signer is still in the keyring, so nothing is switched off.
#[tokio::test]
async fn revoking_a_key_that_leaves_another_applies_at_once() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    pair_first_device(&app, 64, "device:owner").await;
    let second = ed25519_dalek::SigningKey::from_bytes(&[65u8; 32]);
    assert!(state.service.trust_approver_key("device:second", &pubkey_of(&second)));

    let (status, body) = send_with(&app, "DELETE", "/v1/approver-keys/device:second", None, &[]).await;
    assert_eq!(status, StatusCode::OK, "a non-last revocation is fail-safe: {body}");
    assert_eq!(body["trusted"], false);
    assert_eq!(body["emptied_keyring"], false);
    assert!(!key_is_trusted(&state, "device:second"));
    assert!(key_is_trusted(&state, "device:owner"));
}

/// A recovery code revokes the last key at once, is burned, and dies with the trust epoch it belonged
/// to: the next first pairing issues a fresh set and the old ones are refused.
#[tokio::test]
async fn a_recovery_code_revokes_the_last_key_once_and_dies_with_the_epoch() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_sk, codes) = pair_first_device(&app, 66, "device:owner").await;

    let (status, body) = send_with(
        &app,
        "DELETE",
        "/v1/approver-keys/device:owner",
        None,
        &[("x-permaura-recovery-code", codes[0].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a recovery code applies the revocation now: {body}");
    assert_eq!(body["emptied_keyring"], true);
    assert!(!state.service.any_device_trusted());
    // With no device left there is nothing to hold for, which is the documented anti-brick shape.
    let (status, _) = export_status(&app).await;
    assert_eq!(status, StatusCode::OK, "with no device trusted the export proceeds");

    // A new first device: new codes, and every old code is dead.
    let (_sk2, fresh) = pair_first_device(&app, 67, "device:replacement").await;
    assert_ne!(fresh, codes);
    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[("x-permaura-recovery-code", codes[1].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a code from the earlier epoch is refused: {body}");
    assert!(state.service.require_device_signed_approval());
}

/// A code is single use: the same code presented twice is refused the second time, and the audit
/// chain records the refusal.
#[tokio::test]
async fn a_recovery_code_is_single_use() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_sk, codes) = pair_first_device(&app, 68, "device:owner").await;
    let lower = || serde_json::json!({ "floor": "approve" });

    let (status, _) = send_with(&app, "PUT", "/v1/approval-floor", Some(lower()), &[("x-permaura-recovery-code", codes[2].as_str())]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(put_floor(&app, seed::DEMO_TOKEN, "device_signed", None).await, StatusCode::OK);
    let (status, body) = send_with(&app, "PUT", "/v1/approval-floor", Some(lower()), &[("x-permaura-recovery-code", codes[2].as_str())]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the same code must not work twice: {body}");
    assert!(state.service.require_device_signed_approval());

    let (_s, recovery) = send_with(&app, "GET", "/v1/recovery", None, &[]).await;
    assert_eq!(recovery["codes"]["remaining"], 7, "{recovery}");
    assert_eq!(recovery["codes"]["total"], 8);

    let (_s, audit) = get(&app, "/v1/audit-events?limit=100", seed::DEMO_TOKEN).await;
    let refused = audit["events"].as_array().unwrap().iter().any(|e| {
        e["payload"]["action"] == "permaura.approver.pair"
            && e["payload"]["decision"] == "deny"
            && e["payload"]["summary"]["authority"] == "recovery_code"
    });
    assert!(refused, "a refused recovery code must be in the audit chain: {audit}");
}

/// The timer-recovery attack chain, refused at its first step and again at its last.
///
/// The chain was: pair a device and register a push token for it; use only the operator bearer to
/// enrol the SAME approver id with no push token, which left the signing key trusted and removed
/// every notification; ask for the change with `X-Permaura-Recovery: delayed`; wait out the clock;
/// export. Two independent refusals now, either of which alone ends it, because a defence that
/// depends on notifications reaching somebody is not a defence.
#[tokio::test]
async fn a_bearer_can_neither_silence_a_trusted_device_nor_wait_out_a_recovery() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_sk, _codes) = pair_first_device(&app, 73, "device:owner").await;

    // The device registers for notifications the way the phone does.
    let (status, body) = send_with(
        &app,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({
            "name": "Owner phone", "platform": "ios",
            "approver_id": "device:owner", "push_token": "ExponentPushToken[real]",
        })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "setup: the device registers for push: {body}");

    // Step 1 of the chain: the bearer tries to replace that entry with one that has no push token.
    let (status, body) = send_with(
        &app,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({ "name": "Owner phone", "approver_id": "device:owner" })),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operator bearer must not be able to silence a trusted device: {body}"
    );
    let devices = send_with(&app, "GET", "/v1/devices", None, &[]).await.1;
    let owner = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["approver_id"] == "device:owner")
        .expect("the device is still listed");
    assert_eq!(owner["has_push_token"], true, "its push entry must be intact: {devices}");

    // Step 3 of the chain: even with the notification gone, the timer route is refused outright.
    for (method, path, body) in [
        ("PUT", "/v1/approval-floor", Some(serde_json::json!({ "floor": "approve" }))),
        ("DELETE", "/v1/approver-keys/device:owner", None),
    ] {
        let (status, resp) =
            send_with(&app, method, path, body, &[("x-permaura-recovery", "delayed")]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path} must refuse the timer: {resp}");
        let err = resp["error"].as_str().unwrap_or_default();
        assert!(err.contains("completes on a timer has been removed"), "the refusal must say why: {resp}");
        assert!(err.contains("X-Permaura-Recovery-Code"), "and name a real route: {resp}");
    }

    // Nothing moved, so the export the whole chain was aimed at is still held.
    assert!(state.service.require_device_signed_approval());
    assert!(key_is_trusted(&state, "device:owner"));
    assert_eq!(export_status(&app).await.0, StatusCode::ACCEPTED, "the export is still held");
}

/// A device may re-register its own push entry, which is the ordinary phone-relaunch path. What it
/// takes is that device's signature over the token being installed, so a signature obtained once
/// cannot be replayed to install a different token later.
#[tokio::test]
async fn a_trusted_device_re_registers_its_push_entry_with_its_own_signature() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (sk, _codes) = pair_first_device(&app, 74, "device:owner").await;
    let audience = state.service.approval_audience().unwrap();

    let enrol = |token: &'static str, sig_token: &'static str, issued_at: i64| {
        let sig = permaura_relay::sign(
            &sk,
            &permaura_relay::device_control_preimage_v2(
                &audience,
                "device-enroll",
                "device:owner",
                sig_token,
                issued_at,
            ),
        );
        serde_json::json!({
            "name": "Owner phone", "approver_id": "device:owner",
            "push_token": token, "issued_at": issued_at, "sig": sig, "audience": audience,
        })
    };

    // First registration: nothing to displace, so no signature is needed.
    let (status, body) = send_with(
        &app,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({ "name": "Owner phone", "approver_id": "device:owner", "push_token": "tok-1" })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Re-registration, signed over the new token: accepted.
    let now = now_ms();
    let (status, body) =
        send_with(&app, "POST", "/v1/devices/enroll", Some(enrol("tok-2", "tok-2", now)), &[]).await;
    assert_eq!(status, StatusCode::CREATED, "a signed re-registration is the phone's own path: {body}");

    // The same signature aimed at a different token: refused, because the token is signed over.
    let (status, body) =
        send_with(&app, "POST", "/v1/devices/enroll", Some(enrol("", "tok-2", now)), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the signature is bound to its token: {body}");

    // And a stale one, however well formed.
    let stale = now_ms() - 10 * 60 * 1000;
    let (status, body) =
        send_with(&app, "POST", "/v1/devices/enroll", Some(enrol("tok-3", "tok-3", stale)), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a stale signature is refused: {body}");
}

/// The push registry survives a restart. It used to be memory only, so a restart was a way to arrange
/// the silence step 1 of the chain above is now refused for.
#[tokio::test]
async fn the_push_registry_survives_a_restart() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (status, _) = send_with(
        &app,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({
            "name": "Owner phone", "approver_id": "device:owner", "push_token": "ExponentPushToken[x]",
        })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // A second service over the SAME store is what a restart looks like from the registry's side.
    let restarted = permaura_gateway::service::EnforcementService::new(
        state.service.store().clone(),
        std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new()),
    );
    let devices = restarted.list_devices();
    let owner = devices
        .iter()
        .find(|d| d.approver_id.as_deref() == Some("device:owner"))
        .expect("the device must come back after a restart");
    assert_eq!(
        owner.push_token.as_deref(),
        Some("ExponentPushToken[x]"),
        "and with its push token, or the registry is back to announcing to nobody"
    );
}

/// A delayed recovery an older build left on the clock is cancelled at boot, with an audit entry, so
/// it neither applies nor sits in the queue as a change that is still coming.
#[tokio::test]
async fn a_delayed_recovery_left_by_an_older_build_is_cancelled_at_boot() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    pair_first_device(&app, 75, "device:owner").await;

    // The record an older build would have written, with the approval it queued alongside it.
    let (status, body) = send_with(
        &app,
        "DELETE",
        "/v1/approver-keys/device:owner",
        None,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "setup: the revocation is held: {body}");
    let approval_id = body["approval_id"].as_str().unwrap().to_string();
    let record = serde_json::json!({
        "approval_id": approval_id,
        "mutation": { "kind": "approver_key_revoke", "approver_id": "device:owner" },
        "summary": "Stop trusting device:owner",
        "requested_at": now_ms(),
        "effective_at": now_ms() + 86_400_000,
    });
    state
        .service
        .store()
        .put_meta(permaura_gateway::recovery::RECOVERY_PENDING_META, &record.to_string())
        .unwrap();

    let cancelled = state.service.cancel_delayed_recovery(now_ms()).unwrap().expect("a record to cancel");
    assert_eq!(cancelled.approval_id, approval_id);
    assert!(key_is_trusted(&state, "device:owner"), "cancelling applies nothing");
    assert!(
        state.service.cancel_delayed_recovery(now_ms()).unwrap().is_none(),
        "and the second boot finds nothing"
    );

    let (_s, audit) = get(&app, "/v1/audit-events?limit=50", seed::DEMO_TOKEN).await;
    let recorded = audit["events"].as_array().unwrap().iter().any(|e| {
        e["payload"]["summary"]["authority"] == "delayed_recovery"
            && e["payload"]["decision"] == "deny"
    });
    assert!(recorded, "the cancellation must be in the audit chain: {audit}");
}

/// The ordinary route out, and now the primary one: the trusted device co-signs the held change.
///
/// Worth its own test rather than being implied by the refusals around it. With the timer gone,
/// every other test in this area asserts that something is REFUSED, and a suite that only proves
/// what cannot happen would pass just as well on a gateway where recovery is impossible.
#[tokio::test]
async fn a_trusted_device_co_signs_a_held_recovery() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (sk, _codes) = pair_first_device(&app, 78, "device:owner").await;
    assert!(state.service.require_device_signed_approval(), "setup: the floor is raised");

    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "a bearer alone is held: {body}");
    // The hold says what it actually did about notifying, which is not "everyone has been told".
    let notified = body["notified"].as_str().unwrap_or_default();
    assert!(notified.contains("where a push token is registered"), "{body}");
    assert!(notified.contains("not a guarantee"), "{body}");

    let approval_id = body["approval_id"].as_str().expect("approval_id").to_string();
    let audience = served_audience(&app).await;
    let (status, resp) = device_decides_for(&app, &app, &approval_id, "device:owner", &sk, &audience).await;
    assert_eq!(status, StatusCode::OK, "the device co-signs it: {resp}");
    assert!(!state.service.require_device_signed_approval(), "and the change lands");
}

/// A gateway with no OAuth configuration has no identity anchor, and says so rather than pretending.
///
/// This is the conceded case, stated plainly because the alternative was the timer. There is no
/// third API authority here: the device, a code, or physical access to the keyring file on the host.
/// A ticket header is refused rather than ignored, so an owner who tried it is told why.
#[tokio::test]
async fn a_gateway_with_no_authorization_server_refuses_a_recovery_ticket() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    assert!(
        state.service.oauth().is_none(),
        "setup: this gateway has no remote-access configuration"
    );
    pair_first_device(&app, 76, "device:owner").await;

    // Any ticket at all, well formed or not: there is nothing here to verify it against.
    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[("x-permaura-pairing-ticket", "eyJhbGciOiJFZERTQSJ9.e30.AA")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("not an OAuth resource server"),
        "the refusal must say what is missing: {body}"
    );
    assert!(state.service.require_device_signed_approval(), "and nothing may move");

    // And the hold it does get names what is left, not a re-authentication it cannot perform.
    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let hint = body["recovery"].as_str().unwrap_or_default();
    assert!(!hint.contains("permaura.com"), "it must not offer a route it does not have: {body}");
    assert!(hint.contains("recovery codes"), "and must name the one it does: {body}");
    assert!(hint.contains("uninstall --purge-data"), "and say what is left without one: {body}");
}

/// A trusted device can ask for codes on its own signature. Two states need this and a code alone
/// reaches neither: a gateway paired before codes existed has no set to present, and an owner who
/// spent theirs while the phone still works had no way back to one.
#[tokio::test]
async fn a_trusted_device_can_issue_recovery_codes_including_its_first_set() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (sk, codes) = pair_first_device(&app, 77, "device:owner").await;

    // The state a gateway upgraded while already paired arrives in: a trusted device, and no codes.
    permaura_gateway::recovery::clear(state.service.store().as_ref()).unwrap();
    let (_s, status_body) = send_with(&app, "GET", "/v1/recovery", None, &[]).await;
    assert!(status_body["codes"].is_null(), "setup: no codes: {status_body}");
    let (status, body) = send_with(
        &app,
        "POST",
        "/v1/recovery-codes",
        None,
        &[("x-permaura-recovery-code", codes[0].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the old set is dead, so no code can help: {body}");

    let audience = state.service.approval_audience().unwrap();
    let signed = |issued_at: i64| {
        let sig = permaura_relay::sign(
            &sk,
            &permaura_relay::device_control_preimage_v2(&audience, "recovery-codes", "device:owner", "", issued_at),
        );
        serde_json::json!({ "approver_id": "device:owner", "issued_at": issued_at, "sig": sig, "audience": audience })
    };

    let (status, body) =
        send_with(&app, "POST", "/v1/recovery-codes", Some(signed(now_ms())), &[]).await;
    assert_eq!(status, StatusCode::OK, "the device signs for its first set: {body}");
    assert_eq!(body["first_set"], true, "{body}");
    let fresh: Vec<String> = body["recovery_codes"]
        .as_array()
        .expect("codes")
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(fresh.len(), 8);

    // The set really works, which is the whole point of being able to get one.
    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[("x-permaura-recovery-code", fresh[0].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A stale signature is not an authority, and neither is a bearer with no signature at all.
    let stale = now_ms() - 10 * 60 * 1000;
    let (status, body) =
        send_with(&app, "POST", "/v1/recovery-codes", Some(signed(stale)), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a stale signature is refused: {body}");
    let (status, body) = send_with(&app, "POST", "/v1/recovery-codes", None, &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "and a bearer alone is refused: {body}");
}

/// Regenerating the codes needs one of the current codes, so a bearer alone cannot mint itself a set.
#[tokio::test]
async fn recovery_codes_regenerate_only_with_a_code() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_sk, codes) = pair_first_device(&app, 71, "device:owner").await;

    let (status, body) = send_with(&app, "POST", "/v1/recovery-codes", None, &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no code, no new codes: {body}");

    let (status, body) = send_with(&app, "POST", "/v1/recovery-codes", None, &[("x-permaura-recovery-code", codes[0].as_str())]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fresh = body["recovery_codes"].as_array().expect("new codes");
    assert_eq!(fresh.len(), 8);

    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[("x-permaura-recovery-code", codes[1].as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the replaced set is dead: {body}");
    let (status, body) = send_with(
        &app,
        "PUT",
        "/v1/approval-floor",
        Some(serde_json::json!({ "floor": "approve" })),
        &[("x-permaura-recovery-code", fresh[0].as_str().unwrap())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a fresh code works: {body}");
}

// ── Approval audience: a device signature is bound to the gateway it was made for ──────────────

/// This gateway's approval audience, as a paired device reads it from the keyring listing.
async fn served_audience(app: &axum::Router) -> String {
    let (status, body) = send_with(app, "GET", "/v1/approver-keys", None, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["approval_audience"].as_str().expect("the keyring listing serves the audience").to_string()
}

/// Lower the floor, which a gateway with a trusted device holds for that device's signature. Returns
/// the held approval's id. The floor goes back up first, applied at once because raising only
/// tightens, so a test can collect as many holds as it needs.
async fn hold_a_floor_lowering(app: &axum::Router) -> String {
    let (status, body) =
        send_with(app, "PUT", "/v1/approval-floor", Some(serde_json::json!({ "floor": "device_signed" })), &[]).await;
    assert_eq!(status, StatusCode::OK, "setup: raising the floor applies at once: {body}");
    let (status, body) =
        send_with(app, "PUT", "/v1/approval-floor", Some(serde_json::json!({ "floor": "approve" })), &[]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "setup: lowering is held for the device: {body}");
    body["approval_id"].as_str().expect("approval_id").to_string()
}

/// Sign a decision on `approval_id` as served by `app`, bound to `audience` and to the rendering `app`
/// served (v3), and post it to `target`. `app` and `target` differ when the test is replaying a
/// signature collected elsewhere.
async fn device_decides_for(
    app: &axum::Router,
    target: &axum::Router,
    approval_id: &str,
    approver: &str,
    sk: &ed25519_dalek::SigningKey,
    audience: &str,
) -> (StatusCode, serde_json::Value) {
    let (_s, appr) = send_with(app, "GET", &format!("/v1/approvals/{approval_id}"), None, &[]).await;
    let request_hash = appr["request_hash"].as_str().expect("request_hash");
    let job_id = appr["job_id"].as_str().expect("job_id");
    let shown = permaura_relay::approval_display_full_digest_of(&appr).expect("the full rendering");
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
    let body = serde_json::json!({
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
    send_with(target, "POST", "/v1/approvals", Some(body), &[]).await
}

/// The cross-gateway harvest. Two gateways trust the same device key. A device shown gateway B's held call
/// (its id and request_hash) by gateway A signs for A, because A is what it was looking at. That
/// signature must not resolve the hold on B; only one the device made for B does.
#[tokio::test]
async fn a_signature_made_for_another_gateway_does_not_resolve_a_hold_here() {
    let state_b = common::seeded();
    let app_b = build_router(state_b.clone(), "127.0.0.1:7376".parse().unwrap());
    let state_a = common::seeded();
    let app_a = build_router(state_a.clone(), "127.0.0.1:7376".parse().unwrap());
    let (sk, _) = pair_first_device(&app_b, 91, "device:owner").await;
    pair_first_device(&app_a, 91, "device:owner").await;

    let audience_a = served_audience(&app_a).await;
    let audience_b = served_audience(&app_b).await;
    assert_ne!(audience_a, audience_b, "every gateway mints its own audience");

    let held = hold_a_floor_lowering(&app_b).await;
    let (status, body) = device_decides_for(&app_b, &app_b, &held, "device:owner", &sk, &audience_a).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a signature made for gateway A is refused on B: {body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("different gateway"),
        "and the refusal says why: {body}"
    );
    assert!(state_b.service.require_device_signed_approval(), "the held change did not land");

    let (status, body) = device_decides_for(&app_b, &app_b, &held, "device:owner", &sk, &audience_b).await;
    assert_eq!(status, StatusCode::OK, "a signature made for B resolves it: {body}");
    assert!(!state_b.service.require_device_signed_approval(), "and the change lands");
}

/// v1 signatures name no gateway. They are refused by default, with words telling the approver to pair
/// the device again, and taken only once the operator opts back in for an app that predates the
/// audience; a bound signature works either way.
#[tokio::test]
async fn unbound_device_signatures_are_refused_unless_the_gateway_opts_back_in() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (sk, _) = pair_first_device(&app, 92, "device:owner").await;
    assert!(!state.service.accepts_v1_device_signatures(), "v1 is refused by default");

    let held = hold_a_floor_lowering(&app).await;
    let (status, body) = device_decides(&app, &held, "device:owner", &sk, true).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a v1 signature is refused: {body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("paired with this gateway again"), "{body}");
    let audience = served_audience(&app).await;
    let (status, body) = device_decides_for(&app, &app, &held, "device:owner", &sk, &audience).await;
    assert_eq!(status, StatusCode::OK, "a signature bound to this gateway resolves it: {body}");

    state.service.set_accept_v1_device_signatures(true);
    state.service.set_require_display_bound_approvals(false);
    let legacy = ed25519_dalek::SigningKey::from_bytes(&[96u8; 32]);
    assert!(state.service.trust_approver_key("device:legacy", &pubkey_of(&legacy)));
    let held = hold_a_floor_lowering(&app).await;
    let (status, body) = device_decides(&app, &held, "device:legacy", &legacy, true).await;
    assert_eq!(status, StatusCode::OK, "opted back in, an app that predates the audience works: {body}");
}

/// While v1 is still accepted, an approver that has signed v2 here is held to v2: its app binds every
/// signature for this gateway, so a v1 signature carrying its id was collected somewhere else.
#[tokio::test]
async fn an_approver_that_has_signed_for_this_gateway_cannot_be_answered_unbound() {
    let state = common::seeded_accepting_legacy_signatures();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (sk, _) = pair_first_device(&app, 93, "device:owner").await;
    let audience = served_audience(&app).await;

    let held = hold_a_floor_lowering(&app).await;
    let (status, body) = device_decides_for(&app, &app, &held, "device:owner", &sk, &audience).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let held = hold_a_floor_lowering(&app).await;
    let (status, body) = device_decides(&app, &held, "device:owner", &sk, true).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "this approver signs v2 now, so v1 is refused: {body}");

    // Another device that has never signed v2 is unaffected.
    let second = ed25519_dalek::SigningKey::from_bytes(&[94u8; 32]);
    assert!(state.service.trust_approver_key("device:second", &pubkey_of(&second)));
    let (status, body) = device_decides(&app, &held, "device:second", &second, true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Wherever a device learns about this gateway it is told the same audience, and the value outlives
/// the process, because a device pins it at pairing and refuses to sign once it changes.
#[tokio::test]
async fn the_approval_audience_is_served_everywhere_a_device_reads_this_gateway() {
    let store: std::sync::Arc<dyn permaura_gateway::store::Store> =
        std::sync::Arc::new(permaura_gateway::store::memory::MemoryStore::new());
    common::seeded();
    permaura_gateway::seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let state = AppState::new(permaura_gateway::service::EnforcementService::new(store.clone(), http.clone()));
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    let sk = ed25519_dalek::SigningKey::from_bytes(&[95u8; 32]);
    let pk = pubkey_of(&sk);
    let issued_at = now_ms();
    let sig = permaura_relay::sign(&sk, &permaura_relay::approver_pairing_preimage("device:owner", &pk, issued_at));
    let (status, paired) = send_with(
        &app,
        "POST",
        "/v1/approver-keys/pair",
        Some(serde_json::json!({ "approver_id": "device:owner", "approver_pubkey": pk, "issued_at": issued_at, "sig": sig })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{paired}");
    let audience = paired["approval_audience"].as_str().expect("the pairing answer carries the audience").to_string();
    assert!(audience.starts_with("aud_") && audience.len() == 36, "a 128-bit random value: {audience}");

    assert_eq!(served_audience(&app).await, audience);
    let held = hold_a_floor_lowering(&app).await;
    let (_s, one) = send_with(&app, "GET", &format!("/v1/approvals/{held}"), None, &[]).await;
    assert_eq!(one["approval_audience"], audience.as_str(), "{one}");
    let (_s, list) = send_with(&app, "GET", "/v1/approvals?status=pending", None, &[]).await;
    assert!(
        list["approvals"].as_array().unwrap().iter().all(|a| a["approval_audience"] == audience.as_str()),
        "{list}"
    );

    // A second process over the same store serves the same value.
    let restarted = permaura_gateway::service::EnforcementService::new(store, http);
    assert_eq!(restarted.approval_audience().unwrap(), audience);
}

/// Device-control requests carry the same binding: a recovery-code request signed for one gateway
/// cannot be redeemed on another that trusts the same key.
#[tokio::test]
async fn a_recovery_code_request_signed_for_another_gateway_is_refused() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let other = build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap());
    let (sk, _) = pair_first_device(&app, 96, "device:owner").await;
    let ours = served_audience(&app).await;
    let theirs = served_audience(&other).await;

    let signed = |audience: &str| {
        let issued_at = now_ms();
        let sig = permaura_relay::sign(
            &sk,
            &permaura_relay::device_control_preimage_v2(audience, "recovery-codes", "device:owner", "", issued_at),
        );
        serde_json::json!({ "approver_id": "device:owner", "issued_at": issued_at, "sig": sig, "audience": audience })
    };
    let (status, body) = send_with(&app, "POST", "/v1/recovery-codes", Some(signed(&theirs)), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "signed for another gateway: {body}");
    let (status, body) = send_with(&app, "POST", "/v1/recovery-codes", Some(signed(&ours)), &[]).await;
    assert_eq!(status, StatusCode::OK, "signed for this one: {body}");

    // Having signed v2 here, the device is held to it on the device-control path too.
    let issued_at = now_ms();
    let v1 = permaura_relay::sign(
        &sk,
        &permaura_relay::device_control_preimage("recovery-codes", "device:owner", "", issued_at),
    );
    let (status, body) = send_with(
        &app,
        "POST",
        "/v1/recovery-codes",
        Some(serde_json::json!({ "approver_id": "device:owner", "issued_at": issued_at, "sig": v1 })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "an unbound signature from a v2 signer is refused: {body}");

    // And a push re-registration signed v2 for this gateway is the phone's ordinary path.
    let (status, body) = send_with(
        &app,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({ "name": "Owner phone", "approver_id": "device:owner", "push_token": "tok-1" })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let issued_at = now_ms();
    let sig = permaura_relay::sign(
        &sk,
        &permaura_relay::device_control_preimage_v2(&ours, "device-enroll", "device:owner", "tok-2", issued_at),
    );
    let (status, body) = send_with(
        &app,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({
            "name": "Owner phone", "approver_id": "device:owner", "push_token": "tok-2",
            "issued_at": issued_at, "sig": sig, "audience": ours,
        })),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// Every hold that names a connection carries its id and name, so each, and the label, is capped at 128 bytes where an API call creates or renames the connection. Its capability ids are not, so a connection id the cap admits is never refused for the ids its connector's actions make from it.
#[tokio::test]
async fn an_oversized_connection_id_or_name_is_refused_at_creation() {
    let app = app();
    let short = |body: &serde_json::Value| body.to_string().chars().take(300).collect::<String>();
    let huge = "c".repeat(255_000);
    let (status, body) = post(&app, "/v1/connections", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": "Big", "id": huge })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a 255 KB connection id: {}", short(&body));
    assert!(body.to_string().len() < 1024, "the refusal does not echo the id");
    let (_, listed) = get(&app, "/v1/connections", seed::DEMO_TOKEN).await;
    assert!(!listed.to_string().contains(&huge[..1024]), "nothing was stored");

    let long_name = "n".repeat(129);
    for body in [
        serde_json::json!({ "connector": "github", "name": long_name }),
        serde_json::json!({ "connector": "github", "name": "Ok", "label": long_name }),
        serde_json::json!({ "connector": "github", "name": "Ok", "id": "c".repeat(129) }),
    ] {
        let (status, refused) = post(&app, "/v1/connections", Some(seed::DEMO_TOKEN), body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{} -> {}", short(&body), short(&refused));
    }
    let (status, made) = post(&app, "/v1/connections", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": "Ok", "id": "c".repeat(128) })).await;
    assert_eq!(status, StatusCode::CREATED, "a 128-byte id whose capability ids are longer: {}", short(&made));

    let (status, made) = post(&app, "/v1/connections", Some(seed::DEMO_TOKEN),
        serde_json::json!({ "connector": "github", "name": "n".repeat(128), "id": "c".repeat(64) })).await;
    assert_eq!(status, StatusCode::CREATED, "{}", short(&made));
    let uri = format!("/v1/connections/{}", "c".repeat(64));
    let (status, renamed) = req(&app, "PATCH", &uri, seed::DEMO_TOKEN, Some(serde_json::json!({ "name": long_name }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a rename is capped too: {}", short(&renamed));
}
