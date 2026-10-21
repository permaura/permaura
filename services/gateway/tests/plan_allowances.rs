//! Plan allowances at the gateway boundary, driven through the real router.
//!
//! These are the plan allowances the console's `lib/billing/plans.ts` defines, which once bound
//! only the console. The console is not on the agent path: a hosted worker answers `/mcp` and
//! `/v1/invoke` directly, so a limit drawn in a React component is a limit a direct agent never
//! meets. Every test here therefore goes through `build_router` rather than calling the gate, and
//! the agent tests deliberately include the two paths an agent walks on its own.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::allowances::{Allowance, Allowances, AllowancesConfig};
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt; // for `oneshot`

mod common;

/// A seeded estate with one allowance set to exactly what it already holds, so the very next create
/// of that kind is the one that meets the ceiling.
///
/// Set from the live count rather than from a literal, because the demo estate's shape is not this
/// file's business and a seed that grows by one connection should not silently turn a "refused"
/// test into a "still has room" test that passes for the wrong reason.
fn state_at_its_ceiling(allowance: Allowance) -> AppState {
    let probe = common::seeded();
    let at = probe
        .service
        .allowance_count(allowance)
        .expect("the seeded store counts");
    state_with_limit(allowance, at)
}

fn state_with_limit(allowance: Allowance, limit: u64) -> AppState {
    let mut config = AllowancesConfig::default();
    match allowance {
        Allowance::Agents => config.agents = Some(limit),
        Allowance::Secrets => config.secrets = Some(limit),
        Allowance::Grants => config.grants = Some(limit),
        Allowance::Connections => config.connections = Some(limit),
    }
    common::seeded_with_allowances(Arc::new(
        Allowances::new(config).with_log_interval(std::time::Duration::ZERO),
    ))
}

async fn post(
    state: AppState,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The create request for each allowance, so one table drives all four.
fn create_for(allowance: Allowance) -> (&'static str, serde_json::Value) {
    match allowance {
        Allowance::Agents => (
            "/v1/agents/register",
            serde_json::json!({ "id": "one-too-many", "name": "One Too Many" }),
        ),
        Allowance::Secrets => (
            "/v1/secrets",
            serde_json::json!({ "id": "sec_one_too_many", "value": "s3cret" }),
        ),
        Allowance::Grants => (
            "/v1/grants",
            serde_json::json!({
                "grant_id": "gr_one_too_many",
                "name": "One too many",
                "policy_ids": ["pol_ssh_prod"],
                "agents": ["codex-cli"]
            }),
        ),
        Allowance::Connections => (
            "/v1/connections",
            serde_json::json!({ "id": "one-too-many", "connector": "github", "name": "One too many" }),
        ),
    }
}

// ── Every allowance refuses, through the router ─────────────────────────────────

#[tokio::test]
async fn each_allowance_refuses_a_create_at_its_ceiling() {
    for allowance in Allowance::ALL {
        let state = state_at_its_ceiling(allowance);
        let at = state.service.allowance_count(allowance).unwrap();
        let (uri, body) = create_for(allowance);
        let (status, json) = post(state, uri, body).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{} was not refused: {json}",
            allowance.as_str()
        );
        assert_eq!(json["allowance"], allowance.as_str());
        assert_eq!(json["current"], at);
        assert_eq!(json["limit"], at);
    }
}

#[tokio::test]
async fn each_allowance_admits_a_create_with_one_slot_left() {
    for allowance in Allowance::ALL {
        let probe = common::seeded();
        let at = probe.service.allowance_count(allowance).unwrap();
        let state = state_with_limit(allowance, at + 1);
        let (uri, body) = create_for(allowance);
        let (status, json) = post(state, uri, body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{} was refused with a slot free: {json}",
            allowance.as_str()
        );
    }
}

/// Unset is unlimited, which is the whole of the self-hosted story: a gateway nobody provisioned
/// behaves exactly as it did before this module existed.
#[tokio::test]
async fn an_unconfigured_gateway_is_unlimited() {
    assert!(AllowancesConfig::default().is_unlimited());
    for allowance in Allowance::ALL {
        let (uri, body) = create_for(allowance);
        let (status, json) = post(common::seeded(), uri, body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{} was capped on an unconfigured gateway: {json}",
            allowance.as_str()
        );
    }
}

// ── What a refusal costs ────────────────────────────────────────────────────────

/// A refusal must not create the row it refused. Obvious, and worth an assertion: the check sits in
/// the service layer ahead of the write, and a later refactor that moved it after one would leave
/// every other test in this file passing.
#[tokio::test]
async fn a_refused_create_writes_no_row() {
    for allowance in Allowance::ALL {
        let state = state_at_its_ceiling(allowance);
        let before = state.service.allowance_count(allowance).unwrap();
        let (uri, body) = create_for(allowance);
        let (status, _) = post(state.clone(), uri, body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            state.service.allowance_count(allowance).unwrap(),
            before,
            "{} moved on a refusal",
            allowance.as_str()
        );
    }
}

/// The counting half of the refusal is a read. On a hosted worker every store mutation is a full
/// snapshot upload, so what this asserts is that a refusal costs exactly one append, the audited
/// denial, and not the several a create would have cost.
#[tokio::test]
async fn a_refusal_appends_the_denial_and_nothing_else() {
    let state = state_at_its_ceiling(Allowance::Agents);
    let store = state.service.store();
    let before = store.audit_len().expect("the store counts its chain");
    let (uri, body) = create_for(Allowance::Agents);
    let (status, _) = post(state.clone(), uri, body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        store.audit_len().unwrap(),
        before + 1,
        "a refusal wrote more than its denial"
    );
    let last = store
        .audit_events(None)
        .expect("the chain reads")
        .pop()
        .expect("an event");
    assert_eq!(last.payload.decision, "deny");
    assert_eq!(
        last.payload.action,
        permaura_gateway::allowances::AUDIT_ACTION
    );
    assert_eq!(last.payload.summary["allowance"], "agents");
    assert_eq!(last.payload.summary["limit"], 1);
}

// ── The paths a console cannot see ──────────────────────────────────────────────

/// Agent self-enrolment over MCP. This is the request that arrives at a hosted worker without
/// touching permaura.com, and the reason an allowance enforced only in the console binds nothing.
#[tokio::test]
async fn an_agent_enrolling_over_mcp_meets_the_ceiling() {
    let state = state_at_its_ceiling(Allowance::Agents);
    let code = {
        let (status, json) = post(
            state.clone(),
            "/v1/agents/enroll",
            serde_json::json!({ "label": "a new agent" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        json["code"].as_str().expect("a code").to_string()
    };
    let (status, json) = post(
        state.clone(),
        "/mcp",
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "mcp-newcomer" } }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "MCP answers 200 with an error body");
    let message = json["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("allowance exceeded"),
        "the enrolment was not refused: {json}"
    );
    assert!(
        state
            .service
            .store()
            .get_agent("mcp-newcomer")
            .unwrap()
            .is_none(),
        "the refused agent was created anyway"
    );
}

// ── What the count means ────────────────────────────────────────────────────────

/// Neither the operator identity nor the Default baseline grant is a row the customer created, and
/// neither can be deleted, so charging a plan for them would make a plan of N a plan of N-1.
#[tokio::test]
async fn the_structural_rows_are_not_charged_to_the_plan() {
    let state = common::seeded();
    let store = state.service.store();
    store
        .put_agent(permaura_gateway::store::Agent::approved(
            seed::OPERATOR_AGENT_ID,
            "Operator",
            0,
        ))
        .expect("the operator row is written");
    let agents = store.list_agents().unwrap().len() as u64;
    assert_eq!(
        state.service.allowance_count(Allowance::Agents).unwrap(),
        agents - 1,
        "the operator identity was counted as an agent"
    );

    let grants = store.list_grants().unwrap();
    assert!(
        grants.iter().any(|g| g.is_default),
        "the seed guarantees a Default baseline"
    );
    assert_eq!(
        state.service.allowance_count(Allowance::Grants).unwrap(),
        grants.len() as u64 - 1,
        "the Default baseline was counted as a grant"
    );
}

/// A pending agent occupies a row and is one click from approved, so it counts. An allowance that
/// ignored pending agents could be walked straight past by an enrolment loop.
#[tokio::test]
async fn a_pending_agent_counts_against_the_allowance() {
    let state = common::seeded();
    let before = state.service.allowance_count(Allowance::Agents).unwrap();
    state
        .service
        .store()
        .put_agent(permaura_gateway::store::Agent {
            id: "awaiting-approval".into(),
            name: "Awaiting approval".into(),
            status: permaura_gateway::store::AgentStatus::Pending,
            enrolled_at: 0,
        })
        .expect("the store accepts a pending agent");
    assert_eq!(
        state.service.allowance_count(Allowance::Agents).unwrap(),
        before + 1
    );
}

/// A deleted row frees its slot at once. Every one of the four is hard-deleted rather than
/// tombstoned, so there is no soft-delete state for the count to have to exclude. But the property
/// is what makes the 409's "remove one and resubmit" remedy true, so it is asserted rather than
/// assumed.
#[tokio::test]
async fn deleting_a_row_frees_its_slot() {
    let state = state_at_its_ceiling(Allowance::Secrets);
    let (uri, body) = create_for(Allowance::Secrets);
    let (status, _) = post(state.clone(), uri, body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let existing = state
        .service
        .store()
        .list_secret_ids()
        .unwrap()
        .first()
        .expect("the seed holds secrets")
        .clone();
    assert!(state.service.store().delete_secret(&existing).unwrap());
    let (status, json) = post(state, uri, body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the freed slot was not reusable: {json}"
    );
}

// ── The console's window onto it ────────────────────────────────────────────────

#[tokio::test]
async fn health_reports_every_allowance_with_its_usage_and_cap() {
    let state = state_at_its_ceiling(Allowance::Agents);
    let at = state.service.allowance_count(Allowance::Agents).unwrap();
    let (uri, body) = create_for(Allowance::Agents);
    let (status, _) = post(state.clone(), uri, body).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let allowances = &json["allowances"];
    assert_eq!(allowances["agents"]["current"], at);
    assert_eq!(allowances["agents"]["limit"], at);
    assert_eq!(allowances["agents"]["refused"], 1);
    // Unlimited reads as null, never as zero: a console that rendered "0 of 0" for an unset
    // allowance would show a free-tier ceiling on a gateway that has none.
    for other in ["secrets", "grants", "connections"] {
        assert!(
            allowances[other]["limit"].is_null(),
            "{other} should be unlimited"
        );
        assert!(allowances[other]["current"].is_u64());
    }
}

/// Liveness stays closed to a stranger. The allowance block names how much of a customer's plan is
/// consumed, which is exactly the shape of fact the unauthenticated document exists not to carry.
#[tokio::test]
async fn an_unauthenticated_health_read_carries_no_allowances() {
    let resp = build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["allowances"].is_null());
}
