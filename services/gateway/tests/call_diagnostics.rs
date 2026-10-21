//! What an activity view can say about a call that ran: whether the upstream accepted it, the safe
//! headers it answered with, who released it if it was held, and the error text that is kept beside
//! the signed chain rather than in it.
//!
//! Every credential and transport here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

mod common;

/// The seeded estate, with every upstream call answered by `response` (then the mock's own 200).
fn state_answering(response: HttpResponse) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = Arc::new(MockHttpClient::with_response(response));
    AppState::new(EnforcementService::new(store, http))
}

fn params() -> serde_json::Value {
    serde_json::json!({ "owner": "synthetic", "repo": "synthetic" })
}

async fn call(state: &AppState, method: &str, uri: &str, body: Option<serde_json::Value>) -> (StatusCode, serde_json::Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    let body = match body {
        Some(b) => {
            builder = builder.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

/// The one event with `decision` that is not the gateway's own bookkeeping, and its seq.
fn only(audit: &serde_json::Value, decision: &str) -> (u64, serde_json::Value) {
    let found: Vec<&serde_json::Value> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["payload"]["decision"] == decision)
        .filter(|e| !e["payload"]["action"].as_str().unwrap_or_default().starts_with("permaura."))
        .collect();
    assert_eq!(found.len(), 1, "exactly one {decision} event: {audit}");
    (found[0]["seq"].as_u64().unwrap(), found[0]["payload"]["summary"].clone())
}

async fn invoke(state: &AppState, capability: &str) -> InvokeOutcome {
    let session = state.service.store().get_session("sess_demo").unwrap().expect("the demo session");
    state
        .service
        .invoke(&session, capability, &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("the call is admitted")
}

/// The reported case: the call "ran", and nothing said the upstream had refused it.
#[tokio::test]
async fn a_refused_upstream_is_recorded_as_failed_with_its_headers_and_a_purgeable_message() {
    let state = state_answering(HttpResponse {
        status: 401,
        body: serde_json::json!({ "message": "Bad credentials", "documentation_url": "https://docs.example" }),
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("x-github-request-id".into(), "ABCD:1234".into()),
        ],
        text: None,
        memory: Default::default(),
    });
    invoke(&state, "github.pull_requests.list").await;

    let (status, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    assert_eq!(status, StatusCode::OK);
    let (seq, summary) = only(&audit, "allow");
    assert_eq!(summary["status"], 401);
    assert_eq!(summary["ok"], false, "a 401 is not a success, whatever the decision was");
    assert_eq!(summary["headers"], serde_json::json!({ "content-type": "application/json" }));
    assert_eq!(summary["diagnostic"], true);
    let events = serde_json::to_string(&audit["events"]).unwrap();
    assert!(!events.contains("Bad credentials"), "the upstream's words stay out of the signed chain");
    assert!(!events.contains("ABCD:1234"), "and so does its free-text request id");
    let kept = &audit["diagnostics"][seq.to_string()];
    assert_eq!(kept["message"], "Bad credentials");
    assert_eq!(kept["headers"]["x-github-request-id"], "ABCD:1234");
    assert_eq!(audit["diagnostics_retention_days"], 30);

    let (status, purged) = call(&state, "DELETE", "/v1/audit/diagnostics", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(purged["purged"], 1);

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    assert_eq!(audit["diagnostics"], serde_json::json!({}), "the message is gone");
    let (_seq, summary) = only(&audit, "allow");
    assert_eq!(summary["diagnostic"], true, "and the event still says there was one");
    assert_eq!(audit["chain_intact"], true, "purging never touches the chain");
    let purge = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["payload"]["action"] == "permaura.audit.diagnostics.purge")
        .expect("the purge is itself recorded");
    assert_eq!(purge["payload"]["summary"]["purged"], 1);
}

/// A bare string body is upstream text that redaction never touches. Only its length is signed; the
/// text is the purgeable message.
#[tokio::test]
async fn a_bare_string_error_body_is_kept_out_of_the_chain() {
    let state = state_answering(HttpResponse::json(401, serde_json::json!("Invalid API key sk_live_synthetic")));
    invoke(&state, "github.pull_requests.list").await;

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (seq, summary) = only(&audit, "allow");
    assert_eq!(summary["result_summary"], serde_json::json!({ "chars": 33 }));
    assert!(!serde_json::to_string(&audit["events"]).unwrap().contains("sk_live_synthetic"));
    assert_eq!(audit["diagnostics"][seq.to_string()]["message"], "Invalid API key sk_live_synthetic");
}

/// An HTML error page used to become `null` everywhere. The operator now gets its text; the agent's
/// result is unchanged.
#[tokio::test]
async fn a_non_json_error_page_reaches_the_operator_but_not_the_agent() {
    let state = state_answering(HttpResponse {
        status: 502,
        body: serde_json::Value::Null,
        headers: Vec::new(),
        text: Some("<html><body>502 Bad Gateway</body></html>".into()),
        memory: Default::default(),
    });
    match invoke(&state, "github.pull_requests.list").await {
        InvokeOutcome::Allowed { result, status, .. } => {
            assert_eq!(status, 502);
            assert!(result.is_null(), "the agent's answer did not change");
        }
        _ => panic!("a low-risk call runs"),
    }

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (seq, summary) = only(&audit, "allow");
    assert_eq!(summary["ok"], false);
    let message = audit["diagnostics"][seq.to_string()]["message"].as_str().unwrap();
    assert!(message.contains("502 Bad Gateway"), "{message}");
}

/// A JSON error body with none of the conventional message fields leaves no message, and never its raw text, which still holds every member redaction took out of the agent's view.
#[tokio::test]
async fn a_json_error_body_without_a_message_never_reaches_the_diagnostics_raw() {
    let state = state_answering(HttpResponse::json(
        409,
        serde_json::json!({ "code": "conflict", "existing": { "password": "hunter2-SYNTHETIC", "api_key": "ak-SYNTHETIC-123" } }),
    ));
    match invoke(&state, "github.pull_requests.list").await {
        InvokeOutcome::Allowed { result, status, .. } => {
            assert_eq!(status, 409);
            let result: serde_json::Value = serde_json::from_str(result.get()).unwrap();
            assert_eq!(result["existing"]["password"], "[redacted]", "{result}");
            assert_eq!(result["existing"]["api_key"], "[redacted]", "{result}");
        }
        _ => panic!("a low-risk call runs"),
    }

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (seq, summary) = only(&audit, "allow");
    assert_eq!(summary["ok"], false);
    let kept = serde_json::to_string(&audit["diagnostics"]).unwrap();
    assert!(!kept.contains("hunter2-SYNTHETIC") && !kept.contains("ak-SYNTHETIC-123"), "a redacted value reached the diagnostics: {kept}");
    assert!(audit["diagnostics"][seq.to_string()]["message"].is_null(), "no message field, so no message: {kept}");
}

#[tokio::test]
async fn a_successful_call_is_ok_and_leaves_no_diagnostic() {
    let state = state_answering(HttpResponse::json(200, serde_json::json!({ "pulls": [] })));
    invoke(&state, "github.pull_requests.list").await;

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (_seq, summary) = only(&audit, "allow");
    assert_eq!(summary["ok"], true);
    assert!(summary.get("diagnostic").is_none());
    assert!(summary.get("headers").is_none(), "no headers were sent, so none are claimed");
    assert_eq!(audit["diagnostics"], serde_json::json!({}));
}

async fn held(state: &AppState) -> String {
    match invoke(state, "github.pull_requests.create").await {
        InvokeOutcome::RequiresApproval { approval, .. } => approval.id,
        _ => panic!("a High-risk capability must be escalated to a human"),
    }
}

/// Who approved, by the name the owner knows the device by, frozen at the moment of approval.
#[tokio::test]
async fn a_signed_approval_records_the_approving_device_by_name() {
    let state = state_answering(HttpResponse::json(201, serde_json::json!({ "number": 7 })));
    let (status, _) = call(
        &state,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({ "name": "Synthetic iPhone", "platform": "ios", "approver_id": "device:synthetic" })),
    )
    .await;
    assert!(status.is_success(), "{status}");
    let approval_id = held(&state).await;

    state
        .service
        .resolve_approval(&approval_id, true, "device_signed", Some("device:synthetic"))
        .await
        .expect("the upstream answers");

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (_seq, summary) = only(&audit, "approved");
    assert_eq!(summary["approver"], "device:synthetic");
    assert_eq!(summary["approver_name"], "Synthetic iPhone");
    assert_eq!(summary["method"], "device_signed");
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["status"], 201);
}

/// A bearer approval used to record `approver: null`. It now names the operator session it came
/// through, and claims no device name, because no device was involved.
#[tokio::test]
async fn a_bearer_approval_names_the_operator_session() {
    let state = state_answering(HttpResponse::json(201, serde_json::json!({ "number": 7 })));
    let approval_id = held(&state).await;

    let (status, resp) =
        call(&state, "POST", "/v1/approvals", Some(serde_json::json!({ "approval_id": approval_id, "approve": true }))).await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    let operator = state.service.store().session_by_token(seed::DEMO_TOKEN).unwrap().expect("the demo operator");
    assert_eq!(operator.agent_id, "codex-cli", "the demo operator session is minted under an agent's id");
    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (_seq, summary) = only(&audit, "approved");
    assert_eq!(summary["method"], "bearer");
    assert_eq!(summary["approver"], "operator", "an agent is never named as the human who approved");
    assert!(summary.get("approver_name").is_none(), "{summary}");
}

/// A signed approver with no device row (a Watch, a simulator) is named by id only, and a failed
/// execution still names who released it.
#[tokio::test]
async fn an_approver_with_no_device_row_has_no_name_and_a_failed_release_still_names_its_device() {
    let state = state_answering(HttpResponse::json(201, serde_json::json!({})));
    let approval_id = held(&state).await;
    state.service.resolve_approval(&approval_id, true, "device_signed", Some("device:watch")).await.unwrap();
    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (_seq, summary) = only(&audit, "approved");
    assert_eq!(summary["approver"], "device:watch");
    assert!(summary.get("approver_name").is_none(), "{summary}");

    let state = state_answering(HttpResponse::json(201, serde_json::json!({})));
    call(
        &state,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({ "name": "Synthetic iPhone", "approver_id": "device:synthetic" })),
    )
    .await;
    let approval_id = held(&state).await;
    let secret = state.service.store().get_capability("github.pull_requests.create").unwrap().unwrap().secret_id;
    assert!(state.service.store().delete_secret(&secret).unwrap(), "the credential existed");
    state
        .service
        .resolve_approval(&approval_id, true, "device_signed", Some("device:synthetic"))
        .await
        .expect_err("the credential is gone");
    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (_seq, summary) = only(&audit, "error");
    assert_eq!(summary["approver_name"], "Synthetic iPhone");
    assert_eq!(summary["ok"], false);
}

/// A denial says who said no, the same way an approval says who said yes.
#[tokio::test]
async fn a_signed_denial_records_the_device_by_name() {
    let state = state_answering(HttpResponse::json(201, serde_json::json!({})));
    call(
        &state,
        "POST",
        "/v1/devices/enroll",
        Some(serde_json::json!({ "name": "Synthetic Watch", "approver_id": "device:watch" })),
    )
    .await;
    let approval_id = held(&state).await;
    state.service.resolve_approval(&approval_id, false, "device_signed", Some("device:watch")).await.unwrap();

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (_seq, summary) = only(&audit, "denied");
    assert_eq!(summary["approver_name"], "Synthetic Watch");
}

/// When a human approves and the re-check refuses, the event is a `denied` naming someone who said
/// yes. `human_decision` is what lets a reader say "approved, then refused by the gateway".
#[tokio::test]
async fn an_approval_the_recheck_refuses_says_the_human_approved() {
    let state = state_answering(HttpResponse::json(201, serde_json::json!({})));
    let approval_id = held(&state).await;
    let connection = state.service.store().get_connection("github_acme").unwrap().expect("the seeded connection");
    let mut disabled = connection.clone();
    disabled.disabled = true;
    state.service.store().put_connection(disabled).unwrap();

    let resolved = state.service.resolve_approval(&approval_id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(resolved.status, "denied");

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let (_seq, summary) = only(&audit, "denied");
    assert_eq!(summary["human_decision"], "approved");
    assert_eq!(summary["approver"], "operator");
    assert!(summary["reason"].as_str().unwrap().starts_with("re-validation failed"));
}

/// An approved held call was sent upstream with nothing in the chain between the hold and the
/// terminal event, so a worker killed mid-flight left no record that a human had released it. It now
/// gets the same durable `attempt` fence `invoke` has, naming the approval, before the credential is used.
#[tokio::test]
async fn an_approved_held_call_is_fenced_by_an_attempt_record() {
    let state = state_answering(HttpResponse::json(201, serde_json::json!({ "number": 7 })));
    let approval_id = held(&state).await;
    let (status, resp) =
        call(&state, "POST", "/v1/approvals", Some(serde_json::json!({ "approval_id": approval_id, "approve": true }))).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let attempts: Vec<&serde_json::Value> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["payload"]["decision"] == "attempt" && e["payload"]["summary"]["approval_id"] == approval_id.as_str())
        .collect();
    assert_eq!(attempts.len(), 1, "one attempt names the approval: {audit}");
    let (approved_seq, _) = only(&audit, "approved");
    assert!(attempts[0]["seq"].as_u64().unwrap() < approved_seq, "the attempt precedes the execution's terminal event");
}

/// A Vercel answer the projection cannot read reaches the agent as nothing. Here a member that redaction removes nests past serde_json's 128 levels: the projection's tree refuses the body, and the streaming view, which skips that member unread, would have handed the agent the rest of it without the projection ever stripping it.
#[tokio::test]
async fn a_vercel_answer_the_projection_cannot_read_reaches_the_agent_as_nothing() {
    let deep = (0..1_000).fold(serde_json::json!("leaf"), |inner, _| serde_json::json!([inner]));
    let state = state_answering(HttpResponse::json(
        200,
        serde_json::json!({
            "projects": [{ "id": "prj_synthetic", "name": "acme-web" }],
            "deployHooks": [{ "url": "https://api.vercel.com/v1/integrations/deploy/SYNTHETIC-hook" }],
            "password": deep,
        }),
    ));
    match invoke(&state, "vercel.projects.list").await {
        InvokeOutcome::Allowed { result, status, .. } => {
            assert_eq!(status, 200);
            assert_eq!(result.get(), "null", "the agent got an answer the projection never ran on: {}", &result.get()[..result.get().len().min(300)]);
        }
        _ => panic!("a low-risk call runs"),
    }
}
