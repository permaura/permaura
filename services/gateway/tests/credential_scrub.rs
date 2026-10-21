//! An upstream that hands the injected credential back, under a field name the redaction list does
//! not carry, inside an error sentence, in a header, or encoded, does not hand it to the agent: every
//! occurrence reaches the agent, the approval row, the signed chain and the diagnostics table as
//! [`SCRUBBED`], whichever connector family ran the call.
//!
//! Every credential and upstream here is synthetic; the GitHub value is the demo estate's own.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{
    CommandOutput, HttpClient, HttpRequest, HttpResponse, MockHttpClient, MockSshRunner, SshOutcome,
};
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

mod common;

/// What an occurrence of the credential becomes (`permaura_core::SCRUBBED`), spelled out so this file
/// also builds against a gateway that predates it.
const SCRUBBED: &str = "[redacted-credential]";

/// The seeded GitHub connection's credential, injected as `Authorization: Bearer <this>`.
const GITHUB: &str = "ghp_demo_github_token_value";
/// The seeded SSH connection's private key.
const SSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\ndemo-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n";

fn state_with(http: Arc<dyn HttpClient>, ssh: MockSshRunner) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    AppState::new(EnforcementService::new(store, http).with_ssh_runner(Arc::new(ssh)))
}

fn state_answering(response: HttpResponse) -> AppState {
    state_with(Arc::new(MockHttpClient::with_response(response)), MockSshRunner::new())
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

async fn invoke(state: &AppState, capability: &str, params: serde_json::Value) -> Result<InvokeOutcome, String> {
    let session = state.service.store().get_session("sess_demo").unwrap().expect("the demo session");
    state
        .service
        .invoke(&session, capability, &params, Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .map_err(|e| e.to_string())
}

async fn allowed(state: &AppState, capability: &str, params: serde_json::Value) -> serde_json::Value {
    match invoke(state, capability, params).await.expect("the call is admitted") {
        InvokeOutcome::Allowed { result, .. } => result.to_value_unbounded(),
        _ => panic!("expected an allowed call"),
    }
}

async fn list_prs(state: &AppState) -> serde_json::Value {
    allowed(state, "github.pull_requests.list", serde_json::json!({ "owner": "synthetic", "repo": "synthetic" })).await
}

/// Everything the operator's record holds: the signed events and the purgeable diagnostics beside them.
async fn record(state: &AppState) -> String {
    let (status, audit) = call(state, "GET", "/v1/audit-events", None).await;
    assert_eq!(status, StatusCode::OK);
    audit.to_string()
}

/// The base64 characters that spell `secret` and nothing else, at each of the three byte alignments
/// it can have inside a longer encoded blob.
fn base64_spellings(secret: &str) -> Vec<String> {
    (0..3)
        .map(|offset| {
            let mut shifted = vec![0u8; offset];
            shifted.extend_from_slice(secret.as_bytes());
            let encoded = STANDARD_NO_PAD.encode(&shifted);
            encoded[[0, 2, 3][offset]..shifted.len() * 8 / 6].to_string()
        })
        .collect()
}

/// No spelling of `secret` the scrub covers survives in `text`.
fn assert_clean(text: &str, secret: &str, what: &str) {
    assert!(!text.contains(secret), "{what} carries the credential: {text}");
    for spelling in base64_spellings(secret) {
        assert!(!text.contains(&spelling), "{what} carries its base64: {text}");
    }
}

#[tokio::test]
async fn an_error_string_quoting_the_bearer_reaches_the_agent_as_the_marker() {
    let state = state_answering(HttpResponse::json(
        401,
        serde_json::json!({ "message": format!("Bad credentials: Bearer {GITHUB} was rejected") }),
    ));
    let result = list_prs(&state).await;
    assert_eq!(result["message"], format!("Bad credentials: Bearer {SCRUBBED} was rejected"));

    let record = record(&state).await;
    assert_clean(&record, GITHUB, "the audit record");
    assert!(record.contains(&format!("Bearer {SCRUBBED} was rejected")), "the diagnostic keeps the scrubbed message: {record}");
}

#[tokio::test]
async fn a_nested_value_under_an_unrelated_key_is_scrubbed() {
    let state = state_answering(HttpResponse::json(
        200,
        serde_json::json!({
            "data": { "request": { "echo": { "received_with": GITHUB } } },
            "items": [ { "note": format!("key={GITHUB};") }, 7 ],
            GITHUB: "a key named after the credential",
            "title": "keep me",
        }),
    ));
    let result = list_prs(&state).await;
    assert_eq!(result["data"]["request"]["echo"]["received_with"], SCRUBBED);
    assert_eq!(result["items"][0]["note"], format!("key={SCRUBBED};"));
    assert_eq!(result["items"][1], 7);
    assert_eq!(result[SCRUBBED], "a key named after the credential");
    assert_eq!(result["title"], "keep me");
    assert_clean(&result.to_string(), GITHUB, "the agent's result");
    assert_clean(&record(&state).await, GITHUB, "the audit record");
}

#[tokio::test]
async fn a_response_header_echoing_the_bearer_is_scrubbed_from_the_diagnostics() {
    let state = state_answering(HttpResponse {
        status: 401,
        body: serde_json::json!({ "message": "Bad credentials" }),
        headers: vec![
            ("www-authenticate".into(), format!("Bearer error=\"invalid_token\", token=\"{GITHUB}\"")),
            ("x-request-id".into(), format!("req-{GITHUB}")),
            // The client caps a header value, so the cut can land inside the credential.
            ("link".into(), format!("<https://api.example.test/next?t={}", &GITHUB[..15])),
        ],
        text: None,
        memory: Default::default(),
    });
    list_prs(&state).await;

    let (_s, audit) = call(&state, "GET", "/v1/audit-events", None).await;
    let headers = audit["diagnostics"]
        .as_object()
        .and_then(|d| d.values().next())
        .map(|d| d["headers"].clone())
        .expect("the failed call keeps its diagnostic headers");
    assert_eq!(headers["www-authenticate"], format!("Bearer error=\"invalid_token\", token=\"{SCRUBBED}\""));
    assert_eq!(headers["x-request-id"], format!("req-{SCRUBBED}"));
    assert_eq!(headers["link"], format!("<https://api.example.test/next?t={SCRUBBED}"));
    assert_clean(&audit.to_string(), GITHUB, "the audit record");
    assert!(!audit.to_string().contains(&GITHUB[..15]), "nor the start of it");
}

#[tokio::test]
async fn a_base64_encoded_bearer_is_scrubbed() {
    let state = state_answering(HttpResponse::json(
        200,
        serde_json::json!({
            "raw_b64": STANDARD.encode(GITHUB),
            "debug": { "authorization_b64": STANDARD.encode(format!("Bearer {GITHUB}")) },
            "request_dump": STANDARD.encode(format!("GET /pulls HTTP/1.1\r\nAuthorization: Bearer {GITHUB}\r\nAccept: */*\r\n")),
        }),
    ));
    let result = list_prs(&state).await;
    for pointer in ["/raw_b64", "/debug/authorization_b64", "/request_dump"] {
        let value = result.pointer(pointer).and_then(|v| v.as_str()).unwrap();
        assert!(value.contains(SCRUBBED), "{pointer}: {value}");
    }
    assert_clean(&result.to_string(), GITHUB, "the agent's result");
    assert_clean(&record(&state).await, GITHUB, "the audit record");
}

#[tokio::test]
async fn a_percent_encoded_bearer_is_scrubbed() {
    let every: String = GITHUB.bytes().map(|b| format!("%{b:02X}")).collect();
    let state = state_answering(HttpResponse::json(
        200,
        serde_json::json!({
            "links": {
                "next": format!("https://api.example.test/v1/pulls?page=2&access={every}&per=10"),
                "self": format!("https://api.example.test/v1/pulls?access={}", GITHUB.replace('_', "%5f")),
            }
        }),
    ));
    let result = list_prs(&state).await;
    assert_eq!(result["links"]["next"], format!("https://api.example.test/v1/pulls?page=2&access={SCRUBBED}&per=10"));
    assert_eq!(result["links"]["self"], format!("https://api.example.test/v1/pulls?access={SCRUBBED}"));
    assert!(!result.to_string().contains(&every[..24]));
    assert_clean(&record(&state).await, GITHUB, "the audit record");
}

#[tokio::test]
async fn an_ordinary_response_is_returned_unchanged() {
    let body = serde_json::json!({
        "total_count": 2,
        "items": [
            { "number": 41, "title": "Fix the %20 handling in ghp_ links", "head": { "sha": "9f2c1e0" },
              "url": "https://api.example.test/repos/synthetic/synthetic/pulls/41?page=2&q=a%2Bb+c",
              "body_b64": STANDARD.encode("a perfectly ordinary pull request body"),
              "labels": [ "demo", "github" ], "draft": false, "merged_at": null },
            { "number": 42, "title": "Second", "score": 1.5 }
        ]
    });
    let state = state_answering(HttpResponse::json(200, body.clone()));
    assert_eq!(list_prs(&state).await, body);
}

#[tokio::test]
async fn a_short_common_substring_of_the_secret_is_not_mangled() {
    // `ghp_demo` is the credential's first eight bytes and `token_value` its last eleven; neither is
    // the credential, so neither is touched.
    let body = serde_json::json!({
        "hint": "personal tokens start with ghp_demo",
        "field": "token_value",
        "names": [ "ghp_", "demo_github", "github_token" ],
        "note": format!("almost {}", &GITHUB[..GITHUB.len() - 1]),
    });
    let state = state_answering(HttpResponse::json(200, body.clone()));
    assert_eq!(list_prs(&state).await, body);
}

#[tokio::test]
async fn the_key_name_redaction_still_applies_after_the_scrub() {
    let state = state_answering(HttpResponse::json(
        200,
        serde_json::json!({ "authorization": format!("Bearer {GITHUB}"), "token": "unrelated", "seen": GITHUB }),
    ));
    let result = list_prs(&state).await;
    assert_eq!(result["authorization"], permaura_core::REDACTED);
    assert_eq!(result["token"], permaura_core::REDACTED);
    assert_eq!(result["seen"], SCRUBBED);
}

/// A held call is executed later, and its result is stored on the approval row the console and the
/// agent's later poll both read.
#[tokio::test]
async fn a_held_call_approved_later_stores_and_returns_the_scrubbed_result() {
    let state = state_answering(HttpResponse::json(
        422,
        serde_json::json!({ "errors": [ { "message": format!("token {GITHUB} cannot push to synthetic") } ] }),
    ));
    let params = serde_json::json!({ "owner": "synthetic", "repo": "synthetic", "title": "t", "head": "h", "base": "b" });
    let InvokeOutcome::RequiresApproval { approval, .. } =
        invoke(&state, "github.pull_requests.create", params).await.unwrap()
    else {
        panic!("a high-risk create is held")
    };
    let resolved = state.service.resolve_approval(&approval.id, true, "bearer", Some("operator")).await.unwrap();
    let expected = format!("token {SCRUBBED} cannot push to synthetic");
    assert_eq!(resolved.result.as_ref().unwrap().to_value_unbounded()["errors"][0]["message"], expected);

    let row = state.service.store().get_approval(&approval.id).unwrap().unwrap();
    assert_eq!(row.result.unwrap().to_value_unbounded()["errors"][0]["message"], expected);
    let (status, served) = call(&state, "GET", &format!("/v1/approvals/{}", approval.id), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_clean(&served.to_string(), GITHUB, "the served approval");
    assert_clean(&record(&state).await, GITHUB, "the audit record");
}

#[tokio::test]
async fn an_mcp_tool_call_returns_the_scrubbed_result() {
    let state = state_answering(HttpResponse::json(
        401,
        serde_json::json!({ "error": { "detail": format!("invalid credential {GITHUB}") } }),
    ));
    let (status, body) = call(
        &state,
        "POST",
        "/mcp",
        Some(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "github.pull_requests.list", "arguments": { "owner": "synthetic", "repo": "synthetic" } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = body.to_string();
    assert!(text.contains(&format!("invalid credential {SCRUBBED}")), "{text}");
    assert_clean(&text, GITHUB, "the MCP response");
}

/// An upstream whose transport failure text quotes the credential.
struct FailsQuoting;

#[async_trait]
impl HttpClient for FailsQuoting {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        anyhow::bail!("upstream reset the stream after Authorization: Bearer {GITHUB}")
    }
}

#[tokio::test]
async fn an_execution_error_quoting_the_credential_is_scrubbed() {
    let state = state_with(Arc::new(FailsQuoting), MockSshRunner::new());
    let Err(error) = invoke(&state, "github.pull_requests.list", serde_json::json!({ "owner": "s", "repo": "s" })).await
    else {
        panic!("the upstream failed")
    };
    assert!(error.contains(&format!("Bearer {SCRUBBED}")), "{error}");
    assert_clean(&error, GITHUB, "the agent's error");
    assert_clean(&record(&state).await, GITHUB, "the audit record");
}

#[tokio::test]
async fn an_ssh_exec_printing_the_key_returns_the_marker() {
    let ssh = MockSshRunner::with_outcome(SshOutcome::Exec(CommandOutput {
        code: 1,
        stdout: format!("load average 0.1\n{SSH_KEY}"),
        stderr: String::new(),
    }));
    let state = state_with(Arc::new(MockHttpClient::new()), ssh);
    let result = allowed(&state, "ssh.uptime", serde_json::json!({})).await;
    let output = result["output"].as_str().unwrap();
    assert!(output.starts_with("load average 0.1\n"), "{output}");
    assert!(output.contains(SCRUBBED), "{output}");
    assert!(!output.contains("demo-not-a-real-key"), "{output}");
    assert!(!record(&state).await.contains("demo-not-a-real-key"));
}

#[tokio::test]
async fn an_sftp_read_of_the_key_file_returns_no_encoding_of_it() {
    let content = format!("# keys\n{SSH_KEY}");
    let ssh = MockSshRunner::with_outcome(SshOutcome::Get {
        bytes: content.len() as u64,
        content_base64: STANDARD.encode(&content),
    });
    let state = state_with(Arc::new(MockHttpClient::new()), ssh);
    let result = allowed(&state, "ssh.sftp.get", serde_json::json!({ "path": "keys.txt" })).await;
    let served = result["content_base64"].as_str().unwrap();
    assert!(served.contains(SCRUBBED), "{served}");
    assert_clean(served, SSH_KEY, "the transferred file");
    assert!(served.starts_with(&STANDARD.encode("# keys\n")[..8]), "the bytes before the key are kept: {served}");
}
