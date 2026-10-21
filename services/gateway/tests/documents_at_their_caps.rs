//! No realistic document that fits its byte cap is refused for its shape on a hosted worker's memory budget.
//! Upstream lists of two-field and five-field rows and GitHub-style objects up to the 5 MiB response cap, over REST and MCP, through the real HTTP client against a loopback upstream; SSH exec stdout at a configured cap; and 2 MiB of params made of rows.
//!
//! Every credential and upstream here is synthetic.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{
    AuthScheme, BodyStyle, CommandOutput, HttpMethod, HttpSpec, MockHttpClient, MockSshRunner, ReqwestClient, SshOutcome,
    DEFAULT_HTTP_MAX_RESPONSE_BYTES,
};
use permaura_gateway::limits::LimitsConfig;
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

mod common;

const CAPABILITY: &str = "github.pull_requests.list";

/// Serves `body` as JSON to every connection.
async fn upstream(body: Arc<Vec<u8>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && head.len() < 16384 {
                    match sock.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                let status = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(status.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

/// Reads each request's body whole and answers `{"ok":true}`, keeping the last body it read.
async fn upstream_reading(last: Arc<std::sync::Mutex<Vec<u8>>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let last = last.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && head.len() < 16384 {
                    match sock.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                if sock.read_exact(&mut body).await.is_err() {
                    return;
                }
                *last.lock().unwrap() = body;
                let answer = b"{\"ok\":true}";
                let status = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    answer.len()
                );
                let _ = sock.write_all(status.as_bytes()).await;
                let _ = sock.write_all(answer).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

/// The hosted worker's memory budget, on a gateway whose transports this test chooses.
fn hosted_budget() -> MemoryBudget {
    MemoryBudget::from_config(&LimitsConfig::defaults_for(true))
}

/// The seeded estate with the GitHub list capability re-pointed at `base_url`, through the real client at the shipped 5 MiB response cap, on the hosted memory budget.
fn state_pointing_at(base_url: &str) -> AppState {
    state_with(HttpSpec {
        method: HttpMethod::Get,
        base_url: base_url.to_string(),
        path: "/v1/items".to_string(),
        auth: AuthScheme::Bearer,
        ..HttpSpec::default()
    })
}

/// [`state_pointing_at`], with the capability posting its `rows` param to `base_url` as a JSON body.
fn state_posting_rows_to(base_url: &str) -> AppState {
    state_with(HttpSpec {
        method: HttpMethod::Post,
        base_url: base_url.to_string(),
        path: "/v1/items".to_string(),
        body_params: vec!["rows".to_string()],
        auth: AuthScheme::Bearer,
        ..HttpSpec::default()
    })
}

fn state_with(spec: HttpSpec) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let mut cap = store.get_capability(CAPABILITY).unwrap().expect("the seeded capability");
    cap.http = Some(spec);
    store.put_capability(cap).unwrap();
    common::file_as_imported(store.as_ref(), CAPABILITY);
    let http = Arc::new(ReqwestClient::loopback_for_tests(Duration::from_secs(20)).with_response_cap(DEFAULT_HTTP_MAX_RESPONSE_BYTES));
    AppState::new(EnforcementService::new(store, http).with_memory_budget(hosted_budget()))
}

async fn post(state: &AppState, uri: &str, body: Value) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let declared = resp.headers().get("content-length").map(|v| v.to_str().unwrap().parse::<usize>().unwrap());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(declared, Some(bytes.len()), "the declared length is the body's");
    (status, serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())))
}

/// An array of `row(i)` as large as fits under `cap` bytes.
fn rows_up_to(cap: usize, row: impl Fn(usize) -> Value) -> (Vec<u8>, usize) {
    let mut out = b"[".to_vec();
    let mut count = 0;
    loop {
        let next = serde_json::to_vec(&row(count)).unwrap();
        if out.len() + next.len() + 2 > cap {
            break;
        }
        if count > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&next);
        count += 1;
    }
    out.push(b']');
    (out, count)
}

fn two_field(i: usize) -> Value {
    json!({ "id": i, "ok": i.is_multiple_of(2) })
}

fn five_field(i: usize) -> Value {
    json!({ "id": i, "name": format!("item-{i}"), "status": "active", "created_at": "2026-10-16T01:02:03Z", "token": format!("tok_{i:08}") })
}

/// A GitHub issue as the list endpoint returns one, trimmed to its common fields.
fn github_issue(i: usize) -> Value {
    json!({
        "url": format!("https://api.github.com/repos/acme/widgets/issues/{i}"),
        "html_url": format!("https://github.com/acme/widgets/issues/{i}"),
        "id": 1_000_000 + i, "node_id": format!("I_kwDOAbc{i:06}"), "number": i,
        "title": format!("Widget {i} renders off by one pixel in dark mode"),
        "user": { "login": "octocat", "id": 583231, "node_id": "MDQ6VXNlcjU4MzIzMQ==", "type": "User", "site_admin": false,
                  "avatar_url": "https://avatars.githubusercontent.com/u/583231?v=4", "html_url": "https://github.com/octocat" },
        "labels": [{ "id": 208045946, "name": "bug", "color": "d73a4a", "default": true }, { "id": 208045947, "name": "ui", "color": "a2eeef", "default": false }],
        "state": "open", "locked": false, "assignee": null, "assignees": [], "milestone": null, "comments": i % 7,
        "created_at": "2026-10-01T10:00:00Z", "updated_at": "2026-10-15T10:00:00Z", "closed_at": null,
        "author_association": "MEMBER", "body": "Steps to reproduce: open the widget in dark mode and look closely at the left edge.",
        "reactions": { "total_count": 0, "+1": 0, "-1": 0, "laugh": 0, "hooray": 0, "confused": 0, "heart": 0, "rocket": 0, "eyes": 0 }
    })
}

#[tokio::test]
async fn upstream_lists_at_the_response_cap_reach_the_agent_whole_over_rest_and_mcp() {
    let cap = DEFAULT_HTTP_MAX_RESPONSE_BYTES as usize;
    for (shape, row) in [("two-field rows", two_field as fn(usize) -> Value), ("five-field rows", five_field), ("GitHub issues", github_issue)] {
        let (body, count) = rows_up_to(cap, row);
        assert!(body.len() > cap - 1024 && body.len() <= cap, "{shape}: {} bytes", body.len());
        let state = state_pointing_at(&upstream(Arc::new(body)).await);
        let params = json!({});

        let (status, rest) = post(&state, "/v1/invoke", json!({ "capability": CAPABILITY, "params": params })).await;
        assert_eq!(status, StatusCode::OK, "{shape} over REST: {}", rest.to_string().chars().take(300).collect::<String>());
        let items = rest["result"].as_array().unwrap_or_else(|| panic!("{shape}: an array result"));
        assert_eq!(items.len(), count, "{shape}: every row reaches the agent");
        if shape == "five-field rows" {
            assert_eq!(items[count - 1]["token"], "[redacted]", "the default redaction applied at scale");
            assert_eq!(items[count - 1]["name"], format!("item-{}", count - 1));
        }

        let rpc = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": { "name": CAPABILITY, "arguments": params } });
        let (status, mcp) = post(&state, "/mcp", rpc).await;
        assert_eq!(status, StatusCode::OK);
        assert!(mcp.get("error").is_none(), "{shape} over MCP: {}", mcp.to_string().chars().take(300).collect::<String>());
        let structured = &mcp["result"]["structuredContent"];
        assert_eq!(structured["result"], rest["result"], "{shape}: MCP carries the same result");
        let text: Value = serde_json::from_str(mcp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(&text, structured, "{shape}: the text block is the same document");
    }
}

#[tokio::test]
async fn ssh_stdout_at_a_configured_cap_reaches_the_agent_whole() {
    common::isolate_from_the_real_install();
    let cap = 8 * 1024 * 1024;
    let (stdout, count) = rows_up_to(cap, five_field);
    let ssh = MockSshRunner::with_outcome(SshOutcome::Exec(CommandOutput {
        code: 0,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::new(),
    }));
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let state = AppState::new(
        EnforcementService::new(store, Arc::new(MockHttpClient::new())).with_ssh_runner(Arc::new(ssh)).with_memory_budget(hosted_budget()),
    );
    let (status, rest) = post(&state, "/v1/invoke", json!({ "capability": "ssh.uptime", "params": {} })).await;
    assert_eq!(status, StatusCode::OK, "{}", rest.to_string().chars().take(300).collect::<String>());
    let rows = rest["result"]["output"].as_array().expect("JSON stdout is returned as JSON");
    assert_eq!(rows.len(), count);
    assert_eq!(rows[0]["token"], "[redacted]");
}

#[tokio::test]
async fn two_mib_of_params_made_of_rows_is_admitted_on_the_hosted_budget() {
    // Posted on as the request's JSON body: a capability refuses a parameter it does not send. The upstream reads the whole body before it answers, because one that answers and closes with 2 MiB unread resets the connection under the gateway's write.
    let state = state_posting_rows_to(&upstream_reading(Arc::new(std::sync::Mutex::new(Vec::new()))).await);
    // The densest realistic body under the 2 MiB execution limit: a batch of two-field rows.
    let (rows, count) = rows_up_to(2 * 1024 * 1024 - 256, two_field);
    let rows: Value = serde_json::from_slice(&rows).unwrap();
    let body = json!({ "capability": CAPABILITY, "params": { "rows": rows } });
    assert!(body.to_string().len() < 2 * 1024 * 1024);
    let (status, rest) = post(&state, "/v1/invoke", body).await;
    assert_eq!(status, StatusCode::OK, "{rest}");
    assert_eq!(rest["result"], json!({ "ok": true }));
    assert!(count > 80_000, "{count} rows");

    // The same holds across the family of realistic rows and pairs, sent on as the request's JSON body, written from the tree the call holds. A 136 MiB pool answered the first four 413, and reserving the tree twice answered the last four 413 from a rows cap of 1688 KiB for `{id}`, 1800 for `{x, y}`, 2008 for `{k, v}` and 2024 for chart points (8 KiB steps).
    let last = Arc::new(std::sync::Mutex::new(Vec::new()));
    let state = state_posting_rows_to(&upstream_reading(last.clone()).await);
    type Shape = (&'static str, fn(usize) -> Value);
    let family: [Shape; 8] = [
        ("{id, ok: 1}", |i| json!({ "id": i, "ok": 1 })),
        ("{id, v: \"a\"}", |i| json!({ "id": i, "v": "a" })),
        ("Airtable {fields: {Name, Count}}", |i| json!({ "fields": { "Name": format!("n{i}"), "Count": i % 1000 } })),
        ("pairs of digits [d, d]", |i| json!([i % 10, i / 10 % 10])),
        ("{x: d, y: d}", |i| json!({ "x": i % 10, "y": i / 10 % 10 })),
        ("chart points {x: 0-99, y: 0-99}", |i| json!({ "x": i % 100, "y": i / 100 % 100 })),
        ("{k: \"a\", v: d}", |i| json!({ "k": "a", "v": i % 10 })),
        ("one key {id}", |i| json!({ "id": i })),
    ];
    for (shape, row) in family {
        let (rows, _) = rows_up_to(2047 * 1024 - 128, row);
        let sent: Value = serde_json::from_slice(&rows).unwrap();
        let body = json!({ "capability": CAPABILITY, "params": { "rows": sent } });
        assert!(body.to_string().len() < 2 * 1024 * 1024);
        let (status, rest) = post(&state, "/v1/invoke", body).await;
        assert_eq!(status, StatusCode::OK, "2 MiB of {shape}: {rest}");
        let received: Value = serde_json::from_slice(&last.lock().unwrap()).unwrap();
        assert_eq!(received["rows"], serde_json::from_slice::<Value>(&rows).unwrap(), "2 MiB of {shape} reached the upstream whole");
    }
}

/// The RFC 3986 encoding a form body writes a value in: every byte but the unreserved ones as `%XX`.
fn form_encoded(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Ordinary text as a form field is sent whole up to the 2 MiB body, through /v1/invoke and the real client to a loopback upstream that reads it. Its encoding is up to three times its length, which the params' room for the body written from them holds; counted against the 2 MiB bound on what params write outside a JSON body, this test's HTML was refused from 1,283,704 bytes and its CJK text from 699,048 bytes (exact).
#[tokio::test]
async fn long_text_in_a_form_field_reaches_the_upstream_whole() {
    let last = Arc::new(std::sync::Mutex::new(Vec::new()));
    let state = state_with(HttpSpec {
        method: HttpMethod::Post,
        base_url: upstream_reading(last.clone()).await,
        path: "/v1/notes".to_string(),
        body_params: vec!["content".to_string()],
        body_style: BodyStyle::Form,
        auth: AuthScheme::Bearer,
        ..HttpSpec::default()
    });
    const MIB: usize = 1024 * 1024;
    let line = "<li class=\"item\"><a href=\"/items/42?ref=list&amp;page=2\">Widget 42</a> renders off by one pixel</li>\n";
    let html = line.repeat((18 * MIB / 10).div_ceil(line.len()));
    let sentence = "日本語のテキストを送信します。";
    let cjk = sentence.repeat((19 * MIB / 10).div_ceil(sentence.len()));
    for (shape, text) in [("1.8 MiB of HTML", html), ("1.9 MiB of CJK text", cjk)] {
        let body = json!({ "capability": CAPABILITY, "params": { "content": text } });
        assert!(body.to_string().len() < 2 * 1024 * 1024, "{shape} fits the body limit");
        let (status, rest) = post(&state, "/v1/invoke", body).await;
        assert_eq!(status, StatusCode::OK, "{shape}: {}", rest.to_string().chars().take(300).collect::<String>());
        assert_eq!(rest["result"], json!({ "ok": true }), "{shape}");
        let sent = format!("content={}", form_encoded(&text));
        assert!(sent.len() > 2 * 1024 * 1024, "{shape} encodes past 2 MiB");
        assert!(last.lock().unwrap().as_slice() == sent.as_bytes(), "{shape} reached the upstream whole");
    }
}
