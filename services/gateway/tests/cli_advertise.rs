//! `permaura advertise` tells permaura.com where the console should send this gateway's operator bearer, so the address has to prove it is this gateway first, as the launcher does before it presents the token. Each case runs the real binary against a gateway fixture on a free loopback port, which proves the synthetic token or does not, and an account API fixture that records the PATCH and answers with the status under test. Every token, id and address here is synthetic.
#![cfg(unix)]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

const TOKEN: &str = "pgt_cli_advertise_fixture_only";

struct Gateway {
    port: u16,
    proves: bool,
}

async fn gateway(State(g): State<Arc<Gateway>>, uri: Uri, headers: HeaderMap) -> Response {
    if uri.path() != "/health" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut resp = Json(json!({ "service": "permaura-gateway", "status": "ok" })).into_response();
    let challenge = headers.get(permaura_core::health_proof::CHALLENGE_HEADER).and_then(|v| v.to_str().ok());
    if g.proves {
        if let Some(proof) = challenge.and_then(|c| permaura_core::health_proof::proof(TOKEN, g.port, c)) {
            resp.headers_mut().insert(permaura_core::health_proof::PROOF_HEADER, proof.parse().unwrap());
        }
    }
    resp
}

struct Api {
    status: u16,
    body: Value,
    patches: Mutex<Vec<(String, Value)>>,
}

async fn api(State(a): State<Arc<Api>>, method: Method, uri: Uri, Json(body): Json<Value>) -> Response {
    if method != Method::PATCH {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    a.patches.lock().unwrap().push((uri.path().to_string(), body));
    (StatusCode::from_u16(a.status).unwrap(), Json(a.body.clone())).into_response()
}

async fn serve(app: axum::Router) -> SocketAddr {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    assert_ne!(addr.port(), 7376, "never the port a real gateway on this machine listens on");
    tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    addr
}

struct Run {
    code: i32,
    out: String,
    patches: Vec<(String, Value)>,
}

/// Advertise the gateway fixture's own address (`proves` says whether it answers the challenge), or with `unproven` an address nothing listens on, against an API answering `status` with `body`.
async fn advertise(proves: Option<bool>, unproven: bool, status: u16, body: Value) -> Run {
    common::isolate_from_the_real_install();
    let home = std::env::temp_dir().join(format!("permaura-advertise-{}-{}", std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("gateway.id"), "gw_synthetic_advertise\n").unwrap();
    std::fs::write(home.join("operator.token"), format!("{TOKEN}\n")).unwrap();

    let target = match proves {
        Some(proves) => {
            let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let app = axum::Router::new().fallback(gateway).with_state(Arc::new(Gateway { port: addr.port(), proves }));
            tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
            addr
        }
        None => {
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap()
        }
    };
    let account = Arc::new(Api { status, body, patches: Mutex::new(Vec::new()) });
    let api_addr = serve(axum::Router::new().fallback(api).with_state(account.clone())).await;

    let url = format!("http://{target}");
    let mut args = vec!["advertise", url.as_str()];
    if unproven {
        args.push("--unproven");
    }
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"))
            .args(&args)
            .env("PERMAURA_HOME", &home)
            .env("PERMAURA_API", format!("http://{api_addr}"))
            .env("PERMAURA_DEV", "1")
            .env("PERMAURA_NO_UPGRADE", "1")
            .env_remove("PERMAURA_TOKEN")
            .env_remove("PERMAURA_URL")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the CLI finishes")
    .unwrap();
    std::fs::remove_dir_all(&home).ok();
    let patches = account.patches.lock().unwrap().clone();
    Run {
        code: output.status.code().expect("the CLI exited on its own"),
        out: format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)),
        patches,
    }
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

fn ok() -> Value {
    json!({ "id": "gw_synthetic_advertise", "baseUrl": "http://127.0.0.1:1" })
}

#[tokio::test]
async fn a_listener_that_does_not_prove_it_is_this_gateway_is_refused_and_nothing_is_sent() {
    let run = advertise(Some(false), false, 200, ok()).await;
    assert_ne!(run.code, 0, "{}", run.out);
    assert!(run.patches.is_empty(), "permaura.com was told nothing: {:?}", run.patches);
    assert!(run.out.contains("--unproven"), "names the override for a host port forward: {}", run.out);
}

#[tokio::test]
async fn a_proving_gateway_is_advertised() {
    let run = advertise(Some(true), false, 200, ok()).await;
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.patches.len(), 1, "{}", run.out);
    let (path, body) = &run.patches[0];
    assert_eq!(path, "/api/gateways/gw_synthetic_advertise");
    assert!(body["baseUrl"].as_str().unwrap().starts_with("http://127.0.0.1:"), "{body}");
    assert!(body.get("provenPort").is_none(), "permaura.com no longer moves a managed tunnel, so it is not told: {body}");
    assert!(!body.to_string().contains(TOKEN), "the operator token is not sent to the account API");
}

/// The bring-your-own tunnel warning is still printed; a tunnel port in the answer is not, since permaura.com no longer moves a managed tunnel.
#[tokio::test]
async fn a_warning_in_the_answer_is_printed_and_a_tunnel_port_is_not() {
    let warning = "Your own tunnel for this gateway was set up for port 7376. Point it at the new address.";
    let mut body = ok();
    body["warning"] = json!(warning);
    body["tunnelPort"] = json!(7399);
    let run = advertise(Some(true), false, 200, body).await;
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains(warning), "{}", run.out);
    assert!(!run.out.contains("7399") && !run.out.contains("forwards"), "{}", run.out);
}

#[tokio::test]
async fn a_refusal_prints_the_servers_error_and_nothing_about_the_tunnel() {
    let run = advertise(Some(true), false, 502, json!({ "error": "the account API is unavailable" })).await;
    assert_ne!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("the account API is unavailable (502)"), "{}", run.out);
    assert!(!run.out.contains("remote disable"), "{}", run.out);
}

/// A VM guest advertises the host's forward of its port, which the guest itself cannot dial: the override sends it unproven and says what that means.
#[tokio::test]
async fn unproven_sends_an_address_nothing_here_answers_on_and_says_why() {
    let run = advertise(None, true, 200, ok()).await;
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.patches.len(), 1, "{}", run.out);
    assert!(run.patches[0].1.get("provenPort").is_none(), "{:?}", run.patches);
    assert!(run.out.contains("port forward"), "{}", run.out);
}
