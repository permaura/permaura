//! `permaura remote disable` turns remote access off in the running gateway, not only in the files it reads at boot, and checks that it did. When it cannot reach that gateway, or the gateway cannot stop its connector, it says the access stays on until a restart, and exits non-zero.
//!
//! The first two cases run a real `permaura start` with remote access configured: a stand-in `cloudflared` on PATH as its tunnel connector, and a local JWKS standing in for permaura.com, so a permaura.com-shaped token is accepted. The others answer the CLI from a fixture gateway that proves it holds the token. Every credential is synthetic and nothing leaves loopback.
#![cfg(unix)]

mod common;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};

const PUBLIC_URL: &str = "https://g-remoteoff.permaura.app";
const OWNER_SUB: &str = "user_remoteoff";
const AS_ISSUER: &str = "https://permaura.test/api/auth";
const AS_KID: &str = "remote-disable-test-key";
const CREDENTIALS: &str = "{\"AccountTag\":\"acct_remoteoff\",\"TunnelSecret\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"TunnelID\":\"6f3c2a1e-0b4d-4c7e-9a10-2b3c4d5e6f71\",\"Endpoint\":\"\"}";
const FIXTURE_TOKEN: &str = "pgt_remote_disable_fixture_only";

/// The CLI names a loopback listener's owner by listing this process's sockets, so the cases take turns rather than open and close listeners under each other.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("permaura-remoteoff-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn free_addr() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert!(![7376, 8787, 3102, 8081, 8799, 18787].contains(&port), "never a port a real gateway or app on this machine uses");
    format!("127.0.0.1:{port}")
}

fn as_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[73u8; 32])
}

/// A JWKS endpoint for the stand-in authorization server, on a thread of its own.
fn serve_jwks() -> u16 {
    let body = json!({
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": AS_KID, "use": "sig", "alg": "EdDSA",
            "x": URL_SAFE_NO_PAD.encode(as_signing_key().verifying_key().to_bytes()),
        }]
    })
    .to_string();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a JWKS listener");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut scratch = [0u8; 2048];
            let _ = stream.read(&mut scratch);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// What a remote MCP client holds after the owner consented to it at permaura.com.
fn agent_token() -> String {
    let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" }).to_string());
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": AS_ISSUER, "sub": OWNER_SUB, "aud": format!("{PUBLIC_URL}/mcp"), "azp": "client_remoteoff",
            "iat": now_secs(), "exp": now_secs() + 600, "scope": "openid profile mcp offline_access", "name": "remote agent",
        })
        .to_string(),
    );
    let input = format!("{header}.{claims}");
    let sig = as_signing_key().sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// A home where `permaura remote enable` has run, and a `cloudflared` on `bin` that records its pid and keeps running.
fn remote_install(home: &Path, bin: &Path, jwks_port: u16) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(
        home.join("config.toml"),
        format!("public_url = \"{PUBLIC_URL}\"\nowner_sub = \"{OWNER_SUB}\"\nas_issuer = \"{AS_ISSUER}\"\nas_jwks = \"http://127.0.0.1:{jwks_port}/jwks\"\n"),
    )
    .unwrap();
    std::fs::write(home.join("tunnel-credentials.json"), CREDENTIALS).unwrap();
    let pid_file = bin.join("cloudflared.pid");
    let script = bin.join("cloudflared");
    std::fs::write(&script, format!("#!/bin/sh\necho $$ > '{}'\nexec sleep 120\n", pid_file.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    pid_file
}

fn gateway(home: &Path, bin: &Path, addr: &str, public_url_in_env: bool) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    cmd.args(["start", "--addr", addr, "--mock"])
        .env("PERMAURA_HOME", home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_NO_UPGRADE", "1")
        .env("PATH", format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default()))
        .env("RUST_LOG", "info")
        // Unreachable, so nothing here ever reaches permaura.com.
        .env("PERMAURA_API", "https://127.0.0.1:9")
        .env("PERMAURA_CONTROL_PLANE_URL", "https://127.0.0.1:9");
    for key in [
        "PERMAURA_HOSTED",
        "PERMAURA_RELAY_URL",
        "PERMAURA_STORE_PATH",
        "PERMAURA_STORE_BUCKET",
        "PERMAURA_PUBLIC_URL",
        "PERMAURA_PUBLIC_URL_ALIASES",
        "PERMAURA_OWNER_SUB",
        "PERMAURA_AS_ISSUER",
        "PERMAURA_AS_JWKS",
        "PERMAURA_GATEWAY_ID",
        "PERMAURA_ANNOUNCE_SECRET",
        "PERMAURA_ADDR",
        "PERMAURA_SUPERVISED_BY_APP",
        "PERMAURA_APPROVER_KEYS_PATH",
    ] {
        cmd.env_remove(key);
    }
    if public_url_in_env {
        cmd.env("PERMAURA_PUBLIC_URL", PUBLIC_URL);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    cmd
}

struct Cli {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Cli {
    fn log(&self) -> String {
        format!("exit {}\n--- stdout\n{}\n--- stderr\n{}", self.code, self.stdout, self.stderr)
    }
}

async fn cli(home: &Path, addr: &str, token: Option<&str>, args: &[&str]) -> Cli {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    cmd.args(["--url", &format!("http://{addr}")]);
    if let Some(token) = token {
        cmd.args(["--token", token]);
    }
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        cmd.args(args)
            .env_remove("PERMAURA_TOKEN")
            .env_remove("PERMAURA_URL")
            .env_remove("PERMAURA_PUBLIC_URL")
            .env("PERMAURA_HOME", home)
            .env("PERMAURA_DEV", "1")
            .env("PERMAURA_NO_UPGRADE", "1")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the CLI finishes")
    .unwrap();
    Cli {
        code: output.status.code().expect("the CLI exited on its own"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only asks whether the process exists; nothing is delivered.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap()
}

async fn health(addr: &str, token: &str) -> Value {
    client().get(format!("http://{addr}/health")).bearer_auth(token).send().await.unwrap().json().await.unwrap()
}

/// What the remote agent's `tools/list` came to.
async fn remote_call(addr: &str) -> StatusCode {
    let status = client()
        .post(format!("http://{addr}/mcp"))
        .bearer_auth(agent_token())
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .send()
        .await
        .unwrap()
        .status();
    StatusCode::from_u16(status.as_u16()).unwrap()
}

async fn eventually<T>(what: &str, within: Duration, mut probe: impl FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<T>> + Send>>) -> T {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if let Some(found) = probe().await {
            return found;
        }
        assert!(tokio::time::Instant::now() < deadline, "{what} did not happen within {within:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A running gateway serving remote access: its connector's pid and its operator token.
struct Running {
    gateway: tokio::process::Child,
    connector: i32,
    token: String,
}

async fn start_remote_gateway(home: &Path, bin: &Path, addr: &str, public_url_in_env: bool) -> Running {
    let jwks = serve_jwks();
    let pid_file = remote_install(home, bin, jwks);
    let mut gateway = gateway(home, bin, addr, public_url_in_env).spawn().expect("the gateway starts");
    let up = format!("http://{addr}/health");
    eventually("the gateway answering", Duration::from_secs(60), || {
        let up = up.clone();
        Box::pin(async move { matches!(client().get(up).send().await, Ok(r) if r.status().is_success()).then_some(()) })
    })
    .await;
    if let Ok(Some(status)) = gateway.try_wait() {
        panic!("the gateway exited with {status}");
    }
    let token_path = home.join("operator.token");
    let token = eventually("the operator token being published", Duration::from_secs(10), || {
        let path = token_path.clone();
        Box::pin(async move { std::fs::read_to_string(path).ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) })
    })
    .await;
    let connector = eventually("the tunnel connector starting", Duration::from_secs(30), || {
        let path = pid_file.clone();
        Box::pin(async move { std::fs::read_to_string(path).ok().and_then(|p| p.trim().parse::<i32>().ok()) })
    })
    .await;
    Running { gateway, connector, token }
}

async fn serving_remote_access(addr: &str, running: &Running) {
    assert!(alive(running.connector), "the connector runs");
    let before = health(addr, &running.token).await;
    assert_eq!(before["tunnel_ingress"], "local", "{before}");
    // The JWKS lands in the background at boot; until it does the gateway answers 503.
    let accepted = eventually("a remote agent's call being accepted", Duration::from_secs(20), || {
        let addr = addr.to_string();
        Box::pin(async move {
            let status = remote_call(&addr).await;
            (status != StatusCode::SERVICE_UNAVAILABLE).then_some(status)
        })
    })
    .await;
    assert_eq!(accepted, StatusCode::OK, "the remote agent's token is accepted before the disable");
}

#[tokio::test]
async fn remote_disable_stops_the_running_connector_and_refuses_remote_tokens_at_once() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("home");
    let bin = scratch("bin");
    let addr = free_addr();
    let mut running = start_remote_gateway(&home, &bin, &addr, false).await;
    serving_remote_access(&addr, &running).await;

    let run = cli(&home, &addr, None, &["remote", "disable"]).await;

    let connector = running.connector;
    eventually("the connector exiting", Duration::from_secs(5), || Box::pin(async move { (!alive(connector)).then_some(()) })).await;
    assert_eq!(remote_call(&addr).await, StatusCode::UNAUTHORIZED, "the remote agent's token is refused straight after: {}", run.log());
    let after = health(&addr, &running.token).await;
    assert_eq!(after["tunnel_ingress"], "stopped", "{after}");
    assert_eq!(after["remote_tokens"], "refused", "{after}");
    assert!(after["tunnel_stop_reason"].as_str().unwrap_or("").contains("permaura remote disable"), "{after}");
    assert_eq!(run.code, 0, "{}", run.log());
    assert!(run.stdout.contains("Remote access is off"), "{}", run.log());
    assert!(run.stdout.contains(&format!("stopped its tunnel connector (pid {connector})")), "{}", run.log());
    assert!(run.stdout.contains("refuses permaura.com tokens"), "{}", run.log());
    assert!(!run.stdout.contains("PERMAURA_PUBLIC_URL"), "nothing in this gateway's environment brings it back: {}", run.log());

    // A trust change is recorded: the audit chain says remote access was turned off, what was stopped and what is now refused.
    let audit: Value = client()
        .get(format!("http://{addr}/v1/audit-events?limit=50"))
        .bearer_auth(&running.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let recorded = audit["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["payload"]["action"] == "permaura.remote.disable")
        .unwrap_or_else(|| panic!("no permaura.remote.disable event in the audit chain: {audit}"));
    assert_eq!(recorded["payload"]["decision"], "allow", "{recorded}");
    assert_eq!(recorded["payload"]["summary"]["connector"], "stopped", "{recorded}");
    assert_eq!(recorded["payload"]["summary"]["connector_pid"], connector, "{recorded}");
    assert_eq!(recorded["payload"]["summary"]["remote_tokens"], "refused", "{recorded}");
    assert_eq!(recorded["payload"]["summary"]["supervised_by_app"], false, "{recorded}");
    // It names who pulled it: the operator session, not an anonymous row a feed shows as "agent".
    assert_eq!(recorded["payload"]["agent_id"], "operator", "{recorded}");
    assert!(recorded["payload"]["session_id"].as_str().is_some_and(|s| !s.is_empty()), "{recorded}");
    assert_eq!(audit["chain_intact"], true, "{audit}");
    // And the start before it recorded remote access being served, from the file, with a tunnel configured.
    let serving = audit["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["payload"]["action"] == "permaura.remote.serving")
        .unwrap_or_else(|| panic!("no permaura.remote.serving event from the start: {audit}"));
    assert_eq!(serving["payload"]["summary"]["public_url_from"], "file", "{serving}");
    assert_eq!(serving["payload"]["summary"]["tunnel"], "configured", "{serving}");

    // Nothing still advertises the withdrawn resource server: no sign-in challenge pointing at metadata that now 404s, and no recovery ticket route.
    let refused = client()
        .post(format!("http://{addr}/mcp"))
        .bearer_auth(agent_token())
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status().as_u16(), 401);
    assert!(refused.headers().get("www-authenticate").is_none(), "no challenge for a server that is gone: {:?}", refused.headers());
    let refusal: Value = refused.json().await.unwrap_or(Value::Null);
    assert!(refusal["error"].as_str().unwrap_or("").contains("remote access was turned off"), "the 401 says why: {refusal}");
    let recovery: Value = client()
        .get(format!("http://{addr}/v1/recovery"))
        .bearer_auth(&running.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(recovery["recovery_ticket_accepted"], false, "{recovery}");

    let config = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(!config.contains("public_url"), "{config}");
    assert!(!home.join("tunnel-credentials.json").exists());

    let status = cli(&home, &addr, None, &["remote", "status"]).await;
    assert_eq!(status.code, 0, "{}", status.log());
    assert!(status.stdout.contains("Remote access is off"), "{}", status.log());
    assert!(status.stdout.contains("tunnel connector stopped"), "status reads the running gateway too: {}", status.log());

    running.gateway.start_kill().ok();
    let _ = running.gateway.wait().await;
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&bin);
}

/// A public URL the gateway's own environment sets outranks the file, so removing it from the file does not keep the resource server off past a restart. The running one is still stopped, and the CLI says what brings it back.
#[tokio::test]
async fn remote_disable_names_a_public_url_set_in_the_gateways_environment() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("env-home");
    let bin = scratch("env-bin");
    let addr = free_addr();
    let mut running = start_remote_gateway(&home, &bin, &addr, true).await;
    serving_remote_access(&addr, &running).await;

    let run = cli(&home, &addr, None, &["remote", "disable"]).await;

    let connector = running.connector;
    eventually("the connector exiting", Duration::from_secs(5), || Box::pin(async move { (!alive(connector)).then_some(()) })).await;
    assert_eq!(remote_call(&addr).await, StatusCode::UNAUTHORIZED, "{}", run.log());
    assert_eq!(run.code, 0, "{}", run.log());
    assert!(run.stdout.contains("Remote access is off"), "{}", run.log());
    assert!(run.stdout.contains("PERMAURA_PUBLIC_URL"), "{}", run.log());
    assert!(run.stdout.contains("next start"), "{}", run.log());

    running.gateway.start_kill().ok();
    let _ = running.gateway.wait().await;
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&bin);
}

/// Run from a home that holds no remote access (root's, on a service-account install), the CLI edits nothing that matters and the running gateway does not prove it is this home's, so it must never say a restart turns remote access off.
#[tokio::test]
async fn a_disable_from_a_home_that_holds_nothing_never_says_a_restart_turns_it_off() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("empty-home");
    let (addr, server) = fixture(None, json!({ "status": "ok" })).await;
    let run = cli(&home, &addr, None, &["remote", "disable"]).await;
    server.abort();
    let all = format!("{}{}", run.stdout, run.stderr);
    assert_ne!(run.code, 0, "{}", run.log());
    assert!(!all.contains("Removed remote access"), "nothing was removed: {}", run.log());
    assert!(!all.contains("starts again without remote access"), "a restart does not turn it off: {}", run.log());
    assert!(all.contains("Nothing to remove") && all.contains(&home.display().to_string()), "names the home it looked in: {}", run.log());
    assert!(all.contains("as the account whose gateway it is"), "{}", run.log());
    let _ = std::fs::remove_dir_all(&home);
}

/// Files removed from a home whose token the running gateway does not prove may not be that gateway's, so the CLI says whose files it changed instead of promising the restart.
#[tokio::test]
async fn a_disable_whose_gateway_is_not_this_homes_says_whose_files_changed() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("other-home");
    std::fs::write(home.join("config.toml"), format!("public_url = \"{PUBLIC_URL}\"\n")).unwrap();
    std::fs::write(home.join("operator.token"), "pgt_some_other_homes_token").unwrap();
    let (addr, server) = fixture(None, json!({ "status": "ok" })).await;
    let run = cli(&home, &addr, None, &["remote", "disable"]).await;
    server.abort();
    let all = format!("{}{}", run.stdout, run.stderr);
    assert_ne!(run.code, 0, "{}", run.log());
    assert!(!all.contains("starts again without remote access"), "{}", run.log());
    assert!(all.contains("may not be the running gateway's"), "{}", run.log());
    assert!(all.contains(&home.display().to_string()), "{}", run.log());
    let _ = std::fs::remove_dir_all(&home);
}

/// A gateway that runs no tunnel of its own while something else forwards to it (the Permaura app's tunnel here) is not "off": the forwarder still reaches it.
#[tokio::test]
async fn a_gateway_whose_tunnel_something_else_runs_is_not_reported_off() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("app-home");
    let body = json!({ "connector": "none", "connector_pid": null, "remote_tokens": "refused", "environment": ["PERMAURA_PUBLIC_URL"], "supervised_by_app": true, "tunnel_before": null, "audited": true });
    let (addr, server) = fixture(Some((200, body)), json!({ "status": "ok", "tunnel_ingress": null, "remote_tokens": "refused" })).await;
    let run = cli(&home, &addr, Some(FIXTURE_TOKEN), &["remote", "disable"]).await;
    server.abort();
    let all = format!("{}{}", run.stdout, run.stderr);
    assert_ne!(run.code, 0, "{}", run.log());
    assert!(!all.contains("Remote access is off"), "{}", run.log());
    assert!(all.contains("still reaches it") && all.contains("Permaura app"), "{}", run.log());
    assert!(all.contains("agents enrolled with a code"), "the narrowed claim: {}", run.log());
    let _ = std::fs::remove_dir_all(&home);
}

/// A fixture gateway that proves it holds [`FIXTURE_TOKEN`] and answers `POST /v1/remote/disable` with `disable`, or 404 when that is `None`.
async fn fixture(disable: Option<(u16, Value)>, health_body: Value) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    assert!(![7376, 8787, 3102, 8081, 8799, 18787].contains(&addr.port()));
    let port = addr.port();
    let routes = Arc::new((disable, health_body));
    let app = axum::Router::new().fallback(move |method: Method, uri: Uri, headers: HeaderMap| {
        let routes = routes.clone();
        async move {
            if uri.path() == "/health" {
                let authed = headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {FIXTURE_TOKEN}"));
                let body = if authed { routes.1.clone() } else { json!({ "service": "permaura-gateway", "status": "ok" }) };
                let mut resp = Json(body).into_response();
                let challenge = headers.get(permaura_core::health_proof::CHALLENGE_HEADER).and_then(|v| v.to_str().ok());
                if let Some(proof) = challenge.and_then(|c| permaura_core::health_proof::proof(FIXTURE_TOKEN, port, c)) {
                    resp.headers_mut().insert(permaura_core::health_proof::PROOF_HEADER, proof.parse().unwrap());
                }
                return resp;
            }
            match (&routes.0, method == Method::POST && uri.path() == "/v1/remote/disable") {
                (Some((status, body)), true) => (StatusCode::from_u16(*status).unwrap(), Json(body.clone())).into_response(),
                _ => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response(),
            }
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr.to_string(), server)
}

fn stays_on_until_a_restart(run: &Cli) {
    assert_ne!(run.code, 0, "{}", run.log());
    let all = format!("{}{}", run.stdout, run.stderr);
    assert!(!all.contains("Remote access is off."), "never the bare claim: {}", run.log());
    assert!(all.contains("stays on until"), "{}", run.log());
    // A restart is the fix only for this home's own gateway; one proved only by an explicit --token gets the account to run this as instead.
    assert!(
        all.contains("permaura stop && permaura start") || all.contains("systemctl restart permaura") || all.contains("as the account whose gateway it is"),
        "names what to do: {}",
        run.log()
    );
}

/// A gateway too old to have the route keeps serving remote access, and the CLI says so instead of reporting it off.
#[tokio::test]
async fn a_gateway_that_cannot_stop_remote_access_while_running_is_reported_as_still_serving_it() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("old-home");
    std::fs::write(home.join("config.toml"), format!("public_url = \"{PUBLIC_URL}\"\n")).unwrap();
    let (addr, server) = fixture(None, json!({ "status": "ok", "tunnel_ingress": "local" })).await;
    let run = cli(&home, &addr, Some(FIXTURE_TOKEN), &["remote", "disable"]).await;
    server.abort();
    stays_on_until_a_restart(&run);
    assert!(!std::fs::read_to_string(home.join("config.toml")).unwrap().contains("public_url"), "the files are still changed for the next start");
    let _ = std::fs::remove_dir_all(&home);
}

/// The gateway took the request but its connector did not exit: that is reported as a failure, never as off.
#[tokio::test]
async fn a_connector_that_did_not_stop_is_reported_as_still_serving() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("stuck-home");
    let body = json!({
        "connector": "running",
        "connector_pid": 4242,
        "detail": "it had not exited 5 seconds after SIGKILL",
        "remote_tokens": "refused",
        "environment": [],
        "supervised_by_app": false,
    });
    let (addr, server) = fixture(Some((500, body)), json!({ "status": "ok", "tunnel_ingress": "local", "remote_tokens": "refused" })).await;
    let run = cli(&home, &addr, Some(FIXTURE_TOKEN), &["remote", "disable"]).await;
    server.abort();
    stays_on_until_a_restart(&run);
    assert!(run.stdout.contains("4242") || run.stderr.contains("4242"), "{}", run.log());
    let _ = std::fs::remove_dir_all(&home);
}

/// The gateway said it stopped, but its own health document still shows the connector running: the CLI believes the check, not the answer.
#[tokio::test]
async fn a_stop_the_health_document_contradicts_is_reported_as_still_serving() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("contradicted-home");
    let body = json!({ "connector": "stopped", "connector_pid": 4343, "remote_tokens": "refused", "environment": [], "supervised_by_app": false });
    let (addr, server) = fixture(Some((200, body)), json!({ "status": "ok", "tunnel_ingress": "local", "remote_tokens": "refused" })).await;
    let run = cli(&home, &addr, Some(FIXTURE_TOKEN), &["remote", "disable"]).await;
    server.abort();
    stays_on_until_a_restart(&run);
    let _ = std::fs::remove_dir_all(&home);
}

/// Nothing listening at the address: no running gateway was serving remote access there, and the CLI says the change holds from the next start and how to reach a gateway elsewhere.
#[tokio::test]
async fn with_no_gateway_running_the_change_is_said_to_apply_from_the_next_start() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = scratch("idle-home");
    let addr = free_addr();
    let run = cli(&home, &addr, Some(FIXTURE_TOKEN), &["remote", "disable"]).await;
    assert_eq!(run.code, 0, "{}", run.log());
    assert!(run.stdout.contains("No gateway is running at"), "{}", run.log());
    assert!(run.stdout.contains("--url"), "{}", run.log());
    let _ = std::fs::remove_dir_all(&home);
}
