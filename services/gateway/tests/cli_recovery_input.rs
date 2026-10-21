//! Recovery codes and step-up tickets reach the CLI without riding in argv: from `PERMAURA_RECOVERY_CODE` / `PERMAURA_TICKET`, or a masked prompt when the flag is given on its own, which is asked only once a gateway is known to be answering. A value typed after the flag still works and warns. Each case runs the real binary against a responder on a free loopback port that proves the synthetic token the way a gateway does. Every token, code and ticket here is synthetic.
#![cfg(unix)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

const TOKEN: &str = "pgt_cli_recovery_input_fixture_only";
const CODE: &str = "FXTR-CODE-0000-1111";
const TICKET: &str = "fixture.ticket.value";
const RECOVERY_HEADER: &str = "x-permaura-recovery-code";
const TICKET_HEADER: &str = "x-permaura-pairing-ticket";

#[derive(Clone, Debug)]
struct Hit {
    path: String,
    recovery_code: Option<String>,
    ticket: Option<String>,
}

struct Fixture {
    port: u16,
    hits: Mutex<Vec<Hit>>,
}

async fn answer(State(f): State<Arc<Fixture>>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().to_string();
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    f.hits.lock().unwrap().push(Hit { path: path.clone(), recovery_code: header(RECOVERY_HEADER), ticket: header(TICKET_HEADER) });
    if path == "/health" {
        let mut resp = Json(json!({ "service": "permaura-gateway", "status": "ok" })).into_response();
        let challenge = headers
            .get(permaura_core::health_proof::CHALLENGE_HEADER)
            .and_then(|v| v.to_str().ok());
        if let Some(proof) = challenge.and_then(|c| permaura_core::health_proof::proof(TOKEN, f.port, c)) {
            resp.headers_mut()
                .insert(permaura_core::health_proof::PROOF_HEADER, proof.parse().unwrap());
        }
        return resp;
    }
    match (method, path.as_str()) {
        (Method::PUT, "/v1/approval-floor") => {
            Json(json!({ "approval_floor": "approve", "signed_approvals_required": false })).into_response()
        }
        (Method::DELETE, "/v1/approver-keys/device:fixture") => {
            Json(json!({ "approver_id": "device:fixture", "trusted": false, "emptied_keyring": false })).into_response()
        }
        (Method::POST, "/v1/recovery-codes") => {
            Json(json!({ "recovery_codes": ["FXTR-NEW1-0000-0000", "FXTR-NEW2-0000-0000"], "first_set": false })).into_response()
        }
        _ => (StatusCode::IM_A_TEAPOT, Json(json!({ "error": "no such fixture route" }))).into_response(),
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    hits: Vec<Hit>,
}

impl Run {
    fn writes(&self) -> Vec<&Hit> {
        self.hits.iter().filter(|h| h.path != "/health").collect()
    }

    fn log(&self) -> String {
        format!("exit {}\n--- stdout\n{}\n--- stderr\n{}\n--- hits\n{:?}", self.code, self.stdout, self.stderr, self.hits)
    }
}

/// The cases take turns for the reason `cli_write_outcome.rs` gives: the loopback owner check can miss a sibling's listener.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Run the CLI with `args` and `env`, against a fixture gateway unless `answering` is false, in which case the URL names a port nothing listens on.
async fn run(args: &[&str], env: &[(&str, &str)], answering: bool) -> Run {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = std::env::var("PERMAURA_HOME").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    assert_ne!(addr.port(), 7376, "never the port a real gateway on this machine listens on");
    let fixture = Arc::new(Fixture { port: addr.port(), hits: Mutex::new(Vec::new()) });
    let server = if answering {
        let app = axum::Router::new().fallback(answer).with_state(fixture.clone());
        Some(tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }))
    } else {
        drop(listener);
        None
    };

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    command
        .args(["--url", &format!("http://{addr}")])
        .args(args)
        // In the environment, as the CLI asks: `--token` would draw the warning a token on the command line gets.
        .env("PERMAURA_TOKEN", TOKEN)
        .env_remove("PERMAURA_URL")
        .env_remove("PERMAURA_RECOVERY_CODE")
        .env_remove("PERMAURA_TICKET")
        .env("PERMAURA_HOME", &home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_NO_UPGRADE", "1")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    for (k, v) in env {
        command.env(k, v);
    }
    let output = tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .expect("the CLI finishes")
        .unwrap();
    if let Some(server) = server {
        server.abort();
    }
    let hits = fixture.hits.lock().unwrap().clone();
    Run {
        code: output.status.code().expect("the CLI exited on its own"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        hits,
    }
}

#[tokio::test]
async fn a_recovery_code_from_the_environment_is_sent_and_never_in_argv() {
    let args = ["approver", "floor", "approve"];
    let run = run(&args, &[("PERMAURA_RECOVERY_CODE", CODE)], true).await;
    assert_eq!(run.code, 0, "{}", run.log());
    assert!(!args.contains(&CODE));
    let writes = run.writes();
    assert_eq!(writes.len(), 1, "{}", run.log());
    assert_eq!(writes[0].recovery_code.as_deref(), Some(CODE), "the code from the environment was sent: {}", run.log());
    assert!(!run.stderr.contains("warning"), "nothing to warn about: {}", run.log());
}

#[tokio::test]
async fn a_ticket_from_the_environment_is_sent_and_never_in_argv() {
    let run = run(&["approver", "revoke", "device:fixture"], &[("PERMAURA_TICKET", TICKET)], true).await;
    assert_eq!(run.code, 0, "{}", run.log());
    let writes = run.writes();
    assert_eq!(writes.len(), 1, "{}", run.log());
    assert_eq!(writes[0].ticket.as_deref(), Some(TICKET), "the ticket from the environment was sent: {}", run.log());
}

/// `approver codes` takes the step-up ticket its gateway asks for off the host, the same way its sibling approver commands do, so it can be run against a self-run gateway's public address.
#[tokio::test]
async fn approver_codes_carries_a_step_up_ticket_like_its_siblings() {
    let run = run(&["approver", "codes"], &[("PERMAURA_TICKET", TICKET), ("PERMAURA_RECOVERY_CODE", CODE)], true).await;
    assert_eq!(run.code, 0, "{}", run.log());
    let writes = run.writes();
    assert_eq!(writes.len(), 1, "{}", run.log());
    assert_eq!(writes[0].path, "/v1/recovery-codes", "{}", run.log());
    assert_eq!(writes[0].ticket.as_deref(), Some(TICKET), "the ticket from the environment was sent: {}", run.log());
    assert_eq!(writes[0].recovery_code.as_deref(), Some(CODE), "{}", run.log());
    assert!(run.stdout.contains("FXTR-NEW1-0000-0000"), "{}", run.log());

    let run = self::run(&["approver", "codes", "--ticket", TICKET], &[("PERMAURA_RECOVERY_CODE", CODE)], true).await;
    assert_eq!(run.code, 0, "{}", run.log());
    assert_eq!(run.writes()[0].ticket.as_deref(), Some(TICKET), "{}", run.log());
    assert!(run.stderr.contains("warning") && run.stderr.contains("PERMAURA_TICKET"), "{}", run.log());
}

#[tokio::test]
async fn a_code_typed_after_the_flag_still_works_and_warns() {
    let run = run(&["approver", "floor", "approve", "--recovery-code", CODE], &[], true).await;
    assert_eq!(run.code, 0, "{}", run.log());
    assert_eq!(run.writes()[0].recovery_code.as_deref(), Some(CODE), "{}", run.log());
    assert!(
        run.stderr.contains("warning") && run.stderr.contains("shell history") && run.stderr.contains("PERMAURA_RECOVERY_CODE"),
        "{}",
        run.log()
    );
    assert!(!run.stderr.contains(CODE) && !run.stdout.contains(CODE), "the warning does not repeat the code: {}", run.log());

    let run = self::run(&["approver", "revoke", "device:fixture", "--ticket", TICKET], &[], true).await;
    assert_eq!(run.code, 0, "{}", run.log());
    assert_eq!(run.writes()[0].ticket.as_deref(), Some(TICKET), "{}", run.log());
    assert!(run.stderr.contains("warning") && run.stderr.contains("PERMAURA_TICKET"), "{}", run.log());
}

/// The flag on its own asks for the value, and without a terminal to ask on it says how else to give it, having sent nothing.
#[tokio::test]
async fn the_flag_alone_with_no_terminal_names_the_variable_and_sends_nothing() {
    let run = run(&["approver", "floor", "approve", "--recovery-code"], &[], true).await;
    assert_ne!(run.code, 0, "{}", run.log());
    assert!(run.stderr.contains("PERMAURA_RECOVERY_CODE"), "{}", run.log());
    assert!(run.writes().is_empty(), "nothing was sent: {}", run.log());
}

/// The code is asked for only once something is answering, so a gateway that is down cannot be the reason a typed code goes unspent.
#[tokio::test]
async fn nothing_answering_is_reported_before_any_code_is_asked_for() {
    let run = run(&["approver", "floor", "approve", "--recovery-code"], &[], false).await;
    assert_ne!(run.code, 0, "{}", run.log());
    assert!(run.stderr.contains("nothing is answering"), "{}", run.log());
    assert!(!run.stderr.contains("PERMAURA_RECOVERY_CODE"), "it stopped before asking: {}", run.log());
}

/// A reset refuses a running gateway before it asks for the code it would spend.
#[tokio::test]
async fn a_reset_refuses_a_running_gateway_before_asking_for_the_code() {
    let run = run(&["approver", "reset", "--yes", "--recovery-code"], &[], true).await;
    assert_ne!(run.code, 0, "{}", run.log());
    assert!(run.stderr.contains("a gateway is answering"), "{}", run.log());
    assert!(!run.stderr.contains("PERMAURA_RECOVERY_CODE"), "it stopped before asking: {}", run.log());
}

/// This home's gateway listens where `start` binds it (`PERMAURA_ADDR`), which need not be `--url`; a reset refuses a gateway answering there too, before it spends a code or touches the store.
#[tokio::test]
async fn a_reset_refuses_this_homes_gateway_on_its_own_address() {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = std::env::var("PERMAURA_HOME").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fixture = Arc::new(Fixture { port: addr.port(), hits: Mutex::new(Vec::new()) });
    let app = axum::Router::new().fallback(answer).with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let idle = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    assert!(![7376, 8787].contains(&addr.port()) && ![7376, 8787].contains(&idle.port()));
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"))
            .args(["--url", &format!("http://{idle}"), "--token", TOKEN, "approver", "reset", "--yes"])
            .env_remove("PERMAURA_TOKEN")
            .env_remove("PERMAURA_URL")
            .env_remove("PERMAURA_RECOVERY_CODE")
            .env("PERMAURA_ADDR", addr.to_string())
            .env("PERMAURA_HOME", &home)
            .env("PERMAURA_DEV", "1")
            .env("PERMAURA_NO_UPGRADE", "1")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the CLI finishes")
    .unwrap();
    server.abort();
    let log = format!("exit {:?}\n{}{}", output.status.code(), String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(!output.status.success(), "{log}");
    assert!(log.contains("a gateway is answering") && log.contains(&addr.to_string()), "names where it answers: {log}");
    assert!(!log.contains("Nothing to reset") && !log.contains("cleared"), "it touched nothing: {log}");
}
