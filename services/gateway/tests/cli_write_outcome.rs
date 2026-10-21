//! A CLI write reports what the gateway did with it, not that an answer came back.
//!
//! `agent add`, `grant` and `vault add` printed their success line for any answer at all: a 401 or a 500 exited 0 saying the agent, grant or secret existed, and a 202 hid the approval it was waiting on. `vault import` read the 202 for an import that wrote part of a bundle and held the rest as a failure naming no approval, hiding both what it wrote and every approval it was waiting on. Each case runs the real binary against a responder on a free loopback port that proves the synthetic token the way a gateway does, then answers the write with the status under test. Every token, id and value here is synthetic.
#![cfg(unix)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

const TOKEN: &str = "pgt_cli_write_outcome_fixture_only";
const SECRET: &str = "cli-write-outcome-fixture-value-never-real";
const APPROVAL: &str = "appr_fixture_held";
const PASSPHRASE: &str = "cli-write-outcome-fixture-passphrase";
/// The exit status the CLI documents for a write held for approval and not yet applied.
const PENDING: i32 = 3;

#[derive(Clone)]
struct Route {
    method: Method,
    path: &'static str,
    status: u16,
    body: Value,
}

fn route(method: Method, path: &'static str, status: u16, body: Value) -> Route {
    Route { method, path, status, body }
}

#[derive(Clone, Debug)]
struct Hit {
    path: String,
    authorized: bool,
}

struct Fixture {
    port: u16,
    routes: Vec<Route>,
    hits: Mutex<Vec<Hit>>,
}

async fn answer(State(f): State<Arc<Fixture>>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().to_string();
    let bearer = format!("Bearer {TOKEN}");
    let authorized = headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(bearer.as_str());
    f.hits.lock().unwrap().push(Hit { path: path.clone(), authorized });
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
    match f.routes.iter().find(|r| r.method == method && r.path == path) {
        Some(r) => (StatusCode::from_u16(r.status).unwrap(), Json(r.body.clone())).into_response(),
        None => (
            StatusCode::IM_A_TEAPOT,
            Json(json!({ "error": format!("the fixture has no route for {method} {path}") })),
        )
            .into_response(),
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    hits: Vec<Hit>,
}

impl Run {
    fn requests_to(&self, path: &str) -> usize {
        self.hits.iter().filter(|h| h.path == path).count()
    }

    fn log(&self) -> String {
        format!("exit {}\n--- stdout\n{}\n--- stderr\n{}", self.code, self.stdout, self.stderr)
    }
}

/// The CLI names a loopback listener's owner by listing this process's sockets, and that listing can miss the listener while sibling cases open and close theirs, which reads as another user's and is refused. So the cases take turns.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serve(routes: Vec<Route>) -> (std::net::SocketAddr, Arc<Fixture>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    assert_ne!(addr.port(), 7376, "never the port a real gateway on this machine listens on");
    let fixture = Arc::new(Fixture { port: addr.port(), routes, hits: Mutex::new(Vec::new()) });
    let app = axum::Router::new().fallback(answer).with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, fixture, server)
}

fn checked(run: Run) -> Run {
    for never in [SECRET, PASSPHRASE] {
        assert!(!run.stdout.contains(never) && !run.stderr.contains(never), "nothing secret is echoed: {}", run.log());
    }
    assert!(
        run.hits.iter().filter(|h| h.path != "/health").all(|h| h.authorized),
        "every write carried the proved token: {:?}",
        run.hits
    );
    run
}

async fn run(routes: Vec<Route>, args: &[&str]) -> Run {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = std::env::var("PERMAURA_HOME").unwrap();
    let (addr, fixture, server) = serve(routes).await;

    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"))
            .args(["--url", &format!("http://{addr}"), "--token", TOKEN])
            .args(args)
            .env("FIXTURE_SECRET_VALUE", SECRET)
            .env_remove("PERMAURA_TOKEN")
            .env_remove("PERMAURA_URL")
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
    let hits = fixture.hits.lock().unwrap().clone();
    checked(Run {
        code: output.status.code().expect("the CLI exited on its own"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        hits,
    })
}

/// The 202 a held control-plane write answers with, in the shape `held_body` serves.
fn held() -> Value {
    json!({
        "approval_id": APPROVAL,
        "status": "requires_approval",
        "required_tier": "device_signed",
        "required_signatures": 1,
        "message": "Approve only if you made this change. It came through your Permaura account, so a paired device has to confirm it.",
        "notified": "Notified where a push token is registered.",
        "expires_at": null,
        "risk": "high",
        "action_description": "fixture change",
    })
}

fn error(status: u16) -> Value {
    match status {
        401 => json!({ "error": "invalid operator token" }),
        _ => json!({ "error": "fixture storage unavailable" }),
    }
}

/// One of the three writes that printed success for any answer.
struct Write {
    args: &'static [&'static str],
    target: &'static str,
    applied: fn() -> Value,
    claim: &'static str,
    id: &'static str,
}

const AGENT_ADD: Write = Write {
    args: &["agent", "add", "Fixture Agent"],
    target: "/v1/agents/register",
    applied: || json!({ "agent_id": "agent_fixture" }),
    claim: "Agent registered",
    id: "agent_fixture",
};

const VAULT_ADD: Write = Write {
    args: &["vault", "add", "sec_fixture", "--env-var", "FIXTURE_SECRET_VALUE"],
    target: "/v1/secrets",
    applied: || json!({ "secret_id": "sec_fixture", "value": "[REDACTED]" }),
    claim: "Secret stored",
    id: "sec_fixture",
};

const GRANT: Write = Write {
    args: &["grant", "--agent", "agent_fixture", "--resource", "fixture", "--allow", "read"],
    target: "/v1/grants",
    applied: || json!({ "grant_id": "grant_fixture" }),
    claim: "Grant created",
    id: "grant_fixture",
};

fn policy_applied() -> Route {
    route(Method::POST, "/v1/policies", 201, json!({ "policy_id": "policy_fixture" }))
}

async fn answered(w: &Write, status: u16, body: Value) -> Run {
    run(vec![policy_applied(), route(Method::POST, w.target, status, body)], w.args).await
}

async fn applied_is_reported(w: Write) {
    let run = answered(&w, 201, (w.applied)()).await;
    assert_eq!(run.requests_to(w.target), 1, "{}", run.log());
    assert_eq!(run.code, 0, "{}", run.log());
    assert!(run.stdout.contains(w.claim) && run.stdout.contains(w.id), "{}", run.log());
}

async fn held_is_pending(w: Write) {
    let run = answered(&w, 202, held()).await;
    assert_eq!(run.requests_to(w.target), 1, "{}", run.log());
    assert!(!run.stdout.contains(w.claim), "a held write is not applied: {}", run.log());
    assert!(run.stdout.contains(APPROVAL), "the hold is addressable: {}", run.log());
    assert_eq!(run.code, PENDING, "held is neither done nor failed: {}", run.log());
}

async fn failure_fails(w: Write, status: u16) {
    let run = answered(&w, status, error(status)).await;
    assert_eq!(run.requests_to(w.target), 1, "{}", run.log());
    assert!(!run.stdout.contains(w.claim), "a failed write never claims success: {}", run.log());
    assert_eq!(run.code, 1, "a failed write fails the command: {}", run.log());
    let detail = error(status)["error"].as_str().unwrap().to_string();
    assert!(
        run.stderr.contains(&status.to_string()) && run.stderr.contains(&detail),
        "the failure names the status and the gateway's own words: {}",
        run.log()
    );
}

/// `vault list` names every stored secret by its id, which is what `vault add`, a connection's credential and a rotation take; values are never listed.
#[tokio::test]
async fn vault_list_prints_every_secret_id() {
    let secrets = json!({ "secrets": [
        { "id": "stripe_live", "labels": ["billing"], "risk_classification": "high", "allowed_execution_locations": [], "last_used_at": null, "location": "local_vault" },
        { "id": "github_ci", "labels": [], "risk_classification": "high", "allowed_execution_locations": [], "last_used_at": null, "location": "local_vault" },
        { "id": "payroll_kms", "labels": [], "risk_classification": "high", "allowed_execution_locations": [], "last_used_at": null, "location": "kms" },
    ]});
    let run = run(vec![route(Method::GET, "/v1/secrets", 200, secrets)], &["vault", "list"]).await;
    assert_eq!(run.code, 0, "{}", run.log());
    assert_eq!(run.requests_to("/v1/secrets"), 1, "it asks the gateway for the list: {}", run.log());
    for id in ["stripe_live", "github_ci", "payroll_kms"] {
        assert!(run.stdout.contains(id), "{id} is listed: {}", run.log());
    }
    // Where each is held is said, and no last use is claimed, since nothing records one.
    assert!(run.stdout.lines().any(|l| l.contains("payroll_kms") && l.contains("held by KMS")), "{}", run.log());
    assert!(!run.stdout.contains("never used") && !run.stdout.contains("last used"), "{}", run.log());

    let empty = self::run(vec![route(Method::GET, "/v1/secrets", 200, json!({ "secrets": [] }))], &["vault", "list"]).await;
    assert_eq!(empty.code, 0, "{}", empty.log());
    assert!(empty.stdout.contains("No secrets are stored"), "{}", empty.log());

    let refused = self::run(vec![route(Method::GET, "/v1/secrets", 401, error(401))], &["vault", "list"]).await;
    assert_ne!(refused.code, 0, "a refusal is not an empty vault: {}", refused.log());
}

#[tokio::test]
async fn agent_add_reports_201_as_registered() {
    applied_is_reported(AGENT_ADD).await;
}

#[tokio::test]
async fn agent_add_reports_202_as_pending() {
    held_is_pending(AGENT_ADD).await;
}

#[tokio::test]
async fn agent_add_reports_401_as_failed() {
    failure_fails(AGENT_ADD, 401).await;
}

#[tokio::test]
async fn agent_add_reports_500_as_failed() {
    failure_fails(AGENT_ADD, 500).await;
}

#[tokio::test]
async fn vault_add_reports_201_as_stored() {
    applied_is_reported(VAULT_ADD).await;
}

#[tokio::test]
async fn vault_add_reports_202_as_pending() {
    held_is_pending(VAULT_ADD).await;
}

#[tokio::test]
async fn vault_add_reports_401_as_failed() {
    failure_fails(VAULT_ADD, 401).await;
}

#[tokio::test]
async fn vault_add_reports_500_as_failed_and_says_to_keep_the_value() {
    failure_fails(VAULT_ADD, 500).await;
    let run = answered(&VAULT_ADD, 500, error(500)).await;
    assert!(run.stderr.contains("Keep your copy of the value"), "{}", run.log());
}

#[tokio::test]
async fn grant_reports_201_as_created() {
    applied_is_reported(GRANT).await;
}

#[tokio::test]
async fn grant_reports_202_as_pending() {
    held_is_pending(GRANT).await;
}

#[tokio::test]
async fn grant_reports_401_as_failed() {
    failure_fails(GRANT, 401).await;
}

#[tokio::test]
async fn grant_reports_500_as_failed_and_names_the_policy_it_left() {
    failure_fails(GRANT, 500).await;
    let run = answered(&GRANT, 500, error(500)).await;
    assert!(run.stderr.contains("policy_fixture"), "{}", run.log());
}

#[tokio::test]
async fn an_applied_answer_without_its_id_is_not_reported_as_done() {
    for w in [AGENT_ADD, VAULT_ADD, GRANT] {
        let run = answered(&w, 201, json!({})).await;
        assert!(!run.stdout.contains(w.claim), "{}", run.log());
        assert_eq!(run.code, 1, "{}", run.log());
    }
}

#[tokio::test]
async fn a_hold_that_names_no_approval_is_neither_done_nor_pending() {
    for w in [AGENT_ADD, VAULT_ADD, GRANT] {
        let run = answered(&w, 202, json!({ "status": "requires_approval" })).await;
        assert!(!run.stdout.contains(w.claim), "{}", run.log());
        assert_eq!(run.code, 1, "{}", run.log());
    }
}

#[tokio::test]
async fn a_held_policy_stops_grant_before_the_grant() {
    let run = run(
        vec![
            route(Method::POST, "/v1/policies", 202, held()),
            route(Method::POST, "/v1/grants", 201, json!({ "grant_id": "grant_fixture" })),
        ],
        GRANT.args,
    )
    .await;
    assert_eq!(run.requests_to("/v1/grants"), 0, "a grant cannot bind a policy that does not exist yet: {}", run.log());
    assert!(run.stdout.contains(APPROVAL) && !run.stdout.contains("Grant created"), "{}", run.log());
    assert_eq!(run.code, PENDING, "{}", run.log());
}

#[tokio::test]
async fn a_refused_policy_stops_grant_with_the_gateways_reason() {
    let run = run(
        vec![route(
            Method::POST,
            "/v1/policies",
            400,
            json!({ "error": "connection 'fixture' has no capabilities" }),
        )],
        GRANT.args,
    )
    .await;
    assert_eq!(run.requests_to("/v1/grants"), 0, "{}", run.log());
    assert!(run.stderr.contains("connection 'fixture' has no capabilities"), "{}", run.log());
    assert_eq!(run.code, 1, "{}", run.log());
}

fn approvals(status: &str) -> Vec<Route> {
    vec![route(
        Method::POST,
        "/v1/approvals",
        200,
        json!({ "approval_id": "appr_fixture", "status": status, "resolution_reason": "fixture reason" }),
    )]
}

#[tokio::test]
async fn approve_and_deny_report_the_status_they_asked_for() {
    let approved = run(approvals("approved"), &["approve", "appr_fixture"]).await;
    assert_eq!(approved.code, 0, "{}", approved.log());
    assert!(approved.stdout.contains("Approval resolved"), "{}", approved.log());
    let denied = run(approvals("denied"), &["deny", "appr_fixture"]).await;
    assert_eq!(denied.code, 0, "{}", denied.log());
    assert!(denied.stdout.contains("nothing ran upstream"), "{}", denied.log());
}

#[tokio::test]
async fn approve_fails_for_an_approval_that_did_not_run() {
    for status in ["denied", "unresolved"] {
        let run = run(approvals(status), &["approve", "appr_fixture"]).await;
        assert!(!run.stdout.contains("Approval resolved"), "{}", run.log());
        assert!(run.stderr.contains(status), "{}", run.log());
        assert_eq!(run.code, 1, "{}", run.log());
    }
}

#[tokio::test]
async fn deny_never_claims_to_drop_a_call_that_already_ran() {
    let run = run(approvals("approved"), &["deny", "appr_fixture"]).await;
    assert!(!run.stdout.contains("nothing ran upstream"), "{}", run.log());
    assert!(run.stderr.contains("approved"), "{}", run.log());
    assert_eq!(run.code, 1, "{}", run.log());
}

#[tokio::test]
async fn approve_without_a_status_is_not_reported_as_resolved() {
    let run = run(
        vec![route(Method::POST, "/v1/approvals", 200, json!({ "approval_id": "appr_fixture" }))],
        &["approve", "appr_fixture"],
    )
    .await;
    assert!(!run.stdout.contains("Approval resolved"), "{}", run.log());
    assert_eq!(run.code, 1, "{}", run.log());
}

const ADD_SSH: &[&str] = &[
    "connection",
    "add-ssh",
    "conn_fixture",
    "--host",
    "ssh.fixture.test",
    "--user",
    "deploy",
    "--insecure",
    "--password-env",
    "FIXTURE_SECRET_VALUE",
    "--exec",
    "uptime:uptime",
    "--agent",
    "agent_fixture",
];

fn add_ssh(credential: (u16, Value), grant: (u16, Value)) -> Vec<Route> {
    vec![
        route(Method::POST, "/v1/connections", 201, json!({ "connection_id": "conn_fixture" })),
        route(Method::POST, "/v1/connections/conn_fixture/credential", credential.0, credential.1),
        policy_applied(),
        route(Method::POST, "/v1/grants", grant.0, grant.1),
    ]
}

fn credential_applied() -> (u16, Value) {
    (200, json!({ "connection_id": "conn_fixture", "rotated": false }))
}

fn grant_applied() -> (u16, Value) {
    (201, json!({ "grant_id": "grant_fixture" }))
}

#[tokio::test]
async fn add_ssh_reports_every_applied_step() {
    let run = run(add_ssh(credential_applied(), grant_applied()), ADD_SSH).await;
    assert_eq!(run.code, 0, "{}", run.log());
    assert!(run.stdout.contains("credential sealed in the vault"), "{}", run.log());
    assert!(run.stdout.contains("grant grant_fixture"), "{}", run.log());
}

#[tokio::test]
async fn add_ssh_reports_a_held_credential_as_pending_not_sealed() {
    let run = run(add_ssh((202, held()), grant_applied()), ADD_SSH).await;
    assert!(!run.stdout.contains("credential sealed in the vault"), "{}", run.log());
    assert!(run.stdout.contains(APPROVAL), "{}", run.log());
    assert!(run.stdout.contains("grant grant_fixture"), "the grant does not depend on the credential: {}", run.log());
    assert_eq!(run.code, PENDING, "{}", run.log());
}

#[tokio::test]
async fn add_ssh_reports_a_failed_grant_as_failed() {
    let run = run(add_ssh(credential_applied(), (500, error(500))), ADD_SSH).await;
    assert!(!run.stdout.contains("granted to"), "{}", run.log());
    assert!(run.stderr.contains("fixture storage unavailable"), "{}", run.log());
    assert_eq!(run.code, 1, "{}", run.log());
}

#[tokio::test]
async fn add_ssh_reports_a_held_grant_as_pending() {
    let run = run(add_ssh(credential_applied(), (202, held())), ADD_SSH).await;
    assert!(!run.stdout.contains("granted to"), "{}", run.log());
    assert!(run.stdout.contains(APPROVAL), "{}", run.log());
    assert_eq!(run.code, PENDING, "{}", run.log());
}

#[tokio::test]
async fn trust_root_holds_exit_pending_too() {
    let floor = run(
        vec![route(Method::PUT, "/v1/approval-floor", 202, held())],
        &["approver", "floor", "approve"],
    )
    .await;
    assert!(floor.stdout.contains(APPROVAL), "{}", floor.log());
    assert_eq!(floor.code, PENDING, "{}", floor.log());
    let revoke = run(
        vec![route(Method::DELETE, "/v1/approver-keys/appr_device", 202, held())],
        &["approver", "revoke", "appr_device"],
    )
    .await;
    assert!(revoke.stdout.contains(APPROVAL), "{}", revoke.log());
    assert_eq!(revoke.code, PENDING, "{}", revoke.log());
}

#[tokio::test]
async fn a_floor_answer_without_the_floor_is_not_reported_as_set() {
    let run = run(
        vec![route(Method::PUT, "/v1/approval-floor", 200, json!({}))],
        &["approver", "floor", "device_signed"],
    )
    .await;
    assert!(!run.stdout.contains("approval floor:"), "{}", run.log());
    assert_eq!(run.code, 1, "{}", run.log());
}

/// `vault import` reads its passphrase through a masked prompt that opens the controlling terminal, so its cases run the binary on a pseudo-terminal of its own, answer the passphrase only once the prompt has switched echo off, and then confirm. Output arrives on the one terminal, so `stdout` holds both streams.
async fn import(answer: (u16, Value)) -> Run {
    let _turn = TURN.lock().await;
    common::isolate_from_the_real_install();
    let home = std::env::var("PERMAURA_HOME").unwrap();
    static BUNDLES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let bundle = std::path::Path::new(&home)
        .join(format!("fixture-bundle-{}.json", BUNDLES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    std::fs::write(&bundle, "{}").unwrap();
    let preview = json!({
        "source_gateway_id": "gw_fixture_source",
        "source_mode": "fixture",
        "counts": { "connections": 2, "secrets": 2 },
        "conflicts": {},
        "command_capabilities": [],
    });
    let (addr, fixture, server) = serve(vec![
        route(Method::POST, "/v1/vault/import/preview", 200, preview),
        route(Method::POST, "/v1/vault/import", answer.0, answer.1),
    ])
    .await;

    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    command
        .args(["--url", &format!("http://{addr}"), "--token", TOKEN, "vault", "import"])
        .arg(&bundle)
        .env_remove("PERMAURA_TOKEN")
        .env_remove("PERMAURA_URL")
        .env("PERMAURA_HOME", &home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_NO_UPGRADE", "1");
    let (code, output) = tokio::task::spawn_blocking(move || on_a_terminal(command)).await.unwrap();
    server.abort();
    let hits = fixture.hits.lock().unwrap().clone();
    let run = checked(Run { code, stdout: output, stderr: String::new(), hits });
    assert_eq!(run.requests_to("/v1/vault/import/preview"), 1, "{}", run.log());
    assert_eq!(run.requests_to("/v1/vault/import"), 1, "{}", run.log());
    run
}

fn on_a_terminal(mut command: std::process::Command) -> (i32, String) {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;

    let (primary, secondary) = {
        let (mut primary, mut secondary) = (-1, -1);
        let opened = unsafe {
            libc::openpty(&mut primary, &mut secondary, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(opened, 0, "a pseudo-terminal: {}", std::io::Error::last_os_error());
        unsafe { (OwnedFd::from_raw_fd(primary), OwnedFd::from_raw_fd(secondary)) }
    };
    command
        .stdin(secondary.try_clone().unwrap())
        .stdout(secondary.try_clone().unwrap())
        .stderr(secondary);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    // The parent's copies of the secondary side go with the command, so the primary reads end-of-file once the CLI exits.
    drop(command);

    let fd = primary.as_raw_fd();
    let mut terminal = std::fs::File::from(primary);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let echo_is_off = || {
        let mut modes: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(fd, &mut modes) == 0 && modes.c_lflag & libc::ECHO == 0 }
    };
    let mut output = Vec::new();
    let (mut passphrase_sent, mut confirmed) = (false, false);
    loop {
        assert!(std::time::Instant::now() < deadline, "the CLI finishes: {}", String::from_utf8_lossy(&output));
        let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut poll, 1, 100) } > 0 {
            let mut chunk = [0u8; 4096];
            match terminal.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&chunk[..n]),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => panic!("reading the terminal: {e}"),
            }
        }
        let seen = String::from_utf8_lossy(&output);
        if !passphrase_sent && seen.contains("Bundle passphrase: ") && echo_is_off() {
            terminal.write_all(format!("{PASSPHRASE}\n").as_bytes()).unwrap();
            passphrase_sent = true;
        }
        if !confirmed && seen.contains("[type 'yes' to continue]: ") {
            terminal.write_all(b"yes\n").unwrap();
            confirmed = true;
        }
    }
    let status = child.wait().unwrap();
    (status.code().expect("the CLI exited on its own"), String::from_utf8_lossy(&output).into_owned())
}

/// One credential the import held, in the shape `import_vault` lists it: `held_body` plus the secret it would fill.
fn held_credential(approval_id: &str, secret_id: &str) -> Value {
    let mut entry = held();
    entry["approval_id"] = json!(approval_id);
    entry["secret_id"] = json!(secret_id);
    entry
}

/// An import that wrote part of a bundle and held the rest, as `import_vault` answers it: the outcome's counts, no top-level approval, and every hold in `held`.
fn partly_held(held: Vec<Value>) -> (u16, Value) {
    (
        202,
        json!({
            "written": { "connections": 1, "policies": 2 },
            "skipped": { "connections": 1 },
            "refused": ["capability cap_fixture_local runs a local program"],
            "status": "requires_approval",
            "held": held,
        }),
    )
}

#[tokio::test]
async fn import_reports_an_applied_bundle_as_imported() {
    let run = import((
        200,
        json!({ "written": { "connections": 1, "secrets": 1 }, "skipped": {}, "refused": [] }),
    ))
    .await;
    assert_eq!(run.code, 0, "{}", run.log());
    assert!(run.stdout.contains("Imported") && run.stdout.contains("written: 1 connections, 1 secrets"), "{}", run.log());
}

#[tokio::test]
async fn import_reports_one_held_credential_as_pending_with_what_it_wrote() {
    let run = import(partly_held(vec![held_credential("appr_fixture_one", "sec_fixture_one")])).await;
    assert_eq!(run.code, PENDING, "held credentials leave the import pending, not failed: {}", run.log());
    assert!(run.stdout.contains("appr_fixture_one") && run.stdout.contains("sec_fixture_one"), "{}", run.log());
    assert!(run.stdout.contains("written: 1 connections, 2 policies"), "what applied is reported: {}", run.log());
    assert!(!run.stdout.contains("Error:"), "{}", run.log());
}

#[tokio::test]
async fn import_reports_every_held_credential() {
    let ids = [("appr_fixture_one", "sec_fixture_one"), ("appr_fixture_two", "sec_fixture_two"), ("appr_fixture_three", "sec_fixture_three")];
    let run = import(partly_held(ids.iter().map(|(a, s)| held_credential(a, s)).collect())).await;
    assert_eq!(run.code, PENDING, "{}", run.log());
    for (approval, secret) in ids {
        assert!(run.stdout.contains(approval) && run.stdout.contains(secret), "every hold is addressable: {}", run.log());
    }
    assert!(run.stdout.contains("written: 1 connections, 2 policies"), "{}", run.log());
}

#[tokio::test]
async fn import_reports_a_partial_write_in_full() {
    let run = import(partly_held(vec![held_credential("appr_fixture_one", "sec_fixture_one")])).await;
    assert_eq!(run.code, PENDING, "{}", run.log());
    assert!(run.stdout.contains("written: 1 connections, 2 policies"), "{}", run.log());
    assert!(run.stdout.contains("skipped: 1 connections"), "{}", run.log());
    assert!(run.stdout.contains("capability cap_fixture_local runs a local program"), "what was refused is reported: {}", run.log());
}

#[tokio::test]
async fn import_still_reports_a_single_held_import_as_pending() {
    let run = import((202, held())).await;
    assert_eq!(run.code, PENDING, "{}", run.log());
    assert!(run.stdout.contains(APPROVAL), "{}", run.log());
    assert!(!run.stdout.contains("Imported"), "nothing applied yet: {}", run.log());
}

#[tokio::test]
async fn import_fails_a_held_credential_that_names_no_approval() {
    let mut nameless = held_credential("", "sec_fixture_two");
    nameless.as_object_mut().unwrap().remove("approval_id");
    for held in [vec![nameless.clone()], vec![held_credential("appr_fixture_one", "sec_fixture_one"), nameless], vec![]] {
        let run = import(partly_held(held)).await;
        assert_eq!(run.code, 1, "a hold nothing can follow up is neither done nor pending: {}", run.log());
        assert!(!run.stdout.contains("Imported"), "{}", run.log());
    }
}

#[tokio::test]
async fn import_fails_an_answer_that_does_not_say_what_it_wrote() {
    let (status, mut body) = partly_held(vec![held_credential("appr_fixture_one", "sec_fixture_one")]);
    body.as_object_mut().unwrap().remove("written");
    let run = import((status, body)).await;
    assert_eq!(run.code, 1, "{}", run.log());
    assert!(!run.stdout.contains("Imported"), "{}", run.log());
}

#[tokio::test]
async fn import_reports_an_http_failure_as_failed() {
    let run = import((500, error(500))).await;
    assert_eq!(run.code, 1, "{}", run.log());
    assert!(run.stdout.contains("500") && run.stdout.contains("fixture storage unavailable"), "{}", run.log());
    assert!(!run.stdout.contains("Imported"), "{}", run.log());
}
