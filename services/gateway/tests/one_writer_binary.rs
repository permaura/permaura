//! Two real `permaura start` processes on one home: the second serves only once the first has exited.
//!
//! The shipped binary, with a persistent store in a scratch home, mock transports and free ports.
//! `permaura stop` used to report a gateway stopped once its `/health` went quiet, which happens as
//! its drain begins, and nothing kept a second `start` off the store while the first was still
//! writing to it.
#![cfg(all(unix, feature = "sqlite"))]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permaura-one-writer-bin-{name}-{}-{}",
        std::process::id(),
        permaura_gateway::service::short_id()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn free_addr() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert!(![7376, 8787, 3102, 8081, 8799, 18787].contains(&port), "never a port a real gateway or dev server uses");
    format!("127.0.0.1:{port}")
}

/// `permaura` with a scratch home and nothing that reaches beyond this machine.
fn permaura(home: &Path, log: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    cmd.env("PERMAURA_HOME", home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_NO_UPGRADE", "1")
        .env("RUST_LOG", "info")
        .env("PERMAURA_API", "https://127.0.0.1:9")
        .env("PERMAURA_CONTROL_PLANE_URL", "https://127.0.0.1:9");
    for key in [
        "PERMAURA_HOSTED",
        "PERMAURA_RELAY_URL",
        "PERMAURA_STORE_PATH",
        "PERMAURA_STORE_BUCKET",
        "PERMAURA_PUBLIC_URL",
        "PERMAURA_OWNER_SUB",
        "PERMAURA_AS_ISSUER",
        "PERMAURA_GATEWAY_ID",
        "PERMAURA_ANNOUNCE_SECRET",
        "PERMAURA_ADDR",
        "PERMAURA_URL",
        "PERMAURA_TOKEN",
    ] {
        cmd.env_remove(key);
    }
    let out = std::fs::File::create(log).unwrap();
    let err = out.try_clone().unwrap();
    cmd.stdin(std::process::Stdio::null()).stdout(out).stderr(err).kill_on_drop(true);
    cmd
}

fn gateway(home: &Path, addr: &str, log: &Path) -> tokio::process::Child {
    permaura(home, log).args(["start", "--mock", "--addr", addr]).spawn().expect("the gateway binary starts")
}

async fn healthy_within(addr: &str, limit: Duration) -> bool {
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(1)).build().unwrap();
    let health = format!("http://{addr}/health");
    tokio::time::timeout(limit, async {
        loop {
            if matches!(client.get(&health).send().await, Ok(r) if r.status().is_success()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok()
}

/// The one-writer lifecycle: a second gateway on the same home does not serve while the first holds the store; `permaura stop` reports the first stopped only once it has exited; the second then comes up, and says what it waited for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_gateway_on_one_home_serves_only_once_the_first_has_exited() {
    common::isolate_from_the_real_install();
    let home = scratch("home");
    let (first_addr, second_addr) = (free_addr(), free_addr());
    let (first_log, second_log, stop_log) = (home.join("first.log"), home.join("second.log"), home.join("stop.log"));

    let mut first = gateway(&home, &first_addr, &first_log);
    assert!(
        healthy_within(&first_addr, Duration::from_secs(60)).await,
        "the first gateway never answered: {}",
        std::fs::read_to_string(&first_log).unwrap_or_default()
    );
    let first_pid = first.id().expect("running");

    let mut second = gateway(&home, &second_addr, &second_log);
    assert!(
        !healthy_within(&second_addr, Duration::from_secs(3)).await,
        "a second gateway served the same store while the first was still running: {}",
        std::fs::read_to_string(&second_log).unwrap_or_default()
    );

    let stopped = permaura(&home, &stop_log)
        .args(["stop", "--url", &format!("http://{first_addr}")])
        .status()
        .await
        .unwrap();
    let said = std::fs::read_to_string(&stop_log).unwrap_or_default();
    assert!(stopped.success(), "permaura stop failed: {said}");
    assert!(said.contains("has stopped"), "{said}");
    assert!(
        first.try_wait().unwrap().is_some(),
        "permaura stop said the first gateway had stopped while its process was still running: {said}"
    );

    assert!(
        healthy_within(&second_addr, Duration::from_secs(30)).await,
        "the second gateway never came up once the store was free: {}",
        std::fs::read_to_string(&second_log).unwrap_or_default()
    );
    let pid = second.id().expect("running") as i32;
    // SAFETY: signalling the child this test spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let _ = tokio::time::timeout(Duration::from_secs(20), second.wait()).await;
    let second_said = std::fs::read_to_string(&second_log).unwrap_or_default();
    assert!(
        second_said.contains(&format!("pid {first_pid}")),
        "the second gateway says which process it waited for: {second_said}"
    );
    std::fs::remove_dir_all(&home).ok();
}

/// A store that lost its audit key stops `permaura start` with an exit code of its own, so a supervisor can say why rather than count a crash, and the message names the repair and what starting over costs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_that_lost_its_audit_key_stops_start_with_its_own_exit_code() {
    common::isolate_from_the_real_install();
    let home = scratch("lost-key");
    let db = home.join("gateway.db");
    let store = permaura_gateway::store::sqlite::SqliteStore::open(db.to_str().unwrap()).unwrap();
    permaura_gateway::store::Store::append_audit(&store, permaura_core::AuditPayload::new("synthetic.action", "synthetic", "allow")).unwrap();
    drop(store);
    std::fs::remove_file(home.join("gateway.db.auditkey")).unwrap();

    let log = home.join("start.log");
    let mut gateway = gateway(&home, &free_addr(), &log);
    let status = tokio::time::timeout(Duration::from_secs(60), gateway.wait()).await.expect("start refuses").unwrap();
    let said = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(status.code(), Some(74), "its own exit code: {said}");
    assert!(said.contains("permaura audit rekey --yes"), "{said}");
    assert!(said.contains("every connection"), "it says what starting over costs: {said}");
    std::fs::remove_dir_all(&home).ok();
}

/// A second `permaura start` against this home's gateway already serving its address is refused at once, naming it, rather than after the whole store wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_start_against_this_homes_running_gateway_is_refused_at_once() {
    common::isolate_from_the_real_install();
    let home = scratch("second-start");
    let addr = free_addr();
    let mut first = gateway(&home, &addr, &home.join("first.log"));
    assert!(healthy_within(&addr, Duration::from_secs(60)).await, "{}", std::fs::read_to_string(home.join("first.log")).unwrap_or_default());

    let log = home.join("second.log");
    let started = std::time::Instant::now();
    let mut second = gateway(&home, &addr, &log);
    let status = tokio::time::timeout(Duration::from_secs(60), second.wait()).await.expect("the second start ends").unwrap();
    let took = started.elapsed();
    let said = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(status.code(), Some(73), "{said}");
    assert!(took < Duration::from_secs(10), "refused at once, not after the store wait ({took:?}): {said}");
    assert!(said.contains(&addr), "it names the address already served: {said}");
    let pid = first.id().expect("running") as i32;
    // SAFETY: signalling the child this test spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let _ = tokio::time::timeout(Duration::from_secs(20), first.wait()).await;
    std::fs::remove_dir_all(&home).ok();
}
