//! The shipped binary drains on SIGTERM instead of dying where it stands.
//!
//! SIGTERM is how Cloud Run, systemd, launchd and the desktop supervisor stop a gateway. Before the
//! drain, `permaura start` installed no handler for it, so the signal's default action ended the
//! process mid-call with no terminal audit event. This runs the real
//! binary as a throwaway demo gateway: in memory, mock transports, a scratch home, a free port.
#![cfg(unix)]

mod common;

use std::time::Duration;

#[tokio::test]
async fn permaura_start_drains_and_exits_cleanly_on_sigterm() {
    common::isolate_from_the_real_install();
    let home = std::env::var("PERMAURA_HOME").unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert_ne!(port, 7376, "never the port a real gateway on this machine listens on");
    let addr = format!("127.0.0.1:{port}");

    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"))
        .args(["start", "--demo", "--addr", &addr])
        .env("PERMAURA_HOME", &home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_NO_UPGRADE", "1")
        .env_remove("PERMAURA_HOSTED")
        .env_remove("PERMAURA_RELAY_URL")
        .env("RUST_LOG", "info")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("the gateway binary starts");

    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
    let health = format!("http://{addr}/health");
    let up = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if matches!(client.get(&health).send().await, Ok(r) if r.status().is_success()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(up.is_ok(), "the demo gateway never answered {health}");

    let pid = child.id().expect("running") as i32;
    // SAFETY: signalling the child this test spawned.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("a drained gateway exits inside its window")
        .unwrap();
    let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "SIGTERM must drain and exit 0, not end the process by signal: {:?}\n{log}",
        output.status
    );
    assert!(log.contains("SIGTERM received: draining"), "{log}");
    assert!(log.contains("drain finished"), "{log}");
}
