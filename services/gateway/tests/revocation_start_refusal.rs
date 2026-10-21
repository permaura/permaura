//! `permaura start` refuses to start when `PERMAURA_PMCONN_REVOCATION` names a list it cannot verify, rather than running as if nothing were revoked.

mod common;

use std::path::PathBuf;
use std::time::Duration;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("permaura-revocation-start-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn start_with(name: &str, revocation: &str) -> (Option<i32>, String) {
    let home = scratch(name);
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    cmd.args(["start", "--demo", "--addr", &format!("127.0.0.1:{}", free_port())])
        .env("PERMAURA_HOME", &home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_NO_UPGRADE", "1")
        .env("PERMAURA_PMCONN_REVOCATION", revocation)
        .env("PERMAURA_API", "https://127.0.0.1:9")
        .env("PERMAURA_CONTROL_PLANE_URL", "https://127.0.0.1:9")
        .env_remove("PERMAURA_HOSTED")
        .env_remove("PERMAURA_RELAY_URL")
        .env_remove("PERMAURA_STORE_PATH")
        .env_remove("PERMAURA_ADDR")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let child = cmd.spawn().expect("the gateway binary runs");
    let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("{name}: the gateway was still running after 20s, so it started under a list it could not verify"))
        .expect("the gateway's output");
    let _ = std::fs::remove_dir_all(&home);
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[tokio::test]
async fn an_unverifiable_revocation_list_stops_the_gateway_starting() {
    let missing = std::env::temp_dir().join(format!("permaura-no-such-revocation-{}.json", std::process::id()));
    let forged = r#"{"revoked_key_ids":[],"revoked_manifests":[],"issued_at":1,"serial":1,"root_key_id":"pmconn-root-2026a","root_sig":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}"#;
    for (name, revocation, reason) in [
        ("unreadable", missing.to_str().unwrap(), "cannot be read"),
        ("not-json", "{ not a list", "is not a revocation list"),
        ("bad-signature", forged, "does not verify"),
    ] {
        let (code, stderr) = start_with(name, revocation).await;
        assert_ne!(code, Some(0), "{name}: {stderr}");
        assert!(
            stderr.contains("PERMAURA_PMCONN_REVOCATION") && stderr.contains(reason) && stderr.contains("refusing to start"),
            "{name}: the refusal names the variable and why: {stderr}"
        );
    }
}
