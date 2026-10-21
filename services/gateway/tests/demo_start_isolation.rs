//! `permaura start --demo` on a machine with remote access leaves the real install alone.
//!
//! A demo shares the real install's home. Before the fix it applied the real `config.toml`, republished over the real `operator.token` once bound (OAuth was on from the file's public URL), and started a connector for the owner's tunnel with the demo as its origin, so the owner's hostname served a gateway that takes the published demo bearer.
#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

const CONFIG: &str = "public_url = \"https://g-demo.permaura.app\"\nowner_sub = \"user_owner\"\nas_issuer = \"https://permaura.test/api/auth\"\n\n[[announce]]\ngateway_id = \"gw_demo\"\nannounce_secret = \"gwa_demo_synthetic\"\n";
const OPERATOR_TOKEN: &str = "pgt_demo_real_install_placeholder";
const CREDENTIALS: &str = "{\"AccountTag\":\"acct_demo\",\"TunnelSecret\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"TunnelID\":\"6f3c2a1e-0b4d-4c7e-9a10-2b3c4d5e6f70\",\"Endpoint\":\"\"}";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("permaura-demo-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// A home with remote access on: a public URL and an announce link in `config.toml`, a published operator token and stored tunnel credentials.
fn real_install(home: &Path) {
    std::fs::write(home.join("config.toml"), CONFIG).unwrap();
    std::fs::write(home.join("operator.token"), OPERATOR_TOKEN).unwrap();
    std::fs::write(home.join("tunnel-credentials.json"), CREDENTIALS).unwrap();
}

/// A `cloudflared` on PATH that records that it was started.
fn fake_cloudflared(bin: &Path, marker: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let script = bin.join("cloudflared");
    std::fs::write(&script, format!("#!/bin/sh\necho started > '{}'\nexec sleep 60\n", marker.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn demo(home: &Path, bin: &Path, addr: &str, extra: &[&str]) -> tokio::process::Command {
    throwaway(home, bin, addr, &[&["--demo"], extra].concat(), false)
}

/// `permaura start` beside the real install: `--demo`, or `--mock` on an in-memory store when `in_memory` is set.
fn throwaway(home: &Path, bin: &Path, addr: &str, extra: &[&str], in_memory: bool) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    cmd.args(["start", "--addr", addr])
        .args(extra)
        .env("PERMAURA_HOME", home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_NO_UPGRADE", "1")
        .env("PATH", format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default()))
        .env("RUST_LOG", "info")
        // Unreachable, so a regression that pairs or announces never reaches permaura.com.
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
    ] {
        cmd.env_remove(key);
    }
    if in_memory {
        cmd.env("PERMAURA_STORE_PATH", ":memory:");
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    cmd
}

fn snapshot(home: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    ["config.toml", "operator.token", "tunnel-credentials.json", "cloudflared.yml", "tunnel.stopped", "cloudflared.log"]
        .iter()
        .map(|name| (name.to_string(), std::fs::read(home.join(name)).ok()))
        .collect()
}

fn free_addr() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert_ne!(port, 7376, "never the port a real gateway on this machine listens on");
    format!("127.0.0.1:{port}")
}

#[tokio::test]
async fn a_demo_start_leaves_the_real_config_token_and_tunnel_alone_and_starts_no_connector() {
    demo_leaves_the_install_alone("home", false, false, false).await;
}

/// The same with remote access set in the environment rather than the file, which the file's skip cannot reach.
#[tokio::test]
async fn a_demo_with_a_public_url_in_its_environment_still_leaves_the_install_alone() {
    demo_leaves_the_install_alone("env-home", true, false, false).await;
}

/// A pairing code still exported from following the installer's instructions is not a request to pair, so the demo starts and pairs nothing; only `--pair` on the command line is refused.
#[tokio::test]
async fn a_demo_starts_and_ignores_a_pair_code_left_in_its_environment() {
    demo_leaves_the_install_alone("pair-env-home", false, true, false).await;
}

/// The README's throwaway store (`PERMAURA_STORE_PATH=:memory:`) is a throwaway too, so it neither applies the real config nor fronts the owner's tunnel.
#[tokio::test]
async fn an_in_memory_start_leaves_the_real_config_token_and_tunnel_alone_and_starts_no_connector() {
    demo_leaves_the_install_alone("mem-home", false, true, true).await;
}

/// An in-memory gateway is never paired with the account either.
#[tokio::test]
async fn an_in_memory_start_cannot_be_paired() {
    common::isolate_from_the_real_install();
    let home = scratch("mem-pair-home");
    let bin = scratch("mem-pair-bin");
    real_install(&home);
    let addr = free_addr();
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        throwaway(&home, &bin, &addr, &["--mock", "--pair", "PAIR-MEMORY"], true).spawn().unwrap().wait_with_output(),
    )
    .await
    .expect("a refused start exits")
    .unwrap();
    let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(!output.status.success(), "an in-memory --pair is refused:\n{log}");
    assert!(log.contains("cannot be paired"), "{log}");
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&bin);
}

async fn demo_leaves_the_install_alone(name: &str, public_url_in_env: bool, pair_code_in_env: bool, in_memory: bool) {
    common::isolate_from_the_real_install();
    let home = scratch(name);
    let bin = scratch(&format!("{name}-bin"));
    let marker = bin.join("cloudflared-started");
    real_install(&home);
    fake_cloudflared(&bin, &marker);
    let before = snapshot(&home);
    let addr = free_addr();
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();

    let mut cmd = if in_memory { throwaway(&home, &bin, &addr, &["--mock"], true) } else { demo(&home, &bin, &addr, &[]) };
    if public_url_in_env {
        cmd.env("PERMAURA_PUBLIC_URL", "https://g-demo.permaura.app")
            .env("PERMAURA_OWNER_SUB", "user_owner")
            .env("PERMAURA_AS_ISSUER", "https://permaura.test/api/auth");
    }
    if pair_code_in_env {
        cmd.env("PERMAURA_PAIR_CODE", "PGW-DEMOENV1");
    }
    let mut child = cmd.spawn().expect("the gateway binary starts");
    let up = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                panic!("the demo exited with {status}");
            }
            if matches!(client.get(format!("http://{addr}/health")).send().await, Ok(r) if r.status().is_success()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(up.is_ok(), "the demo never answered on {addr}");
    let devices = client
        .get(format!("http://{addr}/v1/devices"))
        .bearer_auth(permaura_gateway::seed::DEMO_TOKEN)
        .send()
        .await
        .unwrap()
        .status();
    if !in_memory {
        assert_eq!(devices.as_u16(), 200, "it is the demo, taking the published bearer");
    }
    // The connector is started once the gateway answers its health check; give that every chance to happen.
    tokio::time::sleep(Duration::from_secs(4)).await;

    child.start_kill().ok();
    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output()).await.unwrap().unwrap();
    let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));

    assert!(!marker.exists(), "no tunnel connector was started for the owner's hostname:\n{log}");
    assert!(!log.contains("this gateway to your account"), "the demo tried to pair:\n{log}");
    // Compared with `assert!`, so a failure never prints the files' bytes.
    for ((name, was), (_, now)) in before.iter().zip(snapshot(&home).iter()) {
        assert!(was == now, "{name} was changed by a demo start:\n{log}");
    }
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&bin);
}

/// A demo serves the published demo operator bearer, so it binds loopback or nothing: an address off the machine is refused before anything binds. The addresses are documentation ranges no machine holds, so even a regression that tried to bind them would bind nothing.
#[tokio::test]
async fn a_demo_refuses_an_address_off_this_machine() {
    common::isolate_from_the_real_install();
    let home = scratch("offhost-home");
    let bin = scratch("offhost-bin");
    let port = free_addr().rsplit_once(':').unwrap().1.to_string();
    for addr in [format!("192.0.2.1:{port}"), format!("[2001:db8::1]:{port}")] {
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            demo(&home, &bin, &addr, &[]).spawn().unwrap().wait_with_output(),
        )
        .await
        .expect("a refused demo exits")
        .unwrap();
        let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(!output.status.success(), "{addr}: {log}");
        assert!(log.contains("--demo binds only a loopback address"), "{addr}: {log}");
    }
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&bin);
}

#[tokio::test]
async fn a_demo_cannot_be_paired() {
    common::isolate_from_the_real_install();
    let home = scratch("pair-home");
    let bin = scratch("pair-bin");
    let marker = bin.join("cloudflared-started");
    real_install(&home);
    fake_cloudflared(&bin, &marker);
    let before = snapshot(&home);
    let addr = free_addr();

    let output = tokio::time::timeout(
        Duration::from_secs(60),
        demo(&home, &bin, &addr, &["--pair", "PAIR-DEMO"]).spawn().unwrap().wait_with_output(),
    )
    .await
    .expect("a refused demo exits")
    .unwrap();
    let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(!output.status.success(), "--demo --pair is refused:\n{log}");
    assert!(log.contains("--demo cannot be paired"), "{log}");
    assert!(!marker.exists());
    for ((name, was), (_, now)) in before.iter().zip(snapshot(&home).iter()) {
        assert!(was == now, "{name} was changed by a refused demo start:\n{log}");
    }
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&bin);
}
