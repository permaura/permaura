//! The boot rotation, on the real binary: a gateway with a public URL replaces `operator.token` and ends every earlier operator token once it holds its address, and a second `permaura start` on the same home that loses the bind changes nothing.
//!
//! The regression: the rotation ran while the state was built, before the bind, so the second process wrote a fresh token, ended the running gateway's, then failed to bind and exited. The running gateway's `/health` proof still named the dead token, so every CLI command refused the listener as not this home's until the refresher's next tick.
#![cfg(all(unix, feature = "sqlite"))]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use permaura_core::health_proof::{new_challenge, verify, CHALLENGE_HEADER, PROOF_HEADER};

fn scratch_home() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("permaura-public-url-second-start-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch home");
    dir
}

fn start(home: &Path, addr: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    cmd.args(["start", "--addr", addr])
        .env("PERMAURA_HOME", home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_NO_UPGRADE", "1")
        .env("PERMAURA_PUBLIC_URL", "https://g-second-start.permaura.test")
        .env("PERMAURA_OWNER_SUB", "user_owner")
        .env("PERMAURA_AS_ISSUER", "https://permaura.test/api/auth")
        .env("RUST_LOG", "info");
    for key in ["PERMAURA_HOSTED", "PERMAURA_RELAY_URL", "PERMAURA_STORE_PATH", "PERMAURA_STORE_BUCKET", "PERMAURA_CONTROL_PLANE_URL"] {
        cmd.env_remove(key);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    cmd
}

fn read_token(home: &Path) -> String {
    std::fs::read_to_string(home.join("operator.token")).expect("operator.token").trim().to_string()
}

/// Whether the listener's `/health` proves `token`, as every CLI command checks before it sends one.
async fn proves(client: &reqwest::Client, addr: &str, port: u16, token: &str) -> bool {
    let challenge = new_challenge();
    let Ok(resp) = client.get(format!("http://{addr}/health")).header(CHALLENGE_HEADER, &challenge).send().await else {
        return false;
    };
    let proof = resp.headers().get(PROOF_HEADER).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    verify(token, port, &challenge, &proof)
}

/// Start a gateway at `addr` and wait until it answers.
async fn serving(home: &Path, addr: &str, client: &reqwest::Client) -> tokio::process::Child {
    let mut child = start(home, addr).spawn().expect("the gateway binary starts");
    let up = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                panic!("the gateway exited with {status}");
            }
            if matches!(client.get(format!("http://{addr}/health")).send().await, Ok(r) if r.status().is_success()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(up.is_ok(), "the gateway never answered on {addr}");
    child
}

async fn status_with(client: &reqwest::Client, addr: &str, token: &str) -> u16 {
    client.get(format!("http://{addr}/v1/devices")).bearer_auth(token).send().await.expect("the gateway answers").status().as_u16()
}

#[tokio::test]
async fn a_second_start_that_loses_the_bind_leaves_the_running_gateways_token_alone() {
    common::isolate_from_the_real_install();
    let home = scratch_home();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert_ne!(port, 7376, "never the port a real gateway on this machine listens on");
    let addr = format!("127.0.0.1:{port}");
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();

    let mut first = serving(&home, &addr, &client).await;
    let earlier = read_token(&home);
    first.start_kill().ok();
    let _ = tokio::time::timeout(Duration::from_secs(20), first.wait()).await;

    let mut running = serving(&home, &addr, &client).await;
    let token = read_token(&home);
    assert!(token.starts_with("pgt_"), "a published operator token");
    // Tokens are compared with `assert!`, never `assert_eq!`, which would print both into the test log on a failure.
    assert!(token != earlier, "a public-URL boot that holds its address replaces the token it found");
    assert_eq!(status_with(&client, &addr, &earlier).await, 401, "and ends it with no grace");
    assert!(proves(&client, &addr, port, &token).await, "the running gateway proves the token it published");
    assert_eq!(status_with(&client, &addr, &token).await, 200, "and takes it");

    let second = start(&home, &addr).spawn().expect("the second start runs");
    let output = tokio::time::timeout(Duration::from_secs(60), second.wait_with_output())
        .await
        .expect("a start that cannot bind exits")
        .unwrap();
    let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(!output.status.success(), "the second start must lose the bind:\n{log}");

    assert!(read_token(&home) == token, "operator.token is unchanged:\n{log}");
    assert!(proves(&client, &addr, port, &token).await, "the running gateway still proves the file's token:\n{log}");
    assert_eq!(status_with(&client, &addr, &token).await, 200, "and the token still works:\n{log}");
    assert!(!log.contains("did not prove it is this home's"), "the second start recognized the home's own gateway:\n{log}");

    running.start_kill().ok();
    let _ = tokio::time::timeout(Duration::from_secs(20), running.wait()).await;
    let _ = std::fs::remove_dir_all(&home);
}
