//! `permad` serves the seeded demo estate, whose operator bearer is published, so it is a throwaway beside the real install, as `permaura start --demo` is.
//!
//! Started in a shell that still carries the install's relay and announce variables, it must not dial the relay as the install's worker, write a worker key into the install's home, or announce to a control plane as the install's gateway. Every value here is synthetic, and nothing is reachable outside loopback.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("permaura-dos02-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn free_port() -> u16 {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert!(![7376, 8787, 3102, 8081, 8799, 18787].contains(&port), "never a port a real gateway or app on this machine uses");
    port
}

/// One HTTP/1.1 request over a plain socket, answered with its status and body.
fn http(port: u16, path: &str, bearer: Option<&str>) -> Option<(u16, String)> {
    http_with(port, path, bearer, "")
}

fn http_with(port: u16, path: &str, bearer: Option<&str>, extra: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let auth = bearer.map(|b| format!("authorization: Bearer {b}\r\n")).unwrap_or_default();
    write!(stream, "GET {path} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\n{auth}{extra}connection: close\r\n\r\n").ok()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    let status = raw.split_whitespace().nth(1)?.parse().ok()?;
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    Some((status, body))
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn permad_takes_none_of_the_installs_relay_or_announce_settings() {
    let home = scratch("home");
    let relay = TcpListener::bind("127.0.0.1:0").expect("a stand-in relay");
    relay.set_nonblocking(true).unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let port = free_port();

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_permad"));
    cmd.env("PERMAURA_HOME", &home)
        .env("PERMAURA_DEV", "1")
        .env("PERMAURA_ADDR", format!("127.0.0.1:{port}"))
        .env("PERMAURA_RELAY_URL", format!("ws://127.0.0.1:{relay_port}/relay"))
        .env("PERMAURA_WORKER_ID", "wk_dos02_synthetic")
        .env("PERMAURA_WORKER_ORG", "org_dos02_synthetic")
        .env("PERMAURA_GATEWAY_ID", "gw_dos02_synthetic")
        .env("PERMAURA_ANNOUNCE_SECRET", "gwa_dos02_synthetic_placeholder")
        // Unreachable, so a regression that announces never reaches permaura.com.
        .env("PERMAURA_CONTROL_PLANE_URL", "https://127.0.0.1:9")
        .env("RUST_LOG", "info")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for key in ["PERMAURA_WORKER_KEY", "PERMAURA_HOSTED", "PERMAURA_PUBLIC_URL", "PERMAURA_STORE_PATH", "PERMAURA_STORE_BUCKET"] {
        cmd.env_remove(key);
    }
    let mut daemon = cmd.spawn().expect("permad starts");

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(Some(status)) = daemon.try_wait() {
            panic!("permad exited with {status}");
        }
        if matches!(http(port, "/health", None), Some((200, _))) {
            break;
        }
        assert!(Instant::now() < deadline, "permad never answered on {port}");
        std::thread::sleep(Duration::from_millis(100));
    }

    let announce = http(port, "/v1/announce", Some(permaura_gateway::seed::DEMO_TOKEN));
    // What a tunnel left pointing at this port forwards is refused, since the bearer is published.
    let forwarded = http_with(port, "/v1/announce", Some(permaura_gateway::seed::DEMO_TOKEN), "cf-connecting-ip: 203.0.113.9\r\n");
    // Long enough for a relay dial that was going to happen at boot to have happened.
    let watch = Instant::now() + Duration::from_secs(3);
    let mut dialled = false;
    while Instant::now() < watch {
        if relay.accept().is_ok() {
            dialled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let left_in_home = listing(&home);
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_dir_all(&home);

    let (status, body) = announce.expect("permad answers /v1/announce");
    assert_eq!(status, 200, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    let (forwarded_status, forwarded_body) = forwarded.expect("permad answers a forwarded request");
    assert_eq!(forwarded_status, 403, "a forwarded request is refused: {forwarded_body}");
    let mut taken = Vec::new();
    if body["links"] != serde_json::json!([]) {
        taken.push(format!("it announces as the install's gateway: {body}"));
    }
    if dialled {
        taken.push("it dialled the relay named in its environment as the install's worker".to_string());
    }
    if !left_in_home.is_empty() {
        taken.push(format!("it wrote into the install's home: {left_in_home:?}"));
    }
    assert!(taken.is_empty(), "permad took the install's settings:\n{}", taken.join("\n"));
}
