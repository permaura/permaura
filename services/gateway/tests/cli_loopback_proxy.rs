//! The CLI reaches the gateway on this machine directly, whatever proxy the environment names.
//!
//! `HTTP_PROXY` applies to 127.0.0.1 unless `NO_PROXY` lists that exact address, and the CLI proved
//! the listener on a proxy-free client and then sent the operator bearer, and for `vault add` the
//! secret itself, on a default one. This runs the real binary against a demo gateway on a free port
//! with a recording proxy in the environment. Every token and value is synthetic.
#![cfg(unix)]

mod common;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use permaura_gateway::{build_router, seed};

/// A proxy that keeps whatever it is sent and answers every request with a 502.
fn recording_proxy() -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 8192];
            if let Ok(n) = stream.read(&mut buf) {
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    (addr, seen)
}

#[tokio::test]
async fn vault_add_sends_its_bearer_and_secret_to_the_gateway_not_the_proxy() {
    common::isolate_from_the_real_install();
    let home = std::env::var("PERMAURA_HOME").unwrap();
    let (proxy, seen) = recording_proxy();

    let state = common::seeded();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    assert_ne!(addr.port(), 7376, "never the port a real gateway on this machine listens on");
    let app = build_router(state.clone(), addr);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });

    let proxy_url = format!("http://{proxy}");
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"))
            .args(["--url", &format!("http://{addr}"), "--token", seed::DEMO_TOKEN])
            .args(["vault", "add", "sec_proxy_probe", "--env-var", "PROXY_PROBE_VALUE"])
            .env("PROXY_PROBE_VALUE", "synthetic-proxy-probe-value")
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
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
    let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));

    let proxied = String::from_utf8_lossy(&seen.lock().unwrap()).to_lowercase();
    // Only the request line is ever printed: the rest is what must not leak.
    let request_line = proxied.lines().next().unwrap_or_default().to_string();
    assert!(!proxied.contains("authorization"), "the proxy was handed the bearer on: {request_line}");
    assert!(!proxied.contains("synthetic-proxy-probe-value"), "the proxy was handed the secret on: {request_line}");
    assert!(proxied.is_empty(), "nothing for this machine's gateway goes to the proxy: {request_line}");
    assert!(output.status.success(), "{log}");
    assert!(
        state.service.store().get_secret("sec_proxy_probe").unwrap().is_some(),
        "the secret reached the gateway: {log}"
    );
}
