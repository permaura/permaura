//! An announcement carries the gateway's announce secret in its body, so it goes over TLS, or over plain http to this machine only, and never follows a redirect, which would resend the body wherever the control plane's address pointed. Its own test binary, because the control plane's address is read from the environment. Every id and secret here is synthetic.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use permaura_gateway::announce::{announce_hold, announce_resolved, AnnouncedHold, Announcer, Config};

const SECRET: &str = "gwa_synthetic_announce_secret_fixture";

/// The environment is process-wide and the tests in this binary run in parallel.
static ENV: Mutex<()> = Mutex::new(());

fn config_for(base: &str) -> Option<Config> {
    common::isolate_from_the_real_install();
    let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PERMAURA_CONTROL_PLANE_URL", base);
    let config = Config::new("gw_synthetic", SECRET);
    std::env::remove_var("PERMAURA_CONTROL_PLANE_URL");
    config
}

fn hold() -> AnnouncedHold {
    AnnouncedHold {
        approval_id: "appr_synthetic".into(),
        capability: "synthetic.refunds.create".into(),
        resource: "synthetic".into(),
        risk: "high".into(),
        required_tier: "approve".into(),
        agent: None,
        expires_at: None,
        requested_by: None,
    }
}

/// A listener on a free loopback port answering every request with `answer`, counting what arrives.
async fn listener(answer: axum::response::Response) -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let answer = Arc::new(Mutex::new(Some(answer)));
    let app = axum::Router::new().fallback(move || {
        let counter = counter.clone();
        let answer = answer.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            answer.lock().unwrap().take().unwrap_or_else(|| StatusCode::OK.into_response())
        }
    });
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    (addr, hits)
}

async fn wait_for(hits: &AtomicUsize, at_least: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) < at_least && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A host that only begins like a loopback address is a public name, and plain http to it would put the announce secret on the wire in clear. Announcing is switched off for it, so nothing is ever sent; a genuine loopback host, and https anywhere, still announce.
#[test]
fn a_host_that_only_begins_like_loopback_switches_announcing_off() {
    for base in [
        "http://127.0.0.1.example",
        "http://127.0.0.1.example:3102",
        "http://localhost.evil.example:3102",
        "http://localhost@evil.example",
        "http://127.0.0.1.nip.io",
        "http://permaura.com",
    ] {
        assert!(config_for(base).is_none(), "{base} must not be announced to");
    }
    for base in [
        "http://127.0.0.1:3102",
        "http://127.8.9.10:3102",
        "http://localhost:3102",
        "http://console.localhost:3102",
        "http://[::1]:3102",
        "http://[::ffff:127.0.0.1]:3102",
        "https://permaura.com",
    ] {
        assert!(config_for(base).is_some(), "{base} is announced to");
    }
}

/// A 307 or 308 resends the body, announce secret included, to wherever it points. The client follows none.
#[tokio::test]
async fn a_redirect_from_the_announce_address_is_not_followed() {
    let (target, target_hits) = listener(StatusCode::OK.into_response()).await;
    for status in [StatusCode::TEMPORARY_REDIRECT, StatusCode::PERMANENT_REDIRECT] {
        let redirect = (status, [(header::LOCATION, format!("http://{target}/api/notify/hold"))]).into_response();
        let (origin, origin_hits) = listener(redirect).await;
        let config = config_for(&format!("http://{origin}")).expect("a loopback control plane");
        announce_hold(vec![config], hold()).await;
        wait_for(&origin_hits, 1).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(origin_hits.load(Ordering::SeqCst), 1, "{status}: asked once, and a redirect is not retried");
    }
    assert_eq!(target_hits.load(Ordering::SeqCst), 0, "the secret never followed a redirect");
}

/// The control: a genuine loopback control plane over plain http still receives the announcement.
#[tokio::test]
async fn a_loopback_control_plane_over_http_still_receives_the_announcement() {
    let (origin, hits) = listener(StatusCode::OK.into_response()).await;
    let config = config_for(&format!("http://{origin}")).expect("a loopback control plane");
    announce_hold(vec![config], hold()).await;
    wait_for(&hits, 1).await;
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// The links an announcer hands out after announcing `hold` to a control plane answering `answer`, and the links it was asked to re-seal.
async fn asked_after(answer: axum::response::Response, resolve: bool) -> Vec<String> {
    let (origin, hits) = listener(answer).await;
    let announcer = Announcer::with(vec![config_for(&format!("http://{origin}")).expect("a loopback control plane")]);
    if resolve {
        announce_resolved(announcer.links(), "appr_synthetic".into()).await;
    } else {
        announce_hold(announcer.links(), hold()).await;
    }
    wait_for(&hits, 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    announcer.reseal_requests().take().into_iter().collect()
}

fn json_answer(body: &str) -> axum::response::Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
}

/// A notification answered with `needs_reseal: true` records the link for the re-seal task, on a hold and on a resolution alike; any other answer, an unknown field, a non-boolean or an oversized body records nothing.
#[tokio::test]
async fn a_notification_answer_asking_for_a_reseal_is_recorded_for_its_link() {
    assert_eq!(asked_after(json_answer(r#"{"ok":true,"needs_reseal":true,"unknown":[1]}"#), false).await, vec!["gw_synthetic"]);
    assert_eq!(asked_after(json_answer(r#"{"needs_reseal":true}"#), true).await, vec!["gw_synthetic"]);
    for quiet in [
        json_answer(r#"{"ok":true}"#),
        json_answer(r#"{"needs_reseal":false}"#),
        json_answer(r#"{"needs_reseal":"true"}"#),
        json_answer("not json"),
        json_answer(&format!(r#"{{"needs_reseal":true,"pad":"{}"}}"#, "x".repeat(32 * 1024))),
        (StatusCode::FORBIDDEN, [(header::CONTENT_TYPE, "application/json")], r#"{"needs_reseal":true}"#).into_response(),
    ] {
        assert!(asked_after(quiet, false).await.is_empty());
    }
}
