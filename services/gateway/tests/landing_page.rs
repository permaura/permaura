//! The gateway answers a browser, not an empty 404.
//!
//! Visiting a gateway is a normal thing for an operator to do (pasting the tunnel URL to check the
//! box is up, following the installer's last line), and every one of those visits used to land on a
//! blank 404 that reads as broken. What it must NOT become is an error page for API clients: the CLI
//! decides whether a gateway is old by which paths 404, so the status stays 404 everywhere but `/`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

struct Answer {
    status: StatusCode,
    content_type: String,
    body: String,
}

async fn get(state: AppState, path: &str, accept: Option<&str>) -> Answer {
    let mut req = Request::builder().uri(path);
    if let Some(a) = accept {
        req = req.header("accept", a);
    }
    let res = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .expect("router answered");
    let status = res.status();
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = axum::body::to_bytes(res.into_body(), 64 * 1024).await.expect("body");
    Answer { status, content_type, body: String::from_utf8_lossy(&body).into_owned() }
}

const BROWSER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

#[tokio::test]
async fn the_root_serves_the_landing_page_without_a_credential() {
    let a = get(common::seeded(), "/", Some(BROWSER)).await;
    assert_eq!(a.status, StatusCode::OK);
    assert!(a.content_type.starts_with("text/html"), "{}", a.content_type);
    assert!(a.body.contains("Your Permaura gateway is running"), "{}", a.body);
    assert!(a.body.contains("/console\">Open console"), "{}", a.body);
}

/// The whole point of the page is the way out of it. A gateway with no console link is the blank
/// 404 again, with styling.
#[tokio::test]
async fn the_landing_page_links_a_console() {
    let a = get(common::seeded(), "/", None).await;
    assert!(a.body.contains("href=\"http"), "no console link on the page:\n{}", a.body);
}

/// It says a gateway is here. It must not say WHICH: `/health` deliberately withholds the version
/// and build from an unauthenticated caller, and this page is reachable by exactly that caller.
#[tokio::test]
async fn the_landing_page_names_no_version_or_build() {
    let a = get(common::seeded(), "/", Some(BROWSER)).await;
    let version = env!("CARGO_PKG_VERSION");
    assert!(!a.body.contains(version), "the landing page prints the version:\n{}", a.body);
    assert!(!a.body.to_lowercase().contains("build"), "{}", a.body);
}

/// The mark turns. The page's whole job is to read as a machine that is working, and a still logo on
/// a page that says "is running" reads as a screenshot of one that is not, so the motion is part of
/// the message, not decoration, and it is the console's own loader rather than a second drawing.
#[tokio::test]
async fn the_mark_animates() {
    let a = get(common::seeded(), "/", Some(BROWSER)).await;
    assert!(a.body.contains("@keyframes logo-turn"), "the mark does not turn:\n{}", a.body);
    assert_eq!(a.body.matches("class=\"blade\"").count(), 3, "the mark is not the three-blade loader");
    assert!(
        a.body.contains("prefers-reduced-motion"),
        "nothing is offered to a viewer who has asked for less motion"
    );
}

#[tokio::test]
async fn an_unknown_path_is_still_a_404_for_a_browser() {
    let a = get(common::seeded(), "/no-such-thing", Some(BROWSER)).await;
    assert_eq!(a.status, StatusCode::NOT_FOUND, "the status is what clients branch on");
    assert!(a.content_type.starts_with("text/html"), "{}", a.content_type);
    assert!(a.body.contains("not part of this gateway"), "{}", a.body);
}

#[tokio::test]
async fn an_unknown_path_stays_json_for_a_client() {
    for accept in [None, Some("application/json"), Some("*/*")] {
        let a = get(common::seeded(), "/v1/nope", accept).await;
        assert_eq!(a.status, StatusCode::NOT_FOUND, "accept: {accept:?}");
        assert!(a.content_type.starts_with("application/json"), "accept: {accept:?} → {}", a.content_type);
        assert!(a.body.contains("\"error\""), "accept: {accept:?} → {}", a.body);
        assert!(!a.body.contains("<html"), "an API caller got a web page: {}", a.body);
    }
}

/// The fallback is mounted before the layers on purpose. If it ever moves after them it answers
/// outside the Host allowlist, and a DNS-rebinding probe gets a reply from a gateway that believes
/// it refused one.
#[tokio::test]
async fn the_fallback_is_still_behind_the_host_allowlist() {
    for path in ["/", "/no-such-thing"] {
        let res = build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap())
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", "evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router answered");
        assert_eq!(
            res.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "{path} answered a request for a host this gateway does not serve"
        );
    }
}
