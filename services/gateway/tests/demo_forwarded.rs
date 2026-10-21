//! A demo gateway answers only this machine. Its operator bearer is the published demo token, so a request a tunnel or proxy forwarded to its loopback port, or one from another address, is refused before any route sees it; a request from this machine is served as before.
//!
//! A raw TCP forwarder that adds no header and connects from loopback (`ssh -R`) cannot be told from a local client, which is why a demo also defaults to a port of its own.

mod common;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, seed};
use tower::ServiceExt;

async fn devices(headers: &[(&str, &str)], peer: &str) -> (StatusCode, String) {
    // How `permaura start --demo` and `permad` build theirs.
    let app = build_router(common::seeded().local_only(), "127.0.0.1:7399".parse().unwrap());
    let mut builder = Request::builder().uri("/v1/devices").header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut req = builder.body(Body::empty()).unwrap();
    req.extensions_mut().insert(ConnectInfo::<std::net::SocketAddr>(peer.parse().unwrap()));
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn a_demo_serves_this_machine() {
    let (status, body) = devices(&[], "127.0.0.1:50000").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_demo_refuses_what_a_tunnel_or_proxy_forwarded() {
    for header in ["cf-connecting-ip", "cf-ray", "x-forwarded-for", "x-real-ip", "forwarded"] {
        let (status, body) = devices(&[(header, "203.0.113.9")], "127.0.0.1:50000").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{header}: {body}");
        assert!(body.contains("a demo gateway answers only this machine"), "{header}: {body}");
    }
}

#[tokio::test]
async fn a_demo_refuses_another_address() {
    let (status, body) = devices(&[], "192.0.2.7:50000").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}
