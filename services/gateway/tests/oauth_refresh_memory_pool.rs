//! An OAuth refresh whose token response arrives while the worker's JSON memory pool is busy still lands its rotation.
//! The provider commits the rotation when it answers, so refusing the answer for want of room loses the new refresh token and the connection needs re-authorizing.
//!
//! Every credential and endpoint here is synthetic.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use permaura_gateway::connectors::{MemoryPool, ReqwestClient};
use permaura_gateway::oauth_credential::{ensure_fresh, OAuthCredential, OAuthLayer};
use tokio::io::AsyncWriteExt;

mod common;

const MIB: u64 = 1024 * 1024;

/// A token endpoint that rotates the refresh token on every call and counts the calls.
async fn token_endpoint(hits: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                if common::raw_http::read_request(&mut sock).await.is_none() {
                    return;
                }
                let n = hits.fetch_add(1, Ordering::SeqCst);
                let body = format!(r#"{{"access_token":"synthetic-access-{n}","refresh_token":"synthetic-rotated-{n}","expires_in":3600,"token_type":"bearer"}}"#);
                let head = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}/token")
}

fn expired(token_url: String) -> OAuthCredential {
    OAuthCredential { token_auth: Default::default(),
        layer: OAuthLayer::ByoApp,
        provider: "synthetic".into(),
        access_token: "synthetic-expired".into(),
        refresh_token: Some("synthetic-refresh".into()),
        expires_at: 1,
        scopes: Vec::new(),
        token_url,
        client_id: Some("synthetic-client".into()),
        client_secret: Some("synthetic-client-secret".into()),
    }
}

#[tokio::test]
async fn a_refresh_answered_while_the_pool_is_busy_keeps_its_rotation() {
    common::isolate_from_the_real_install();
    let hits = Arc::new(AtomicUsize::new(0));
    let url = token_endpoint(hits.clone()).await;
    let pool = Arc::new(MemoryPool::new(16 * MIB));
    let client = ReqwestClient::loopback_for_tests(Duration::from_secs(10)).with_memory(pool.clone());

    // The probe's shape: one call holds 10 MiB of a 16 MiB pool and another waits for 10 MiB, so the semaphore's queue is not empty.
    let held = pool.reserve(10 * MIB, Duration::ZERO).await.unwrap();
    let waiter = {
        let pool = pool.clone();
        tokio::spawn(async move { pool.reserve(10 * MIB, Duration::from_secs(30)).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let refreshed = tokio::time::timeout(Duration::from_secs(5), ensure_fresh(&expired(url), &client, 1_000, 0))
        .await
        .expect("the refresh does not wait on the pool");
    let (access, updated) = refreshed.expect("the token response is read, whatever the pool holds");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the provider was called once and committed its rotation");
    assert_eq!(access, "synthetic-access-0");
    let updated = updated.expect("a refreshed credential to persist");
    assert_eq!(updated.refresh_token.as_ref().map(|t| t.expose()), Some("synthetic-rotated-0"), "the rotated refresh token survives");

    drop(held);
    assert!(waiter.await.unwrap().is_ok());
}
