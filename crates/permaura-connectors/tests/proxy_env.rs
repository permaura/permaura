//! The production clients never route through a proxy named in the environment. Through a proxy the
//! target resolves at the proxy, so the egress guard's post-resolution screen (the DNS-rebinding
//! close) never sees the address the request reaches.
//!
//! Its own test binary, because proxy variables are process-wide.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use permaura_connectors::{HttpClient, HttpRequest, ReqwestClient};

/// A listener standing in for a proxy, counting the connections it is offered.
async fn counting_proxy() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(sock);
        }
    });
    (format!("http://{addr}"), seen)
}

#[tokio::test]
async fn neither_production_client_uses_a_proxy_from_the_environment() {
    let (proxy, seen) = counting_proxy().await;
    for var in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(var, &proxy);
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    for (name, client) in [("new", ReqwestClient::new().unwrap()), ("new_infra", ReqwestClient::new_infra().unwrap())] {
        let request = HttpRequest::get("http://permaura-proxy-test.invalid/v1/items");
        let outcome = tokio::time::timeout(Duration::from_secs(20), client.send(request)).await;
        assert!(!matches!(outcome, Ok(Ok(_))), "{name}: nothing answers this host");
        assert_eq!(seen.load(Ordering::SeqCst), 0, "{name} sent its request to the proxy");
    }
}
