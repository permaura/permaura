//! Measured: four held calls whose params are 2 MiB of one-key objects, written the way a gateway before the hold budget wrote them, are read by every listing (the queue, the boot settlement, the expiry sweep, `GET /v1/approvals`) without a tree of their params.
//! Before, each listing rebuilt about 166 MiB per row, and four rows ended a hosted worker on every boot.
//! The rows are over the hosted ceiling on an agent call's unpacked size (128 MiB, the hosted pool less 64 MiB), which this binary sets by setting the hosted pool; under a self-run gateway's 448 MiB ceiling a rendering builds each in turn, charged to its pool.
//!
//! A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak. Every credential here is synthetic.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures_util::StreamExt;
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{PendingApproval, Store};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::Value;
use tower::ServiceExt;

mod common;
mod metered_alloc;

use metered_alloc::{peak_growth, peak_growth_sync, MIB};

fn one_key_objects(cap: usize) -> String {
    let mut body = String::from("[");
    while body.len() + 9 < cap {
        body.push_str("{\"a\":1},");
    }
    body.pop();
    body.push(']');
    body
}

/// A pending agent hold as a gateway before the hold budget stored it: its whole row as text.
fn legacy_row(id: &str, params: &str, created_at: i64) -> String {
    format!(
        r#"{{"id":"{id}","session_id":"sess_demo","capability":"github.pull_requests.create","resource":"github_acme","message":"Approve?","status":"pending","grant_id":"gr_github_prs","policy_id":"pol_github_prs","params":{{"rows":{params}}},"result":null,"result_status":null,"created_at":{created_at},"expires_at":null,"risk":"high","action_description":"Create pull requests","required_tier":"approve","required_signatures":1,"signatures":[]}}"#
    )
}

#[tokio::test]
async fn listings_of_held_calls_build_no_tree_of_their_params() {
    common::isolate_from_the_real_install();
    std::env::set_var("PERMAURA_LIMIT_JSON_POOL_BYTES", permaura_gateway::limits::DEFAULT_HOSTED_JSON_POOL_BYTES.to_string());
    let dir = std::env::temp_dir().join(format!("held-rows-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(path.to_str().unwrap()).unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let params = one_key_objects(2 * MIB - 512);
    let now = permaura_gateway::service::now_ms();
    for i in 0..4 {
        // A row as an earlier build wrote it, which this build reads back and writes unchanged.
        let row: PendingApproval = serde_json::from_str(&legacy_row(&format!("appr_legacy_{i}"), &params, now - 3_600_000)).unwrap();
        store.put_approval(row).unwrap();
    }
    let state = AppState::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));

    let (tree, control) = peak_growth_sync(|| serde_json::from_str::<Value>(&legacy_row("x", &params, now)).unwrap());
    drop(tree);
    assert!(control > 150 * MIB, "one row's tree: {} MiB", control / MIB);

    let (listed, listing) = peak_growth_sync(|| store.list_approvals(Some("pending")).unwrap());
    assert_eq!(listed.len(), 4);
    drop(listed);
    assert!(listing < 24 * MIB, "the queue listing held {} MiB (four trees were {} MiB)", listing / MIB, 4 * control / MIB);

    let (settled, settle) = peak_growth_sync(|| state.service.settle_interrupted_approvals(Duration::ZERO, u64::MAX));
    settled.expect("the boot settlement runs");
    assert!(settle < 24 * MIB, "the boot settlement held {} MiB", settle / MIB);

    let (retired, sweep) = peak_growth_sync(|| state.service.retire_expired_holds(now));
    retired.expect("the sweep runs");
    assert!(sweep < 24 * MIB, "the expiry sweep held {} MiB", sweep / MIB);

    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let ((status, served), served_peak) = peak_growth(async {
        let request = Request::builder()
            .uri("/v1/approvals?status=pending")
            .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(request).await.unwrap();
        let status = resp.status();
        let mut stream = resp.into_body().into_data_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        (status, body)
    })
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(served_peak < 48 * MIB, "GET /v1/approvals held {} MiB", served_peak / MIB);
    let served: Value = serde_json::from_slice(&served).unwrap();
    let rows = served["approvals"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        assert_eq!(row["params_display"]["complete"], false, "too large to show: {}", row["params_display"]);
        assert_eq!(row["request_hash"].as_str().unwrap().len(), 64, "the hash is still served, from the row's text");
    }

    history_listing_moves_each_result().await;

    // The row written back is the row that was read: no schema change, nothing reformatted.
    let raw = rusqlite::Connection::open(&path).unwrap();
    let data: String = raw.query_row("SELECT data FROM approvals WHERE id = 'appr_legacy_0'", [], |r| r.get(0)).unwrap();
    assert!(data == legacy_row("appr_legacy_0", &params, now - 3_600_000), "the stored row changed");
    drop(raw);
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "measured: one row's tree {} MiB; listing {} MiB; boot settlement {} MiB; sweep {} MiB; GET /v1/approvals {} MiB",
        control / MIB,
        listing / MIB,
        settle / MIB,
        sweep / MIB,
        served_peak / MIB
    );
}

/// The unfiltered `GET /v1/approvals` (the history) lists every resolved row with its result, and each result is written from the row it was read into, neither copied beside it nor serialized again into one body.
async fn history_listing_moves_each_result() {
    let dir = std::env::temp_dir().join(format!("held-rows-history-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(dir.join("gateway.db").to_str().unwrap()).unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let result = format!(r#"{{"blob":"{}"}}"#, "r".repeat(4 * MIB));
    for i in 0..4 {
        let row = format!(
            r#"{{"id":"appr_done_{i}","session_id":"sess_demo","capability":"github.pull_requests.create","resource":"github_acme","message":"Approve?","status":"approved","grant_id":null,"policy_id":null,"params":{{"title":"t{i}"}},"result":{result},"result_status":200,"created_at":{i},"expires_at":null,"risk":"high","action_description":"Create pull requests","required_tier":"approve","required_signatures":1,"signatures":[]}}"#
        );
        store.put_approval(serde_json::from_str::<PendingApproval>(&row).unwrap()).unwrap();
    }
    let state = AppState::new(EnforcementService::new(store, Arc::new(MockHttpClient::new())));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    let ((status, len), peak) = peak_growth(async {
        let request = Request::builder()
            .uri("/v1/approvals")
            .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(request).await.unwrap();
        let status = resp.status();
        let mut stream = resp.into_body().into_data_stream();
        let mut len = 0;
        while let Some(chunk) = stream.next().await {
            len += chunk.unwrap().len();
        }
        (status, len)
    })
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(len > 16 * MIB, "every result is served: {len} bytes");
    // The four results once, as the rows they were read into; serialized whole, the listing held them twice.
    assert!(peak < 24 * MIB, "the history listing held {} MiB for 16 MiB of results", peak / MIB);
    eprintln!("measured: the history listing of four 4 MiB results held {} MiB", peak / MIB);
    let _ = std::fs::remove_dir_all(&dir);
}
