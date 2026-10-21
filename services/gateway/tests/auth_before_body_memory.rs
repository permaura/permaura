//! Measured: a stranger's hostile bulk body is never built into a tree, which a parse would show as an allocation many times the body's size.
//!
//! A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

mod common;

struct Metered;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::SeqCst) + by;
    PEAK.fetch_max(now, Ordering::SeqCst);
}

unsafe impl GlobalAlloc for Metered {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = System.realloc(ptr, layout, new_size);
        if !moved.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        moved
    }
}

#[global_allocator]
static METER: Metered = Metered;

fn one_key_objects(size: usize) -> String {
    let mut body = String::from("{\"manifest\":[");
    while body.len() + 24 < size {
        body.push_str("{\"a\":1},");
    }
    body.pop();
    body.push_str("],\"version\":1}");
    body
}

/// The most memory live at once above what was live when the request started, and the status.
async fn peak_growth(state: &AppState, bearer: Option<&str>, body: String) -> (usize, StatusCode) {
    let router = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut request = Request::builder().method("POST").uri("/v1/connectors/install").header("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let request = request.body(Body::from(body)).unwrap();
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let status = router.oneshot(request).await.unwrap().status();
    (PEAK.load(Ordering::SeqCst).saturating_sub(base), status)
}

#[tokio::test(flavor = "current_thread")]
async fn a_strangers_hostile_bulk_body_is_never_built_into_a_tree() {
    const MIB: usize = 1024 * 1024;
    let state = common::seeded();

    // The control: an operator's body is parsed, and the meter sees the tree, about 83 times the body.
    let (operator_peak, _) = peak_growth(&state, Some(seed::DEMO_TOKEN), one_key_objects(2 * MIB)).await;
    assert!(operator_peak > 100 * MIB, "the meter must see a parse: {} MiB", operator_peak / MIB);

    // The reproduction's body, four times the control's, from a caller with no bearer.
    let (stranger_peak, status) = peak_growth(&state, None, one_key_objects(8 * MIB - 4096)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(stranger_peak < 16 * MIB, "a refused body must not be parsed: {} MiB", stranger_peak / MIB);
    println!("operator 2 MiB body peak {} MiB; stranger 8 MiB body peak {} KiB", operator_peak / MIB, stranger_peak / 1024);
}
