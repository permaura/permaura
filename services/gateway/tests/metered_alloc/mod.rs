//! A process-wide allocator that counts the bytes live and the most live at once, for the tests that measure what a request holds.
//! Including this module installs it, so a binary that does should run its measurements in one test: anything running beside a measurement moves its peak.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct Metered;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static REALLOC_COPIES: AtomicBool = AtomicBool::new(false);

/// Count every growing `realloc` as glibc does one it cannot extend in place: the new block allocated while the old one is still live, then the old one freed.
/// The system allocator here often grows a large block in place, which would hide a buffer that doubles while its old copy is still held; the hosted worker's allocator does not promise that.
#[allow(dead_code)]
pub fn count_realloc_as_copy(on: bool) {
    REALLOC_COPIES.store(on, Ordering::SeqCst);
}

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
            if new_size >= layout.size() && REALLOC_COPIES.load(Ordering::SeqCst) {
                grew(new_size);
                LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
            } else if new_size >= layout.size() {
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

pub const MIB: usize = 1024 * 1024;

/// Run `f` and answer what it returned and the most memory live at once above what was live when it started.
#[allow(dead_code)]
pub async fn peak_growth<F: std::future::Future>(f: F) -> (F::Output, usize) {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = f.await;
    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(base);
    (out, peak)
}

/// [`peak_growth`] for synchronous work.
#[allow(dead_code)]
pub fn peak_growth_sync<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = f();
    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(base);
    (out, peak)
}
