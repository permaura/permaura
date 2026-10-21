//! A connector closure that panics must not leave the decrypted secret in freed memory: both
//! `Vault::use_secret` and `Vault::use_secret_cached` wipe their temporary on unwind as well as on
//! return. This binary installs its own global allocator to look at the buffer as it is freed, so it
//! lives on its own rather than among the crate's unit tests.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

static WATCH: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static LEN: AtomicUsize = AtomicUsize::new(0);
/// 0 = not freed yet, 1 = all zero when freed, 2 = still holding bytes when freed.
static AT_FREE: AtomicUsize = AtomicUsize::new(0);

struct Observer;

unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCH.compare_exchange(ptr, std::ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            let bytes = std::slice::from_raw_parts(ptr, LEN.load(Ordering::SeqCst));
            AT_FREE.store(if bytes.iter().all(|b| *b == 0) { 1 } else { 2 }, Ordering::SeqCst);
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOC: Observer = Observer;

fn watch(bytes: &[u8]) {
    LEN.store(bytes.len(), Ordering::SeqCst);
    WATCH.store(bytes.as_ptr() as *mut u8, Ordering::SeqCst);
    AT_FREE.store(0, Ordering::SeqCst);
}

#[test]
fn both_secret_callbacks_wipe_the_plaintext_on_return_and_on_unwind() {
    let mut vault = permaura_core::Vault::new();
    vault
        .put_secret("synthetic", b"synthetic-pass", b"public synthetic probe bytes only", Default::default())
        .unwrap();

    vault
        .use_secret("synthetic", b"synthetic-pass", |b| {
            watch(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(AT_FREE.load(Ordering::SeqCst), 1, "use_secret: wiped before it is freed on return");

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: permaura_core::Result<()> = vault.use_secret("synthetic", b"synthetic-pass", |b| {
            watch(b);
            panic!("synthetic connector panic")
        });
    }));
    assert!(unwound.is_err());
    assert_eq!(AT_FREE.load(Ordering::SeqCst), 1, "use_secret: wiped before it is freed on unwind");

    let keks = permaura_core::crypto::KekCache::new(b"synthetic-pass".to_vec());
    vault
        .use_secret_cached("synthetic", &keks, |b| {
            watch(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(AT_FREE.load(Ordering::SeqCst), 1, "use_secret_cached: wiped before it is freed on return");

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: permaura_core::Result<()> = vault.use_secret_cached("synthetic", &keks, |b| {
            watch(b);
            panic!("synthetic cached connector panic")
        });
    }));
    assert!(unwound.is_err());
    assert_eq!(AT_FREE.load(Ordering::SeqCst), 1, "use_secret_cached: wiped before it is freed on unwind");
}
