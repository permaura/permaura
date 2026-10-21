//! A global allocator that reads every block as it is freed and counts the blocks still holding a watched byte string, so a test can show that a secret's plaintext was wiped wherever it was copied, rather than only in the one buffer it names.
//!
//! A binary installs it with `#[global_allocator] static ALLOC: FreedScan = FreedScan;`. It does not override `realloc`, so a growing buffer frees its old block through `dealloc` and is read too: that is the copy a `Zeroizing` wrapper never sees, and the allocator a release build links may move the block the same way. The watch is process-wide, so every test in a binary that uses it runs under [`watch`]'s lock.

#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

const MAX_NEEDLES: usize = 128;

static NEEDLES: [AtomicPtr<u8>; MAX_NEEDLES] = [const { AtomicPtr::new(std::ptr::null_mut()) }; MAX_NEEDLES];
static LENS: [AtomicUsize; MAX_NEEDLES] = [const { AtomicUsize::new(0) }; MAX_NEEDLES];
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static HITS: AtomicUsize = AtomicUsize::new(0);
static LAST_NEEDLE: AtomicUsize = AtomicUsize::new(usize::MAX);
static LAST_SIZE: AtomicUsize = AtomicUsize::new(0);
static LOCK: Mutex<()> = Mutex::new(());

/// The allocator: [`System`], plus a read of every freed block while a [`Watch`] is live.
pub struct FreedScan;

unsafe impl GlobalAlloc for FreedScan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let watched = WATCHED.load(Ordering::Acquire);
        if watched > 0 && layout.size() > 0 {
            let block = std::slice::from_raw_parts(ptr, layout.size());
            for i in 0..watched {
                let needle = std::slice::from_raw_parts(NEEDLES[i].load(Ordering::Acquire), LENS[i].load(Ordering::Acquire));
                if contains(block, needle) {
                    LAST_NEEDLE.store(i, Ordering::Release);
                    LAST_SIZE.store(layout.size(), Ordering::Release);
                    HITS.fetch_add(1, Ordering::AcqRel);
                    break;
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

fn contains(block: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || block.len() < needle.len() {
        return false;
    }
    let first = needle[0];
    (0..=block.len() - needle.len()).any(|i| block[i] == first && &block[i..i + needle.len()] == needle)
}

/// A live watch: freed blocks are read while it is held, and the lock keeps every other test in the binary out.
pub struct Watch {
    _held: MutexGuard<'static, ()>,
}

impl Watch {
    /// How many blocks freed since the watch began (or since [`Self::reset`]) still held a needle.
    pub fn hits(&self) -> usize {
        HITS.load(Ordering::Acquire)
    }

    /// The needle (its index in what [`watch`] was given) and the block size of the most recent hit, to say which secret a failure left and roughly where.
    pub fn last_hit(&self) -> Option<(usize, usize)> {
        (self.hits() > 0).then(|| (LAST_NEEDLE.load(Ordering::Acquire), LAST_SIZE.load(Ordering::Acquire)))
    }

    /// Start counting again from zero.
    pub fn reset(&self) {
        HITS.store(0, Ordering::Release);
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        WATCHED.store(0, Ordering::Release);
    }
}

/// Count every freed block that holds any of `needles` until the returned [`Watch`] drops.
pub fn watch(needles: &[&'static [u8]]) -> Watch {
    assert!(needles.len() <= MAX_NEEDLES, "at most {MAX_NEEDLES} needles");
    let held = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    WATCHED.store(0, Ordering::Release);
    for (i, needle) in needles.iter().enumerate() {
        NEEDLES[i].store(needle.as_ptr() as *mut u8, Ordering::Release);
        LENS[i].store(needle.len(), Ordering::Release);
    }
    HITS.store(0, Ordering::Release);
    WATCHED.store(needles.len(), Ordering::Release);
    Watch { _held: held }
}

/// The needles that find a copy of `secret`, whole or in part, as 12-byte windows at each end of: its bytes; its percent-encodings (RFC 3986 unreserved kept, and the form encoding, which keeps `*` and writes a space as `+`); and its base64 in both alphabets at each of the three byte offsets a longer blob can start it at. Any length works. Every intermediate is wiped, so building needles in one test never shows up under another test's watch, and the needles themselves are leaked so they outlive every watch.
pub fn needles_for(secret: &'static str) -> Vec<&'static [u8]> {
    use base64::Engine as _;
    use zeroize::Zeroizing;
    const WINDOW: usize = 12;
    let bytes = secret.as_bytes();
    assert!(bytes.len() >= 2 * WINDOW, "a probe secret is at least {} bytes", 2 * WINDOW);
    let mut forms: Vec<Zeroizing<Vec<u8>>> = vec![Zeroizing::new(bytes.to_vec())];
    for keep in [&b"-._~"[..], &b"*-._"[..]] {
        let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() * 3));
        for &b in bytes {
            if b.is_ascii_alphanumeric() || keep.contains(&b) {
                out.push(b);
            } else if b == b' ' && keep.contains(&b'*') {
                out.push(b'+');
            } else {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
            }
        }
        forms.push(out);
    }
    let mut needles: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(32);
    for form in &forms {
        needles.push(Zeroizing::new(form[..WINDOW].to_vec()));
        needles.push(Zeroizing::new(form[form.len() - WINDOW..].to_vec()));
    }
    for engine in [base64::engine::general_purpose::STANDARD_NO_PAD, base64::engine::general_purpose::URL_SAFE_NO_PAD] {
        for offset in 0..3 {
            let mut shifted = Zeroizing::new(Vec::with_capacity(offset + bytes.len()));
            shifted.resize(offset, 0);
            shifted.extend_from_slice(bytes);
            let encoded = Zeroizing::new(engine.encode(shifted.as_slice()).into_bytes());
            let skip = [0, 2, 3][offset];
            let whole = shifted.len() * 8 / 6;
            if whole >= skip + WINDOW {
                needles.push(Zeroizing::new(encoded[skip..skip + WINDOW].to_vec()));
                needles.push(Zeroizing::new(encoded[whole - WINDOW..whole].to_vec()));
            }
        }
    }
    needles.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    needles.dedup_by(|a, b| a.as_slice() == b.as_slice());
    needles.iter().map(|n| &*Box::leak(n.to_vec().into_boxed_slice())).collect()
}
