//! What building a `serde_json::Value` from untrusted bytes costs, and a worker-wide pool those costs are charged to.
//!
//! A byte cap bounds what arrives; a `Value` costs per node: 5 MiB of `[{"a":1},...]` builds about 450 MiB, more than a hosted worker. Wherever the gateway builds a tree of an untrusted document on a path that can wait (an agent's params, a Vercel response it projects), it:
//!
//! 1. estimates the tree from one allocation-free pass over the bytes ([`estimate`]),
//! 2. reserves that much, with what the code path holds beside the tree, from the worker's [`MemoryPool`], waiting a bounded time for room, and
//! 3. builds the tree with [`value_from_slice`], whose own visitor charges every allocation it makes against the estimate and stops the parse the moment the charge would pass it.
//!
//! A body parsed by [`crate::http::ReqwestClient`]'s `send` is the exception: the request has already gone out, so its tree is charged to the pool only when there is room at once, and is otherwise built beside the pool under the client's fixed tree ceiling.
//!
//! The [`MemoryCharge`] the pool hands back is meant to live beside the tree it paid for (the gateway keeps them in one `Arc`), so the room is given back exactly when the last holder of the tree drops it, whichever task that is.
//!
//! The cost model is what serde_json (without `preserve_order`) allocates for a `Value`, in glibc chunks (the request plus an 8-byte header, rounded up to 16, and never under 32):
//!
//! - an object allocates nothing until its first member, then a 632-byte B-tree leaf that holds eleven members; the twelfth splits it into two leaves under a 728-byte internal root, and every member after that is charged [`MEMBER_BYTES`], above the per-member cost of a B-tree whose nodes are never less than half full, which insertion guarantees whatever order the keys arrive in;
//! - an array is a `Vec` of 32-byte `Value`s at the capacity pushing grows it to (four, then doubling), plus the old buffer the largest array holds while `realloc` copies it;
//! - every string, key or value, is its own chunk, at least [`STRING_MIN_BYTES`] however short;
//! - the deserializer's scratch buffer grows to twice the longest escaped string or long number.
//!
//! The estimate, and the visitor's charge, are therefore upper bounds on the heap the tree holds at any point of the parse.
//! The visitor reads serde_json's `raw_value` key (`$serde_json::private::RawValue`) as an ordinary key: `Value`'s own visitor would parse the string under it as a second document no estimate sees, which is why no untrusted document reaches `Value::deserialize` on a path that uses this module.

use std::sync::Arc;
use std::time::Duration;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// One `serde_json::Value`: the slot every element and member occupies in its container.
pub const SLOT_BYTES: u64 = 32;

/// An object's first allocation: a 632-byte B-tree leaf in a 640-byte chunk.
pub const LEAF_BYTES: u64 = 640;

/// What an object's twelfth member adds: a second leaf, and a 728-byte internal root in a 736-byte chunk.
pub const SPLIT_BYTES: u64 = LEAF_BYTES + 736;

/// What each member after an object's twelfth is charged. A non-root node always holds at least five keys, so a member costs at most a sixth of a leaf plus a fifth of that for the internal levels, about 131 bytes; the rest is margin for the moments an internal node splits.
pub const MEMBER_BYTES: u64 = 144;

/// The least any string is charged: glibc's smallest chunk, which holds up to 24 bytes.
pub const STRING_MIN_BYTES: u64 = 32;

/// The members a B-tree leaf holds before it splits.
const LEAF_MEMBERS: u64 = 11;

/// How deep the scan tracks containers. serde_json refuses a document nested deeper than 128 before it builds anything there, so past this depth the scan only charges what each token could cost.
const TRACKED_DEPTH: usize = 256;

/// The glibc chunk an allocation of `request` bytes takes.
pub const fn chunk_bytes(request: u64) -> u64 {
    let chunk = (request + 8 + 15) & !15;
    if chunk < STRING_MIN_BYTES {
        STRING_MIN_BYTES
    } else {
        chunk
    }
}

/// What an array's `n`th element (counting from one) adds to the array's own buffer, and the old buffer that is still held while a growing array is copied.
const fn element_bytes(n: u64) -> (u64, u64) {
    if n == 1 {
        return (chunk_bytes(4 * SLOT_BYTES), 0);
    }
    if n > 4 && (n - 1).is_power_of_two() {
        let old = chunk_bytes((n - 1) * SLOT_BYTES);
        return (chunk_bytes(2 * (n - 1) * SLOT_BYTES) - old, old);
    }
    (0, 0)
}

/// What an object's `n`th member (counting from one) adds to its B-tree, its key excluded.
const fn member_bytes(n: u64) -> u64 {
    match n {
        1 => LEAF_BYTES,
        n if n <= LEAF_MEMBERS => 0,
        n if n == LEAF_MEMBERS + 1 => SPLIT_BYTES,
        _ => MEMBER_BYTES,
    }
}

#[derive(Clone, Copy)]
struct Frame {
    object: bool,
    count: u64,
    awaiting_first: bool,
}

/// An upper bound on the heap a `Value` parsed from `bytes` holds at any point of the parse, from one pass that allocates nothing. Meaningful only for JSON: for anything else it counts punctuation.
pub fn estimate(bytes: &[u8]) -> u64 {
    let mut frames = [Frame { object: false, count: 0, awaiting_first: false }; TRACKED_DEPTH];
    let mut depth = 0usize;
    let mut total = 0u64;
    let mut transient = 0u64;
    let mut scratch = 0u64;
    let mut in_string = false;
    let mut escaped = false;
    let mut string_escaped = false;
    let mut string_start = 0usize;
    let mut token = 0u64;
    for (at, &b) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
                string_escaped = true;
            } else if b == b'"' {
                in_string = false;
                let len = (at - string_start) as u64;
                total += chunk_bytes(len);
                if string_escaped {
                    scratch = scratch.max(chunk_bytes(2 * len));
                }
            }
            continue;
        }
        let whitespace = matches!(b, b' ' | b'\t' | b'\n' | b'\r');
        if whitespace || matches!(b, b'{' | b'[' | b'}' | b']' | b',' | b':' | b'"') {
            if token > 0 {
                scratch = scratch.max(chunk_bytes(2 * token));
                token = 0;
            }
        } else {
            token += 1;
        }
        if (1..=TRACKED_DEPTH).contains(&depth) {
            let top = &mut frames[depth - 1];
            if top.object {
                if b == b':' {
                    top.count += 1;
                    total += member_bytes(top.count);
                }
            } else {
                // An element starts at a comma, or at the first byte after `[` that does not close it.
                let starts = match b {
                    b',' => true,
                    b']' => false,
                    _ if whitespace => false,
                    _ => top.awaiting_first,
                };
                if starts {
                    top.awaiting_first = false;
                    top.count += 1;
                    let (added, old) = element_bytes(top.count);
                    total += added;
                    transient = transient.max(old);
                }
            }
        }
        match b {
            b'"' => {
                in_string = true;
                string_escaped = false;
                string_start = at + 1;
            }
            b'{' | b'[' => {
                if depth < TRACKED_DEPTH {
                    frames[depth] = Frame { object: b == b'{', count: 0, awaiting_first: b == b'[' };
                } else {
                    total += if b == b'{' { LEAF_BYTES } else { chunk_bytes(4 * SLOT_BYTES) };
                }
                depth += 1;
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b',' | b':' if depth > TRACKED_DEPTH => total += 2 * SLOT_BYTES,
            _ => {}
        }
    }
    if in_string && string_escaped {
        // An unterminated string allocates nothing of its own, but its escapes still grew the scratch.
        scratch = scratch.max(chunk_bytes(2 * (bytes.len() - string_start) as u64));
    }
    if token > 0 {
        scratch = scratch.max(chunk_bytes(2 * token));
    }
    total + transient + scratch
}

// ── Building a value under a limit ──────────────────────────────────────────────

/// Why [`value_from_slice`] or [`value_from`] built nothing.
#[derive(Debug)]
pub enum BuildError<E> {
    /// What the value would hold passed the limit it was built under; what was built has been dropped.
    OverLimit {
        /// The limit, in bytes.
        limit: u64,
    },
    /// The input is not a document the target reads (syntax, nesting, trailing characters).
    Parse(E),
}

impl<E: std::fmt::Display> std::fmt::Display for BuildError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::OverLimit { limit } => {
                write!(f, "the JSON document would take more than the {limit} bytes reserved for it once parsed")
            }
            BuildError::Parse(e) => e.fmt(f),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for BuildError<E> {}

/// The running charge of one value being built.
struct Meter {
    limit: u64,
    charged: std::cell::Cell<u64>,
    over: std::cell::Cell<bool>,
}

impl Meter {
    fn new(limit: u64) -> Self {
        Meter { limit, charged: std::cell::Cell::new(0), over: std::cell::Cell::new(false) }
    }

    /// Charge `held` for good and check that `passing` more, held only for a moment, still fits.
    fn charge<E: de::Error>(&self, held: u64, passing: u64) -> Result<(), E> {
        let charged = self.charged.get().saturating_add(held);
        if charged.saturating_add(passing) > self.limit {
            self.over.set(true);
            return Err(E::custom("the value is over the memory reserved for it"));
        }
        self.charged.set(charged);
        Ok(())
    }
}

/// Build a [`Value`] from `bytes` (one JSON document, as `serde_json::from_slice` reads one) charging what each node allocates, and stop as soon as the charge would pass `limit`.
/// With `limit` set to [`estimate`]`(bytes)` a JSON document always fits; the limit is what makes the bound hold even if the estimate were ever wrong.
pub fn value_from_slice(bytes: &[u8], limit: u64) -> Result<Value, BuildError<serde_json::Error>> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = value_from(&mut de, limit)?;
    de.end().map_err(BuildError::Parse)?;
    Ok(value)
}

/// [`value_from_slice`] over any deserializer.
pub fn value_from<'de, D: Deserializer<'de>>(deserializer: D, limit: u64) -> Result<Value, BuildError<D::Error>> {
    let meter = Meter::new(limit);
    match Node(&meter).deserialize(deserializer) {
        Ok(value) => Ok(value),
        Err(_) if meter.over.get() => Err(BuildError::OverLimit { limit }),
        Err(e) => Err(BuildError::Parse(e)),
    }
}

/// What [`value_from`] charged for `value`, rebuilt from the value itself: the same model, for tests and for a caller that holds a tree it did not build here.
pub fn charged_for(value: &Value) -> u64 {
    match value {
        Value::String(s) => chunk_bytes(s.len() as u64),
        Value::Array(items) => {
            let mut total = 0;
            for (i, item) in items.iter().enumerate() {
                total += element_bytes(i as u64 + 1).0 + charged_for(item);
            }
            total
        }
        Value::Object(map) => {
            let mut total = 0;
            for (i, (key, item)) in map.iter().enumerate() {
                total += chunk_bytes(key.len() as u64) + member_bytes(i as u64 + 1) + charged_for(item);
            }
            total
        }
        _ => 0,
    }
}

#[derive(Clone, Copy)]
struct Node<'m>(&'m Meter);

impl<'de> DeserializeSeed<'de> for Node<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Node<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any value JSON can hold")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Value, E> {
        serde::Deserialize::deserialize(de::value::I128Deserializer::<E>::new(v)).map(Value::Number)
    }

    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Value, E> {
        serde::Deserialize::deserialize(de::value::U128Deserializer::<E>::new(v)).map(Value::Number)
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        self.0.charge(chunk_bytes(v.len() as u64), 0)?;
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        self.0.charge(chunk_bytes(v.len() as u64), 0)?;
        Ok(Value::String(v))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        self.deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self)? {
            let (added, old) = element_bytes(items.len() as u64 + 1);
            self.0.charge(added, old)?;
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        let mut count = 0u64;
        while let Some(key) = map.next_key_seed(Key(self.0))? {
            let value = map.next_value_seed(self)?;
            count += 1;
            self.0.charge(member_bytes(count), 0)?;
            members.insert(key, value);
        }
        Ok(Value::Object(members))
    }
}

/// A map key, read as a string the way `serde_json::Value` reads one and charged like any string.
struct Key<'m>(&'m Meter);

impl<'de> DeserializeSeed<'de> for Key<'_> {
    type Value = String;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        let key = <String as serde::Deserialize>::deserialize(deserializer)?;
        self.0.charge(chunk_bytes(key.len() as u64), 0)?;
        Ok(key)
    }
}

// ── A meter for a typed parse ───────────────────────────────────────────────────

thread_local! {
    static AMBIENT: std::cell::RefCell<Option<std::rc::Rc<Meter>>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` with every [`MeteredValue`] it deserializes charged to one meter of `limit` bytes, and say whether the limit was passed. For a typed parse (a request struct with a `MeteredValue` field) whose other fields serde reads as usual.
/// `f` must not await: the meter is per thread.
pub fn with_limit<R>(limit: u64, f: impl FnOnce() -> R) -> (R, bool) {
    struct Restore(Option<std::rc::Rc<Meter>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            AMBIENT.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let meter = std::rc::Rc::new(Meter::new(limit));
    let _restore = Restore(AMBIENT.with(|slot| slot.replace(Some(meter.clone()))));
    let out = f();
    (out, meter.over.get())
}

/// A `Value` read by this module's visitor rather than `Value`'s own, so serde_json's raw-value key is an ordinary key, charged to the meter [`with_limit`] set (with none set, to a meter of its own with no limit: a tree already in memory, or a parse nobody bounded).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MeteredValue(pub Value);

impl<'de> serde::Deserialize<'de> for MeteredValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let meter = AMBIENT.with(|slot| slot.borrow().clone()).unwrap_or_else(|| std::rc::Rc::new(Meter::new(u64::MAX)));
        Node(&meter).deserialize(deserializer).map(MeteredValue)
    }
}

// ── The worker-wide pool ────────────────────────────────────────────────────────

/// The worker's budget for the trees its calls hold at once, counted in KiB.
///
/// A tree built on a path that can wait reserves its charge here first, waiting a bounded time for room; a reservation larger than the whole pool is refused at once rather than queued, since no amount of waiting makes room for it. An upstream response body read by [`crate::http::ReqwestClient`] is charged only when there is room at once, and is otherwise built beside the pool under a fixed ceiling ([`crate::http::ReqwestClient::with_memory`]).
/// The semaphore is first-come first-served, so a large reservation waiting at the head is not starved by smaller ones behind it.
#[derive(Debug)]
pub struct MemoryPool {
    permits: Arc<Semaphore>,
    max_kib: u32,
}

const KIB: u64 = 1024;

fn kib(bytes: u64) -> u64 {
    bytes.div_ceil(KIB)
}

impl MemoryPool {
    /// A pool of `max_bytes`, rounded up to a whole KiB.
    pub fn new(max_bytes: u64) -> Self {
        let max_kib = kib(max_bytes).clamp(1, u32::MAX as u64 >> 3) as u32;
        MemoryPool { permits: Arc::new(Semaphore::new(max_kib as usize)), max_kib }
    }

    /// The pool's size in bytes.
    pub fn max_bytes(&self) -> u64 {
        self.max_kib as u64 * KIB
    }

    /// What is not reserved right now, in bytes.
    pub fn available_bytes(&self) -> u64 {
        self.permits.available_permits() as u64 * KIB
    }

    /// Reserve `bytes`, waiting up to `wait` for room.
    pub async fn reserve(&self, bytes: u64, wait: Duration) -> Result<MemoryCharge, PoolRefusal> {
        let needed = kib(bytes);
        if needed == 0 {
            return Ok(MemoryCharge::none());
        }
        if needed > self.max_kib as u64 {
            return Err(PoolRefusal::TooLarge { needed_bytes: bytes, pool_bytes: self.max_bytes() });
        }
        let busy = PoolRefusal::Busy { needed_bytes: bytes, pool_bytes: self.max_bytes(), waited: wait };
        match tokio::time::timeout(wait, self.permits.clone().acquire_many_owned(needed as u32)).await {
            Ok(Ok(permit)) => Ok(MemoryCharge(Some(Arc::new(permit)))),
            _ => Err(busy),
        }
    }

    /// Reserve `bytes` only if the pool has that room now, without waiting or joining the queue, so a reservation behind a large waiter does not wait on it.
    pub fn try_reserve(&self, bytes: u64) -> Option<MemoryCharge> {
        let needed = kib(bytes);
        if needed == 0 {
            return Some(MemoryCharge::none());
        }
        let needed = u32::try_from(needed).ok().filter(|&n| n <= self.max_kib)?;
        self.permits.clone().try_acquire_many_owned(needed).ok().map(|permit| MemoryCharge(Some(Arc::new(permit))))
    }
}

/// Room reserved in a [`MemoryPool`], given back when the last clone of this charge is dropped. Keep it beside the tree it paid for.
#[derive(Clone, Default)]
pub struct MemoryCharge(Option<Arc<OwnedSemaphorePermit>>);

impl MemoryCharge {
    /// A charge that holds nothing: for a tree that was not built from untrusted bytes, or a caller with no pool.
    pub fn none() -> Self {
        MemoryCharge(None)
    }

    /// The bytes this charge holds (whole KiB).
    pub fn bytes(&self) -> u64 {
        self.0.as_ref().map_or(0, |permit| permit.num_permits() as u64 * KIB)
    }
}

impl std::fmt::Debug for MemoryCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemoryCharge({} bytes)", self.bytes())
    }
}

/// Two responses are equal whatever room they hold.
impl PartialEq for MemoryCharge {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for MemoryCharge {}

/// Why a [`MemoryPool`] did not reserve. The text carries sizes only, never the document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolRefusal {
    /// More than the whole pool: it can never be reserved.
    TooLarge {
        /// What was asked for.
        needed_bytes: u64,
        /// The pool's size.
        pool_bytes: u64,
    },
    /// The pool had no room within the wait; retrying later can succeed.
    Busy {
        /// What was asked for.
        needed_bytes: u64,
        /// The pool's size.
        pool_bytes: u64,
        /// How long it waited.
        waited: Duration,
    },
}

impl std::fmt::Display for PoolRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolRefusal::TooLarge { needed_bytes, pool_bytes } => write!(
                f,
                "the JSON document needs about {needed_bytes} bytes of memory once parsed, more than this gateway's {pool_bytes}-byte budget for the documents its calls hold: it is made of too many objects, arrays or elements for its size"
            ),
            PoolRefusal::Busy { needed_bytes, pool_bytes, waited } => write!(
                f,
                "this gateway's {pool_bytes}-byte budget for the documents its calls hold had no room for one needing about {needed_bytes} bytes within {} ms; retry shortly",
                waited.as_millis()
            ),
        }
    }
}

impl std::error::Error for PoolRefusal {}

/// Why [`parse_charged`] built nothing.
#[derive(Debug)]
pub enum ChargedParseError {
    /// The pool refused the reservation; nothing was parsed.
    Pool(PoolRefusal),
    /// The bytes are not one JSON document.
    Json(serde_json::Error),
    /// The tree passed what was reserved for it (the estimate was wrong); nothing is kept.
    OverLimit(u64),
}

impl std::fmt::Display for ChargedParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChargedParseError::Pool(refusal) => refusal.fmt(f),
            ChargedParseError::Json(e) => e.fmt(f),
            ChargedParseError::OverLimit(limit) => BuildError::<serde_json::Error>::OverLimit { limit: *limit }.fmt(f),
        }
    }
}

impl std::error::Error for ChargedParseError {}

/// Parse `bytes` into a tree charged to `pool`: estimate it, reserve the estimate `copies` times (waiting up to `wait`), and build it under the estimate. Bytes that are not JSON are reported as such whatever the pool says, which is checked without building anything.
pub async fn parse_charged(
    pool: &MemoryPool,
    bytes: &[u8],
    copies: u64,
    wait: Duration,
) -> Result<(Value, MemoryCharge), ChargedParseError> {
    let estimate = estimate(bytes);
    parse_reserved(pool, bytes, estimate, estimate.saturating_mul(copies.max(1)), wait).await
}

/// [`parse_charged`], reserving the tree's estimate and `beside` more for what the caller writes from the tree while it holds it.
pub async fn parse_charged_beside(
    pool: &MemoryPool,
    bytes: &[u8],
    beside: u64,
    wait: Duration,
) -> Result<(Value, MemoryCharge), ChargedParseError> {
    let estimate = estimate(bytes);
    parse_reserved(pool, bytes, estimate, estimate.saturating_add(beside), wait).await
}

async fn parse_reserved(
    pool: &MemoryPool,
    bytes: &[u8],
    estimate: u64,
    reserve: u64,
    wait: Duration,
) -> Result<(Value, MemoryCharge), ChargedParseError> {
    let charge = match pool.reserve(reserve, wait).await {
        Ok(charge) => charge,
        Err(refusal) => {
            serde_json::from_slice::<de::IgnoredAny>(bytes).map_err(ChargedParseError::Json)?;
            return Err(ChargedParseError::Pool(refusal));
        }
    };
    match value_from_slice(bytes, estimate) {
        Ok(value) => Ok((value, charge)),
        Err(BuildError::Parse(e)) => Err(ChargedParseError::Json(e)),
        Err(BuildError::OverLimit { limit }) => Err(ChargedParseError::OverLimit(limit)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one_key_objects(size: usize) -> Vec<u8> {
        let mut body = String::from("[");
        while body.len() + 9 < size {
            body.push_str("{\"a\":1},");
        }
        body.pop();
        body.push(']');
        body.into_bytes()
    }

    #[test]
    fn the_estimate_covers_what_the_visitor_charges_and_the_visitor_builds_what_serde_json_builds() {
        let docs = vec![
            json!({ "a": [1, 2, { "b": "c" }], "d": "x".repeat(100), "e": null, "f": 1.5 }),
            json!((0..40).map(|i| json!({ "id": i, "ok": true })).collect::<Vec<_>>()),
            json!((0..30).map(|i| (format!("k{i}"), json!(i))).collect::<serde_json::Map<_, _>>()),
            json!("plain"),
            json!([[[[[]]]]]),
            json!({ "esc": "a\"b\\c\u{1}é", "big": 18446744073709551615u64, "neg": -1 }),
        ];
        for doc in docs {
            let bytes = serde_json::to_vec(&doc).unwrap();
            let est = estimate(&bytes);
            let built = value_from_slice(&bytes, est).expect("a document fits its own estimate");
            assert_eq!(built, doc);
            assert_eq!(built, serde_json::from_slice::<Value>(&bytes).unwrap());
            assert!(charged_for(&built) <= est, "charged {} over estimate {est} for {doc}", charged_for(&built));
        }
    }

    #[test]
    fn a_value_over_its_limit_is_stopped_and_nothing_is_kept() {
        let bytes = one_key_objects(64 * 1024);
        let est = estimate(&bytes);
        assert!(est > 80 * bytes.len() as u64, "one-key objects cost about 85 bytes a byte: {est}");
        assert!(matches!(value_from_slice(&bytes, est / 2), Err(BuildError::OverLimit { .. })));
        assert!(value_from_slice(&bytes, est).is_ok());
    }

    #[test]
    fn the_raw_value_key_builds_an_ordinary_member() {
        let inner = String::from_utf8(one_key_objects(32 * 1024)).unwrap();
        let doc = serde_json::to_vec(&json!({ "$serde_json::private::RawValue": inner })).unwrap();
        let est = estimate(&doc);
        assert!(est < 4 * doc.len() as u64, "one string and the scratch for its escapes, not a tree: {est}");
        let built = value_from_slice(&doc, est).unwrap();
        assert!(built["$serde_json::private::RawValue"].is_string());
    }

    #[test]
    fn bytes_that_are_not_one_document_are_a_parse_error() {
        for bad in [&b"{\"a\":"[..], b"[1] [2]", b"<html>", b""] {
            assert!(matches!(value_from_slice(bad, 1 << 20), Err(BuildError::Parse(_))), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_typed_parse_charges_its_metered_field_and_stops_at_the_limit() {
        #[derive(serde::Deserialize)]
        struct Req {
            name: String,
            #[serde(default)]
            params: MeteredValue,
        }
        let rows = String::from_utf8(one_key_objects(16 * 1024)).unwrap();
        let body = format!(r#"{{"name":"n","params":{rows}}}"#);
        let est = estimate(body.as_bytes());
        let (ok, over) = with_limit(est, || serde_json::from_str::<Req>(&body));
        assert!(!over);
        let ok = ok.unwrap();
        assert_eq!(ok.name, "n");
        assert!(ok.params.0.is_array());
        let (refused, over) = with_limit(est / 4, || serde_json::from_str::<Req>(&body));
        assert!(over && refused.is_err());
        let raw = r#"{"name":"n","params":{"$serde_json::private::RawValue":"[1,2,3]"}}"#;
        let (read, _) = with_limit(1 << 20, || serde_json::from_str::<Req>(raw));
        assert_eq!(read.unwrap().params.0, json!({ "$serde_json::private::RawValue": "[1,2,3]" }), "the key is ordinary");
    }

    #[tokio::test]
    async fn the_pool_waits_for_room_and_refuses_what_never_fits() {
        let pool = MemoryPool::new(1024 * 1024);
        let first = pool.reserve(700 * 1024, Duration::from_millis(10)).await.unwrap();
        assert_eq!(first.bytes(), 700 * 1024);
        assert!(matches!(
            pool.reserve(400 * 1024, Duration::from_millis(20)).await,
            Err(PoolRefusal::Busy { .. })
        ));
        assert!(matches!(pool.reserve(2 * 1024 * 1024, Duration::from_secs(5)).await, Err(PoolRefusal::TooLarge { .. })));
        let held = first.clone();
        drop(first);
        assert_eq!(pool.available_bytes(), 324 * 1024, "a clone keeps the room");
        let waiting = tokio::spawn({
            let pool = Arc::new(pool);
            async move {
                let charge = pool.reserve(400 * 1024, Duration::from_secs(5)).await;
                (charge.map(|c| c.bytes()), pool)
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(held);
        let (charge, pool) = waiting.await.unwrap();
        assert_eq!(charge.unwrap(), 400 * 1024);
        assert_eq!(pool.available_bytes(), 1024 * 1024, "the waiter's charge went with it");
    }

    #[tokio::test]
    async fn parse_charged_reserves_the_estimate_times_its_copies() {
        let pool = MemoryPool::new(64 * 1024 * 1024);
        let bytes = serde_json::to_vec(&json!({ "rows": (0..100).map(|i| json!({ "id": i })).collect::<Vec<_>>() })).unwrap();
        let (value, charge) = parse_charged(&pool, &bytes, 2, Duration::from_millis(10)).await.unwrap();
        assert_eq!(value["rows"][99]["id"], 99);
        assert!(charge.bytes() >= 2 * estimate(&bytes));
        drop(value);
        assert!(pool.available_bytes() < pool.max_bytes());
        drop(charge);
        assert_eq!(pool.available_bytes(), pool.max_bytes());
        let not_json = parse_charged(&MemoryPool::new(1024), b"<html>not json</html>", 1, Duration::ZERO).await;
        assert!(matches!(not_json, Err(ChargedParseError::Json(_))), "not JSON is said to be not JSON, whatever the pool says");
    }
}
