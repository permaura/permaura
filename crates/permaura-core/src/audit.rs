//! Tamper-evident audit log.
//!
//! The gateway records every policy decision on an invoke and every execution outcome as an
//! [`AuditEvent`]. Refusals it makes before policy are not recorded: the execution hold, agents paused, a
//! draining gateway, a session over its denial budget, an unknown capability, a call over the
//! unpacked-size ceiling, and an unauthenticated or rate-limited request. Events form
//! a hash chain: each event's `hash = sha256(prev_hash || canonical_json(payload))`,
//! where `payload` is the event with its own `hash`/`signature` fields blank. The
//! whole event is then signed with an ed25519 key so the log is both *chained*
//! (you cannot edit a past event without breaking every later hash) and *signed*
//! (you cannot forge or re-chain events without the private key).
//!
//! [`AuditLog::verify`] walks the chain and returns the sequence number of the
//! first event that fails either check, or `None` if the whole chain is intact.
//!
//! # What this does NOT prove
//!
//! Read "you cannot re-chain events without the private key" literally: the guarantee is exactly as
//! strong as the key's custody, and no stronger. Without a KMS key the store keeps the key inside the
//! same blast radius as the records (in the database, or in a `0600` file beside it), so an attacker
//! who can rewrite the rows can also sign the rewrite, and `verify()` will bless it.
//! Against an outsider the log is tamper-evident; against whoever holds the store it is not.
//!
//! Nor does a chain detect its own **truncation**: drop the last N events and the surviving prefix
//! verifies perfectly, because nothing in the log remembers how long it was.
//!
//! Neither is a flaw in this module: both are custody questions, and they live in
//! `services/gateway/src/custody.rs` ([`KeyCustody`], [`AuditCheckpoint`]) with the honest description
//! of what a given deployment actually guarantees. Do not upgrade these claims in prose without
//! upgrading the custody backend first.
//!
//! # The base, and why sequence numbers are absolute
//!
//! A log does not have to hold every event it has ever recorded. [`AuditLog`] carries a `base_seq`
//! and a `base_hash`: the absolute sequence number of the oldest event it still holds, and the chain
//! hash that event links back to. A log with nothing archived has `base_seq = 0` and
//! [`GENESIS_PREV_HASH`], which is the whole of the old behaviour, so a chain written before any of
//! this verifies unchanged and every signature ever produced stays valid, because the event format
//! does not move. What changes is that a sequence number now means "the nth event this tenant ever recorded"
//! rather than "the nth event in this vector", which is what lets a prefix leave the hot store
//! without the remaining events renumbering themselves underneath their own signatures.
//!
//! The base itself is only as trustworthy as whatever states it. [`AuditBoundary`] is that
//! statement, signed under the same key and domain-separated so it can never be presented as an
//! event.
//!
//! # A rekey
//!
//! A store whose key is gone can be given a new one (`permaura audit rekey`, [`AuditRekey`]). The first
//! event under the new key names the old chain's head, and every event below it is then checked for its
//! hash and its link but not its signature, which nothing can check again. A rekey is a recorded fork,
//! not a repair: verification reports it, and an old event whose contents changed still breaks the chain.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{PermauraError, Result};

/// The genesis previous-hash for the first event in a chain (32 zero bytes, hex).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// The application payload of an audit event: the *facts* being recorded, which are
/// who, which agent/device/session, the action,
/// the resource, the decision, execution location, and a redacted result summary.
/// It deliberately contains **no raw request/response bodies and no secrets**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPayload {
    /// The action / capability id (e.g. `braintree.transactions.search`).
    pub action: String,
    /// The resource short name (e.g. `braintree_production`).
    pub resource: String,
    /// The decision verbatim (`allow` / `deny` / `requires_approval`).
    pub decision: String,
    /// The responsible user id, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// The agent that made the call, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// The device the call originated from, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// The agent session id, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Where the action executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_location: Option<String>,
    /// Free-form, already-redacted summary of the result (record counts, status, ...). Never raw bodies.
    #[serde(default)]
    pub summary: serde_json::Value,
}

impl AuditPayload {
    /// Minimal constructor for the common case.
    pub fn new(
        action: impl Into<String>,
        resource: impl Into<String>,
        decision: impl Into<String>,
    ) -> Self {
        AuditPayload {
            action: action.into(),
            resource: resource.into(),
            decision: decision.into(),
            user_id: None,
            agent_id: None,
            device_id: None,
            session_id: None,
            execution_location: None,
            summary: serde_json::Value::Null,
        }
    }
}

/// A single, sealed audit event. `seq`, `timestamp`, `prev_hash`, the application
/// `payload`, then the computed `hash` and ed25519 `signature` over the canonical
/// pre-hash form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic sequence number, starting at 0.
    pub seq: u64,
    /// Unix-millisecond timestamp the event was appended.
    pub timestamp: i64,
    /// The hash of the previous event (or [`GENESIS_PREV_HASH`] for the first).
    pub prev_hash: String,
    /// The recorded facts.
    pub payload: AuditPayload,
    /// `sha256(prev_hash || canonical_json(seq,timestamp,prev_hash,payload))`, hex-encoded.
    pub hash: String,
    /// ed25519 signature over the raw 32-byte hash, hex-encoded.
    pub signature: String,
}

/// Internal canonical form used for hashing. Excludes `hash` and `signature` so the
/// hash is computed over a stable, deterministic serialization.
#[derive(Serialize)]
struct Canonical<'a> {
    seq: u64,
    timestamp: i64,
    prev_hash: &'a str,
    payload: &'a AuditPayload,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(PermauraError::AuditIntegrity("odd-length hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| PermauraError::AuditIntegrity("invalid hex".into()))
        })
        .collect()
}

/// Compute the chain hash for an event's fields. `serde_json` serializes struct
/// fields in declaration order, which gives us a stable canonicalization without
/// pulling in a separate canonical-JSON crate.
fn compute_hash(
    seq: u64,
    timestamp: i64,
    prev_hash: &str,
    payload: &AuditPayload,
) -> Result<[u8; 32]> {
    let canonical = Canonical {
        seq,
        timestamp,
        prev_hash,
        payload,
    };
    let bytes = serde_json::to_vec(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

/// An append-only, hash-chained, signed audit log held in memory. The gateway/daemon
/// persists the resulting [`AuditEvent`]s; this type owns the chaining and signing
/// invariants so persistence layers cannot get them subtly wrong.
pub struct AuditLog {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// Absolute seq of `events[0]`. Zero when nothing has been archived.
    base_seq: u64,
    /// Chain hash the first held event links to. [`GENESIS_PREV_HASH`] when `base_seq` is zero.
    base_hash: String,
    events: Vec<AuditEvent>,
    /// How much of `events` an earlier [`AuditLog::verify`] proved, so the next one checks only what
    /// was appended since. Held events cannot change in place, only be appended to or have a prefix
    /// archived, so a proven prefix stays proven while the base it was proven from is unchanged.
    proven: std::sync::Mutex<ProvenPrefix>,
    /// The seq a recorded [`AuditRekey`] moved the chain to this key at. Events below it were signed
    /// under a key this log does not hold, so they are checked for their hash and linkage only.
    signed_from: u64,
}

/// The leading events of a log that verification has already proven, from the base they were
/// proven against.
#[derive(Default)]
struct ProvenPrefix {
    base_seq: u64,
    base_hash: String,
    len: usize,
}

/// Held events no verification has proven yet, copied out of an [`AuditLog`] by
/// [`AuditLog::unproven`] so their signatures can be checked without holding whatever guards it.
pub struct UnprovenEvents {
    base_seq: u64,
    base_hash: String,
    /// Where `events[0]` sat among the log's held events when it was copied.
    start: usize,
    /// What `events[0]` must link back to.
    link: String,
    verifying_key: VerifyingKey,
    events: Vec<AuditEvent>,
    signed_from: u64,
}

impl UnprovenEvents {
    /// Check every copied event, stopping at the first that does not verify.
    pub fn check(&self) -> CheckedEvents {
        AuditLog::verify_prefix(&self.events, &self.verifying_key, self.first_seq(), &self.link, self.signed_from)
    }

    /// The absolute seq of the first copied event.
    pub fn first_seq(&self) -> u64 {
        self.base_seq + self.start as u64
    }
}

/// What [`UnprovenEvents::check`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedEvents {
    /// How many events verified before the first that did not.
    pub proven: usize,
    /// The seq of the first event that did not verify, if one did not.
    pub broken: Option<u64>,
}

impl CheckedEvents {
    /// How many events the check looked at, the one that broke included.
    pub fn checked(&self) -> usize {
        self.proven + usize::from(self.broken.is_some())
    }
}

impl AuditLog {
    /// Create a fresh, empty log with a freshly generated ed25519 keypair.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        Self::empty_at_genesis(signing_key)
    }

    /// Create a log from an existing signing key (the one a store loads when it opens).
    pub fn with_signing_key(signing_key: SigningKey) -> Self {
        Self::empty_at_genesis(signing_key)
    }

    fn empty_at_genesis(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        AuditLog {
            signing_key,
            verifying_key,
            base_seq: 0,
            base_hash: GENESIS_PREV_HASH.to_string(),
            events: Vec::new(),
            proven: std::sync::Mutex::new(ProvenPrefix::default()),
            signed_from: 0,
        }
    }

    /// Rehydrate a log from a persisted signing key and its already-chained events, the path a
    /// persistent store takes on restart so the chain continues from the right head/seq and the
    /// whole history still verifies under the same key. The events are taken as stored; the caller
    /// can run [`AuditLog::verify`] to confirm they're intact.
    pub fn restore(signing_key: SigningKey, events: Vec<AuditEvent>) -> Self {
        Self::restore_from(signing_key, 0, GENESIS_PREV_HASH.to_string(), events)
    }

    /// Rehydrate a log whose oldest held event is not the first one ever recorded, because the
    /// events below `base_seq` have been archived. `base_hash` is the hash of event `base_seq - 1`,
    /// which is what the first held event links to and what a store reads out of its signed
    /// [`AuditBoundary`]; a caller with nothing archived wants [`AuditLog::restore`].
    pub fn restore_from(
        signing_key: SigningKey,
        base_seq: u64,
        base_hash: String,
        events: Vec<AuditEvent>,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        AuditLog {
            signing_key,
            verifying_key,
            base_seq,
            base_hash,
            events,
            proven: std::sync::Mutex::new(ProvenPrefix::default()),
            signed_from: 0,
        }
    }

    /// Take `rekey` as where this chain moved to this log's key: every event below its seq is then
    /// checked for its hash and linkage only, because the key that signed it is gone. The caller has
    /// already proven the rekey is this key's: its event is held ([`AuditLog::held_rekey`]), or its
    /// signed record verifies ([`AuditRekey::verify`]) and the event has been archived.
    pub fn honor_rekey(&mut self, rekey: &AuditRekey) {
        self.signed_from = rekey.seq;
        *self.proven.lock().unwrap_or_else(|p| p.into_inner()) = ProvenPrefix::default();
    }

    /// The latest held event that records a rekey to this log's key ([`AuditRekey::from_event`]).
    pub fn held_rekey(&self) -> Option<AuditRekey> {
        self.events.iter().rev().find_map(|event| AuditRekey::from_event(event, &self.verifying_key))
    }

    /// The seq from which every event must carry this key's signature: zero unless a rekey is honored.
    pub fn signed_from(&self) -> u64 {
        self.signed_from
    }

    /// The public verifying key, so a verifier (cloud, auditor) can check the chain
    /// without the private key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// The absolute seq the next appended event will carry.
    pub fn next_seq(&self) -> u64 {
        self.base_seq + self.events.len() as u64
    }

    /// The absolute seq of the oldest event still held.
    pub fn base_seq(&self) -> u64 {
        self.base_seq
    }

    /// The hash the oldest held event links back to.
    pub fn base_hash(&self) -> &str {
        &self.base_hash
    }

    /// The current chain head hash. An empty log answers its base, which is [`GENESIS_PREV_HASH`]
    /// only when nothing has been archived: a log whose whole hot window has been archived still
    /// links the next event to the archive's head rather than restarting the chain.
    pub fn head_hash(&self) -> String {
        self.events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| self.base_hash.clone())
    }

    /// Borrow the recorded events.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Append a payload, computing the chain hash and signing it. `timestamp` is the
    /// Unix-millisecond time the event occurred.
    pub fn append_at(&mut self, payload: AuditPayload, timestamp: i64) -> Result<&AuditEvent> {
        let event = self.seal_at(payload, timestamp)?;
        self.accept(event)
    }

    /// The event [`AuditLog::append_at`] would add, sealed and signed but not yet held. A store that
    /// must make the event durable before the chain moves seals it, writes it, and only then
    /// [`AuditLog::accept`]s it, so a failed write leaves the chain where the rows are.
    pub fn seal_at(&self, payload: AuditPayload, timestamp: i64) -> Result<AuditEvent> {
        let seq = self.next_seq();
        let prev_hash = self.head_hash();
        let hash = compute_hash(seq, timestamp, &prev_hash, &payload)?;
        let signature = self.signing_key.sign(&hash);
        Ok(AuditEvent {
            seq,
            timestamp,
            prev_hash,
            payload,
            hash: hex(&hash),
            signature: hex(&signature.to_bytes()),
        })
    }

    /// [`AuditLog::seal_at`] at the current wall-clock time (Unix ms).
    pub fn seal(&self, payload: AuditPayload) -> Result<AuditEvent> {
        self.seal_at(payload, now_unix_ms())
    }

    /// Hold an event [`AuditLog::seal_at`] produced. Refused unless it is the next event of this
    /// chain, so an event sealed before another was accepted can never be held out of order.
    pub fn accept(&mut self, event: AuditEvent) -> Result<&AuditEvent> {
        if event.seq != self.next_seq() || event.prev_hash != self.head_hash() {
            return Err(PermauraError::AuditIntegrity(format!(
                "event {} was not sealed against this chain's head (next is {})",
                event.seq,
                self.next_seq()
            )));
        }
        self.events.push(event);
        Ok(self.events.last().expect("just pushed"))
    }

    /// Append using the current wall-clock time (Unix ms).
    pub fn append(&mut self, payload: AuditPayload) -> Result<&AuditEvent> {
        self.append_at(payload, now_unix_ms())
    }

    /// Walk the chain and verify every event against the supplied verifying key:
    /// recompute each hash, confirm `prev_hash` linkage, and verify the signature.
    /// Returns the `seq` of the first tampered/broken event, or `None` if intact.
    pub fn verify_with(events: &[AuditEvent], verifying_key: &VerifyingKey) -> Option<u64> {
        Self::verify_from(events, verifying_key, 0, GENESIS_PREV_HASH)
    }

    /// The same walk over a window that starts at `base_seq` and links back to `base_hash`. The
    /// events below the base are not consulted and cannot be: this answers "is the window I hold
    /// intact and does it hang off the base I was told", which is the most a bounded store can say
    /// on its own.
    pub fn verify_from(
        events: &[AuditEvent],
        verifying_key: &VerifyingKey,
        base_seq: u64,
        base_hash: &str,
    ) -> Option<u64> {
        Self::verify_prefix(events, verifying_key, base_seq, base_hash, 0).broken
    }

    /// [`AuditLog::verify_from`] over a chain re-keyed at `signed_from` ([`AuditRekey`]): events below
    /// it are checked for their seq, hash and linkage, and not for a signature by `verifying_key`,
    /// which never made one. Zero is the strict walk.
    pub fn verify_from_rekeyed(
        events: &[AuditEvent],
        verifying_key: &VerifyingKey,
        base_seq: u64,
        base_hash: &str,
        signed_from: u64,
    ) -> Option<u64> {
        Self::verify_prefix(events, verifying_key, base_seq, base_hash, signed_from).broken
    }

    /// [`AuditLog::verify_from_rekeyed`], and how many events verified before the first that did not.
    fn verify_prefix(
        events: &[AuditEvent],
        verifying_key: &VerifyingKey,
        base_seq: u64,
        base_hash: &str,
        signed_from: u64,
    ) -> CheckedEvents {
        let mut expected_prev = base_hash.to_string();
        for (idx, event) in events.iter().enumerate() {
            let seq = base_seq + idx as u64;
            if !Self::event_verifies(event, verifying_key, seq, &expected_prev, seq >= signed_from) {
                return CheckedEvents { proven: idx, broken: Some(event.seq) };
            }
            expected_prev = event.hash.clone();
        }
        CheckedEvents { proven: events.len(), broken: None }
    }

    /// Whether `event` is the event at `seq`, links to `prev_hash`, hashes to what it says and, when
    /// `signed` asks, is signed by `verifying_key`.
    fn event_verifies(event: &AuditEvent, verifying_key: &VerifyingKey, seq: u64, prev_hash: &str, signed: bool) -> bool {
        // Sequence numbers must be contiguous from the base.
        if event.seq != seq {
            return false;
        }
        // Linkage: prev_hash must match the previous event's hash.
        if event.prev_hash != prev_hash {
            return false;
        }
        // Recompute the hash over the canonical pre-hash form.
        let Ok(recomputed) = compute_hash(event.seq, event.timestamp, &event.prev_hash, &event.payload) else {
            return false;
        };
        if hex(&recomputed) != event.hash {
            return false;
        }
        if !signed {
            return true;
        }
        // Verify the signature over the raw hash.
        let Ok(sig_bytes) = unhex(&event.signature) else {
            return false;
        };
        let Ok(arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        verifying_key.verify_strict(&recomputed, &Signature::from_bytes(&arr)).is_ok()
    }

    /// Seal an [`AuditBoundary`] under this log's own signing key.
    ///
    /// The key stays private: a caller that has to re-sign a boundary (a restore fork bumping the
    /// epoch, and later the archive writer moving the base) must not be handed the key that signs
    /// events, and the boundary that a store will verify on its next open is exactly the one signed
    /// by the key that store resolved.
    pub fn seal_boundary(
        &self,
        epoch: u64,
        base_seq: u64,
        base_hash: impl Into<String>,
        segment_head: Option<String>,
        lineage: Vec<AuditFork>,
        taken_at: i64,
    ) -> AuditBoundary {
        AuditBoundary::create_in_lineage(
            &self.signing_key,
            epoch,
            base_seq,
            base_hash,
            segment_head,
            lineage,
            taken_at,
        )
    }

    /// Seal an [`AuditSegment`] manifest under this log's own signing key.
    ///
    /// The key stays private, for the reason [`AuditLog::seal_boundary`] gives: the archive writer
    /// must be able to publish a segment a verifier will accept without ever holding the key that
    /// signs events.
    pub fn seal_segment(&self, draft: AuditSegmentDraft) -> AuditSegment {
        let mut segment = AuditSegment {
            manifest_version: AUDIT_SEGMENT_VERSION,
            segment_id: segment_id(draft.base_seq, draft.end_seq),
            tenant: draft.tenant,
            epoch: draft.epoch,
            base_seq: draft.base_seq,
            end_seq: draft.end_seq,
            count: draft.count,
            prev_hash: draft.prev_hash,
            head_hash: draft.head_hash,
            sha256: draft.sha256,
            verifying_key: verifying_key_b64(&self.verifying_key),
            signature: String::new(),
            written_at: draft.written_at,
            gateway_version: draft.gateway_version,
        };
        segment.signature = hex(&self.signing_key.sign(&segment.preimage()).to_bytes());
        segment
    }

    /// Seal an [`AuditArchiveIndex`] under this log's own signing key, on the same terms.
    pub fn seal_index(
        &self,
        mut index: AuditArchiveIndex,
        written_at: impl Into<String>,
    ) -> AuditArchiveIndex {
        index.index_version = AUDIT_INDEX_VERSION;
        index.verifying_key = verifying_key_b64(&self.verifying_key);
        index.written_at = written_at.into();
        index.signature = String::new();
        index.signature = hex(&self.signing_key.sign(&index.preimage()).to_bytes());
        index
    }

    /// Verify this log's own events with its own verifying key, from its own base.
    ///
    /// The first call walks every held event and later calls walk only what no earlier call proved,
    /// so a caller that asks on every request (`/health`, the console's audit poll) pays for each
    /// event once rather than for the whole window every time. A chain that fails is proven up to the
    /// event that broke it, so the next call starts at that event rather than at the top. A moved
    /// base starts the walk over from the top.
    pub fn verify(&self) -> Option<u64> {
        self.verify_counting().0
    }

    /// [`AuditLog::verify`], and how many events this call checked.
    fn verify_counting(&self) -> (Option<u64>, usize) {
        let mut proven = self.proven.lock().unwrap_or_else(|p| p.into_inner());
        let start = self.resume_point(&proven);
        let link = self.link_before(start);
        let from_seq = self.base_seq + start as u64;
        let checked = Self::verify_prefix(&self.events[start..], &self.verifying_key, from_seq, &link, self.signed_from);
        *proven = ProvenPrefix {
            base_seq: self.base_seq,
            base_hash: self.base_hash.clone(),
            len: start + checked.proven,
        };
        (checked.broken, checked.checked())
    }

    /// Up to `limit` held events that no earlier verification proved, copied out with everything
    /// needed to check them, or `None` when every held event is proven.
    ///
    /// For a caller whose log sits behind a lock other requests need: it copies under the lock,
    /// checks with [`UnprovenEvents::check`] after releasing it, and takes it again only to
    /// [`AuditLog::record_proven`].
    pub fn unproven(&self, limit: usize) -> Option<UnprovenEvents> {
        let proven = self.proven.lock().unwrap_or_else(|p| p.into_inner());
        let start = self.resume_point(&proven);
        if start >= self.events.len() {
            return None;
        }
        let end = start.saturating_add(limit.max(1)).min(self.events.len());
        Some(UnprovenEvents {
            base_seq: self.base_seq,
            base_hash: self.base_hash.clone(),
            start,
            link: self.link_before(start),
            verifying_key: self.verifying_key,
            events: self.events[start..end].to_vec(),
            signed_from: self.signed_from,
        })
    }

    /// Keep what checking `events` proved, so the next verification starts after it.
    ///
    /// Only while this log still starts from the base they were copied against: a prune in between
    /// renumbers the window, and what was proven is then checked again from the new base.
    pub fn record_proven(&self, events: &UnprovenEvents, checked: CheckedEvents) {
        if events.base_seq != self.base_seq || events.base_hash != self.base_hash {
            return;
        }
        let mut proven = self.proven.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.resume_point(&proven);
        let reached = events.start + checked.proven;
        if events.start <= current && current < reached && reached <= self.events.len() {
            *proven = ProvenPrefix { base_seq: self.base_seq, base_hash: self.base_hash.clone(), len: reached };
        }
    }

    /// Where the next verification starts: the end of the proven prefix while it was proven from
    /// this log's current base, else the top.
    fn resume_point(&self, proven: &ProvenPrefix) -> usize {
        let resumable = proven.base_seq == self.base_seq
            && proven.base_hash == self.base_hash
            && proven.len <= self.events.len();
        if resumable {
            proven.len
        } else {
            0
        }
    }

    /// What held event `index` must link back to.
    fn link_before(&self, index: usize) -> String {
        match index {
            0 => self.base_hash.clone(),
            n => self.events[n - 1].hash.clone(),
        }
    }

    /// Drop every held event at or below absolute `end_seq`, moving the base to `end_seq + 1` and
    /// linking what remains to `new_base_hash`.
    ///
    /// The in-memory half of a prune. The other half is the rows and the re-signed
    /// [`AuditBoundary`], and the two have to move in one unit or this process ends up describing a
    /// chain its own database no longer claims.
    ///
    /// Three refusals, and each of them is a way a prune could silently break the chain rather than
    /// fail loudly:
    ///
    /// - a base that would move **backwards** or not at all, which would renumber nothing but would
    ///   let a caller believe it had archived something twice;
    /// - a base **above** the events actually held, which would leave the next append at a sequence
    ///   number with no linkage behind it;
    /// - a `new_base_hash` that is **not** what the first surviving event links to, which is the one
    ///   check that a segment's head really is the event just below the new base. Without it a prune
    ///   could hand the chain any hash at all and `verify()` would then be asserting a link the
    ///   archive does not support.
    ///
    /// Pruning the whole window is legal, and then `new_base_hash` must be the current head: the
    /// chain continues from the archive rather than restarting at genesis.
    pub fn advance_base(&mut self, end_seq: u64, new_base_hash: String) -> Result<()> {
        let new_base = end_seq
            .checked_add(1)
            .ok_or_else(|| PermauraError::AuditIntegrity("audit base overflow".into()))?;
        if new_base <= self.base_seq {
            return Err(PermauraError::AuditIntegrity(format!(
                "the audit base is already {} and a prune to {new_base} would not move it forwards",
                self.base_seq
            )));
        }
        if new_base > self.next_seq() {
            return Err(PermauraError::AuditIntegrity(format!(
                "a prune to base {new_base} would pass the {} events this log holds (next seq {})",
                self.events.len(),
                self.next_seq()
            )));
        }
        let dropped = (new_base - self.base_seq) as usize;
        let expected_link = match self.events.get(dropped) {
            Some(first) => first.prev_hash.clone(),
            // Everything held is being archived, so the link the chain continues from is the head.
            None => self.head_hash(),
        };
        if expected_link != new_base_hash {
            return Err(PermauraError::AuditIntegrity(format!(
                "the new audit base hash does not match what event {new_base} links back to: refusing to prune, because a base nothing hangs off is a chain that cannot be verified"
            )));
        }
        self.events.drain(..dropped);
        self.base_seq = new_base;
        self.base_hash = new_base_hash;
        Ok(())
    }
}

/// The domain the boundary preimage is prefixed with, so a boundary signature can never be
/// presented as an event signature or as an `AuditCheckpoint` one.
const AUDIT_BOUNDARY_DOMAIN: &[u8] = b"permaura:audit-boundary:v1";

/// The only [`AuditBoundary`] format there has been.
pub const AUDIT_BOUNDARY_VERSION: u32 = 1;

/// Where a store's hot window starts, stated under the audit signing key.
///
/// A [`AuditLog`]'s `base_seq` and `base_hash` decide which sequence numbers it will issue and what
/// its oldest event links to, so anything that can rewrite them can hide a prune. This record is the
/// claim itself, signed, and a store reads it before it reads a single event: a boundary that names
/// a base must carry a valid signature or the store refuses to open.
///
/// The genesis boundary (`epoch 0`, `base_seq 0`, [`GENESIS_PREV_HASH`], no segment) is the one
/// exception, because it asserts nothing that was not already true of every chain written before
/// this record existed. It is legal unsigned, which is what lets the schema migration write it
/// without a key, and a store seals it under its own key the first time it opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditBoundary {
    /// [`AUDIT_BOUNDARY_VERSION`].
    pub version: u32,
    /// Bumped by a restore fork, so events from two forks of one tenant are never confused.
    pub epoch: u64,
    /// The absolute seq of the oldest event in the hot store.
    pub base_seq: u64,
    /// The hash of event `base_seq - 1`, or [`GENESIS_PREV_HASH`].
    pub base_hash: String,
    /// The newest durably published archive segment, once there is an archive.
    #[serde(default)]
    pub segment_head: Option<String>,
    /// Every restore fork between the root epoch and this one, oldest first. Empty for a store that
    /// has never been restored. This is what says which history the store is: epochs are branches,
    /// not a sequence, so the archive of a restored store is the root epoch up to the first fork,
    /// then each fork's epoch up to the next, and never every epoch concatenated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage: Vec<AuditFork>,
    /// Unix-millisecond time this boundary was written.
    pub taken_at: i64,
    /// ed25519 over the domain-separated preimage, hex. Empty only on an unsealed genesis boundary.
    pub signature: String,
}

/// One restore fork: where a restored store's history leaves its parent's.
///
/// Everything below `base_seq` is the parent epoch's history and everything at or above it is this
/// epoch's. Whatever the parent archived at or past `base_seq` is the abandoned suffix: kept as
/// evidence, never part of this store's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFork {
    /// The epoch the fork opened.
    pub epoch: u64,
    /// The epoch it branched from.
    pub parent_epoch: u64,
    /// The first seq this epoch owns: the restored checkpoint's hot-window base.
    pub base_seq: u64,
    /// The hash of event `base_seq - 1`, the last event kept from the parent.
    pub base_hash: String,
    /// The restore that opened the epoch (its hold id), which is what tells two restores of one
    /// checkpoint apart: they share a parent and a cutoff and nothing else.
    pub restore_id: String,
}

impl AuditFork {
    fn hash_into(&self, hasher: &mut Sha256) {
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.parent_epoch.to_be_bytes());
        hasher.update(self.base_seq.to_be_bytes());
        for field in [&self.base_hash, &self.restore_id] {
            hasher.update((field.len() as u32).to_be_bytes());
            hasher.update(field.as_bytes());
        }
    }
}

/// The action of the event `permaura audit rekey` appends first under a new key.
pub const AUDIT_REKEY_ACTION: &str = "permaura.audit.rekey";

/// The domain an [`AuditRekey`]'s preimage is prefixed with.
const AUDIT_REKEY_DOMAIN: &[u8] = b"permaura:audit-rekey:v1";

/// A recorded move of the chain to a new signing key, for an owner whose old key is gone.
///
/// Every event below `seq` was signed under a key this store no longer holds, so its signature can
/// never be checked again; its hash and its link to the next event still can, and are. The event at
/// `seq` is the chain's own record of the move ([`AUDIT_REKEY_ACTION`]), signed under the new key and
/// linked to the old head, `prior_head_hash`. This record is signed under the new key too, so the store
/// can honor the move after that event has been archived out of the hot window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRekey {
    /// The seq of the rekey event: the first event signed under the new key.
    pub seq: u64,
    /// The hash of event `seq - 1`, the old chain's head, which the rekey event links to.
    pub prior_head_hash: String,
    /// Unix-millisecond time of the rekey.
    pub taken_at: i64,
    /// ed25519 under the new key over the domain-separated preimage, hex.
    pub signature: String,
}

impl AuditRekey {
    /// Sign the record of a rekey at `seq`, continuing from `prior_head_hash`, under the new key.
    pub fn create(signing_key: &SigningKey, seq: u64, prior_head_hash: impl Into<String>, taken_at: i64) -> Self {
        let mut rekey = AuditRekey { seq, prior_head_hash: prior_head_hash.into(), taken_at, signature: String::new() };
        rekey.signature = hex(&signing_key.sign(&rekey.preimage()).to_bytes());
        rekey
    }

    /// Whether the signature is this key's over exactly these fields.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let Ok(bytes) = unhex(&self.signature) else { return false };
        let Ok(raw) = <[u8; 64]>::try_from(bytes.as_slice()) else { return false };
        verifying_key.verify_strict(&self.preimage(), &Signature::from_bytes(&raw)).is_ok()
    }

    /// The rekey `event` records, when it is one: the rekey action, naming as the old head (seq and
    /// hash) the event it links to, and signed under `verifying_key`. The record's own signature is
    /// left empty, because the event's signature is the proof.
    pub fn from_event(event: &AuditEvent, verifying_key: &VerifyingKey) -> Option<AuditRekey> {
        if event.payload.action != AUDIT_REKEY_ACTION
            || !AuditLog::event_verifies(event, verifying_key, event.seq, &event.prev_hash, true)
        {
            return None;
        }
        let rekey = AuditRekey {
            seq: event.seq,
            prior_head_hash: event.prev_hash.clone(),
            taken_at: event.timestamp,
            signature: String::new(),
        };
        rekey.recorded_by(event).then_some(rekey)
    }

    /// Whether `event` is the chain's record of this rekey: the rekey action at this seq, linked to
    /// the old head, and naming that head (seq and hash) in its summary.
    pub fn recorded_by(&self, event: &AuditEvent) -> bool {
        let summary = &event.payload.summary;
        event.seq == self.seq
            && event.prev_hash == self.prior_head_hash
            && event.payload.action == AUDIT_REKEY_ACTION
            && summary.get("prior_head_hash").and_then(|v| v.as_str()) == Some(self.prior_head_hash.as_str())
            && summary.get("prior_head_seq").and_then(|v| v.as_u64()) == self.seq.checked_sub(1)
    }

    fn preimage(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(AUDIT_REKEY_DOMAIN);
        hasher.update(self.seq.to_be_bytes());
        hasher.update((self.prior_head_hash.len() as u32).to_be_bytes());
        hasher.update(self.prior_head_hash.as_bytes());
        hasher.update(self.taken_at.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Separates the lineage from the fields before it in a boundary preimage.
const AUDIT_LINEAGE_DOMAIN: &[u8] = b"permaura:audit-lineage:v1";

impl AuditBoundary {
    /// The boundary of a store that has never archived anything, unsealed. Identical in meaning to
    /// no boundary row at all.
    pub fn genesis() -> Self {
        AuditBoundary {
            version: AUDIT_BOUNDARY_VERSION,
            epoch: 0,
            base_seq: 0,
            base_hash: GENESIS_PREV_HASH.to_string(),
            segment_head: None,
            lineage: Vec::new(),
            taken_at: 0,
            signature: String::new(),
        }
    }

    /// Sign a boundary under the audit key, for a store that has never been restored.
    pub fn create(
        signing_key: &SigningKey,
        epoch: u64,
        base_seq: u64,
        base_hash: impl Into<String>,
        segment_head: Option<String>,
        taken_at: i64,
    ) -> Self {
        Self::create_in_lineage(signing_key, epoch, base_seq, base_hash, segment_head, Vec::new(), taken_at)
    }

    /// Sign a boundary under the audit key, with the restore forks that led to it.
    pub fn create_in_lineage(
        signing_key: &SigningKey,
        epoch: u64,
        base_seq: u64,
        base_hash: impl Into<String>,
        segment_head: Option<String>,
        lineage: Vec<AuditFork>,
        taken_at: i64,
    ) -> Self {
        let mut boundary = AuditBoundary {
            version: AUDIT_BOUNDARY_VERSION,
            epoch,
            base_seq,
            base_hash: base_hash.into(),
            segment_head,
            lineage,
            taken_at,
            signature: String::new(),
        };
        let signature = signing_key.sign(&boundary.preimage());
        boundary.signature = hex(&signature.to_bytes());
        boundary
    }

    /// Whether this is the boundary of a store with nothing archived. `taken_at` is deliberately not
    /// part of the answer: a genesis boundary claims nothing beyond the default, so when it was
    /// written carries no weight.
    pub fn is_genesis(&self) -> bool {
        self.version == AUDIT_BOUNDARY_VERSION
            && self.epoch == 0
            && self.base_seq == 0
            && self.base_hash == GENESIS_PREV_HASH
            && self.segment_head.is_none()
            && self.lineage.is_empty()
    }

    /// Whether the signature is this key's over exactly these fields.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let Ok(bytes) = unhex(&self.signature) else {
            return false;
        };
        let Ok(raw) = <[u8; 64]>::try_from(bytes.as_slice()) else {
            return false;
        };
        verifying_key
            .verify_strict(&self.preimage(), &Signature::from_bytes(&raw))
            .is_ok()
    }

    /// Length-prefixed and domain-separated rather than JSON, so the bytes signed here cannot be
    /// produced by any other preimage in the system and two variable-length fields cannot be slid
    /// past each other.
    fn preimage(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(AUDIT_BOUNDARY_DOMAIN);
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.base_seq.to_be_bytes());
        hasher.update((self.base_hash.len() as u32).to_be_bytes());
        hasher.update(self.base_hash.as_bytes());
        let segment_head = self.segment_head.as_deref().unwrap_or("");
        hasher.update((segment_head.len() as u32).to_be_bytes());
        hasher.update(segment_head.as_bytes());
        hasher.update(self.taken_at.to_be_bytes());
        // Only when there is one, so every boundary signed before lineage existed still verifies,
        // and an older build that cannot see the field refuses a boundary that has one rather than
        // reading it as unforked.
        if !self.lineage.is_empty() {
            hasher.update(AUDIT_LINEAGE_DOMAIN);
            hasher.update((self.lineage.len() as u32).to_be_bytes());
            for fork in &self.lineage {
                fork.hash_into(&mut hasher);
            }
        }
        hasher.finalize().into()
    }
}

/// The domain a segment manifest's preimage is prefixed with.
const AUDIT_SEGMENT_DOMAIN: &[u8] = b"permaura:audit-segment:v1";

/// The domain the archive index's preimage is prefixed with.
const AUDIT_INDEX_DOMAIN: &[u8] = b"permaura:audit-index:v1";

/// The only segment manifest format there has been.
pub const AUDIT_SEGMENT_VERSION: u32 = 1;

/// The only archive index format there has been.
pub const AUDIT_INDEX_VERSION: u32 = 1;

/// A segment's id, zero-padded so lexical order is sequence order in any listing.
pub fn segment_id(base_seq: u64, end_seq: u64) -> String {
    format!("seg-{base_seq:020}-{end_seq:020}")
}

/// The verifying key as the archive records it, so a verifier holding only object storage can check
/// a signature without being handed the key out of band.
fn verifying_key_b64(key: &VerifyingKey) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

/// The hex sha256 of some bytes, so a writer and a verifier compute the segment digest the same way.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Everything a segment manifest needs that is not the signature or the key.
///
/// A struct rather than ten positional arguments, because six of them are `u64`s and strings whose
/// order a caller could get wrong silently: a `base_seq` and an `end_seq` transposed, or a
/// `prev_hash` and a `head_hash`, would produce a manifest that signs and verifies and describes the
/// wrong run of events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSegmentDraft {
    /// The tenant slug this segment is written for.
    pub tenant: String,
    /// The chain epoch.
    pub epoch: u64,
    /// The absolute seq of the first event in the segment.
    pub base_seq: u64,
    /// The absolute seq of the last event in the segment.
    pub end_seq: u64,
    /// How many events the segment holds.
    pub count: u64,
    /// The hash the first event links back to.
    pub prev_hash: String,
    /// The last event's hash.
    pub head_hash: String,
    /// Hex sha256 of the exact `.ndjson` bytes.
    pub sha256: String,
    /// RFC 3339 time the segment was published.
    pub written_at: String,
    /// The gateway version that wrote it.
    pub gateway_version: String,
}

/// What one published archive segment claims about itself, stated under the audit signing key.
///
/// A segment is a contiguous run of events that has left the hot store. Its manifest is what lets a
/// verifier check the run without trusting whoever served it: the signature covers the range, the
/// linkage at both ends, and the digest of the bytes, so a segment cannot be swapped for another
/// tenant's, moved to a different position in the chain, or edited.
///
/// `tenant`, `written_at` and `gateway_version` are outside the signature on purpose. They describe
/// the act of writing rather than the contents, and the binding that actually keeps one tenant's
/// segments out of another's is the namespace they are published under plus the verifying key they
/// are checked against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSegment {
    /// [`AUDIT_SEGMENT_VERSION`].
    pub manifest_version: u32,
    /// `seg-<base_seq:020>-<end_seq:020>`, which is also the object's basename.
    pub segment_id: String,
    /// The tenant slug this segment was written for.
    pub tenant: String,
    /// The chain epoch. Two epochs of one tenant never share a namespace.
    pub epoch: u64,
    /// The absolute seq of the first event in the segment.
    pub base_seq: u64,
    /// The absolute seq of the last event in the segment.
    pub end_seq: u64,
    /// How many events the segment holds. `end_seq - base_seq + 1` for a segment with no holes.
    pub count: u64,
    /// The hash the first event links back to.
    pub prev_hash: String,
    /// The last event's hash, which the next segment links to and which the hot store's base hash
    /// becomes once this one is pruned.
    pub head_hash: String,
    /// Hex sha256 of the exact `.ndjson` bytes.
    pub sha256: String,
    /// The audit verifying key, base64, so a verifier holding only the archive can check it.
    pub verifying_key: String,
    /// ed25519 over the domain-separated preimage, hex.
    pub signature: String,
    /// RFC 3339 time the segment was published.
    pub written_at: String,
    /// The gateway version that wrote it.
    pub gateway_version: String,
}

impl AuditSegment {
    /// Whether the signature is this key's over exactly the fields it covers.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let Ok(bytes) = unhex(&self.signature) else { return false };
        let Ok(raw) = <[u8; 64]>::try_from(bytes.as_slice()) else { return false };
        verifying_key.verify_strict(&self.preimage(), &Signature::from_bytes(&raw)).is_ok()
    }

    /// Length-prefixed and domain-separated, for the reason [`AuditBoundary`]'s is.
    fn preimage(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(AUDIT_SEGMENT_DOMAIN);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.base_seq.to_be_bytes());
        hasher.update(self.end_seq.to_be_bytes());
        for field in [&self.prev_hash, &self.head_hash, &self.sha256] {
            hasher.update((field.len() as u32).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.finalize().into()
    }
}

/// One line of the archive index: everything a verifier needs to know a segment should be there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditIndexEntry {
    /// The segment's id, which is its object basename.
    pub segment_id: String,
    /// First absolute seq in the segment.
    pub base_seq: u64,
    /// Last absolute seq in the segment.
    pub end_seq: u64,
    /// What the segment's first event links back to.
    pub prev_hash: String,
    /// The segment's last event's hash.
    pub head_hash: String,
    /// Hex sha256 of the segment's bytes.
    pub sha256: String,
}

/// The signed list of every segment published for one epoch.
///
/// It is what makes a **missing** segment detectable rather than invisible. Without it a verifier
/// walking object storage sees the segments that are there and has nothing to say about the ones
/// that are not, and a gap between two segments reads as a chain that simply skips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditArchiveIndex {
    /// [`AUDIT_INDEX_VERSION`].
    pub index_version: u32,
    /// The tenant slug.
    pub tenant: String,
    /// The chain epoch this index covers.
    pub epoch: u64,
    /// Every published segment, ascending by `base_seq`, contiguous.
    pub segments: Vec<AuditIndexEntry>,
    /// The restore fork that opened this epoch, `None` for a root epoch. Signed, so a verifier
    /// holding only the bucket can follow a restored tenant's lineage without the hot store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork: Option<AuditFork>,
    /// The audit verifying key, base64.
    pub verifying_key: String,
    /// ed25519 over the domain-separated preimage, hex.
    pub signature: String,
    /// RFC 3339 time this version of the index was written.
    pub written_at: String,
}

impl AuditArchiveIndex {
    /// An index with nothing in it yet, for an epoch that has published no segment.
    pub fn empty(tenant: impl Into<String>, epoch: u64) -> Self {
        AuditArchiveIndex {
            index_version: AUDIT_INDEX_VERSION,
            tenant: tenant.into(),
            epoch,
            segments: Vec::new(),
            fork: None,
            verifying_key: String::new(),
            signature: String::new(),
            written_at: String::new(),
        }
    }

    /// Whether the signature is this key's over exactly the segments listed.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let Ok(bytes) = unhex(&self.signature) else { return false };
        let Ok(raw) = <[u8; 64]>::try_from(bytes.as_slice()) else { return false };
        verifying_key.verify_strict(&self.preimage(), &Signature::from_bytes(&raw)).is_ok()
    }

    /// Length-prefixed and domain-separated over every entry in order, so neither the order nor the
    /// membership of the list can be changed without the signature failing.
    fn preimage(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(AUDIT_INDEX_DOMAIN);
        hasher.update(self.index_version.to_be_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update((self.segments.len() as u32).to_be_bytes());
        for entry in &self.segments {
            hasher.update(entry.base_seq.to_be_bytes());
            hasher.update(entry.end_seq.to_be_bytes());
            for field in [&entry.segment_id, &entry.prev_hash, &entry.head_hash, &entry.sha256] {
                hasher.update((field.len() as u32).to_be_bytes());
                hasher.update(field.as_bytes());
            }
        }
        if let Some(fork) = &self.fork {
            hasher.update(AUDIT_LINEAGE_DOMAIN);
            fork.hash_into(&mut hasher);
        }
        hasher.finalize().into()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(action: &str, decision: &str) -> AuditPayload {
        let mut p = AuditPayload::new(action, "braintree_production", decision);
        p.agent_id = Some("codex-cli".into());
        p.session_id = Some("sess_456".into());
        p
    }

    #[test]
    fn empty_chain_verifies() {
        let log = AuditLog::new();
        assert_eq!(log.verify(), None);
        assert_eq!(log.head_hash(), GENESIS_PREV_HASH);
    }

    #[test]
    fn intact_chain_verifies() {
        let mut log = AuditLog::new();
        log.append_at(payload("transactions.search", "allow"), 1000)
            .unwrap();
        log.append_at(payload("transactions.refund", "deny"), 2000)
            .unwrap();
        log.append_at(payload("transactions.read", "allow"), 3000)
            .unwrap();
        assert_eq!(log.verify(), None);
        // First event links to genesis; subsequent events chain.
        assert_eq!(log.events()[0].prev_hash, GENESIS_PREV_HASH);
        assert_eq!(log.events()[1].prev_hash, log.events()[0].hash);
        assert_eq!(log.events()[2].prev_hash, log.events()[1].hash);
    }

    #[test]
    fn tampering_with_payload_is_detected() {
        let mut log = AuditLog::new();
        log.append_at(payload("transactions.search", "allow"), 1000)
            .unwrap();
        log.append_at(payload("transactions.refund", "deny"), 2000)
            .unwrap();

        let vk = log.verifying_key();
        let mut events = log.events().to_vec();
        // An attacker flips a denied refund into an allowed one, but leaves the hash/signature.
        events[1].payload.decision = "allow".to_string();
        assert_eq!(AuditLog::verify_with(&events, &vk), Some(1));
    }

    #[test]
    fn tampering_with_hash_is_detected() {
        let mut log = AuditLog::new();
        log.append_at(payload("a", "allow"), 1).unwrap();
        log.append_at(payload("b", "allow"), 2).unwrap();
        let vk = log.verifying_key();
        let mut events = log.events().to_vec();
        // Attacker recomputes a "matching" hash but cannot sign it without the key.
        events[0].hash = hex(&[0xAB; 32]);
        assert_eq!(AuditLog::verify_with(&events, &vk), Some(0));
    }

    #[test]
    fn deleting_a_middle_event_breaks_the_chain() {
        let mut log = AuditLog::new();
        log.append_at(payload("a", "allow"), 1).unwrap();
        log.append_at(payload("b", "allow"), 2).unwrap();
        log.append_at(payload("c", "allow"), 3).unwrap();
        let vk = log.verifying_key();
        let mut events = log.events().to_vec();
        events.remove(1); // drop seq 1; seq 2 now sits at index 1 with a stale seq number
        assert_eq!(AuditLog::verify_with(&events, &vk), Some(2));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let mut log = AuditLog::new();
        log.append_at(payload("a", "allow"), 1).unwrap();
        let other = AuditLog::new();
        // A different keypair must not validate this chain's signatures.
        assert_eq!(
            AuditLog::verify_with(log.events(), &other.verifying_key()),
            Some(0)
        );
    }

    /// Everything above this line is the suite as it stood before the base existed, and it is the
    /// compatibility check for this change: a chain written by the old code still verifies, and
    /// nothing about the event format moved.
    fn based_log(base_seq: u64, base_hash: &str) -> AuditLog {
        AuditLog::restore_from(
            SigningKey::generate(&mut rand::rngs::OsRng),
            base_seq,
            base_hash.to_string(),
            Vec::new(),
        )
    }

    #[test]
    fn an_empty_archive_behaves_exactly_like_today() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut old = AuditLog::restore(key.clone(), Vec::new());
        let mut new = AuditLog::restore_from(key, 0, GENESIS_PREV_HASH.to_string(), Vec::new());
        for (action, at) in [("a", 1000), ("b", 2000), ("c", 3000)] {
            old.append_at(payload(action, "allow"), at).unwrap();
            new.append_at(payload(action, "allow"), at).unwrap();
        }
        assert_eq!(old.events(), new.events(), "same key, same inputs, byte-identical events");
        assert_eq!(new.head_hash(), old.head_hash());
        assert_eq!(new.next_seq(), 3);
        assert_eq!(new.verify(), None);
    }

    #[test]
    fn a_based_log_appends_at_absolute_sequence() {
        let mut log = based_log(9000, &hex(&[0x11; 32]));
        assert_eq!(log.next_seq(), 9000);
        for n in 0..3 {
            let event = log.append_at(payload("a", "allow"), 1000 + n as i64).unwrap();
            assert_eq!(event.seq, 9000 + n);
        }
        assert_eq!(log.next_seq(), 9003);
        assert_eq!(log.verify(), None);
    }

    #[test]
    fn a_based_log_links_its_first_event_to_the_base_hash() {
        let base_hash = hex(&[0x22; 32]);
        let mut log = based_log(9000, &base_hash);
        assert_eq!(log.head_hash(), base_hash, "an empty based log heads at its base, not at genesis");
        log.append_at(payload("a", "allow"), 1000).unwrap();
        assert_eq!(log.events()[0].prev_hash, base_hash);
        assert_eq!(
            AuditLog::verify_from(log.events(), &log.verifying_key(), 9000, &base_hash),
            None
        );
    }

    #[test]
    fn verify_from_rejects_a_log_whose_first_seq_is_not_the_base() {
        let base_hash = hex(&[0x33; 32]);
        let mut log = based_log(9000, &base_hash);
        log.append_at(payload("a", "allow"), 1000).unwrap();
        // The same events, read as though the boundary said the window started one event later.
        assert_eq!(
            AuditLog::verify_from(log.events(), &log.verifying_key(), 9001, &base_hash),
            Some(9000)
        );
    }

    #[test]
    fn verify_from_rejects_a_hole_in_the_middle_of_a_based_log() {
        let base_hash = hex(&[0x44; 32]);
        let mut log = based_log(9000, &base_hash);
        for n in 0..3 {
            log.append_at(payload("a", "allow"), 1000 + n).unwrap();
        }
        let vk = log.verifying_key();
        let mut events = log.events().to_vec();
        events.remove(1);
        assert_eq!(AuditLog::verify_from(&events, &vk, 9000, &base_hash), Some(9002));
    }

    #[test]
    fn a_based_log_that_links_to_the_wrong_base_is_rejected() {
        let mut log = based_log(9000, &hex(&[0x55; 32]));
        log.append_at(payload("a", "allow"), 1000).unwrap();
        assert_eq!(
            AuditLog::verify_from(log.events(), &log.verifying_key(), 9000, &hex(&[0x66; 32])),
            Some(9000)
        );
    }

    #[test]
    fn a_boundary_verifies_under_its_own_key_and_not_another() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        let boundary = AuditBoundary::create(&key, 0, 9000, hex(&[0x77; 32]), None, 1_700_000_000_000);
        assert!(boundary.verify(&key.verifying_key()));
        assert!(!boundary.verify(&other.verifying_key()));
        assert!(!boundary.is_genesis());
    }

    #[test]
    fn a_boundary_whose_base_was_moved_no_longer_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signed = AuditBoundary::create(&key, 0, 9000, hex(&[0x88; 32]), None, 1_700_000_000_000);
        for rewritten in [
            AuditBoundary { base_seq: 8000, ..signed.clone() },
            AuditBoundary { epoch: 1, ..signed.clone() },
            AuditBoundary { base_hash: hex(&[0x99; 32]), ..signed.clone() },
            AuditBoundary { segment_head: Some("seg-0".into()), ..signed.clone() },
            AuditBoundary { taken_at: 1, ..signed.clone() },
        ] {
            assert!(!rewritten.verify(&key.verifying_key()), "{rewritten:?} must not verify");
        }
    }

    fn fork(epoch: u64, parent_epoch: u64, base_seq: u64, restore_id: &str) -> AuditFork {
        AuditFork {
            epoch,
            parent_epoch,
            base_seq,
            base_hash: hex(&[base_seq as u8; 32]),
            restore_id: restore_id.into(),
        }
    }

    /// A restored store's lineage is part of what its boundary claims, so no fork in it can be
    /// dropped, reordered or re-pointed without the signature failing.
    #[test]
    fn every_fork_in_a_boundary_lineage_is_covered_by_its_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let lineage = vec![fork(1, 0, 40, "hold-a"), fork(3, 1, 60, "hold-b")];
        let signed =
            AuditBoundary::create_in_lineage(&key, 3, 80, hex(&[0x88; 32]), None, lineage.clone(), 1);
        assert!(signed.verify(&key.verifying_key()));
        assert!(!signed.is_genesis());

        let mut rewritten = Vec::new();
        rewritten.push(AuditBoundary { lineage: Vec::new(), ..signed.clone() });
        rewritten.push(AuditBoundary { lineage: vec![lineage[1].clone(), lineage[0].clone()], ..signed.clone() });
        rewritten.push(AuditBoundary { lineage: vec![lineage[0].clone()], ..signed.clone() });
        for edit in [
            |f: &mut AuditFork| f.epoch = 2,
            |f: &mut AuditFork| f.parent_epoch = 0,
            |f: &mut AuditFork| f.base_seq = 61,
            |f: &mut AuditFork| f.base_hash = hex(&[0x01; 32]),
            |f: &mut AuditFork| f.restore_id = "hold-c".into(),
        ] {
            let mut lineage = lineage.clone();
            edit(&mut lineage[1]);
            rewritten.push(AuditBoundary { lineage, ..signed.clone() });
        }
        for boundary in rewritten {
            assert!(!boundary.verify(&key.verifying_key()), "{boundary:?} must not verify");
        }
    }

    /// Lineage is signed only when there is some, so a boundary written before it existed, which
    /// carries none, verifies exactly as it did.
    #[test]
    fn a_boundary_with_no_lineage_signs_what_it_always_signed() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let plain = AuditBoundary::create(&key, 1, 9000, hex(&[0x88; 32]), Some("seg-0".into()), 5);
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("lineage").is_none(), "an unforked boundary serialises as it always did");
        let read_back: AuditBoundary = serde_json::from_value(json).unwrap();
        assert!(read_back.verify(&key.verifying_key()));
    }

    /// An index names the fork that opened its epoch under the same signature as its segments.
    #[test]
    fn the_fork_an_index_names_is_covered_by_its_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let log = AuditLog::restore(key.clone(), Vec::new());
        let mut index = AuditArchiveIndex::empty("acme", 2);
        index.fork = Some(fork(2, 0, 40, "hold-a"));
        let sealed = log.seal_index(index, "2026-09-24T00:00:00Z");
        assert!(sealed.verify(&key.verifying_key()));

        let mut unforked = sealed.clone();
        unforked.fork = None;
        assert!(!unforked.verify(&key.verifying_key()), "the fork cannot be dropped");
        let mut repointed = sealed.clone();
        repointed.fork = Some(fork(2, 1, 40, "hold-a"));
        assert!(!repointed.verify(&key.verifying_key()), "or pointed at another parent");
    }

    /// The domain separation, stated as a test: a boundary signature is over a different preimage,
    /// so presenting one as an event's signature cannot pass.
    #[test]
    fn the_boundary_signature_cannot_be_replayed_as_an_event_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut log = AuditLog::restore(key.clone(), Vec::new());
        log.append_at(payload("a", "allow"), 1000).unwrap();
        let vk = log.verifying_key();
        let head = log.head_hash();
        let boundary = AuditBoundary::create(&key, 0, 1, head, None, 1000);

        let mut events = log.events().to_vec();
        events[0].signature = boundary.signature.clone();
        assert_eq!(AuditLog::verify_with(&events, &vk), Some(0));
    }

    // ── advancing the base, which is the in-memory half of a prune ────────────────────────────

    #[test]
    fn a_repeated_verify_checks_only_what_was_appended_since() {
        let mut log = AuditLog::new();
        for n in 0..50 {
            log.append_at(payload("a", "allow"), n).unwrap();
        }
        assert_eq!(log.verify_counting(), (None, 50), "the first walk proves every held event");
        assert_eq!(log.verify_counting(), (None, 0), "and asking again costs nothing");
        log.append_at(payload("b", "allow"), 100).unwrap();
        assert_eq!(log.verify_counting(), (None, 1), "only the new event is checked");
    }

    #[test]
    fn an_event_appended_after_the_proven_prefix_is_still_checked() {
        let mut log = AuditLog::new();
        log.append_at(payload("a", "allow"), 1).unwrap();
        log.append_at(payload("b", "allow"), 2).unwrap();
        assert_eq!(log.verify(), None);
        log.append_at(payload("c", "deny"), 3).unwrap();
        log.events[2].payload.decision = "allow".to_string();
        assert_eq!(log.verify(), Some(2), "the proven prefix does not excuse what came after it");
        assert_eq!(log.verify(), Some(2), "and the event that broke it is checked again, not excused");
    }

    #[test]
    fn a_failed_verify_resumes_at_the_event_that_broke_it() {
        let mut log = AuditLog::new();
        for n in 0..50 {
            log.append_at(payload("a", "allow"), n).unwrap();
        }
        log.events[40].payload.decision = "deny".to_string();
        assert_eq!(log.verify_counting(), (Some(40), 41), "the first walk checks up to and including the break");
        assert_eq!(log.verify_counting(), (Some(40), 1), "the next starts at the break rather than at the top");
    }

    #[test]
    fn events_checked_outside_the_log_extend_what_it_has_proven() {
        let mut log = AuditLog::new();
        for n in 0..10 {
            log.append_at(payload("a", "allow"), n).unwrap();
        }
        let first = log.unproven(4).expect("nothing is proven yet");
        assert_eq!(first.first_seq(), 0);
        let checked = first.check();
        assert_eq!(checked, CheckedEvents { proven: 4, broken: None });
        log.record_proven(&first, checked);
        let second = log.unproven(100).expect("six are left");
        assert_eq!(second.first_seq(), 4, "the next copy starts after what was recorded");
        log.record_proven(&first, checked);
        assert_eq!(log.unproven(100).unwrap().first_seq(), 4, "recording the same proof twice moves nothing");
        log.record_proven(&second, second.check());
        assert!(log.unproven(100).is_none(), "every held event is proven");
        assert_eq!(log.verify_counting(), (None, 0));
    }

    #[test]
    fn a_proof_copied_before_a_prune_is_not_recorded_after_it() {
        let mut log = AuditLog::new();
        for n in 0..6 {
            log.append_at(payload("a", "allow"), n).unwrap();
        }
        let copied = log.unproven(6).unwrap();
        let checked = copied.check();
        let head_of_prefix = log.events()[2].hash.clone();
        log.advance_base(2, head_of_prefix).unwrap();
        log.record_proven(&copied, checked);
        assert_eq!(log.verify_counting(), (None, 3), "the window is checked again from its new base");
    }

    #[test]
    fn a_moved_base_is_walked_again_from_the_top() {
        let mut log = AuditLog::new();
        for n in 0..6 {
            log.append_at(payload("a", "allow"), n).unwrap();
        }
        assert_eq!(log.verify(), None);
        let head_of_prefix = log.events()[2].hash.clone();
        log.advance_base(2, head_of_prefix).unwrap();
        assert_eq!(log.verify_counting(), (None, 3), "every surviving event is checked against the new base");
    }

    #[test]
    fn advancing_the_base_drops_the_archived_prefix_and_keeps_the_chain_verifying() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut log = AuditLog::restore(key, Vec::new());
        for n in 0..6 {
            log.append_at(payload("a", "allow"), 1000 + n).unwrap();
        }
        let head_of_prefix = log.events()[2].hash.clone();
        log.advance_base(2, head_of_prefix.clone()).unwrap();

        assert_eq!(log.base_seq(), 3);
        assert_eq!(log.base_hash(), head_of_prefix);
        assert_eq!(log.events().len(), 3);
        assert_eq!(log.events()[0].seq, 3);
        assert_eq!(log.next_seq(), 6, "the next event still lands at the absolute sequence");
        assert_eq!(log.verify(), None);

        let event = log.append_at(payload("b", "allow"), 2000).unwrap().clone();
        assert_eq!(event.seq, 6);
        assert_eq!(log.verify(), None);
    }

    /// Everything can be archived, and then the chain continues from the archive's head rather than
    /// restarting at genesis.
    #[test]
    fn advancing_the_base_past_every_held_event_continues_from_the_archive_head() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut log = AuditLog::restore(key, Vec::new());
        for n in 0..3 {
            log.append_at(payload("a", "allow"), 1000 + n).unwrap();
        }
        let head = log.head_hash();
        log.advance_base(2, head.clone()).unwrap();
        assert!(log.events().is_empty());
        assert_eq!(log.head_hash(), head, "an empty window heads at its base, not at genesis");

        let event = log.append_at(payload("b", "allow"), 2000).unwrap().clone();
        assert_eq!(event.seq, 3);
        assert_eq!(event.prev_hash, head);
        assert_eq!(log.verify(), None);
    }

    /// The three refusals, each of them a way a prune could quietly break the chain.
    #[test]
    fn advancing_the_base_refuses_every_move_that_would_break_the_chain() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut log = AuditLog::restore(key, Vec::new());
        for n in 0..4 {
            log.append_at(payload("a", "allow"), 1000 + n).unwrap();
        }
        let good = log.events()[1].hash.clone();

        // A hash the surviving window does not link to.
        assert!(log.advance_base(1, hex(&[0x11; 32])).is_err());
        // Past the events actually held.
        assert!(log.advance_base(9, good.clone()).is_err());

        log.advance_base(1, good.clone()).unwrap();
        // And now backwards, or not forwards at all.
        assert!(log.advance_base(1, good.clone()).is_err(), "not forwards is refused");
        assert!(log.advance_base(0, GENESIS_PREV_HASH.to_string()).is_err(), "backwards is refused");
        assert_eq!(log.base_seq(), 2, "and none of them moved it");
        assert_eq!(log.verify(), None);
    }

    // ── archive segments and the index ────────────────────────────────────────────────────────

    #[test]
    fn a_segment_manifest_verifies_under_its_own_key_and_not_another() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let other = AuditLog::new();
        let log = AuditLog::restore(key.clone(), Vec::new());
        let segment = log.seal_segment(AuditSegmentDraft {
            tenant: "acme".into(),
            epoch: 0,
            base_seq: 0,
            end_seq: 9999,
            count: 10_000,
            prev_hash: GENESIS_PREV_HASH.to_string(),
            head_hash: hex(&[0xAA; 32]),
            sha256: hex(&[0xBB; 32]),
            written_at: "2026-09-21T02:10:00Z".into(),
            gateway_version: "1.3.19".into(),
        });
        assert!(segment.verify(&key.verifying_key()));
        assert!(!segment.verify(&other.verifying_key()));
        assert_eq!(segment.segment_id, "seg-00000000000000000000-00000000000000009999");
    }

    /// The index is what makes a *missing* segment detectable, so removing one has to break it.
    #[test]
    fn dropping_or_reordering_a_segment_breaks_the_index_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let log = AuditLog::restore(key.clone(), Vec::new());
        let entry = |base: u64, end: u64| AuditIndexEntry {
            segment_id: segment_id(base, end),
            base_seq: base,
            end_seq: end,
            prev_hash: hex(&[base as u8; 32]),
            head_hash: hex(&[end as u8; 32]),
            sha256: hex(&[0xCC; 32]),
        };
        let mut index = AuditArchiveIndex::empty("acme", 0);
        index.segments = vec![entry(0, 9), entry(10, 19), entry(20, 29)];
        let sealed = log.seal_index(index, "2026-09-21T02:10:00Z");
        assert!(sealed.verify(&key.verifying_key()));

        let mut missing = sealed.clone();
        missing.segments.remove(1);
        assert!(!missing.verify(&key.verifying_key()), "a dropped segment must be detectable");

        let mut reordered = sealed.clone();
        reordered.segments.swap(0, 2);
        assert!(!reordered.verify(&key.verifying_key()), "and so must a reordered one");
    }

    /// The three domains are separate, so no signature from one can be presented as another's.
    #[test]
    fn a_segment_signature_cannot_be_replayed_as_a_boundary_or_an_event_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut log = AuditLog::restore(key.clone(), Vec::new());
        log.append_at(payload("a", "allow"), 1000).unwrap();
        let vk = log.verifying_key();
        let head = log.head_hash();
        let segment = log.seal_segment(AuditSegmentDraft {
            tenant: "acme".into(),
            epoch: 0,
            base_seq: 0,
            end_seq: 0,
            count: 1,
            prev_hash: GENESIS_PREV_HASH.to_string(),
            head_hash: head.clone(),
            sha256: hex(&[0xDD; 32]),
            written_at: String::new(),
            gateway_version: String::new(),
        });

        let mut events = log.events().to_vec();
        events[0].signature = segment.signature.clone();
        assert_eq!(AuditLog::verify_with(&events, &vk), Some(0));

        let mut boundary = AuditBoundary::create(&key, 0, 1, head, None, 1000);
        boundary.signature = segment.signature.clone();
        assert!(!boundary.verify(&vk));
    }

    /// And the genesis boundary is the unsigned one, because it states nothing a chain written
    /// before boundaries existed did not already state.
    #[test]
    fn the_genesis_boundary_is_todays_behaviour_and_carries_no_claim() {
        let genesis = AuditBoundary::genesis();
        assert!(genesis.is_genesis());
        assert!(genesis.signature.is_empty());
        assert_eq!(genesis.base_hash, GENESIS_PREV_HASH);

        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let sealed = AuditBoundary::create(&key, 0, 0, GENESIS_PREV_HASH, None, 1000);
        assert!(sealed.is_genesis(), "sealing it does not change what it says");
        assert!(sealed.verify(&key.verifying_key()));
    }

    /// A small-order key with the 64 bytes `R = identity, s = 0` "signs" every message under a non-strict verify, so no audit record may verify under one: the key is only ever the store's own, and this pins that a planted one buys nothing.
    #[test]
    fn a_small_order_key_verifies_no_audit_signature() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).unwrap();
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let forged = hex(&forged);

        let mut log = AuditLog::new();
        log.append_at(payload("transactions.refund", "allow"), 1000).unwrap();
        log.append_at(payload("transactions.read", "allow"), 2000).unwrap();
        let mut events = log.events().to_vec();
        for event in &mut events {
            event.signature = forged.clone();
        }
        assert_eq!(AuditLog::verify_with(&events, &weak), Some(0), "no event verifies under a weak key");

        let mut boundary = AuditBoundary::create(&SigningKey::from_bytes(&[3; 32]), 0, 9000, hex(&[0x77; 32]), None, 1000);
        boundary.signature = forged.clone();
        assert!(!boundary.verify(&weak), "nor does a boundary");

        let mut segment = log.seal_segment(AuditSegmentDraft {
            tenant: "acme".into(),
            epoch: 0,
            base_seq: 0,
            end_seq: 1,
            count: 2,
            prev_hash: GENESIS_PREV_HASH.to_string(),
            head_hash: log.head_hash(),
            sha256: hex(&[0xBB; 32]),
            written_at: String::new(),
            gateway_version: String::new(),
        });
        segment.signature = forged.clone();
        assert!(!segment.verify(&weak), "nor a segment manifest");

        let mut index = log.seal_index(AuditArchiveIndex::empty("acme", 0), "");
        index.signature = forged;
        assert!(!index.verify(&weak), "nor an archive index");
    }
}
