//! Where the audit signing key lives, and how honest we are about it.
//!
//! The audit log is hash-chained AND ed25519-signed, and [`permaura_core::audit`] says you cannot
//! forge or re-chain events without the private key. True. The question here is a different one:
//! **who holds that key?**
//!
//! Without a KMS key the store keeps it inside the same blast radius as the records it protects:
//!
//!   * **In the database**: base64 in `gateway_meta`, in the *same database* as `audit_events`. One
//!     SQL connection yields the key *and* the rows. An attacker deletes what they did, re-chains,
//!     re-signs, and `verify()` returns a clean bill of health.
//!   * **Beside the database**: a `0600` file next to `gateway.db`. Better (a stray `SELECT` doesn't
//!     reach it), but the same owner on the same host can read both.
//!
//! A signature only proves custody. If the key and the records share a custodian, the signature proves
//! nothing against *that* custodian, precisely the attacker an audit trail exists to catch. That is
//! not a bug in the chain; it is the limit of where the key is kept.
//!
//! So this module makes custody an explicit, describable boundary rather than an implementation detail:
//!   1. [`KeyCustody`]: a seam for a key that signs behind an API. No store uses it today: the SQLite store keeps its own custody (a sidecar file, `gateway_meta`, or a KMS-wrapped seed) and reports it through the description below.
//!   2. [`CustodyDescription::separated_from_records`]: the honest answer, reportable through the API
//!      instead of a README claiming more than the deployment delivers.
//!   3. [`AuditCheckpoint`]: a signed head marker. A hash chain cannot detect its own **truncation**:
//!      lop off the last N events and what remains verifies perfectly, because nothing outside the log
//!      remembers how long it was. A checkpoint published *elsewhere* is what makes that visible.
//!
//! KMS envelope custody of the audit key is built into the SQLite store for a hosted worker with a key, and a signed head checkpoint is logged at each hosted cold start ([`LogCheckpointSink`]); nothing compares a store against it automatically.
//! Signing inside a Keychain or KMS, so the key never enters this process, is not built: [`UnwiredCustody`] stands for it, is unused, and refuses rather than pretending.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::GatewayError;

/// What a custody backend actually guarantees. Deliberately not a bool: "we sign the audit log" and
/// "the signature means something against a database compromise" are different claims, and collapsing
/// them is how a security README starts lying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyDescription {
    /// Backend id for logs/telemetry: `database` | `file` | `keychain` | `kms`.
    pub backend: &'static str,
    /// **The load-bearing field.** Is the key outside the reach of whoever can write the records?
    ///
    /// `false` means the audit log is tamper-*evident* against an outsider and tamper-*transparent* to
    /// anyone holding the store. Report it; do not round it up.
    pub separated_from_records: bool,
    /// One line, safe to surface to an operator, explaining the guarantee in plain terms.
    pub summary: &'static str,
}

/// The boundary between "where the signing key lives" and "everything that signs with it".
///
/// No store calls this today: the SQLite store reads its key from the sidecar file or `gateway_meta` itself.
/// It is kept as the seam a key that signs behind an API would use.
pub trait KeyCustody: Send + Sync {
    /// Load the existing key, or create and persist one on first use.
    fn audit_signing_key(&self) -> Result<SigningKey, GatewayError>;
    /// What this backend actually guarantees. Never optimistic.
    fn describe(&self) -> CustodyDescription;
}

/// The audit key in `gateway_meta` with no KMS key to wrap it, named for what it is.
///
/// `separated_from_records: false` is the whole point of the type existing: an honest description
/// beats a silent one.
pub struct DatabaseCustody;

impl DatabaseCustody {
    pub const DESCRIPTION: CustodyDescription = CustodyDescription {
        backend: "database",
        separated_from_records: false,
        summary: "The audit signing key is stored in the same database as the audit events. The log is \
                  tamper-evident against an outsider, but anyone with database access can rewrite \
                  history and re-sign it.",
    };
}

/// The self-hosted default: a `0600` file beside the database.
///
/// Better than [`DatabaseCustody`] (a SQL injection does not reach the filesystem), but the same OS
/// user reads both, so it is still not separation.
pub struct FileCustody;

impl FileCustody {
    pub const DESCRIPTION: CustodyDescription = CustodyDescription {
        backend: "file",
        separated_from_records: false,
        summary: "The audit signing key is a 0600 file beside the database. A database-only compromise \
                  cannot reach it, but the same OS user can read both.",
    };
}

/// Tier-A envelope custody: the ed25519 seed is stored **KMS-wrapped** in the store,
/// so the row holds only ciphertext and unwrapping requires KMS `Decrypt`, which the worker's service account holds and a copy of
/// the database or a snapshot does not; that same service account also writes the store bucket, so whoever can act as it can both
/// rewrite history and re-sign it.
///
/// Why `separated_from_records` is `true` here and not rounding up: the field asks whether the key is
/// outside the reach of *whoever can write the records*. On the hosted worker that adversary is anyone
/// who can read the store: a copy of the snapshot, a stray `SELECT`, the operator reading the
/// table. Under envelope custody they hold ciphertext and lack KMS `Decrypt`, so they cannot
/// re-sign history. What stays out of scope is a compromise of the *running process*, which unwraps the
/// seed into memory at startup; closing that is Tier B: signing inside KMS so the key never leaves the
/// HSM. The summary states exactly this rather than implying more.
pub struct KmsEnvelopeCustody;

impl KmsEnvelopeCustody {
    pub const DESCRIPTION: CustodyDescription = CustodyDescription {
        backend: "kms",
        separated_from_records: true,
        summary: "The audit signing key is stored wrapped under a cloud KMS key; the database holds \
                  only ciphertext, so database access alone cannot re-sign history. The key is \
                  unwrapped into process memory at startup, so a host compromise is out of scope \
                  (that is Tier B: signing inside KMS).",
    };
}

/// The seam a real backend fills: macOS Keychain / cloud KMS, where signing happens **behind** an API
/// and the private key never enters this process.
///
/// That is what flips `separated_from_records` to `true`: not "the key is somewhere else", but "the key
/// cannot be exported, so compromising the records does not yield the ability to re-sign them".
pub struct UnwiredCustody {
    pub backend: &'static str,
}

impl KeyCustody for UnwiredCustody {
    fn audit_signing_key(&self) -> Result<SigningKey, GatewayError> {
        Err(GatewayError::Internal(format!(
            "{} key custody is not wired up yet. Configure a real backend or use the file/database \
             custody the store defaults to. This backend refuses rather than silently falling back to \
             keeping the key next to the records.",
            self.backend
        )))
    }
    fn describe(&self) -> CustodyDescription {
        CustodyDescription {
            backend: self.backend,
            separated_from_records: true,
            summary: "Signing happens behind an external key store; the private key never enters this \
                      process, so database access alone cannot re-sign history.",
        }
    }
}

// ── head checkpoints: making truncation visible ──────────────────────────────

/// A signed statement that "at this moment the log was N events long and ended here".
///
/// Why this is needed at all: a hash chain detects *edits* (every later hash breaks) but is blind to
/// *truncation*. Delete the last 500 events and the surviving prefix verifies perfectly: the chain has
/// no idea it was ever longer. Only something remembering the head **outside** the log can tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    /// Number of events in the log when this was taken (i.e. the head's seq + 1).
    pub len: u64,
    /// The head event's chain hash.
    pub head_hash: String,
    /// Unix ms.
    pub taken_at: i64,
    /// base64 ed25519 over [`AuditCheckpoint::preimage`].
    pub signature: String,
}

impl AuditCheckpoint {
    /// Domain-separated so a checkpoint signature can never be replayed as an audit-event signature.
    fn preimage(len: u64, head_hash: &str, taken_at: i64) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"permaura:audit-checkpoint:v1");
        h.update(len.to_be_bytes());
        h.update(head_hash.as_bytes());
        h.update(taken_at.to_be_bytes());
        h.finalize().to_vec()
    }

    pub fn create(key: &SigningKey, len: u64, head_hash: &str, taken_at: i64) -> Self {
        let sig = key.sign(&Self::preimage(len, head_hash, taken_at));
        Self {
            len,
            head_hash: head_hash.to_string(),
            taken_at,
            signature: base64_encode(&sig.to_bytes()),
        }
    }

    pub fn verify(&self, vk: &VerifyingKey) -> Result<(), GatewayError> {
        let raw = base64_decode(&self.signature)
            .ok_or_else(|| GatewayError::Internal("checkpoint signature is not base64".into()))?;
        let arr: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| GatewayError::Internal("checkpoint signature must be 64 bytes".into()))?;
        vk.verify_strict(
            &Self::preimage(self.len, &self.head_hash, self.taken_at),
            &Signature::from_bytes(&arr),
        )
        .map_err(|_| GatewayError::Internal("checkpoint signature did not verify".into()))
    }
}

/// What a log's current head looks like when compared against the last checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointVerdict {
    /// The log has grown (or stayed put) and still contains the checkpointed head.
    Consistent,
    /// The log is SHORTER than the checkpoint says it was: events were removed. The chain alone
    /// cannot see this; this is the entire reason checkpoints exist.
    Truncated { was: u64, now: u64 },
    /// Same length or longer, but the checkpointed position no longer holds the same hash: history
    /// was rewritten under a key the attacker controls.
    Diverged,
}

/// Compare a checkpoint against the log's current state.
///
/// `hash_at(len)` returns the chain hash of the event at index `len - 1`, or `None` if the log is
/// shorter than that. Kept as a closure so this is pure and testable without a store.
pub fn check_against(
    checkpoint: &AuditCheckpoint,
    current_len: u64,
    hash_at: impl Fn(u64) -> Option<String>,
) -> CheckpointVerdict {
    if current_len < checkpoint.len {
        return CheckpointVerdict::Truncated { was: checkpoint.len, now: current_len };
    }
    match hash_at(checkpoint.len) {
        Some(h) if h == checkpoint.head_hash => CheckpointVerdict::Consistent,
        _ => CheckpointVerdict::Diverged,
    }
}

/// Where a checkpoint is published. The value is entirely in the sink being somewhere the holder of the
/// database cannot quietly edit: an append-only bucket, a transparency log, a second account.
///
/// A sink inside the same database would be theatre: the attacker rewriting events would rewrite the
/// checkpoint in the same transaction.
pub trait CheckpointSink: Send + Sync {
    fn publish(&self, checkpoint: &AuditCheckpoint) -> Result<(), GatewayError>;
    fn latest(&self) -> Result<Option<AuditCheckpoint>, GatewayError>;
}

/// A sink that publishes nowhere, used by nothing today. Wherever it would apply, truncation stays undetectable, stated plainly
/// rather than implied by absence, so nobody reads "checkpoints exist in the codebase" as "truncation is covered".
pub struct NullCheckpointSink;

impl CheckpointSink for NullCheckpointSink {
    fn publish(&self, _c: &AuditCheckpoint) -> Result<(), GatewayError> {
        Ok(())
    }
    fn latest(&self) -> Result<Option<AuditCheckpoint>, GatewayError> {
        Ok(None)
    }
}

/// Publishes each checkpoint to the process's structured log, which on the hosted worker (Cloud Run)
/// flows to **Cloud Logging**, a store the holder of the audit database cannot rewrite. That external,
/// append-only record of the head is what makes truncation *evidenced*: if the database is later cut
/// short, the signed checkpoints in Cloud Logging still attest the log was once longer.
///
/// `latest()` returns `None`: this sink is write-only (a log is not queried back inline), so it
/// establishes the external record but does not itself run the comparison. Reading checkpoints back for
/// automated [`check_against`] is deliberately left as the next step, so nobody reads "checkpoints are
/// published" as "truncation is auto-detected".
pub struct LogCheckpointSink;

impl CheckpointSink for LogCheckpointSink {
    fn publish(&self, c: &AuditCheckpoint) -> Result<(), GatewayError> {
        tracing::info!(
            target: "audit_checkpoint",
            len = c.len,
            head_hash = %c.head_hash,
            taken_at = c.taken_at,
            signature = %c.signature,
            "audit head checkpoint (external anchor: append-only log)"
        );
        Ok(())
    }
    fn latest(&self) -> Result<Option<AuditCheckpoint>, GatewayError> {
        Ok(None)
    }
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    #[test]
    fn a_checkpoint_verifies_under_its_own_key_and_not_another() {
        let k = key();
        let c = AuditCheckpoint::create(&k, 10, "abc", 1_000);
        assert!(c.verify(&k.verifying_key()).is_ok());

        let other = SigningKey::from_bytes(&[3u8; 32]);
        assert!(c.verify(&other.verifying_key()).is_err());
    }

    #[test]
    fn a_small_order_key_verifies_no_checkpoint() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).unwrap();
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let c = AuditCheckpoint { len: 100, head_hash: "head-at-100".into(), taken_at: 1_000, signature: base64_encode(&forged) };
        assert!(c.verify(&weak).is_err(), "R = identity, s = 0 must not pass for a weak key");
    }

    #[test]
    fn tampering_with_any_field_breaks_the_checkpoint() {
        let k = key();
        let base = AuditCheckpoint::create(&k, 10, "abc", 1_000);
        for mutated in [
            AuditCheckpoint { len: 9, ..base.clone() },
            AuditCheckpoint { head_hash: "def".into(), ..base.clone() },
            AuditCheckpoint { taken_at: 2_000, ..base.clone() },
        ] {
            assert!(mutated.verify(&k.verifying_key()).is_err(), "{mutated:?} should not verify");
        }
    }

    /// A hash chain cannot see its own tail being cut off.
    #[test]
    fn truncation_is_detected_by_the_checkpoint_and_only_by_the_checkpoint() {
        let k = key();
        // The log was 100 events long and we said so, out loud, somewhere else.
        let c = AuditCheckpoint::create(&k, 100, "head-at-100", 1_000);

        // The attacker deletes the last 40 events. The surviving 60 still chain perfectly to each
        // other, so verify() is happy. The checkpoint is what notices.
        let verdict = check_against(&c, 60, |_| None);
        assert_eq!(verdict, CheckpointVerdict::Truncated { was: 100, now: 60 });
    }

    #[test]
    fn a_log_that_grew_past_the_checkpoint_is_consistent() {
        let k = key();
        let c = AuditCheckpoint::create(&k, 100, "head-at-100", 1_000);
        let verdict = check_against(&c, 250, |len| {
            (len == 100).then(|| "head-at-100".to_string())
        });
        assert_eq!(verdict, CheckpointVerdict::Consistent);
    }

    #[test]
    fn rewritten_history_at_the_checkpointed_position_is_divergence_not_growth() {
        let k = key();
        let c = AuditCheckpoint::create(&k, 100, "head-at-100", 1_000);
        // Same length, different hash: re-chained and re-signed under a key the attacker holds.
        let verdict = check_against(&c, 100, |_| Some("forged-head".to_string()));
        assert_eq!(verdict, CheckpointVerdict::Diverged);
    }

    #[test]
    fn checkpoint_signatures_cannot_be_replayed_as_audit_event_signatures() {
        // Domain separation: the preimage is a hash over a tagged prefix, not the raw fields.
        let a = AuditCheckpoint::preimage(1, "x", 0);
        let mut naive = Vec::new();
        naive.extend_from_slice(&1u64.to_be_bytes());
        naive.extend_from_slice(b"x");
        naive.extend_from_slice(&0i64.to_be_bytes());
        assert_ne!(a, naive);
    }

    #[test]
    fn todays_custody_reports_itself_as_not_separated() {
        // If either of these ever flips to true without a real backend behind it, the API starts
        // claiming a guarantee the deployment does not have. That is the whole point of the field.
        assert!(!DatabaseCustody::DESCRIPTION.separated_from_records);
        assert!(!FileCustody::DESCRIPTION.separated_from_records);
        assert_eq!(DatabaseCustody::DESCRIPTION.backend, "database");
        assert_eq!(FileCustody::DESCRIPTION.backend, "file");
    }

    #[test]
    fn an_unwired_backend_refuses_rather_than_falling_back() {
        // The dangerous failure would be "KMS unavailable, so keep the key next to the records",
        // a silent fallback to weaker custody. It must be an error.
        let c = UnwiredCustody { backend: "kms" };
        assert!(c.audit_signing_key().is_err());
        assert!(c.describe().separated_from_records);
    }

    #[test]
    fn the_null_sink_admits_it_remembers_nothing() {
        let s = NullCheckpointSink;
        let c = AuditCheckpoint::create(&key(), 1, "h", 0);
        assert!(s.publish(&c).is_ok());
        // No checkpoint to compare against => truncation stays invisible. Stated, not implied.
        assert!(s.latest().unwrap().is_none());
    }

    #[test]
    #[allow(clippy::assertions_on_constants)] // deliberately asserting the shipped const description
    fn kms_envelope_custody_reports_separation_with_an_honest_summary() {
        // Tier A legitimately flips separation to true, but only because the summary names the exact
        // residual (process memory), so the claim matches what envelope custody actually delivers.
        assert!(KmsEnvelopeCustody::DESCRIPTION.separated_from_records);
        assert_eq!(KmsEnvelopeCustody::DESCRIPTION.backend, "kms");
        assert!(
            KmsEnvelopeCustody::DESCRIPTION.summary.contains("process memory"),
            "the summary must disclose the in-process residual, not imply Tier B"
        );
    }

    #[test]
    fn the_log_sink_publishes_the_head_but_does_not_read_it_back() {
        let s = LogCheckpointSink;
        let c = AuditCheckpoint::create(&key(), 42, "head-at-42", 1_000);
        // Publishing to the external append-only log succeeds (the anchor is established)...
        assert!(s.publish(&c).is_ok());
        // ...but inline read-back is not this sink's job: automated comparison is the next step.
        assert!(s.latest().unwrap().is_none());
    }
}
