//! Optional `rusqlite`-backed [`Store`], behind the `sqlite` feature.
//!
//! Entities are persisted as JSON blobs keyed by id, enough to give the daemon a
//! durable local database without re-deriving a relational schema. The hash-chained [`AuditLog`] is kept in memory (it
//! owns the signing key and chaining invariants) and its sealed events are mirrored
//! into an `audit_events` table so the chain survives restarts for inspection.
//!
//! The default in-memory store is what the rest of the gateway and the tests exercise;
//! this exists so `--features sqlite` compiles and runs against a real, if simple,
//! durable store. The schema is created and upgraded by the versioned runner in
//! [`super::migrations`]. See that module for the version gate and backup story.

use std::sync::{Mutex, MutexGuard};
use std::thread::ThreadId;

use ed25519_dalek::SigningKey;
use permaura_core::audit::{AuditBoundary, AuditFork, AuditRekey, AUDIT_REKEY_ACTION};
use permaura_core::{AuditEvent, AuditLog, AuditPayload, Connection as Conn, Grant, Policy, SealedSecret, SecretRecord};
use rusqlite::{Connection, OptionalExtension};

use crate::backend::AuditKeyWrap;
use crate::connectors::Capability;
use crate::custody::{CustodyDescription, DatabaseCustody, FileCustody, KmsEnvelopeCustody};
use crate::error::GatewayError;
use crate::manifest::InstalledManifest;

use super::{Agent, EnrolmentCode, PendingApproval, SecretCustody, Session, Store};

/// Load (or generate + persist `0600`) the audit signing key beside the DB. The same pattern the
/// relay's `FileKeystore` uses for the worker key: the key is owner-only from its first byte
/// (`create_new` + mode), never momentarily world-readable.
///
/// A key is generated only for a store with nothing signed in it yet. `history` names what the store
/// already holds under the missing key, and then the open is refused: events signed onward under a new
/// key could never again be verified together with the old ones, and restoring the old key later would
/// break the new ones instead. The repair is the key copied from the old machine or a backup, or, when it is gone for
/// good, `permaura audit rekey --yes` ([`SqliteStore::rekey`]), which records the fork in the chain.
fn load_or_create_audit_key(key_path: &str, history: Option<&str>) -> Result<SigningKey, GatewayError> {
    match std::fs::read(key_path) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                GatewayError::Internal(format!("audit key file {key_path} must be 32 bytes"))
            })?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && history.is_some() => {
            let db = key_path.strip_suffix(".auditkey").unwrap_or(key_path);
            Err(GatewayError::AuditKeyMissing(format!(
                "{key_path} is missing, but {db} already holds {} signed under the key that was in it: refusing to open the store rather than sign onward under a new key, which would break the audit chain for good. Restore {key_path} (32 bytes, owner-only; it belongs with gateway.db wherever the store goes) from the backup or the machine this store came from. If it is gone for good, stop the gateway and run `permaura audit rekey --yes`: it gives this store a new key and records the fork in the chain, and keeps every connection, credential, grant and agent. Moving {db} aside to start over gives all of those up, though the moved file can still be opened with its key, or rekeyed",
                history.unwrap_or_default()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            // Shared owner-only secret write (`0600` on Unix, atomic `create_new`, creates parent dirs),
            // then the Windows half of the same guarantee, where mode bits do not exist.
            let path = std::path::Path::new(key_path);
            permaura_core::write_secret_file(path, &sk.to_bytes())
                .map_err(|e| GatewayError::Internal(format!("write audit key: {e}")))?;
            permaura_credential_store::restrict_to_owner(path)
                .map_err(|e| GatewayError::Internal(format!("restrict audit key: {e}")))?;
            Ok(sk)
        }
        Err(e) => Err(GatewayError::Internal(format!("read audit key: {e}"))),
    }
}

/// Where a store's audit signing key lives.
enum KeyCustody {
    /// A `0600` `{path}.auditkey` file beside the database. The self-hosted default.
    Sidecar,
    /// A `gateway_meta` row, KMS-wrapped when a CMK is configured. The only durable choice when the
    /// database file is the whole of what survives a restart.
    Meta(Option<AuditKeyWrap>),
}

/// The `gateway_meta` key the audit signing key is stored under.
const AUDIT_KEY_META: &str = "audit_signing_key";

/// Prefix marking a `gateway_meta.audit_signing_key` value as KMS-wrapped ciphertext (base64
/// follows). The base64 alphabet contains no ':', so a legacy plaintext value is unambiguous by the
/// prefix's absence.
const KMS_WRAP_PREFIX: &str = "kms:v1:";

/// The same, with the KMS key version that produced the ciphertext:
/// `kms:v2:<keyVersionResourceName>:<base64 ciphertext>`. A GCP key-version resource name is a path
/// and carries no ':', and neither does base64, so one `split_once` after the prefix is unambiguous.
///
/// The version is what makes a years-old snapshot openable: a ciphertext outlives only the version
/// that produced it, and `kms:v1:` recorded no version at all, so a manifest could name the key but
/// never the version it actually depended on. Reading `kms:v1:` stays supported forever, because
/// decrypting does not need it.
const KMS_WRAP_V2_PREFIX: &str = "kms:v2:";

/// How a store's audit signing key is held, as the upload metadata states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditKeyStamp {
    /// `kms:v2`, `kms:v1`, `plain:v1`, or `file:v1` for a sidecar-custody store.
    pub wrap: &'static str,
    /// The KMS key version the wrap depends on, when the format records one.
    pub version: Option<String>,
}

/// Load (or create) the audit signing key from `gateway_meta`, sealing it under KMS when a CMK is
/// configured. Five cases:
///
/// - **No row, CMK present:** a new key is generated and stored **wrapped**, so the database holds
///   only ciphertext. A CMK that cannot wrap is a failure here, not a plaintext fallback, or the very
///   first key would land in weak custody on a hosted worker.
/// - **No row, no CMK:** plaintext base64, [`DatabaseCustody`]. The key shares the database's blast
///   radius, which is the honest description.
/// - **Wrapped row:** unwrapped through the CMK. A `kms:v1:` row is rewrapped to `kms:v2:` on the
///   way past, so the version it depends on stops being unrecorded; the rewrap is best-effort and a
///   store that cannot do it keeps running on the perfectly good v1 ciphertext.
/// - **Wrapped row, no CMK:** refused. Running on a fresh key instead would fork the audit chain and
///   quietly orphan the history.
/// - **Plaintext row, CMK present:** refused, unless the wrap says `adopt_plaintext` (a one-time
///   migration), when it is re-wrapped in place, best-effort. A store that has a CMK writes its key
///   wrapped from the first open, so a plaintext row is what something holding the bucket but not the
///   key leaves behind: a key of its own, under which it re-signed a rewritten history. Adopting it
///   would wrap the forger's key under the CMK and report KMS custody over the forged chain.
fn load_or_create_meta_audit_key(
    conn: &Connection,
    wrap: Option<&AuditKeyWrap>,
) -> Result<(SigningKey, CustodyDescription, AuditKeyStamp), GatewayError> {
    let existing: Option<String> = conn
        .query_row("SELECT value FROM gateway_meta WHERE key = ?1", [AUDIT_KEY_META], |r| r.get(0))
        .optional()
        .map_err(map_sql)?;

    let value = match existing {
        Some(v) => v,
        None => {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let stored = match wrap {
                Some(w) => wrapped_value(w, &sk.to_bytes())?,
                None => b64_encode(&sk.to_bytes()),
            };
            // A concurrent opener may have won the race; keep whoever wrote first, then re-read.
            conn.execute(
                "INSERT OR IGNORE INTO gateway_meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![AUDIT_KEY_META, &stored],
            )
            .map_err(map_sql)?;
            conn.query_row("SELECT value FROM gateway_meta WHERE key = ?1", [AUDIT_KEY_META], |r| r.get(0))
                .map_err(map_sql)?
        }
    };

    if let Some(rest) = value.strip_prefix(KMS_WRAP_V2_PREFIX) {
        let w = require_cmk(wrap)?;
        let (version, ct_b64) = rest.split_once(':').ok_or_else(|| {
            GatewayError::Internal(
                "audit signing key is kms:v2-wrapped but names no key version: refusing to start rather \
                 than abandon the audit chain"
                    .into(),
            )
        })?;
        let plaintext = crate::store::bridge::block_on(w.kms.decrypt(&w.key_id, &b64_decode(ct_b64)?))?;
        let stamp = AuditKeyStamp { wrap: "kms:v2", version: Some(version.to_string()) };
        return Ok((SigningKey::from_bytes(&to_seed(&plaintext)?), KmsEnvelopeCustody::DESCRIPTION, stamp));
    }

    if let Some(ct_b64) = value.strip_prefix(KMS_WRAP_PREFIX) {
        let w = require_cmk(wrap)?;
        let plaintext = crate::store::bridge::block_on(w.kms.decrypt(&w.key_id, &b64_decode(ct_b64)?))?;
        let seed = to_seed(&plaintext)?;
        // The version has to come from a wrap, because a decrypt response does not carry one. So the
        // upgrade is a rewrap of the same key material, once, on the first open under a CMK.
        let stamp = wrap_in_place(conn, w, &seed, &value, true)
            .unwrap_or(AuditKeyStamp { wrap: "kms:v1", version: None });
        return Ok((SigningKey::from_bytes(&seed), KmsEnvelopeCustody::DESCRIPTION, stamp));
    }

    let seed = to_seed(&zeroize::Zeroizing::new(b64_decode(&value)?))?;
    let sk = SigningKey::from_bytes(&seed);
    let Some(w) = wrap else {
        return Ok((sk, DatabaseCustody::DESCRIPTION, AuditKeyStamp { wrap: "plain:v1", version: None }));
    };
    if !w.adopt_plaintext {
        return Err(GatewayError::Internal(
            "the audit signing key is stored in plaintext but this gateway has a KMS key: a store with a \
             CMK never writes its key unwrapped, so this one may have been replaced along with the history \
             it signs. Refusing to start. If this store genuinely predates KMS custody, set \
             PERMAURA_AUDIT_KEY_ADOPT_PLAINTEXT=1 for one start to wrap it, then remove it"
                .into(),
        ));
    }
    match wrap_in_place(conn, w, &seed, &value, false) {
        Some(stamp) => {
            tracing::info!("upgraded audit signing key to KMS-wrapped custody");
            Ok((sk, KmsEnvelopeCustody::DESCRIPTION, stamp))
        }
        None => Ok((sk, DatabaseCustody::DESCRIPTION, AuditKeyStamp { wrap: "plain:v1", version: None })),
    }
}

/// The refusal a wrapped row with no CMK gets, in one place so both wrap formats give the same one.
fn require_cmk(wrap: Option<&AuditKeyWrap>) -> Result<&AuditKeyWrap, GatewayError> {
    wrap.ok_or_else(|| {
        GatewayError::Internal(
            "audit signing key is KMS-wrapped but no KMS client is configured (PERMAURA_KMS_KEY_ID / \
             PERMAURA_KMS_PROVIDER): refusing to start rather than abandon the audit chain"
                .into(),
        )
    })
}

/// Wrap `seed` under the CMK, in the newest format the KMS gives us enough to write.
fn wrapped_value(w: &AuditKeyWrap, seed: &[u8]) -> Result<String, GatewayError> {
    let wrapped = crate::store::bridge::block_on(w.kms.encrypt_versioned(&w.key_id, seed))?;
    let ct = b64_encode(&wrapped.ciphertext);
    Ok(match wrapped.key_version {
        Some(version) => format!("{KMS_WRAP_V2_PREFIX}{version}:{ct}"),
        None => format!("{KMS_WRAP_PREFIX}{ct}"),
    })
}

/// Wrap the key under the CMK and store the result, conditional on the value we read so a
/// concurrent opener's write is not clobbered.
///
/// `only_to_record_a_version` separates the two reasons to rewrite a row, which want opposite
/// answers when the KMS does not name versions. A **plaintext** row is wrapped either way, because
/// getting the key out of the database is the whole point and an unversioned wrap does that. An
/// existing **`kms:v1`** row is rewritten only to record the version, so a KMS that cannot name one
/// leaves it exactly where it is: v1 is readable forever, and a v2 that could not name a version
/// would be strictly worse than the v1 it replaced.
///
/// `None` means the row is kept as it stands, which is always still valid. A missing `Encrypt` grant
/// is a reason to carry on, never to fail an open.
fn wrap_in_place(
    conn: &Connection,
    w: &AuditKeyWrap,
    seed: &[u8],
    current: &str,
    only_to_record_a_version: bool,
) -> Option<AuditKeyStamp> {
    let wrapped = match crate::store::bridge::block_on(w.kms.encrypt_versioned(&w.key_id, seed)) {
        Ok(wrapped) => wrapped,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "a KMS CMK is configured but wrapping the audit key failed (missing cryptoKeyEncrypter \
                 grant?). Continuing on the key as it is stored; grant Encrypt to upgrade on the next restart"
            );
            return None;
        }
    };
    if only_to_record_a_version && wrapped.key_version.is_none() {
        return None;
    }
    let ct = b64_encode(&wrapped.ciphertext);
    let (value, stamp) = match wrapped.key_version {
        Some(version) => (
            format!("{KMS_WRAP_V2_PREFIX}{version}:{ct}"),
            AuditKeyStamp { wrap: "kms:v2", version: Some(version) },
        ),
        None => (format!("{KMS_WRAP_PREFIX}{ct}"), AuditKeyStamp { wrap: "kms:v1", version: None }),
    };
    if value == current {
        return Some(stamp);
    }
    if let Err(e) = conn.execute(
        "UPDATE gateway_meta SET value = ?1 WHERE key = ?2 AND value = ?3",
        rusqlite::params![&value, AUDIT_KEY_META, current],
    ) {
        tracing::warn!(error = %e, "could not rewrite the wrapped audit key: continuing on the stored wrap");
        return None;
    }
    Some(stamp)
}

/// Publish a signed checkpoint of the audit head to the process log at a hosted cold start.
///
/// The log is a store the holder of this database cannot rewrite (Cloud Logging on Cloud Run), which
/// is what makes a later truncation of `audit_events` evidenced rather than invisible. Best-effort:
/// startup never waits on the anchor.
///
/// The length is absolute (the base plus what is held), because a checkpoint anchored on the size of
/// the hot window would fall by exactly as much as an archive legitimately removed, and the one
/// number that must keep growing is the one truncation is detected by.
fn anchor_audit_head(key: &SigningKey, base_seq: u64, events: &[AuditEvent]) {
    let Some(head) = events.last() else {
        return;
    };
    let len = base_seq + events.len() as u64;
    let checkpoint = crate::custody::AuditCheckpoint::create(key, len, &head.hash, super::now_ms());
    let _ = crate::custody::CheckpointSink::publish(&crate::custody::LogCheckpointSink, &checkpoint);
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, GatewayError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| GatewayError::Internal(format!("audit key base64: {e}")))
}

fn to_seed(bytes: &[u8]) -> Result<[u8; 32], GatewayError> {
    bytes
        .try_into()
        .map_err(|_| GatewayError::Internal("audit signing key must be 32 bytes".into()))
}

/// The `gateway_meta` key the audit boundary record is stored under.
pub(crate) const AUDIT_BOUNDARY_META: &str = "audit_boundary";

/// The `gateway_meta` row holding the latest [`AuditRekey`], once `permaura audit rekey` has run.
pub(crate) const AUDIT_REKEY_META: &str = "audit_rekey";

/// The recorded rekey this store honors, or `None`: the latest rekey event the hot window holds under
/// this store's key, else the signed record of one whose event has been archived. A record that does
/// not verify, or names an event that should be held and is not, is ignored and logged: the chain is
/// then checked strictly, and the old key's events read as a break.
fn load_audit_rekey(conn: &Connection, log: &AuditLog) -> Result<Option<AuditRekey>, GatewayError> {
    if let Some(rekey) = log.held_rekey() {
        return Ok(Some(rekey));
    }
    let stored: Option<String> = conn
        .query_row("SELECT value FROM gateway_meta WHERE key = ?1", [AUDIT_REKEY_META], |r| r.get(0))
        .optional()
        .map_err(map_sql)?;
    let Some(stored) = stored else { return Ok(None) };
    match serde_json::from_str::<AuditRekey>(&stored) {
        Ok(rekey) if rekey.verify(&log.verifying_key()) && rekey.seq < log.base_seq() => Ok(Some(rekey)),
        _ => {
            tracing::error!("the audit rekey record is unreadable, not signed by this store's audit key, or names an event the hot window should hold and does not: ignored, so the chain is checked strictly");
            Ok(None)
        }
    }
}

/// Read the [`AuditBoundary`], which is what decides where this store's hot window starts.
///
/// No row at all is a store from before boundaries existed, and it means the genesis boundary (base
/// seq 0, genesis hash, nothing archived), which is exactly what such a store already was.
///
/// A boundary that names a base, an epoch or a segment must carry a signature this key verifies, or
/// the store refuses to open: that boundary is the only thing standing between a prune and an
/// undetectable one, and a boundary anyone can rewrite protects nothing. The genesis boundary is
/// accepted whatever its signature says, because it claims nothing that was not already true of
/// every store written before this record existed, and because it has to be: the schema migration
/// writes it before any key has been resolved, and a `VACUUM INTO` copy of a sidecar-custody store
/// opens under a key of its own.
///
/// Rewinding a pruned store's boundary to genesis is not a way past this. The window would then
/// have to start at seq 0, and the events that would have to be there were the ones pruned, so
/// `load_audit_events` refuses it as a hole.
fn load_audit_boundary(
    conn: &Connection,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<AuditBoundary, GatewayError> {
    let stored: Option<String> = conn
        .query_row("SELECT value FROM gateway_meta WHERE key = ?1", [AUDIT_BOUNDARY_META], |r| r.get(0))
        .optional()
        .map_err(map_sql)?;
    let Some(stored) = stored else {
        return Ok(AuditBoundary::genesis());
    };
    let boundary: AuditBoundary = serde_json::from_str(&stored).map_err(|e| {
        GatewayError::Internal(format!(
            "the audit boundary row is not a readable boundary record ({e}): refusing to open rather than guess where the audit chain starts"
        ))
    })?;
    if boundary.is_genesis() {
        return Ok(boundary);
    }
    if boundary.signature.is_empty() {
        return Err(GatewayError::Internal(format!(
            "the audit boundary claims the chain starts at seq {} but carries no signature: refusing to open, because an unsigned boundary is a prune anyone could have made",
            boundary.base_seq
        )));
    }
    if !boundary.verify(verifying_key) {
        return Err(GatewayError::Internal(format!(
            "the audit boundary signature does not verify under this store's audit key (base seq {}, epoch {}): refusing to open",
            boundary.base_seq, boundary.epoch
        )));
    }
    Ok(boundary)
}

/// What a store holds that only the key it was signed under can verify, or `None` when nothing is signed
/// in it yet. A boundary that cannot be read counts, since it is only ever written over a signed chain.
fn recorded_audit_history(conn: &Connection) -> Result<Option<String>, GatewayError> {
    let events: i64 = conn
        .query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
        .map_err(map_sql)?;
    if events > 0 {
        return Ok(Some(format!("{events} audit events")));
    }
    let boundary: Option<String> = conn
        .query_row("SELECT value FROM gateway_meta WHERE key = ?1", [AUDIT_BOUNDARY_META], |r| r.get(0))
        .optional()
        .map_err(map_sql)?;
    Ok(match boundary.map(|raw| serde_json::from_str::<AuditBoundary>(&raw)) {
        None => None,
        Some(Ok(boundary)) if boundary.is_genesis() => None,
        Some(Ok(boundary)) => Some(format!("an audit chain archived up to seq {}", boundary.base_seq)),
        Some(Err(_)) => Some("an audit boundary record".to_string()),
    })
}

/// Replay the persisted audit events from the boundary so the in-memory chain resumes from the
/// stored head. The rows are taken as stored; `verify_audit()` re-checks them under the key.
///
/// The two structural checks here are not the same as verification and cannot be deferred to it: a
/// window whose first row is not the base, or that has a hole in it, is a store whose events and
/// whose boundary disagree about what it holds. That is corruption or a partial prune, never a
/// shift to absorb, so it fails the open rather than producing a chain that renumbers itself.
fn load_audit_events(conn: &Connection, base_seq: u64) -> Result<Vec<AuditEvent>, GatewayError> {
    let mut stmt = conn
        .prepare("SELECT seq, data FROM audit_events WHERE seq >= ?1 ORDER BY seq ASC")
        .map_err(map_sql)?;
    let rows = stmt
        .query_map([base_seq as i64], |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?)))
        .map_err(map_sql)?;
    let mut events: Vec<AuditEvent> = Vec::new();
    for row in rows {
        let (seq, data) = row.map_err(map_sql)?;
        let expected = base_seq + events.len() as u64;
        if seq != expected {
            return Err(GatewayError::Internal(format!(
                "the audit events below seq {expected} are missing (the next stored row is {seq}, and the boundary says the window starts at {base_seq}): refusing to open a chain with a hole in it"
            )));
        }
        events.push(serde_json::from_str::<AuditEvent>(&data).map_err(map_sql)?);
    }
    Ok(events)
}

/// File one charge against the materialised counter, inside whatever transaction `conn` is in.
///
/// One row per `(grant, agent, millisecond)`, so the read predicate `period_start >= since` selects
/// exactly the events an audit scan's `timestamp >= since` would. The grant total is the sum across
/// every agent of the grant, including the empty one a charge with no agent on it files under, which
/// is what makes the total and the per-agent tier one table rather than two.
pub(crate) fn file_grant_charge(
    conn: &Connection,
    grant_id: &str,
    agent_id: &str,
    timestamp: i64,
) -> Result<(), GatewayError> {
    conn.execute(
        "INSERT INTO grant_usage (grant_id, agent_id, period_start, count) VALUES (?1, ?2, ?3, 1)
         ON CONFLICT(grant_id, agent_id, period_start) DO UPDATE SET count = count + 1",
        rusqlite::params![grant_id, agent_id, super::charge_period_start(timestamp)],
    )
    .map_err(map_sql)?;
    Ok(())
}

/// A usage rebuild's history, counted with the store's lock released: the archive it was handed, and the hot window as it stood when the walk began.
///
/// It keeps where it read the hot window up to, so [`SqliteStore::apply_grant_usage`] can charge what was appended after and can tell whether an archive pass moved events out of the window that the walk never counted.
pub(crate) struct WalkedUsage {
    tally: UsageTally,
    /// The seq the next append would have taken when the hot window was read.
    next_seq: u64,
    /// The hash of event `next_seq - 1`, or the base hash when the window held nothing.
    head_hash: String,
}

/// Charges counted in memory the way the counter table holds them, one entry per grant, agent and period, with the ids interned so a long history costs a few integers per entry.
#[derive(Default)]
struct UsageTally {
    ids: Vec<String>,
    by_id: std::collections::HashMap<String, u32>,
    rows: std::collections::HashMap<(u32, u32, i64), i64>,
    filed: u64,
}

impl UsageTally {
    fn intern(&mut self, id: &str) -> u32 {
        if let Some(&n) = self.by_id.get(id) {
            return n;
        }
        let n = self.ids.len() as u32;
        self.ids.push(id.to_string());
        self.by_id.insert(id.to_string(), n);
        n
    }

    /// Count `event` if it is a charge. A period older than `horizon` goes straight into the folded row, where `compact_grant_usage` would move it after the commit anyway, so years of history hold one entry per grant and agent rather than one per event.
    fn charge(&mut self, event: &AuditEvent, horizon: i64) {
        let Some(grant_id) = super::charged_grant(event) else { return };
        let period = super::charge_period_start(event.timestamp);
        let period = if period > 0 && period < horizon { 0 } else { period };
        let key = (self.intern(grant_id), self.intern(super::charge_agent(&event.payload)), period);
        *self.rows.entry(key).or_insert(0) += 1;
        self.filed += 1;
    }

    fn file(&self, conn: &Connection) -> Result<(), GatewayError> {
        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO grant_usage (grant_id, agent_id, period_start, count) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(grant_id, agent_id, period_start) DO UPDATE SET count = count + excluded.count",
            )
            .map_err(map_sql)?;
        for (&(grant, agent, period), &count) in &self.rows {
            stmt.execute(rusqlite::params![self.ids[grant as usize], self.ids[agent as usize], period, count])
                .map_err(map_sql)?;
        }
        Ok(())
    }
}

/// Fold every row older than the detail window into its `period_start = 0` row, in one transaction.
///
/// Best effort at every call site, and deliberately so: this is housekeeping that keeps the table
/// proportional to the live windows, and a failure to run it must never fail the audit append that
/// happened to be the one that tried. An audit event is never dropped, at any pressure, for any
/// reason.
fn compact_grant_usage(conn: &Connection, now_ms: i64) -> Result<usize, GatewayError> {
    let horizon = now_ms - super::GRANT_USAGE_DETAIL_MS;
    let tx = conn.unchecked_transaction().map_err(map_sql)?;
    let folded = tx
        .execute(
            "INSERT INTO grant_usage (grant_id, agent_id, period_start, count)
             SELECT grant_id, agent_id, 0, sum(count) FROM grant_usage
             WHERE period_start > 0 AND period_start < ?1
             GROUP BY grant_id, agent_id
             ON CONFLICT(grant_id, agent_id, period_start) DO UPDATE SET count = count + excluded.count",
            [horizon],
        )
        .map_err(map_sql)?;
    tx.execute("DELETE FROM grant_usage WHERE period_start > 0 AND period_start < ?1", [horizon])
        .map_err(map_sql)?;
    tx.commit().map_err(map_sql)?;
    Ok(folded)
}

/// Both budget tiers for `windows`, summed out of the counter table.
fn read_grant_usage_rows(
    conn: &Connection,
    windows: &[super::GrantWindow<'_>],
) -> Result<super::GrantUsageCounts, GatewayError> {
    let mut counts = super::GrantUsageCounts::default();
    if windows.is_empty() {
        return Ok(counts);
    }
    let mut stmt = conn
        .prepare_cached(
            "SELECT agent_id, sum(count) FROM grant_usage
             WHERE grant_id = ?1 AND period_start >= ?2 GROUP BY agent_id",
        )
        .map_err(map_sql)?;
    for window in windows {
        let rows = stmt
            .query_map(rusqlite::params![window.grant_id, window.since_ms], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(map_sql)?;
        for row in rows {
            let (agent_id, count) = row.map_err(map_sql)?;
            counts.add(window.grant_id, &agent_id, count);
        }
    }
    Ok(counts)
}

/// How many audit events [`Store::verify_audit`] copies out per hold of the lock: a few milliseconds of copying, and well under a second of checking.
const AUDIT_VERIFY_CHUNK: usize = 1024;

/// A SQLite-backed store. The single connection is mutex-guarded; the audit log lives
/// alongside it so appends update both the in-memory chain and the mirror table atomically under the same lock.
pub struct SqliteStore {
    inner: Mutex<Inner>,
    /// Held for the whole of a [`SqliteStore::transaction`]: the connection is shared, so a statement
    /// from another thread would otherwise land inside the open savepoint and be undone with it.
    serial: Mutex<()>,
    /// The thread inside a transaction and how deeply nested it is, so its own calls pass `serial`
    /// rather than deadlocking on it.
    owner: Mutex<Option<(ThreadId, u32)>>,
    custody: CustodyDescription,
    /// How the audit signing key is held, resolved at open. Stamped on every upload so a reader that
    /// may not open the database still knows which key material the snapshot depends on.
    audit_key: AuditKeyStamp,
    /// The database file, or `None` for `:memory:`. Needed by [`SqliteStore::snapshot_to`]'s caller
    /// to place the snapshot beside it, and by [`SqliteStore::size_bytes`].
    path: Option<String>,
    /// How many audit events [`Store::verify_audit`] has checked over this store's life.
    audit_checked: std::sync::atomic::AtomicU64,
    /// Why this store can no longer append its audit log, once another writer took a seq it holds in memory.
    collided: Mutex<Option<String>>,
    /// What happens on that collision beyond the refusal and the degraded note: `permaura start` exits,
    /// so a restart reloads the chain from the table.
    on_collision: Box<dyn Fn(&str) + Send + Sync>,
    /// The cross-process lock a self-run store is held by. Last, so it is released only after the
    /// connection above has closed.
    lock: Option<super::lock::StoreLock>,
}

/// What a snapshot's own bytes say about themselves, read under the lock that produced them.
///
/// Every field here is something a reader would otherwise have to open the database to learn, and
/// the checkpoint job is not allowed to open one. Taken together with the bytes it describes, this
/// is the durability contract: if the two can disagree, a manifest built from it is worthless.
#[derive(Debug, Clone)]
pub struct SnapshotStamp {
    /// `PRAGMA user_version` of the snapshot.
    pub schema_version: i32,
    /// The audit epoch, bumped only by a restore fork.
    pub epoch: u64,
    /// The absolute seq of the oldest event the snapshot holds.
    pub base_seq: u64,
    /// The hash that event links back to.
    pub base_hash: String,
    /// The absolute seq of the chain head, or `None` when the chain is empty. A store that has
    /// archived everything it holds still has a head: the event just below the base.
    pub head_seq: Option<u64>,
    /// The chain head's hash, on the same terms.
    pub head_hash: Option<String>,
    /// The newest durably published archive segment, once there is an archive.
    pub segment_head: Option<String>,
    /// How the audit signing key is held.
    pub audit_key: AuditKeyStamp,
    /// The stored approval-floor override, verbatim (`approve` / `device_signed`), or `None` when
    /// no row has been written.
    ///
    /// The **stored** override rather than the effective floor, which is what
    /// [`crate::service::EnforcementService::approval_floor`] answers. The effective floor also
    /// depends on `PERMAURA_REQUIRE_DEVICE_SIGNED_APPROVAL`, which is a property of the deployment
    /// and not of these bytes, and a restore takes `max(restored, retained)` over exactly this row.
    /// Stamping the effective value would make the maximum compare a deployment setting against a
    /// database fact.
    pub approval_floor: Option<String>,
    /// The stored replay floor in unix milliseconds, or `None` when no row has been written, which
    /// is every gateway that has never been restored.
    pub replay_floor_ms: Option<i64>,
}

struct Inner {
    conn: Connection,
    audit: AuditLog,
    /// The boundary as it stands on disk. `audit`'s base is read out of it at open, and the archive
    /// writer will re-sign it in the same transaction as a prune.
    boundary: AuditBoundary,
    /// When the grant-usage fold last ran in this process. Zero means never, so a worker that has
    /// just cold-started folds on its first charge, which is the case that matters, because the
    /// rows it folds are the ones the instance before it left behind.
    grant_usage_compacted_ms: i64,
    /// The recorded rekey `audit` honors, read at open.
    rekey: Option<AuditRekey>,
}

fn map_sql<E: std::fmt::Display>(e: E) -> GatewayError {
    GatewayError::Internal(format!("sqlite error: {e}"))
}

/// Whether `e` is a row refused because its primary key is taken, and nothing else: a trigger's abort or
/// a full disk is not a second writer.
fn is_primary_key_collision(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
}

/// An enrolment code written over one already there would revive it as unused, so the write is refused.
fn enrolment_code_collision(e: rusqlite::Error) -> GatewayError {
    if is_primary_key_collision(&e) {
        GatewayError::Conflict("the new enrolment code collided with one already issued; mint another".into())
    } else {
        map_sql(e)
    }
}

/// What an append refused because another writer recorded its seq says. The event is refused, never
/// written over, and the chain in memory stays where the rows are.
fn audit_collision_message(seq: u64) -> String {
    format!(
        "audit event seq {seq} is already recorded in this store by another writer: refusing to write over it. Another process (a gateway from before the store lock, or a hand edit) is writing this store, and this gateway can no longer append its audit log; stop the other writer, then restart this gateway"
    )
}

/// Narrow a store file to owner-only, best effort, on whichever mechanism the platform has.
///
/// Best effort on purpose: a store on a filesystem that cannot express this (an SMB or FAT mount)
/// would otherwise make the gateway refuse to start somewhere it is no less safe than it was.
///
/// Two mechanisms, because the exposure is the same and the expression is not. On Unix the case is the
/// default umask handing out `0644`. On Windows a new file inherits the parent directory's ACL, which
/// under a default profile is usually already owner-only and under a `PERMAURA_HOME` on a data volume
/// or a share is not; the DACL states it instead of hoping for it. A WAL-mode database keeps two
/// sidecars with the same content exposure, so they get the same treatment, and so do the
/// pre-migration backups, each of which is a whole second copy of the sealed store.
pub(super) fn restrict_to_owner(path: &str) {
    let p = std::path::Path::new(path);
    if !p.exists() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(error = %e, path, "could not restrict the store to owner-only");
            return;
        }
    }
    if let Err(e) = permaura_credential_store::restrict_to_owner(p) {
        tracing::warn!(error = %e, path, "could not restrict the store to owner-only");
    }
}

/// Create the store's directory: `Connection::open` won't create missing dirs, and the default path
/// (`~/.permaura/gateway.db`) lives in a dir that may not exist on first run.
fn create_parent_dir(path: &str) -> Result<(), GatewayError> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| GatewayError::Internal(format!("store dir {}: {e}", parent.display())))?;
        }
    }
    Ok(())
}

/// Tighten every pre-migration copy sitting beside the store.
///
/// Migrations write `{store}.backup-v{n}` and, from now on, write it `0600`. The copies already on
/// disk were made before that and are `0644`: a whole second store each, holding the same sealed
/// credentials, the same KDF salt and the same audit chain as the file that was just tightened. Nothing
/// else ever revisits them, so boot is the only place this gets fixed for an existing install.
fn restrict_backups_to_owner(path: &str) {
    let p = std::path::Path::new(path);
    let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let prefix = format!("{name}.backup-v");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_str().is_some_and(|n| n.starts_with(&prefix)) {
            restrict_to_owner(&entry.path().to_string_lossy());
        }
    }
}

/// Say so when the Permaura home is readable by anyone but its owner.
///
/// A warning and not a repair. The files inside are narrowed on every open, but the directory itself
/// is one an operator may have chosen and may share deliberately, and silently changing the
/// permissions of a directory the gateway did not create would take whatever else lives there with it.
/// A home this call created is already `0700`; `permaura_core`'s secret writers see to that.
///
/// Group and world bits only. Owner bits vary legitimately, and a home with no execute bit for its
/// owner would have failed long before this line.
#[cfg(unix)]
fn warn_if_home_is_wide() {
    use std::os::unix::fs::PermissionsExt;
    let Some(home) = permaura_core::permaura_home() else {
        return;
    };
    let Ok(meta) = std::fs::metadata(&home) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if home_is_wider_than_owner_only(mode) {
        tracing::warn!(
            home = %home.display(),
            mode = format!("{:04o}", mode),
            "the Permaura home is readable or writable by accounts other than its owner; chmod 700 it"
        );
    }
}

/// The rule on its own, so it is testable without a filesystem: any group or other bit is too wide.
#[cfg(unix)]
fn home_is_wider_than_owner_only(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// The directory's ACL is not a mode, and the files inside it now carry their own protected DACLs, so
/// there is no equivalent number to compare against here.
#[cfg(not(unix))]
fn warn_if_home_is_wide() {}

impl SqliteStore {
    /// Open (or create) a SQLite store at `path`. Use `":memory:"` for an ephemeral DB.
    ///
    /// For a real file path the audit chain is made durable: its ed25519 signing key is persisted
    /// in a `0600` sidecar (`{path}.auditkey`) and the stored events are replayed on open, so across
    /// restarts the chain continues from the right head/seq and the whole history still verifies
    /// under one key. (`:memory:` is ephemeral by definition: a fresh key, no sidecar.)
    ///
    /// The store is held for as long as the returned value lives (see [`super::lock`]), and an open
    /// while another process or handle holds it waits [`super::lock::BRIEF_WAIT`], then is refused.
    /// [`Self::open_waiting`] waits as long as it is told.
    pub fn open(path: &str) -> Result<Self, GatewayError> {
        Self::open_waiting(path, super::lock::BRIEF_WAIT)
    }

    /// [`Store::put_approval`], or with `insert_only` [`Store::insert_approval`]: a new row is a plain INSERT, an
    /// existing one is updated only over the row as read, and a settled status never changes.
    fn write_approval(&self, mut approval: PendingApproval, insert_only: bool) -> Result<(), GatewayError> {
        super::bound_stored_result(&mut approval);
        let data = super::row_text(&approval).map_err(map_sql)?;
        let pending = approval.status == "pending";
        let status = std::mem::take(&mut approval.status);
        let id = std::mem::take(&mut approval.id);
        // From here the row is its text, so its result is not held a second time while SQLite copies the text in.
        drop(approval);
        let inner = self.lock()?;
        // The stored status, `Some(None)` for a row whose status cannot be read.
        let stored: Option<Option<String>> = inner
            .conn
            .query_row(
                "SELECT CASE WHEN json_valid(data) THEN json_extract(data, '$.status') END FROM approvals WHERE id = ?1",
                [&id],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(map_sql)?;
        if let Some(Some(from)) = &stored {
            super::refuse_settled_approval_rewrite(&id, from, &status)?;
        }
        if insert_only && stored.is_some() {
            return Err(GatewayError::Conflict(format!(
                "an approval with id '{id}' already exists, and a new hold never writes over one"
            )));
        }
        // The cap the in-memory store has always had, now on the store that actually ships. Two
        // conditions, and both matter. Only a row that is not already here counts, so resolving,
        // denying or re-writing a hold works at the ceiling, which is the only way the queue ever
        // comes down. And only a pending row counts, so a resolved one (a cached result) never
        // stands between an operator and a new hold.
        //
        // The count is a SQL count rather than a listing: a hold carries the agent's whole `params`,
        // so deserializing every row to count them would make the check cost more than the write.
        if pending && stored.is_none() {
            let pending: i64 = inner
                .conn
                .query_row(
                    "SELECT count(*) FROM approvals WHERE json_valid(data) AND json_extract(data, '$.status') = 'pending'",
                    [],
                    |r| r.get(0),
                )
                .map_err(map_sql)?;
            if pending as usize >= super::MAX_PENDING_APPROVALS {
                // Before the INSERT, and before anything else this call would do: on a hosted
                // worker the write is a full snapshot upload, so a refusal that wrote would make
                // refusing a flood more expensive than serving it.
                return Err(super::too_many_pending_approvals(pending as usize));
            }
        }
        match &stored {
            None => inner
                .conn
                .execute("INSERT INTO approvals (id, data) VALUES (?1, ?2)", rusqlite::params![id, data])
                .map(|_| ())
                .map_err(|e| {
                    if is_primary_key_collision(&e) {
                        GatewayError::Conflict(format!("an approval with id '{id}' was written by another writer as this one was"))
                    } else {
                        map_sql(e)
                    }
                })?,
            Some(read) => {
                // Only while the stored status is still the one just read, so another writer's change of status in between is refused rather than replaced. The rule is about status alone: every other field is this write's.
                let changed = inner
                    .conn
                    .execute(
                        "UPDATE approvals SET data = ?2 WHERE id = ?1 \
                         AND (CASE WHEN json_valid(data) THEN json_extract(data, '$.status') END) IS ?3",
                        rusqlite::params![id, data, read],
                    )
                    .map_err(map_sql)?;
                if changed == 0 {
                    return Err(GatewayError::Conflict(format!(
                        "approval '{id}' changed while it was being written; read it again"
                    )));
                }
            }
        }
        Ok(())
    }

    /// What to do, beyond refusing the append and reporting the store degraded, when another writer has
    /// recorded a seq this store holds in memory.
    pub fn with_on_collision(mut self, on_collision: Box<dyn Fn(&str) + Send + Sync>) -> Self {
        self.on_collision = on_collision;
        self
    }

    /// Give a store whose audit key is gone a new one, loudly: the explicit repair the refusal in
    /// [`load_or_create_audit_key`] names, for an owner who cannot restore `{path}.auditkey`.
    ///
    /// Refused while anything holds the store, while the key file is there, and for a store with
    /// nothing signed in it. Otherwise it mints a new key into `{path}.auditkey`, re-signs the boundary
    /// under it, and appends one [`AUDIT_REKEY_ACTION`] event under it that names the old chain's head
    /// (seq and hash), with a signed [`AuditRekey`] record beside it. Every event below the rekey keeps
    /// its hash and its link but can never have its signature checked again, and verification says so
    /// rather than reporting a break. A store that has archived events starts a new archive epoch, so
    /// archiving carries on under the new key; the history the old key signed stays where it was.
    pub fn rekey(path: &str, now: i64) -> Result<(Self, permaura_core::AuditEvent), GatewayError> {
        if path == ":memory:" || !std::path::Path::new(path).exists() {
            return Err(GatewayError::BadRequest(format!("there is no store at {path} to rekey")));
        }
        let lock = super::lock::StoreLock::acquire(path, super::lock::BRIEF_WAIT)?;
        let key_path = format!("{path}.auditkey");
        if std::path::Path::new(&key_path).exists() {
            return Err(GatewayError::Conflict(format!(
                "{key_path} is there, so this store has a key and nothing to rekey. If it is the wrong key and the right one is gone too, move it aside first"
            )));
        }
        let conn = Connection::open(path).map_err(map_sql)?;
        super::migrations::run(&conn, Some(path))?;
        let Some(history) = recorded_audit_history(&conn)? else {
            return Err(GatewayError::Conflict(format!(
                "{path} has nothing signed in it, so it gets a new key on its next start and needs no rekey"
            )));
        };
        // Read as stored and not verified: the key that signed the boundary is the one that is gone.
        let boundary = conn
            .query_row("SELECT value FROM gateway_meta WHERE key = ?1", [AUDIT_BOUNDARY_META], |r| r.get::<_, String>(0))
            .optional()
            .map_err(map_sql)?
            .map(|raw| serde_json::from_str::<AuditBoundary>(&raw))
            .transpose()
            .map_err(|e| GatewayError::Internal(format!("the audit boundary row is not readable ({e}): refusing to rekey a chain whose start is unknown")))?
            .unwrap_or_else(AuditBoundary::genesis);
        let events = load_audit_events(&conn, boundary.base_seq)?;
        let seq = boundary.base_seq + events.len() as u64;
        let prior_head_hash = events.last().map_or_else(|| boundary.base_hash.clone(), |e| e.hash.clone());

        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        permaura_core::write_secret_file(std::path::Path::new(&key_path), &key.to_bytes())
            .map_err(|e| GatewayError::Internal(format!("write audit key: {e}")))?;
        permaura_credential_store::restrict_to_owner(std::path::Path::new(&key_path))
            .map_err(|e| GatewayError::Internal(format!("restrict audit key: {e}")))?;
        let archived = !boundary.is_genesis();
        let tx = conn.unchecked_transaction().map_err(map_sql)?;
        if archived {
            let resigned = AuditBoundary::create_in_lineage(
                &key,
                boundary.epoch,
                boundary.base_seq,
                boundary.base_hash.clone(),
                boundary.segment_head.clone(),
                boundary.lineage.clone(),
                now,
            );
            tx.execute(
                "INSERT OR REPLACE INTO gateway_meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![AUDIT_BOUNDARY_META, serde_json::to_string(&resigned).map_err(map_sql)?],
            )
            .map_err(map_sql)?;
        }
        tx.commit().map_err(map_sql)?;
        drop(conn);
        let rekey = AuditRekey::create(&key, seq, prior_head_hash.clone(), now);

        let mut store = Self::open_with(path, KeyCustody::Sidecar)?;
        store.lock = Some(lock);
        // A new epoch for the archive, so the next pass publishes under the new key rather than over pages the old one signed.
        let epoch = if archived {
            store.fork_audit_epoch(boundary.epoch + 1, &format!("rekey-{now}"))?;
            Some(boundary.epoch + 1)
        } else {
            None
        };
        let mut payload = AuditPayload::new(AUDIT_REKEY_ACTION, "audit-key", "allow");
        payload.summary = serde_json::json!({
            "prior_head_seq": seq.checked_sub(1),
            "prior_head_hash": prior_head_hash,
            "held_under_lost_key": history,
            "key_fingerprint": crate::audit_key::fingerprint(&key.verifying_key().to_bytes()),
            "archive_epoch": epoch,
            "method": "permaura audit rekey",
        });
        let event = store.append_audit(payload)?;
        if !rekey.recorded_by(&event) {
            return Err(GatewayError::Internal(format!(
                "the rekey event landed at seq {} rather than {seq}: the store moved while it was being rekeyed",
                event.seq
            )));
        }
        {
            let mut inner = store.lock()?;
            // Kept for when the event has been archived out of the hot window: until then the event is the proof.
            if let Err(e) = inner.conn.execute(
                "INSERT OR REPLACE INTO gateway_meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![AUDIT_REKEY_META, serde_json::to_string(&rekey).map_err(map_sql)?],
            ) {
                tracing::error!(error = %e, "the rekey is recorded in the chain, but its signed record could not be kept beside it; the fork is honored while its event is in the hot window");
            }
            inner.audit.honor_rekey(&rekey);
            inner.rekey = Some(rekey);
        }
        Ok((store, event))
    }

    /// [`Self::open`], waiting up to `wait` for a holder to let the store go: the open `permaura start`
    /// makes, so a gateway started while its predecessor drains comes up once the predecessor has
    /// exited rather than beside it.
    pub fn open_waiting(path: &str, wait: std::time::Duration) -> Result<Self, GatewayError> {
        if path == ":memory:" {
            return Self::open_with(path, KeyCustody::Sidecar);
        }
        create_parent_dir(path)?;
        let lock = super::lock::StoreLock::acquire(path, wait)?;
        let mut store = Self::open_with(path, KeyCustody::Sidecar)?;
        store.lock = Some(lock);
        Ok(store)
    }

    /// Open a store that keeps its audit signing key in a `gateway_meta` row instead of a sidecar,
    /// KMS-wrapped when `wrap` is `Some`: the shape a stateless worker needs, where the database
    /// file is the only thing that survives a restart and a sidecar would silently fork the chain
    /// onto a fresh key at every cold start.
    ///
    /// `{path}.auditkey` is never read or written in this mode, even when one is lying beside the
    /// database from an earlier local run.
    pub fn open_with_custody(path: &str, wrap: Option<AuditKeyWrap>) -> Result<Self, GatewayError> {
        Self::open_with(path, KeyCustody::Meta(wrap))
    }

    fn open_with(path: &str, custody: KeyCustody) -> Result<Self, GatewayError> {
        if path != ":memory:" {
            create_parent_dir(path)?;
        }
        let conn = Connection::open(path).map_err(map_sql)?;
        // Owner-only, every open (not just at create). The sidecars beside it (`.auditkey`, the vault
        // KEK, the operator token) have always been 0600, but the store itself inherited the process
        // umask and landed 0644 on a default macOS install: world-readable. It holds every sealed
        // credential, so anyone else on the machine could take a copy and keep it against the day they
        // get the KEK. Re-applied on open rather than only on create, because the stores already on
        // disk were made under the old behaviour and nothing else would ever come back for them.
        if path != ":memory:" {
            restrict_to_owner(path);
            restrict_to_owner(&format!("{path}-wal"));
            restrict_to_owner(&format!("{path}-shm"));
            restrict_backups_to_owner(path);
            warn_if_home_is_wide();
        }
        let db_path = (path != ":memory:").then_some(path);
        Self::init(conn, custody, db_path)
    }

    /// Open an in-memory SQLite database (handy for tests of the sqlite path).
    pub fn open_in_memory() -> Result<Self, GatewayError> {
        let conn = Connection::open_in_memory().map_err(map_sql)?;
        Self::init(conn, KeyCustody::Sidecar, None)
    }

    fn init(conn: Connection, custody: KeyCustody, db_path: Option<&str>) -> Result<Self, GatewayError> {
        // Schema creation/upgrade lives in the versioned migration runner: it gates on
        // PRAGMA user_version, backs the file up, and fails closed on a newer-than-us DB.
        super::migrations::run(&conn, db_path)?;
        reseal_dev_sealed_secrets(&conn, crate::service::vault_passphrase())?;
        // The key has to be resolved after the migration, because the `gateway_meta` custody keeps it
        // in a table the migration creates.
        let sidecar_stamp = AuditKeyStamp { wrap: "file:v1", version: None };
        let (signing_key, custody, audit_key) = match (custody, db_path) {
            (_, None) => (None, FileCustody::DESCRIPTION, sidecar_stamp),
            (KeyCustody::Sidecar, Some(p)) => {
                let history = recorded_audit_history(&conn)?;
                (
                    Some((load_or_create_audit_key(&format!("{p}.auditkey"), history.as_deref())?, false)),
                    FileCustody::DESCRIPTION,
                    sidecar_stamp,
                )
            }
            (KeyCustody::Meta(wrap), Some(_)) => {
                let hosted = wrap.is_some();
                let (key, description, stamp) = load_or_create_meta_audit_key(&conn, wrap.as_ref())?;
                // Said on every boot: "is this worker's audit key actually sealed?" is the question
                // the custody summary exists to answer, and a custody claim nobody states is a custody claim nobody
                // can check.
                tracing::info!(
                    backend = description.backend,
                    separated_from_records = description.separated_from_records,
                    "audit key custody: {}",
                    description.summary
                );
                (Some((key, hosted)), description, stamp)
            }
        };
        // Rehydrate the hash-chained audit log from the persisted key + rows; without this a reopen
        // would restart the chain at genesis under a new key and collide with seq 0.
        // The boundary is read first, and under the key, because it is what says which rows are the
        // window and what the oldest of them links back to.
        let (audit, boundary, rekey) = match signing_key {
            Some((key, hosted)) => {
                let boundary = load_audit_boundary(&conn, &key.verifying_key())?;
                let events = load_audit_events(&conn, boundary.base_seq)?;
                if hosted {
                    anchor_audit_head(&key, boundary.base_seq, &events);
                }
                let mut log = AuditLog::restore_from(
                    key,
                    boundary.base_seq,
                    boundary.base_hash.clone(),
                    events,
                );
                let rekey = load_audit_rekey(&conn, &log)?;
                if let Some(rekey) = &rekey {
                    log.honor_rekey(rekey);
                }
                (log, boundary, rekey)
            }
            // No persisted key, so no persisted chain either: an ephemeral log at genesis, and a
            // boundary that says so.
            None => (AuditLog::new(), AuditBoundary::genesis(), None),
        };
        Ok(SqliteStore {
            inner: Mutex::new(Inner { conn, audit, boundary, grant_usage_compacted_ms: 0, rekey }),
            serial: Mutex::new(()),
            owner: Mutex::new(None),
            custody,
            audit_key,
            path: db_path.map(str::to_string),
            audit_checked: std::sync::atomic::AtomicU64::new(0),
            collided: Mutex::new(None),
            on_collision: Box::new(|_| {}),
            lock: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn audit_events_checked(&self) -> u64 {
        self.audit_checked.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// What this store's audit signing key custody actually guarantees: reportable, never optimistic.
    pub fn audit_custody(&self) -> CustodyDescription {
        self.custody
    }


    /// Write a consistent, standalone copy of the database to `out`, and describe it.
    ///
    /// `VACUUM INTO` rather than a file copy: it takes SQLite's own read lock, folds the WAL in, and
    /// produces a single file with no sidecars, which is what makes the result safe to upload while
    /// the store is live. It cannot run inside a transaction, and this store never holds one across
    /// calls.
    ///
    /// The description is taken under the same held lock as the copy, and that is the point of
    /// returning it from here rather than letting the caller ask afterwards. Another thread commits
    /// and appends without holding the caller's lock, so a stamp read a moment later would describe
    /// a chain head the uploaded bytes do not contain, and every reader downstream would be
    /// comparing one snapshot's metadata against another snapshot's contents.
    pub fn snapshot_to(&self, out: &std::path::Path) -> Result<SnapshotStamp, GatewayError> {
        // VACUUM INTO refuses to overwrite, so an interrupted snapshot must not strand its target.
        let _ = std::fs::remove_file(out);
        let g = self.lock()?;
        g.conn
            .execute("VACUUM INTO ?1", [out.to_string_lossy().as_ref()])
            .map_err(map_sql)?;
        let schema_version = super::migrations::user_version(&g.conn)?;
        let (head_seq, head_hash) = match g.audit.events().last() {
            Some(event) => (Some(event.seq), Some(event.hash.clone())),
            // Everything held has been archived, so the head is the event just below the base. Only
            // a chain with nothing in it at all answers "none".
            None if g.boundary.base_seq > 0 => {
                (Some(g.boundary.base_seq - 1), Some(g.boundary.base_hash.clone()))
            }
            None => (None, None),
        };
        // Both floors are read under the lock that produced the copy, for the same reason the chain
        // head is: a floor read after the `VACUUM INTO` could be one a concurrent mutation raised,
        // and the stamp would then describe a database the uploaded bytes are not.
        let meta_row = |key: &str| -> Result<Option<String>, GatewayError> {
            match g.conn.query_row(
                "SELECT value FROM gateway_meta WHERE key = ?1",
                [key],
                |r| r.get::<_, String>(0),
            ) {
                Ok(value) if value.trim().is_empty() => Ok(None),
                Ok(value) => Ok(Some(value)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(map_sql(e)),
            }
        };
        let approval_floor = meta_row(super::APPROVAL_FLOOR_META)?;
        let replay_floor_ms = meta_row(super::REPLAY_FLOOR_META)?
            .and_then(|raw| raw.trim().parse::<i64>().ok());
        let stamp = SnapshotStamp {
            schema_version,
            epoch: g.boundary.epoch,
            base_seq: g.boundary.base_seq,
            base_hash: g.boundary.base_hash.clone(),
            head_seq,
            head_hash,
            segment_head: g.boundary.segment_head.clone(),
            audit_key: self.audit_key.clone(),
            approval_floor,
            replay_floor_ms,
        };
        drop(g);
        restrict_to_owner(&out.to_string_lossy());
        Ok(stamp)
    }

    /// How many rows this connection has inserted, updated or deleted since it was opened.
    ///
    /// SQLite's own counter, and monotonic, so comparing it either side of a call answers "did that
    /// actually change anything" without the store having to guess. The persisted store gates its
    /// uploads on it: a mutating method that changed no row leaves the database byte-identical, and
    /// re-uploading it costs a full-size PUT and a round-trip for nothing.
    pub fn change_count(&self) -> Result<u64, GatewayError> {
        Ok(self.lock()?.conn.total_changes())
    }

    /// The database file's size on disk, or `None` for `:memory:` and for a path that cannot be
    /// stat'd. Feeds the persisted store's size guard.
    pub fn size_bytes(&self) -> Option<u64> {
        let path = self.path.as_ref()?;
        std::fs::metadata(path).ok().map(|m| m.len())
    }

    fn lock(&self) -> Result<Locked<'_>, GatewayError> {
        let serial = if self.owns_transaction() {
            None
        } else {
            Some(self.wait_for_serial())
        };
        let inner = self
            .inner
            .lock()
            .map_err(|_| GatewayError::Internal("sqlite lock poisoned".into()))?;
        Ok(Locked { inner, _serial: serial })
    }

    pub(super) fn owns_transaction(&self) -> bool {
        let owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
        matches!(*owner, Some((t, _)) if t == std::thread::current().id())
    }

    /// Take `serial`, giving this runtime worker back first if another thread holds it: the holder can be waiting on a request only a runtime worker can answer, and on one vCPU a parked waiter leaves nothing to answer it.
    fn wait_for_serial(&self) -> MutexGuard<'_, ()> {
        super::bridge::lock_donating(&self.serial).unwrap_or_else(|p| p.into_inner())
    }

    fn set_owner(&self, value: Option<(ThreadId, u32)>) {
        *self.owner.lock().unwrap_or_else(|p| p.into_inner()) = value;
    }

    /// Run `f` as one SQLite transaction: every write inside it lands together or not at all, and
    /// every other thread's call waits until it has ended. Nests as savepoints. `f` must not append
    /// to the audit log, whose in-memory chain cannot be rolled back; `append_audit` refuses inside.
    pub fn transaction<T>(&self, f: impl FnOnce() -> Result<T, GatewayError>) -> Result<T, GatewayError> {
        let me = std::thread::current().id();
        let nested = self.owns_transaction();
        let _serial = if nested {
            None
        } else {
            Some(self.wait_for_serial())
        };
        let depth = {
            let owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
            owner.map(|(_, d)| d).unwrap_or(0) + 1
        };
        self.set_owner(Some((me, depth)));
        let name = format!("store_tx_{depth}");
        let restore_owner = |store: &SqliteStore| {
            store.set_owner(if depth > 1 { Some((me, depth - 1)) } else { None });
        };
        if let Err(e) = self.lock().and_then(|g| g.conn.execute_batch(&format!("SAVEPOINT {name}")).map_err(map_sql)) {
            restore_owner(self);
            return Err(e);
        }
        // A panic inside `f` must not leave the connection inside an open savepoint, where every later
        // write from every thread would sit uncommitted for ever.
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let end = match &out {
            Ok(Ok(_)) => format!("RELEASE {name}"),
            _ => format!("ROLLBACK TO {name}; RELEASE {name}"),
        };
        let ended = self.lock().and_then(|g| g.conn.execute_batch(&end).map_err(map_sql));
        restore_owner(self);
        match out {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(out) => {
                ended?;
                out
            }
        }
    }
}

impl SqliteStore {
    /// The read half of [`Store::rebuild_grant_usage`]: the hot window counted in one short hold of the lock, then `archived` walked and counted with it released.
    ///
    /// Walking the archive fetches and checks every segment of the tenant's history, minutes of work at a million events, and every other request on the store, `/health`'s liveness touch included, waits for whoever holds `serial`.
    pub(crate) fn walk_grant_usage(
        &self,
        archived: &mut dyn Iterator<Item = Result<AuditEvent, GatewayError>>,
    ) -> Result<WalkedUsage, GatewayError> {
        let horizon = super::now_ms() - super::GRANT_USAGE_DETAIL_MS;
        let mut tally = UsageTally::default();
        let (base_seq, base_hash, next_seq, head_hash) = {
            let inner = self.lock()?;
            for event in inner.audit.events() {
                tally.charge(event, horizon);
            }
            (inner.boundary.base_seq, inner.boundary.base_hash.clone(), inner.audit.next_seq(), inner.audit.head_hash())
        };
        // The archive is the part of the chain this store can no longer check event by event, so
        // what it can check is that the events it was handed are exactly seq 0 up to the base of the
        // window it just counted, each linking to the one before, and ending on the hash that base
        // names. A hole is an undercharged grant and an overlap a double-charged one, and both would
        // be silent.
        let mut expected_seq = 0u64;
        let mut expected_hash = permaura_core::GENESIS_PREV_HASH.to_string();
        for event in archived {
            let event = event?;
            if event.seq != expected_seq || event.prev_hash != expected_hash {
                return Err(GatewayError::Internal(format!(
                    "the archived history handed to the rebuild has seq {} where seq {expected_seq} belongs: refusing to rebuild a budget from a history with a hole or an overlap in it",
                    event.seq
                )));
            }
            if event.seq >= base_seq {
                return Err(GatewayError::Internal(format!(
                    "archived event {} is at or above this store's base seq {base_seq}, so it is also in the hot window: refusing to charge it twice",
                    event.seq
                )));
            }
            expected_seq = event.seq + 1;
            expected_hash = event.hash.clone();
            tally.charge(&event, horizon);
        }
        if expected_seq != base_seq || expected_hash != base_hash {
            return Err(GatewayError::Internal(format!(
                "the archived history handed to the rebuild ends before seq {expected_seq} and this store's hot window starts at seq {base_seq}: refusing to rebuild a budget without the events in between, and leaving the counter as it was"
            )));
        }
        Ok(WalkedUsage { tally, next_seq, head_hash })
    }

    /// The write half: clear the counter and file what [`SqliteStore::walk_grant_usage`] counted, plus every charge appended since it read the hot window, in one transaction.
    ///
    /// Refused, with the counter left as it was, unless the window still continues from what the walk read. A prune that landed during the walk is absorbed while it stopped inside the events the walk counted from the window; one that went past them archived events neither half of the walk read.
    pub(crate) fn apply_grant_usage(&self, walked: WalkedUsage) -> Result<u64, GatewayError> {
        let WalkedUsage { tally, next_seq, head_hash } = walked;
        let inner = self.lock()?;
        let base = inner.audit.base_seq();
        let held = inner.audit.events();
        let Some(counted) = next_seq.checked_sub(base) else {
            return Err(GatewayError::Internal(format!(
                "an archive pass moved this store's base to seq {base} while the usage rebuild read the archive, past seq {next_seq} where its count of the hot window ended: the events in between were counted by neither half, so the counter is left as it was and the rebuild can be run again"
            )));
        };
        let continues = match counted {
            0 => inner.audit.base_hash() == head_hash,
            n => held.get(n as usize - 1).is_some_and(|e| e.hash == head_hash),
        };
        if !continues {
            return Err(GatewayError::Internal(format!(
                "the hot window no longer continues from the chain the usage rebuild counted up to seq {next_seq}: refusing to file a count of history this store no longer holds, and leaving the counter as it was"
            )));
        }
        let tx = inner.conn.unchecked_transaction().map_err(map_sql)?;
        tx.execute("DELETE FROM grant_usage", []).map_err(map_sql)?;
        tally.file(&tx)?;
        let mut filed = tally.filed;
        for event in &held[counted as usize..] {
            let Some(grant_id) = super::charged_grant(event) else { continue };
            file_grant_charge(&tx, grant_id, super::charge_agent(&event.payload), event.timestamp)?;
            filed += 1;
        }
        tx.commit().map_err(map_sql)?;
        // Outside the rebuild's own transaction: the fold is housekeeping and its failure must not
        // undo a counter that is now correct.
        if let Err(e) = compact_grant_usage(&inner.conn, super::now_ms()) {
            tracing::warn!(error = %e, "rebuilt the grant usage counter but could not fold it");
        }
        Ok(filed)
    }
}

/// The store's connection, with any transaction on another thread waited out first.
struct Locked<'a> {
    inner: MutexGuard<'a, Inner>,
    _serial: Option<MutexGuard<'a, ()>>,
}

impl std::ops::Deref for Locked<'_> {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.inner
    }
}

impl std::ops::DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }
}

/// Re-seal anything still under the public dev KEK. Runs on every open. See [`super::reseal`] for
/// why this is deliberately not a stamped one-shot migration.
/// How many credentials in the store at `path` are sealed under a real vault KEK, read without opening
/// the store for writing and without resolving a KEK.
///
/// What [`crate::service::vault_passphrase`] asks before it mints a fresh per-install KEK: a non-zero
/// answer is a vault the fresh key could never open. Credentials under the dev constant are not
/// counted, because the re-seal sweep moves them to whatever key is resolved, which is how an install
/// that predates the per-install KEK upgrades. No store, or a store with no secrets table, is zero.
pub(crate) fn credentials_sealed_under_a_real_kek(path: &str) -> Result<usize, GatewayError> {
    use super::reseal;
    if path == ":memory:" || !std::path::Path::new(path).exists() {
        return Ok(0);
    }
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(map_sql)?;
    let has_table: bool = conn
        .query_row("SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'secrets')", [], |r| r.get(0))
        .map_err(map_sql)?;
    if !has_table {
        return Ok(0);
    }
    let mut stmt = conn.prepare("SELECT data FROM secrets").map_err(map_sql)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(map_sql)?;
    let mut sealed = 0usize;
    for data in rows {
        if !reseal::opens_under_dev(&data.map_err(map_sql)?) {
            sealed += 1;
        }
    }
    Ok(sealed)
}

fn reseal_dev_sealed_secrets(conn: &Connection, real_kek: &[u8]) -> Result<usize, GatewayError> {
    use super::reseal;
    if !reseal::is_worth_running(real_kek) {
        return Ok(0);
    }
    let rows: Vec<(String, String)> = {
        let mut stmt = conn.prepare("SELECT id, data FROM secrets").map_err(map_sql)?;
        let mapped = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(map_sql)?;
        mapped.collect::<rusqlite::Result<Vec<_>>>().map_err(map_sql)?
    };

    // One transaction for the whole sweep: a partial re-seal that left some rows under the old KEK
    // and some under the new one would be indistinguishable from the state we are here to repair.
    let tx = conn.unchecked_transaction().map_err(map_sql)?;
    let mut count = 0usize;
    for (id, data) in rows {
        if let Some(updated) = reseal::reseal_blob(&data, real_kek)? {
            tx.execute("UPDATE secrets SET data = ?1 WHERE id = ?2", rusqlite::params![updated, id])
                .map_err(map_sql)?;
            count += 1;
        }
    }
    if count > 0 {
        tx.execute(
            "INSERT OR REPLACE INTO gateway_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![reseal::MARKER_KEY, reseal::marker(count, reseal::now_ms())],
        )
        .map_err(map_sql)?;
    }
    tx.commit().map_err(map_sql)?;
    reseal::report(count);
    Ok(count)
}

/// Log an approval row the listing skipped, once per row per process: every console poll lists the table.
fn report_unreadable_approval(id: &str, error: &serde_json::Error) {
    static REPORTED: std::sync::OnceLock<Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    let first = REPORTED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id.to_string());
    if first {
        tracing::error!(
            approval = %id,
            error = %error,
            "skipped an approval row this gateway cannot read: it stays in the store and is left out of every listing"
        );
    }
}

impl Store for SqliteStore {
    fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError> {
        self.transaction(|| f(self))
    }
    fn liveness_touch(&self) -> Result<bool, GatewayError> {
        let _serial = match self.serial.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
        };
        let inner = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(GatewayError::Internal("sqlite lock poisoned".into()))
            }
        };
        inner.conn.query_row("SELECT 1", [], |_| Ok(())).map_err(map_sql)?;
        Ok(true)
    }
    fn kind(&self) -> &'static str {
        "sqlite"
    }

    fn put_agent(&self, agent: Agent) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&agent).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO agents (id, data) VALUES (?1, ?2)",
                rusqlite::params![agent.id, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn get_agent(&self, id: &str) -> Result<Option<Agent>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row("SELECT data FROM agents WHERE id = ?1", [id], |r| r.get(0))
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn list_agents(&self) -> Result<Vec<Agent>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner.conn.prepare("SELECT data FROM agents").map_err(map_sql)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?);
        }
        Ok(out)
    }

    fn delete_agent(&self, id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM agents WHERE id = ?1", [id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn put_session(&self, session: Session) -> Result<(), GatewayError> {
        let hash = crate::store::session_token_hash(&session.token);
        let data = serde_json::to_string(&crate::store::session_at_rest(&session)).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO sessions (id, token, data) VALUES (?1, ?2, ?3)",
                rusqlite::params![session.id, hash, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn insert_session(&self, session: Session) -> Result<bool, GatewayError> {
        let hash = crate::store::session_token_hash(&session.token);
        let data = serde_json::to_string(&crate::store::session_at_rest(&session)).map_err(map_sql)?;
        let n = self
            .lock()?
            .conn
            .execute(
                "INSERT INTO sessions (id, token, data) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO NOTHING",
                rusqlite::params![session.id, hash, data],
            )
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn touch_session(&self, id: &str, token: &str, now: i64, extend_expiry_to: Option<i64>) -> Result<bool, GatewayError> {
        // One statement, so the revoked, token and expiry guards are evaluated against the row as it is
        // when the write lands rather than as some earlier read saw it.
        let n = self
            .lock()?
            .conn
            .execute(
                "UPDATE sessions SET data = CASE WHEN ?4 IS NULL
                     THEN json_set(data,
                         '$.last_used_at', max(coalesce(json_extract(data, '$.last_used_at'), ?3), ?3))
                     ELSE json_set(data,
                         '$.last_used_at', max(coalesce(json_extract(data, '$.last_used_at'), ?3), ?3),
                         '$.expires_at', max(coalesce(json_extract(data, '$.expires_at'), ?4), ?4))
                 END
                 WHERE id = ?1
                   AND token = ?2
                   AND json_extract(data, '$.revoked') = 0
                   AND (json_extract(data, '$.expires_at') IS NULL OR json_extract(data, '$.expires_at') > ?3)",
                rusqlite::params![id, crate::store::session_token_hash(token), now, extend_expiry_to],
            )
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn session_by_token(&self, token: &str) -> Result<Option<Session>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row(
                "SELECT data FROM sessions WHERE token = ?1",
                [crate::store::bearer_lookup_hash(token)],
                |r| r.get(0),
            )
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn get_session(&self, id: &str) -> Result<Option<Session>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row("SELECT data FROM sessions WHERE id = ?1", [id], |r| r.get(0))
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn list_sessions(&self) -> Result<Vec<Session>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner.conn.prepare("SELECT data FROM sessions").map_err(map_sql)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?);
        }
        Ok(out)
    }

    fn revoke_session(&self, id: &str) -> Result<bool, GatewayError> {
        // In place rather than read-then-replace, so it can neither write back a stale copy of the row
        // nor recreate one deleted since it was read.
        let n = self
            .lock()?
            .conn
            .execute("UPDATE sessions SET data = json_set(data, '$.revoked', json('true')) WHERE id = ?1", [id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn expire_session_by(&self, id: &str, at: i64) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute(
                "UPDATE sessions SET data = json_set(data, '$.expires_at', min(coalesce(json_extract(data, '$.expires_at'), ?2), ?2))
                 WHERE id = ?1 AND json_extract(data, '$.revoked') = 0",
                rusqlite::params![id, at],
            )
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn delete_session(&self, id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM sessions WHERE id = ?1", [id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn delete_session_if(&self, id: &str, dead: &dyn Fn(&Session) -> bool) -> Result<bool, GatewayError> {
        // `transaction` holds `serial` from the read to the release, and every other operation on this
        // store takes it first, so no revocation can land between the judgement and the delete.
        self.transaction(|| match self.get_session(id)? {
            Some(row) if dead(&row) => self.delete_session(id),
            _ => Ok(false),
        })
    }

    fn delete_live_sessions(&self) -> Result<u64, GatewayError> {
        let inner = self.lock()?;
        let rows: Vec<(String, String)> = {
            let mut stmt = inner.conn.prepare("SELECT id, data FROM sessions").map_err(map_sql)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(map_sql)?;
            rows.collect::<Result<_, _>>().map_err(map_sql)?
        };
        let mut deleted = 0u64;
        for (id, data) in rows {
            // A row this build cannot read is deleted: it can authenticate nobody, and keeping it would
            // be keeping something nobody can say is a tombstone.
            let tombstone = serde_json::from_str::<Session>(&data).is_ok_and(|s| s.is_revocation_tombstone());
            if !tombstone {
                deleted += inner.conn.execute("DELETE FROM sessions WHERE id = ?1", [&id]).map_err(map_sql)? as u64;
            }
        }
        Ok(deleted)
    }

    fn put_connection(&self, connection: Conn) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&connection).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO connections (id, data) VALUES (?1, ?2)",
                rusqlite::params![connection.id, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn get_connection(&self, id: &str) -> Result<Option<Conn>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row("SELECT data FROM connections WHERE id = ?1", [id], |r| r.get(0))
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn list_connections(&self) -> Result<Vec<Conn>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner.conn.prepare("SELECT data FROM connections").map_err(map_sql)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?);
        }
        Ok(out)
    }

    fn delete_connection(&self, id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM connections WHERE id = ?1", [id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn put_policy(&self, policy: Policy) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&policy).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO policies (id, connection_id, data) VALUES (?1, ?2, ?3)",
                rusqlite::params![policy.id, policy.connection_id, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn get_policy(&self, id: &str) -> Result<Option<Policy>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row("SELECT data FROM policies WHERE id = ?1", [id], |r| r.get(0))
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn list_policies(&self) -> Result<Vec<Policy>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner.conn.prepare("SELECT data FROM policies").map_err(map_sql)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?);
        }
        Ok(out)
    }

    fn policies_for_connection(&self, connection_id: &str) -> Result<Vec<Policy>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner
            .conn
            .prepare("SELECT data FROM policies WHERE connection_id = ?1")
            .map_err(map_sql)?;
        let rows = stmt
            .query_map([connection_id], |r| r.get::<_, String>(0))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?);
        }
        Ok(out)
    }

    fn delete_policy(&self, id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM policies WHERE id = ?1", [id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn put_grant(&self, grant: Grant) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&grant).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO grants (grant_id, data) VALUES (?1, ?2)",
                rusqlite::params![grant.grant_id, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn get_grant(&self, grant_id: &str) -> Result<Option<Grant>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row("SELECT data FROM grants WHERE grant_id = ?1", [grant_id], |r| r.get(0))
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn list_grants(&self) -> Result<Vec<Grant>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner.conn.prepare("SELECT data FROM grants").map_err(map_sql)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?);
        }
        Ok(out)
    }

    fn update_grant(&self, grant: Grant) -> Result<bool, GatewayError> {
        let data = serde_json::to_string(&grant).map_err(map_sql)?;
        let n = self
            .lock()?
            .conn
            .execute(
                "UPDATE grants SET data = ?1 WHERE grant_id = ?2",
                rusqlite::params![data, grant.grant_id],
            )
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn delete_grant(&self, grant_id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM grants WHERE grant_id = ?1", [grant_id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn put_enrolment_code(&self, code: EnrolmentCode) -> Result<(), GatewayError> {
        let code = crate::store::enrolment_code_at_rest(&code);
        let data = serde_json::to_string(&code).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute("INSERT INTO enrolment_codes (code, data) VALUES (?1, ?2)", rusqlite::params![code.code, data])
            .map_err(enrolment_code_collision)?;
        Ok(())
    }

    fn mint_enrolment_code(&self, code: EnrolmentCode, now_ms: i64, live_max: usize) -> Result<(), GatewayError> {
        let code = crate::store::enrolment_code_at_rest(&code);
        let data = serde_json::to_string(&code).map_err(map_sql)?;
        let inner = self.lock()?;
        let live: i64 = inner
            .conn
            .query_row(
                "SELECT count(*) FROM enrolment_codes WHERE json_extract(data, '$.used') = 0 AND json_extract(data, '$.expires_at') > ?1",
                [now_ms],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        if live.max(0) as usize >= live_max {
            return Err(super::too_many_enrolment_codes(live.max(0) as usize));
        }
        inner
            .conn
            .execute("DELETE FROM enrolment_codes WHERE json_extract(data, '$.expires_at') <= ?1", [now_ms])
            .map_err(map_sql)?;
        // A plain insert: a code that collided with one already issued must never revive it as unused.
        inner
            .conn
            .execute(
                "INSERT INTO enrolment_codes (code, data) VALUES (?1, ?2)",
                rusqlite::params![code.code, data],
            )
            .map_err(enrolment_code_collision)?;
        Ok(())
    }

    fn consume_enrolment_code(
        &self,
        code: &str,
        now_ms: i64,
    ) -> Result<Option<EnrolmentCode>, GatewayError> {
        // Read-check-write inside ONE held lock so the single-use guarantee actually holds:
        // the previous version dropped the lock between the read and the write, letting two
        // concurrent redeems both observe `used == false`. The conditional UPDATE (only when
        // the stored row is still unused) is belt-and-suspenders on top of the held mutex.
        let key = crate::store::bearer_lookup_hash(code);
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row(
                "SELECT data FROM enrolment_codes WHERE code = ?1",
                [&key],
                |r| r.get(0),
            )
            .ok();
        let mut ticket: EnrolmentCode = match row {
            Some(d) => serde_json::from_str(&d).map_err(map_sql)?,
            None => return Ok(None),
        };
        if ticket.used || now_ms >= ticket.expires_at {
            return Ok(None);
        }
        ticket.used = true;
        let data = serde_json::to_string(&ticket).map_err(map_sql)?;
        let n = inner
            .conn
            .execute(
                "UPDATE enrolment_codes SET data = ?1 WHERE code = ?2 AND json_extract(data, '$.used') = 0",
                rusqlite::params![data, key],
            )
            .map_err(map_sql)?;
        if n == 0 {
            // A concurrent redeem won the race.
            return Ok(None);
        }
        Ok(Some(ticket))
    }

    fn enrolment_code_redeemable(&self, code: &str, now_ms: i64) -> Result<bool, GatewayError> {
        let key = crate::store::bearer_lookup_hash(code);
        let row: Option<String> = self
            .lock()?
            .conn
            .query_row("SELECT data FROM enrolment_codes WHERE code = ?1", [&key], |r| r.get(0))
            .optional()
            .map_err(map_sql)?;
        let Some(data) = row else { return Ok(false) };
        let ticket: EnrolmentCode = serde_json::from_str(&data).map_err(map_sql)?;
        Ok(!ticket.used && now_ms < ticket.expires_at)
    }

    fn live_enrolment_code_digests(&self, now_ms: i64) -> Result<Vec<String>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner
            .conn
            .prepare("SELECT code, data FROM enrolment_codes WHERE json_extract(data, '$.used') = 0")
            .map_err(map_sql)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(map_sql)?;
        let mut live = Vec::new();
        for row in rows {
            let (code, data) = row.map_err(map_sql)?;
            let ticket: EnrolmentCode = serde_json::from_str(&data).map_err(map_sql)?;
            if now_ms < ticket.expires_at {
                live.push(code);
            }
        }
        Ok(live)
    }

    fn delete_unconsumed_enrolment_codes(&self) -> Result<u64, GatewayError> {
        let inner = self.lock()?;
        // `json_extract(...) = 0` rather than `IS NOT 1`, matching the predicate
        // `consume_enrolment_code` already uses on this column, so one spelling of "unused" decides
        // both which codes can still be redeemed and which ones a restore removes.
        let deleted = inner
            .conn
            .execute(
                "DELETE FROM enrolment_codes WHERE json_extract(data, '$.used') = 0",
                [],
            )
            .map_err(map_sql)?;
        Ok(deleted as u64)
    }

    fn put_secret(&self, record: SecretRecord) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&record).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO secrets (id, data) VALUES (?1, ?2)",
                rusqlite::params![record.id, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn get_secret(&self, id: &str) -> Result<Option<SecretRecord>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row("SELECT data FROM secrets WHERE id = ?1", [id], |r| r.get(0))
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn put_secret_if_unchanged(&self, id: &str, expected: &SealedSecret, sealed: SealedSecret) -> Result<bool, GatewayError> {
        let inner = self.lock()?;
        let Some(stored) = inner
            .conn
            .query_row("SELECT data FROM secrets WHERE id = ?1", [id], |r| r.get::<_, String>(0))
            .optional()
            .map_err(map_sql)?
        else {
            return Ok(false);
        };
        let mut record: SecretRecord = serde_json::from_str(&stored).map_err(map_sql)?;
        if record.sealed != *expected {
            return Ok(false);
        }
        record.sealed = sealed;
        let data = serde_json::to_string(&record).map_err(map_sql)?;
        // Conditioned on the row's current bytes as well as held under the store lock, so the swap is one statement whatever else reaches the file.
        let n = inner
            .conn
            .execute(
                "UPDATE secrets SET data = ?1 WHERE id = ?2 AND data = ?3",
                rusqlite::params![data, id, stored],
            )
            .map_err(map_sql)?;
        Ok(n == 1)
    }

    fn list_secret_ids(&self) -> Result<Vec<String>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner.conn.prepare("SELECT id FROM secrets").map_err(map_sql)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_sql)?);
        }
        Ok(out)
    }

    fn delete_secret(&self, id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM secrets WHERE id = ?1", [id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn put_secret_custody(&self, custody: SecretCustody) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&custody).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO secret_custody (secret_id, data) VALUES (?1, ?2)",
                rusqlite::params![custody.secret_id, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn get_secret_custody(&self, secret_id: &str) -> Result<Option<SecretCustody>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row(
                "SELECT data FROM secret_custody WHERE secret_id = ?1",
                [secret_id],
                |r| r.get(0),
            )
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn list_secret_custody(&self) -> Result<Vec<SecretCustody>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner.conn.prepare("SELECT data FROM secret_custody").map_err(map_sql)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?);
        }
        Ok(out)
    }

    fn delete_secret_custody(&self, secret_id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM secret_custody WHERE secret_id = ?1", [secret_id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn put_capability(&self, cap: Capability) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&CapabilityWire::from(&cap)).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO capabilities (id, data) VALUES (?1, ?2)",
                rusqlite::params![cap.id, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn get_capability(&self, id: &str) -> Result<Option<Capability>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row(
                "SELECT data FROM capabilities WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .ok();
        match row {
            Some(d) => {
                let wire: CapabilityWire = serde_json::from_str(&d).map_err(map_sql)?;
                Ok(Some(wire.into()))
            }
            None => Ok(None),
        }
    }

    fn list_capabilities(&self) -> Result<Vec<Capability>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner
            .conn
            .prepare("SELECT data FROM capabilities")
            .map_err(map_sql)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            let wire: CapabilityWire = serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?;
            out.push(wire.into());
        }
        Ok(out)
    }

    fn delete_capability(&self, id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM capabilities WHERE id = ?1", [id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn put_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        self.write_approval(approval, false)
    }

    fn insert_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        self.write_approval(approval, true)
    }

    fn get_approval(&self, id: &str) -> Result<Option<PendingApproval>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row("SELECT data FROM approvals WHERE id = ?1", [id], |r| r.get(0))
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn get_approval_outcome(&self, id: &str) -> Result<Option<super::ApprovalOutcome>, GatewayError> {
        let row: Option<String> = {
            let inner = self.lock()?;
            inner.conn.query_row("SELECT data FROM approvals WHERE id = ?1", [id], |r| r.get(0)).ok()
        };
        row.map(|d| super::ApprovalOutcome::from_row_text(d).map_err(map_sql)).transpose()
    }

    fn set_approval_status(
        &self,
        id: &str,
        status: &str,
    ) -> Result<Option<PendingApproval>, GatewayError> {
        let mut approval = match self.get_approval(id)? {
            Some(a) => a,
            None => return Ok(None),
        };
        approval.status = status.to_string();
        self.put_approval(approval.clone())?;
        Ok(Some(approval))
    }

    fn list_pending_control_plane_holds(&self) -> Result<Vec<PendingApproval>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner
            .conn
            .prepare(
                "SELECT id, data FROM approvals WHERE json_valid(data) AND json_extract(data, '$.status') = 'pending' \
                 AND json_extract(data, '$.session_id') = '' AND json_extract(data, '$.resource') = ?1",
            )
            .map_err(map_sql)?;
        let rows = stmt
            .query_map([super::CONTROL_PLANE_RESOURCE], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, data) = row.map_err(map_sql)?;
            match serde_json::from_str::<PendingApproval>(&data) {
                Ok(a) => out.push(a),
                Err(e) => report_unreadable_approval(&id, &e),
            }
        }
        out.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        Ok(out)
    }

    fn pending_control_plane_hold_bytes(&self) -> Result<u64, GatewayError> {
        let inner = self.lock()?;
        let total: i64 = inner
            .conn
            .query_row(
                "SELECT coalesce(sum(length(CAST(data AS BLOB))), 0) FROM approvals \
                 WHERE json_valid(data) AND json_extract(data, '$.status') = 'pending' AND json_extract(data, '$.session_id') = '' \
                 AND json_extract(data, '$.resource') = ?1",
                [super::CONTROL_PLANE_RESOURCE],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        Ok(total.max(0) as u64)
    }

    fn capability_bytes(&self) -> Result<u64, GatewayError> {
        let total: i64 = self
            .lock()?
            .conn
            .query_row("SELECT coalesce(sum(length(CAST(data AS BLOB))), 0) FROM capabilities", [], |r| r.get(0))
            .map_err(map_sql)?;
        Ok(total.max(0) as u64)
    }

    fn pending_hold_bytes(&self) -> Result<u64, GatewayError> {
        let inner = self.lock()?;
        let total: i64 = inner
            .conn
            .query_row(
                "SELECT coalesce(sum(length(CAST(data AS BLOB))), 0) FROM approvals \
                 WHERE json_valid(data) AND json_extract(data, '$.status') = 'pending' AND json_extract(data, '$.session_id') != ''",
                [],
                |r| r.get(0),
            )
            .map_err(map_sql)?;
        Ok(total.max(0) as u64)
    }

    fn count_pending_approvals(&self) -> Result<usize, GatewayError> {
        let inner = self.lock()?;
        let pending: i64 = inner
            .conn
            .query_row("SELECT count(*) FROM approvals WHERE json_valid(data) AND json_extract(data, '$.status') = 'pending'", [], |r| {
                r.get(0)
            })
            .map_err(map_sql)?;
        Ok(pending as usize)
    }

    fn pending_staging_owners(&self) -> Result<Vec<(String, Option<super::HoldRequester>)>, GatewayError> {
        let inner = self.lock()?;
        // A row that is not JSON at all reads as `{}` so it is passed over rather than failing every hold, as the listing skips it.
        let mut stmt = inner
            .conn
            .prepare(
                "SELECT json_extract(d, '$.params.staging_secret_id'), json_extract(d, '$.requested_by')
                 FROM (SELECT CASE WHEN json_valid(data) THEN data ELSE '{}' END AS d FROM approvals)
                 WHERE json_extract(d, '$.status') = 'pending'
                   AND json_extract(d, '$.session_id') = ''
                   AND json_extract(d, '$.resource') = ?1
                   AND json_type(d, '$.params.staging_secret_id') = 'text'",
            )
            .map_err(map_sql)?;
        let rows = stmt
            .query_map([super::CONTROL_PLANE_RESOURCE], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)))
            .map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            let (staging_secret_id, requested_by) = r.map_err(map_sql)?;
            let requested_by = requested_by.and_then(|json| serde_json::from_str(&json).ok());
            out.push((staging_secret_id, requested_by));
        }
        Ok(out)
    }

    fn list_approvals(&self, status: Option<&str>) -> Result<Vec<PendingApproval>, GatewayError> {
        let inner = self.lock()?;
        // Filtered here, so a listing of the pending queue never reads the resolved rows and their results.
        let mut stmt = inner
            .conn
            .prepare("SELECT id, data FROM approvals WHERE ?1 IS NULL OR (json_valid(data) AND json_extract(data, '$.status') = ?1)")
            .map_err(map_sql)?;
        let rows = stmt
            .query_map([status], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(map_sql)?;
        let mut out: Vec<PendingApproval> = Vec::new();
        for r in rows {
            let (id, data) = r.map_err(map_sql)?;
            // One row nothing can read must not take the queue, every control-plane hold, settlement and restore reconciliation down with it.
            let a: PendingApproval = match serde_json::from_str(&data) {
                Ok(a) => a,
                Err(e) => {
                    report_unreadable_approval(&id, &e);
                    continue;
                }
            };
            if status.map_or(true, |s| a.status == s) {
                out.push(a);
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    fn put_connector_manifest(&self, manifest: InstalledManifest) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&manifest).map_err(map_sql)?;
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO connector_manifests (id, data) VALUES (?1, ?2)",
                rusqlite::params![manifest.manifest.id, data],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn get_connector_manifest(&self, id: &str) -> Result<Option<InstalledManifest>, GatewayError> {
        let inner = self.lock()?;
        let row: Option<String> = inner
            .conn
            .query_row("SELECT data FROM connector_manifests WHERE id = ?1", [id], |r| r.get(0))
            .ok();
        row.map(|d| serde_json::from_str(&d).map_err(map_sql)).transpose()
    }

    fn list_connector_manifests(&self) -> Result<Vec<InstalledManifest>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner.conn.prepare("SELECT data FROM connector_manifests").map_err(map_sql)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(map_sql)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(map_sql)?).map_err(map_sql)?);
        }
        Ok(out)
    }

    fn delete_connector_manifest(&self, id: &str) -> Result<bool, GatewayError> {
        let n = self
            .lock()?
            .conn
            .execute("DELETE FROM connector_manifests WHERE id = ?1", [id])
            .map_err(map_sql)?;
        Ok(n > 0)
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>, GatewayError> {
        let inner = self.lock()?;
        // Not the `.ok()` shape the entity reads in this file use: those turn any failure into "no
        // such row", and for the approver keyring that reads as "no device has ever been paired",
        // which lowers the approval floor. A read that fails must surface as an error.
        match inner
            .conn
            .query_row("SELECT value FROM gateway_meta WHERE key = ?1", [key], |r| r.get(0))
        {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(map_sql(e)),
        }
    }

    fn put_meta(&self, key: &str, value: &str) -> Result<(), GatewayError> {
        self.lock()?
            .conn
            .execute(
                "INSERT OR REPLACE INTO gateway_meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, value],
            )
            .map_err(map_sql)?;
        Ok(())
    }

    fn claim_once(&self, scope: &str, jti: &str, expires_at_ms: i64) -> Result<bool, GatewayError> {
        let inner = self.lock()?;
        // Prune first, under the same held lock as the insert: a claim whose token has expired is
        // dead weight, and dropping it keeps the table proportional to live tokens rather than to
        // every token ever issued.
        inner
            .conn
            .execute("DELETE FROM one_time_claims WHERE expires_at_ms <= ?1", [super::now_ms()])
            .map_err(map_sql)?;
        inner
            .conn
            .execute(
                "INSERT OR IGNORE INTO one_time_claims (scope, jti, expires_at_ms) VALUES (?1, ?2, ?3)",
                rusqlite::params![scope, jti, expires_at_ms],
            )
            .map_err(map_sql)?;
        // The primary key is what decides, not a prior SELECT: IGNORE means the row was already
        // there, so this is a replay and the caller must refuse it.
        Ok(inner.conn.changes() == 1)
    }

    fn append_audit_charged(
        &self,
        mut payload: AuditPayload,
        charge: Option<super::GrantCharge>,
    ) -> Result<AuditEvent, GatewayError> {
        crate::audit_bound::cut_ids(&mut payload);
        if self.owns_transaction() {
            return Err(GatewayError::Internal(
                "audit events cannot be appended inside a store transaction: the signed chain in memory has no rollback".into(),
            ));
        }
        let mut inner = self.lock()?;
        // Before the event is sealed, and best effort. The fold is housekeeping; an event is never
        // dropped for any reason, so a table that could not be tidied must not cost a record.
        if charge.is_some() {
            let now = super::now_ms();
            if now - inner.grant_usage_compacted_ms >= super::GRANT_USAGE_COMPACT_INTERVAL_MS {
                inner.grant_usage_compacted_ms = now;
                if let Err(e) = compact_grant_usage(&inner.conn, now) {
                    tracing::warn!(error = %e, "could not fold the grant usage counter; the count is unaffected");
                }
            }
        }
        // Sealed, written, and only then held: a write that fails (a full disk) must leave the chain where the rows are, or the next append writes above a hole the next open refuses.
        let event = inner
            .audit
            .seal(payload)
            .map_err(|e| GatewayError::Internal(format!("audit append failed: {e}")))?;
        let data = serde_json::to_string(&event).map_err(map_sql)?;
        // One transaction, because the charge is part of the record rather than beside it: a row
        // that landed without its charge is a budget that silently widens, and the only reason this
        // cannot be a caller-side `run_atomically` is the refusal above.
        let tx = inner.conn.unchecked_transaction().map_err(map_sql)?;
        tx.execute(
            "INSERT INTO audit_events (seq, data) VALUES (?1, ?2)",
            rusqlite::params![event.seq as i64, data],
        )
        .map_err(|e| {
            if !is_primary_key_collision(&e) {
                return map_sql(e);
            }
            let message = audit_collision_message(event.seq);
            *self.collided.lock().unwrap_or_else(|p| p.into_inner()) = Some(message.clone());
            (self.on_collision)(&message);
            GatewayError::Internal(message)
        })?;
        if let Some(charge) = charge {
            file_grant_charge(
                &tx,
                &charge.grant_id,
                super::charge_agent(&event.payload),
                event.timestamp,
            )?;
        }
        tx.commit().map_err(map_sql)?;
        inner
            .audit
            .accept(event.clone())
            .map_err(|e| GatewayError::Internal(format!("audit append failed: {e}")))?;
        Ok(event)
    }

    fn put_call_diagnostic(&self, diagnostic: super::CallDiagnostic) -> Result<(), GatewayError> {
        let data = serde_json::to_string(&diagnostic)
            .map_err(|e| GatewayError::Internal(format!("could not encode a call diagnostic: {e}")))?;
        let inner = self.lock()?;
        inner
            .conn
            .execute(
                "INSERT OR REPLACE INTO call_diagnostics (audit_seq, recorded_at, data) VALUES (?1, ?2, ?3)",
                rusqlite::params![diagnostic.audit_seq as i64, diagnostic.recorded_at, data],
            )
            .map_err(map_sql)?;
        with_secure_delete(&inner.conn, |conn| {
            conn.execute(
                "DELETE FROM call_diagnostics WHERE recorded_at < ?1",
                [super::now_ms() - super::CALL_DIAGNOSTICS_RETENTION_MS],
            )?;
            conn.execute(
                "DELETE FROM call_diagnostics WHERE audit_seq NOT IN \
                 (SELECT audit_seq FROM call_diagnostics ORDER BY audit_seq DESC LIMIT ?1)",
                [super::CALL_DIAGNOSTICS_MAX as i64],
            )
        })
        .map_err(map_sql)?;
        Ok(())
    }

    fn call_diagnostics(&self, from_seq: u64) -> Result<Vec<super::CallDiagnostic>, GatewayError> {
        let inner = self.lock()?;
        let mut stmt = inner
            .conn
            .prepare("SELECT data FROM call_diagnostics WHERE audit_seq >= ?1 ORDER BY audit_seq ASC")
            .map_err(map_sql)?;
        let rows = stmt
            .query_map([from_seq as i64], |r| r.get::<_, String>(0))
            .map_err(map_sql)?
            .collect::<rusqlite::Result<Vec<String>>>()
            .map_err(map_sql)?;
        rows.iter()
            .map(|data| {
                serde_json::from_str(data).map_err(|e| {
                    GatewayError::Internal(format!("a stored call diagnostic is not readable: {e}"))
                })
            })
            .collect()
    }

    fn purge_call_diagnostics(&self) -> Result<u64, GatewayError> {
        let inner = self.lock()?;
        let n = with_secure_delete(&inner.conn, |conn| conn.execute("DELETE FROM call_diagnostics", []))
            .map_err(map_sql)?;
        Ok(n as u64)
    }

    fn audit_events(&self, limit: Option<usize>) -> Result<Vec<AuditEvent>, GatewayError> {
        let inner = self.lock()?;
        let events = inner.audit.events();
        let slice = match limit {
            Some(n) if n < events.len() => &events[events.len() - n..],
            _ => events,
        };
        Ok(slice.to_vec())
    }

    fn audit_events_from(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, GatewayError> {
        // Out of the resident chain rather than out of SQL: the rows and the chain agree event for
        // event above the boundary, and reading here costs a lock rather than a parse per row.
        let inner = self.lock()?;
        let base = inner.audit.base_seq();
        let start = from_seq.saturating_sub(base) as usize;
        let events = inner.audit.events();
        if start >= events.len() {
            return Ok(Vec::new());
        }
        let end = start.saturating_add(limit).min(events.len());
        Ok(events[start..end].to_vec())
    }

    fn prune_audit_to(
        &self,
        end_seq: u64,
        base_hash: &str,
        segment_head: &str,
    ) -> Result<u64, GatewayError> {
        if self.path.is_none() {
            return Err(GatewayError::Internal(
                "this store holds no persisted audit key, so a boundary signed now could not be verified by anything that opened these bytes later: refusing to prune the audit chain".into(),
            ));
        }
        if self.owns_transaction() {
            return Err(GatewayError::Internal(
                "the audit chain cannot be pruned inside a store transaction: the in-memory chain has no rollback, so the rows and the chain would part company if the transaction were undone".into(),
            ));
        }
        let mut inner = self.lock()?;
        // Everything that can refuse, refuses before a single row moves. `advance_base` repeats
        // these checks below, but by then the transaction has committed and a refusal would leave
        // the rows and the chain describing different windows.
        let base = inner.audit.base_seq();
        if end_seq < base {
            return Err(GatewayError::Internal(format!(
                "a prune to {end_seq} is below this store's base seq {base}: those events are already archived"
            )));
        }
        let dropped = (end_seq + 1 - base) as usize;
        let held = inner.audit.events().len();
        if dropped > held {
            return Err(GatewayError::Internal(format!(
                "a prune to {end_seq} would remove {dropped} events from a window holding {held}: refusing"
            )));
        }
        let expected_link = match inner.audit.events().get(dropped) {
            Some(first) => first.prev_hash.clone(),
            None => inner.audit.head_hash(),
        };
        if expected_link != base_hash {
            return Err(GatewayError::Internal(format!(
                "the segment's head hash is not what event {} links back to: refusing to prune, because a base nothing hangs off is a chain that cannot be verified",
                end_seq + 1
            )));
        }

        let boundary = inner.audit.seal_boundary(
            inner.boundary.epoch,
            end_seq + 1,
            base_hash.to_string(),
            Some(segment_head.to_string()),
            inner.boundary.lineage.clone(),
            super::now_ms(),
        );
        let value = serde_json::to_string(&boundary).map_err(map_sql)?;
        let tx = inner.conn.unchecked_transaction().map_err(map_sql)?;
        let removed = tx
            .execute("DELETE FROM audit_events WHERE seq <= ?1", [end_seq as i64])
            .map_err(map_sql)?;
        tx.execute(
            "INSERT OR REPLACE INTO gateway_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![AUDIT_BOUNDARY_META, value],
        )
        .map_err(map_sql)?;
        tx.commit().map_err(map_sql)?;

        inner
            .audit
            .advance_base(end_seq, base_hash.to_string())
            .map_err(|e| GatewayError::Internal(format!("audit prune: {e}")))?;
        inner.boundary = boundary;
        Ok(removed as u64)
    }

    fn seal_audit_segment(
        &self,
        draft: permaura_core::audit::AuditSegmentDraft,
    ) -> Result<permaura_core::audit::AuditSegment, GatewayError> {
        Ok(self.lock()?.audit.seal_segment(draft))
    }

    fn seal_audit_index(
        &self,
        index: permaura_core::audit::AuditArchiveIndex,
        written_at: &str,
    ) -> Result<permaura_core::audit::AuditArchiveIndex, GatewayError> {
        Ok(self.lock()?.audit.seal_index(index, written_at))
    }

    fn audit_rekey(&self) -> Result<Option<AuditRekey>, GatewayError> {
        Ok(self.lock()?.rekey.clone())
    }

    fn degraded(&self) -> Option<String> {
        self.collided.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn audit_verifying_key(&self) -> Result<[u8; 32], GatewayError> {
        Ok(self.lock()?.audit.verifying_key().to_bytes())
    }

    fn audit_len(&self) -> Result<u64, GatewayError> {
        // The in-memory chain, not `SELECT count(*)`: the two agree row for row above the boundary,
        // and this one costs a lock rather than a table scan on the execution path.
        let inner = self.lock()?;
        Ok(inner.audit.events().len() as u64)
    }

    fn count_grant_usage(
        &self,
        windows: &[super::GrantWindow<'_>],
    ) -> Result<super::GrantUsageCounts, GatewayError> {
        // In memory rather than in SQL, and over the same `Vec` `audit_events` used to clone. The
        // rows and the resident chain agree event for event above the boundary, and a SQL count
        // would have to re-parse every `data` blob to read a decision and a grant id out of JSON.
        let inner = self.lock()?;
        Ok(super::tally_grant_usage(windows, inner.audit.events().iter()))
    }

    fn read_grant_usage(
        &self,
        windows: &[super::GrantWindow<'_>],
    ) -> Result<super::GrantUsageCounts, GatewayError> {
        let inner = self.lock()?;
        read_grant_usage_rows(&inner.conn, windows)
    }

    fn grant_usage_series(
        &self,
        grant_id: &str,
        since_ms: i64,
        bucket_ms: i64,
        buckets: usize,
    ) -> Result<Vec<u64>, GatewayError> {
        let mut counts = vec![0u64; buckets];
        if buckets == 0 || bucket_ms <= 0 {
            return Ok(counts);
        }
        let inner = self.lock()?;
        let mut stmt = inner
            .conn
            .prepare_cached(
                "SELECT min((period_start - ?2) / ?3, ?4 - 1), sum(count) FROM grant_usage
                 WHERE grant_id = ?1 AND period_start >= ?2 GROUP BY 1",
            )
            .map_err(map_sql)?;
        let rows = stmt
            .query_map(rusqlite::params![grant_id, since_ms, bucket_ms, buckets as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(map_sql)?;
        for row in rows {
            let (bucket, count) = row.map_err(map_sql)?;
            counts[(bucket.max(0) as usize).min(buckets - 1)] += count.max(0) as u64;
        }
        Ok(counts)
    }

    /// Clear the counter and refile the whole chain: `archived` first, then this store's own hot
    /// window, so the two together are every event there has ever been.
    ///
    /// Read with the lock released and filed in one transaction. A rebuild that failed halfway would
    /// leave a counter holding part of the history and reading as though the rest had never been
    /// charged, which is the exact failure the counter exists to prevent, and it would be silent.
    fn rebuild_grant_usage(
        &self,
        archived: &mut dyn Iterator<Item = Result<AuditEvent, GatewayError>>,
    ) -> Result<u64, GatewayError> {
        let walked = self.walk_grant_usage(archived)?;
        self.apply_grant_usage(walked)
    }

    /// Checked a chunk at a time, each copied out under a short hold of the lock and verified with it released and this runtime worker given back.
    ///
    /// The first call after a cold start checks every held event, up to the hot ceiling of ed25519 verifications, and it runs on the request that asked (an authenticated `/health`, the console's audit poll), so held under `serial` or on the only worker it is seconds in which `/health`'s liveness touch cannot answer.
    fn verify_audit(&self) -> Result<Option<u64>, GatewayError> {
        super::bridge::blocking_section(|| {
            // Events appended after this call began are left to the next one, so a busy chain cannot keep it walking.
            let until = self.lock()?.audit.next_seq();
            loop {
                let Some(events) = self.lock()?.audit.unproven(AUDIT_VERIFY_CHUNK) else { return Ok(None) };
                if events.first_seq() >= until {
                    return Ok(None);
                }
                let checked = events.check();
                self.audit_checked.fetch_add(checked.checked() as u64, std::sync::atomic::Ordering::Relaxed);
                self.lock()?.audit.record_proven(&events, checked);
                if checked.broken.is_some() {
                    return Ok(checked.broken);
                }
            }
        })
    }

    /// The boundary this store is running under: where its hot window starts, which epoch it is in,
    /// and the newest archive segment there is. Read by anything that has to describe the chain
    /// rather than walk it.
    fn audit_boundary(&self) -> Result<Option<AuditBoundary>, GatewayError> {
        Ok(Some(self.lock()?.boundary.clone()))
    }

    /// The signing order, in the only order that works.
    ///
    /// The boundary is re-signed under the key this store resolved at open, and the row and the
    /// in-memory copy move together under one held lock. Both halves matter: a row written without
    /// the in-memory copy following it would leave this process describing a chain its own database
    /// no longer claims, and a boundary signed by anything other than the key
    /// [`load_audit_boundary`] will verify against on the next open is a store that refuses to open.
    ///
    /// Which is why a store with no persisted key refuses outright. Its key is generated per process
    /// ([`AuditLog::new`]), so a non-genesis boundary written under it verifies exactly once, in the
    /// process that wrote it, and bricks the database for every later reader of those bytes.
    fn fork_audit_epoch(&self, epoch: u64, restore_id: &str) -> Result<bool, GatewayError> {
        if self.path.is_none() {
            return Err(GatewayError::Internal(
                "this store holds no persisted audit key, so a boundary signed now could not be verified by anything that opened these bytes later: refusing to fork the audit epoch".into(),
            ));
        }
        let mut inner = self.lock()?;
        if inner.boundary.epoch == epoch {
            return Ok(false);
        }
        if epoch < inner.boundary.epoch {
            return Err(GatewayError::Internal(format!(
                "the audit epoch is {} and a fork to {epoch} would move it backwards: refusing, because two forks of one tenant sharing an epoch is the confusion the epoch exists to prevent",
                inner.boundary.epoch
            )));
        }
        let mut lineage = inner.boundary.lineage.clone();
        lineage.push(AuditFork {
            epoch,
            parent_epoch: inner.boundary.epoch,
            base_seq: inner.boundary.base_seq,
            base_hash: inner.boundary.base_hash.clone(),
            restore_id: restore_id.to_string(),
        });
        let boundary = inner.audit.seal_boundary(
            epoch,
            inner.boundary.base_seq,
            inner.boundary.base_hash.clone(),
            inner.boundary.segment_head.clone(),
            lineage,
            super::now_ms(),
        );
        let value = serde_json::to_string(&boundary).map_err(map_sql)?;
        inner
            .conn
            .execute(
                "INSERT OR REPLACE INTO gateway_meta (key, value) VALUES (?1, ?2)",
                rusqlite::params![AUDIT_BOUNDARY_META, value],
            )
            .map_err(map_sql)?;
        inner.boundary = boundary;
        Ok(true)
    }
}

/// Serializable mirror of [`Capability`] (which is a plain struct without serde) so it
/// can round-trip through the SQLite blob column.
#[derive(serde::Serialize, serde::Deserialize)]
struct CapabilityWire {
    id: String,
    description: String,
    risk: permaura_core::RiskTier,
    action: permaura_core::Action,
    requires_approval: bool,
    resource: String,
    secret_id: String,
    // `kind`/`command` default so capability blobs persisted before the command connector
    // landed still deserialize as plain HTTP capabilities.
    #[serde(default)]
    kind: crate::connectors::CapabilityKind,
    #[serde(default)]
    command: Option<crate::connectors::CommandSpec>,
    // Defaults so capability blobs persisted before OpenAPI import landed deserialize unchanged.
    #[serde(default)]
    http: Option<crate::connectors::HttpSpec>,
    // Defaults so capability blobs persisted before the SSH connector landed deserialize unchanged.
    #[serde(default)]
    ssh: Option<crate::connectors::SshSpec>,
}

impl From<&Capability> for CapabilityWire {
    fn from(c: &Capability) -> Self {
        CapabilityWire {
            id: c.id.clone(),
            description: c.description.clone(),
            risk: c.risk,
            action: c.action,
            requires_approval: c.requires_approval,
            resource: c.resource.clone(),
            secret_id: c.secret_id.clone(),
            kind: c.kind,
            command: c.command.clone(),
            http: c.http.clone(),
            ssh: c.ssh.clone(),
        }
    }
}

impl From<CapabilityWire> for Capability {
    fn from(w: CapabilityWire) -> Self {
        Capability {
            id: w.id,
            description: w.description,
            risk: w.risk,
            action: w.action,
            requires_approval: w.requires_approval,
            resource: w.resource,
            secret_id: w.secret_id,
            kind: w.kind,
            command: w.command,
            http: w.http,
            ssh: w.ssh,
        }
    }
}

/// Run `f` with SQLite overwriting deleted content, so a purged or aged-out error message does not
/// linger in the database file's free pages. Scoped to these statements because it costs a write per
/// deleted page, and restored afterwards to whatever the connection had.
fn with_secure_delete<T>(
    conn: &rusqlite::Connection,
    f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    let previous: i64 = conn.query_row("PRAGMA secure_delete", [], |r| r.get(0))?;
    conn.pragma_update(None, "secure_delete", 1)?;
    let out = f(conn);
    let restored = conn.pragma_update(None, "secure_delete", previous);
    let out = out?;
    restored?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use permaura_core::AuditPayload;
    use std::sync::Arc;

    /// The conditional write swaps only while the stored envelope is the one the caller read,
    /// keeps the stored metadata, and never brings back a deleted secret.
    #[test]
    fn put_secret_if_unchanged_swaps_only_the_envelope_it_was_given() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, b"pass", b"first").unwrap();
        let metadata = permaura_core::SecretMetadata { labels: vec!["kept".into()], ..Default::default() };
        store
            .put_secret(SecretRecord { id: "sec_a".into(), sealed: first.clone(), metadata: metadata.clone() })
            .unwrap();

        let second = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, b"pass", b"second").unwrap();
        assert!(store.put_secret_if_unchanged("sec_a", &first, second.clone()).unwrap());
        let row = store.get_secret("sec_a").unwrap().unwrap();
        assert_eq!(row.sealed, second);
        assert_eq!(row.metadata, metadata, "the swap keeps the stored metadata");

        // Replaced since `first` was read: the stale write is refused and the replacement stays.
        let stale = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, b"pass", b"stale").unwrap();
        assert!(!store.put_secret_if_unchanged("sec_a", &first, stale.clone()).unwrap());
        assert_eq!(store.get_secret("sec_a").unwrap().unwrap().sealed, second);

        // Removed: the stale write does not bring it back.
        assert!(store.delete_secret("sec_a").unwrap());
        assert!(!store.put_secret_if_unchanged("sec_a", &second, stale).unwrap());
        assert!(store.get_secret("sec_a").unwrap().is_none());
    }

    fn diagnostic(seq: u64, recorded_at: i64) -> crate::store::CallDiagnostic {
        crate::store::CallDiagnostic {
            audit_seq: seq,
            recorded_at,
            message: format!("failure {seq}"),
            headers: Default::default(),
        }
    }

    /// The chain is resident and read back whole, so an id of any length is sealed cut, and the stored row and a reopened chain agree on it.
    #[test]
    fn an_appended_event_keeps_a_long_action_cut() {
        let dir = std::env::temp_dir().join(format!("permaura-sqlite-cut-ids-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gateway.db").to_string_lossy().into_owned();
        let long = format!("ssh_long.{}", "a".repeat(200_000));
        {
            let store = SqliteStore::open(&path).unwrap();
            let event = store.append_audit(AuditPayload::new(long.clone(), "ssh_long", "deny")).unwrap();
            assert!(event.payload.action.contains(&format!("cut from {} bytes", long.len())), "{}", event.payload.action);
            assert_eq!(event.payload.resource, "ssh_long");
        }
        let reopened = SqliteStore::open(&path).unwrap();
        let events = reopened.audit_events(None).unwrap();
        assert!(events[0].payload.action.len() < 1024);
        assert_eq!(reopened.verify_audit().unwrap(), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Diagnostics age out, are capped by count keeping the newest, and purge without touching the
    /// chain. The memory store runs the same rules; this pins the SQL.
    #[test]
    fn call_diagnostics_age_out_cap_and_purge() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.append_audit(AuditPayload::new("a", "r", "allow")).unwrap();
        let now = crate::store::now_ms();

        store.put_call_diagnostic(diagnostic(1, now - crate::store::CALL_DIAGNOSTICS_RETENTION_MS - 1)).unwrap();
        store.put_call_diagnostic(diagnostic(2, now)).unwrap();
        let kept: Vec<u64> = store.call_diagnostics(0).unwrap().iter().map(|d| d.audit_seq).collect();
        assert_eq!(kept, vec![2], "the expired row was pruned by the next write");

        for seq in 3..(3 + crate::store::CALL_DIAGNOSTICS_MAX as u64) {
            store.put_call_diagnostic(diagnostic(seq, now)).unwrap();
        }
        let kept = store.call_diagnostics(0).unwrap();
        assert_eq!(kept.len(), crate::store::CALL_DIAGNOSTICS_MAX);
        assert_eq!(kept[0].audit_seq, 3, "the oldest seq went first");
        assert_eq!(store.call_diagnostics(1_000).unwrap().first().map(|d| d.audit_seq), Some(1_000));

        assert_eq!(store.purge_call_diagnostics().unwrap(), crate::store::CALL_DIAGNOSTICS_MAX as u64);
        assert!(store.call_diagnostics(0).unwrap().is_empty());
        assert_eq!(store.audit_len().unwrap(), 1, "the chain is untouched");
        assert!(store.verify_audit().unwrap().is_none());
    }

    #[test]
    fn sqlite_round_trips_entities_and_chains_audit() {
        let store = SqliteStore::open_in_memory().unwrap();

        // Agent + session by token.
        store
            .put_agent(Agent::approved("codex-cli", "Codex CLI", 0))
            .unwrap();
        store
            .put_session(Session {
                class: Default::default(),
                opened_by: None,
                id: "sess_1".into(),
                agent_id: "codex-cli".into(),
                user_id: Some("sam".into()),
                device_id: None,
                token: "tok_abc".into(),
                role: crate::store::SessionRole::Operator,
                created_at: 0,
                revoked: false,
                expires_at: None,
                last_used_at: None,
                actor: None,
            })
            .unwrap();
        assert_eq!(store.session_by_token("tok_abc").unwrap().unwrap().id, "sess_1");

        // Capability round-trips through the JSON wire shape.
        store
            .put_capability(Capability {
                id: "braintree.transactions.search".into(),
                description: "Search".into(),
                risk: permaura_core::RiskTier::Medium,
                action: permaura_core::Action::Search,
                requires_approval: false,
                resource: "braintree_production".into(),
                secret_id: "sec_braintree_prod".into(),
                kind: crate::connectors::CapabilityKind::Http,
                command: None,
                http: None,
                ssh: None,
            })
            .unwrap();
        let cap = store
            .get_capability("braintree.transactions.search")
            .unwrap()
            .unwrap();
        assert_eq!(cap.resource, "braintree_production");

        // Audit log chains across appends and verifies.
        store
            .append_audit(AuditPayload::new("a", "r", "allow"))
            .unwrap();
        let e2 = store
            .append_audit(AuditPayload::new("b", "r", "deny"))
            .unwrap();
        assert_eq!(e2.seq, 1);
        assert_eq!(store.audit_events(None).unwrap().len(), 2);
        assert_eq!(store.verify_audit().unwrap(), None);
    }

    #[test]
    fn reopening_a_file_store_preserves_data_and_continues_the_audit_chain() {
        // A unique temp path so the test is hermetic and parallel-safe.
        let dir = std::env::temp_dir();
        let path = dir
            .join(format!("permaura-test-{}.db", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.auditkey"));

        // First boot: write an agent + two audit events, then drop the store (close the DB).
        {
            let store = SqliteStore::open(&path).unwrap();
            store
                .put_agent(Agent::approved("codex-cli", "Codex CLI", 0))
                .unwrap();
            store.append_audit(AuditPayload::new("a", "r", "allow")).unwrap();
            store.append_audit(AuditPayload::new("b", "r", "deny")).unwrap();
            assert_eq!(store.verify_audit().unwrap(), None);
        }

        // Second boot: the agent survives, the chain resumes at seq 2 (not restarting at 0), and the
        // whole history still verifies under the persisted signing key.
        {
            let store = SqliteStore::open(&path).unwrap();
            assert!(store.get_agent("codex-cli").unwrap().is_some());
            assert_eq!(store.audit_events(None).unwrap().len(), 2);
            assert_eq!(store.verify_audit().unwrap(), None, "chain must verify after reopen");
            let next = store.append_audit(AuditPayload::new("c", "r", "allow")).unwrap();
            assert_eq!(next.seq, 2, "seq must continue, not restart");
            assert_eq!(store.verify_audit().unwrap(), None);
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.auditkey"));
    }

    /// Only group and other bits count. An owner-only home is `0700`, and the owner's own bits vary
    /// legitimately: a home with no execute bit for its owner would have failed long before boot got
    /// as far as warning about it.
    #[cfg(unix)]
    #[test]
    fn only_group_and_other_bits_make_the_home_too_wide() {
        assert!(!super::home_is_wider_than_owner_only(0o700), "the intended mode");
        assert!(!super::home_is_wider_than_owner_only(0o600), "no execute, still nobody else's");

        assert!(super::home_is_wider_than_owner_only(0o755), "the default umask on a created dir");
        assert!(super::home_is_wider_than_owner_only(0o750), "a group that can read the vault");
        assert!(super::home_is_wider_than_owner_only(0o701), "and a single other-bit is enough");
    }

    /// Operator-token retirement against the store every self-run install has. The bearer being retired is the one written
    /// to `$PERMAURA_HOME/operator.token`, so it lives in a SQLite file rather than in memory, and
    /// the retirement has to survive being written back and read again.
    #[test]
    fn an_immortal_operator_bearer_is_retired_through_the_sqlite_store() {
        use crate::store::SessionRole;
        let path = std::env::temp_dir()
            .join(format!("permaura-retire-{}.db", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.auditkey"));

        {
            let store = SqliteStore::open(&path).unwrap();
            let seed = |token: &str, role: SessionRole, expires_at: Option<i64>| {
                store
                    .put_session(Session {
                        class: Default::default(),
                        opened_by: None,
                        id: format!("sess_{token}"),
                        agent_id: "operator".into(),
                        user_id: None,
                        device_id: None,
                        token: token.into(),
                        role,
                        created_at: 0,
                        revoked: false,
                        expires_at,
                        last_used_at: None,
                        actor: None,
                    })
                    .unwrap();
            };
            seed("pgt_immortal", SessionRole::Operator, None);
            seed("tok_agent", SessionRole::Agent, None);
        }

        {
            let store = SqliteStore::open(&path).unwrap();
            crate::revoke_immortal_operator_sessions(&store);
        }

        // A third open, because the point is that the revocation reached the file rather than a
        // copy of the row this process happened to be holding.
        {
            let store = SqliteStore::open(&path).unwrap();
            assert!(
                store.session_by_token("pgt_immortal").unwrap().unwrap().revoked,
                "the pre-TTL bearer must be dead in the file, not just in memory"
            );
            assert!(!store.session_by_token("tok_agent").unwrap().unwrap().revoked);
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}.auditkey"));
    }

    /// Custody is keyed by `secret_id`: writing it twice must replace, not accumulate.
    #[test]
    fn putting_custody_twice_replaces_the_row() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.put_secret_custody(SecretCustody::local("sec_a", 1)).unwrap();
        store
            .put_secret_custody(SecretCustody::kms("sec_a", b"ct".to_vec(), "cmk", 2))
            .unwrap();

        let all = store.list_secret_custody().unwrap();
        assert_eq!(all.len(), 1, "one row per secret_id");
        assert_eq!(all[0].kind, crate::store::CustodyKind::Kms, "the later write wins");
    }

    #[test]
    fn custody_round_trips_through_the_json_blob_and_deletes() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(store.get_secret_custody("sec_a").unwrap().is_none());
        assert!(!store.delete_secret_custody("sec_a").unwrap());

        let custody = SecretCustody::kms("sec_a", b"\x00\x01opaque".to_vec(), "arn:cmk", 5);
        store.put_secret_custody(custody.clone()).unwrap();
        assert_eq!(
            store.get_secret_custody("sec_a").unwrap().unwrap(),
            custody,
            "the ciphertext bytes must survive the round trip intact"
        );

        assert!(store.delete_secret_custody("sec_a").unwrap());
        assert!(store.list_secret_custody().unwrap().is_empty());
    }

    /// The self-hosted half of the dev-constant seal: an install that predates the per-install KEK sealed under the
    /// public dev constant, and upgrading hands it a real KEK that cannot open its own secrets. The
    /// sweep must repair that on open, and must be a no-op the second time.
    #[test]
    fn a_dev_sealed_secret_is_resealed_on_open_and_the_dev_constant_stops_opening_it() {
        use permaura_core::crypto::{self, Cipher};
        use permaura_core::vault::SecretMetadata;
        const REAL: &[u8] = b"a-real-per-install-kek";

        let store = SqliteStore::open_in_memory().unwrap();
        store
            .put_secret(SecretRecord {
                id: "sec_dev".into(),
                sealed: crypto::seal(Cipher::Aes256Gcm, crate::service::DEV_VAULT_PASSPHRASE, b"hunter2").unwrap(),
                metadata: SecretMetadata::default(),
            })
            .unwrap();

        let resealed = {
            let inner = store.lock().unwrap();
            reseal_dev_sealed_secrets(&inner.conn, REAL).unwrap()
        };
        assert_eq!(resealed, 1);

        let after = store.get_secret("sec_dev").unwrap().unwrap();
        assert_eq!(crypto::open(&after.sealed, REAL).unwrap().as_slice(), b"hunter2", "value must read back");
        assert!(
            crypto::open(&after.sealed, crate::service::DEV_VAULT_PASSPHRASE).is_err(),
            "the dev constant must no longer open it"
        );

        let inner = store.lock().unwrap();
        let marker: String = inner
            .conn
            .query_row("SELECT value FROM gateway_meta WHERE key = ?1", [crate::store::reseal::MARKER_KEY], |r| r.get(0))
            .unwrap();
        assert!(marker.contains(r#""resealed":1"#), "the sweep must record what it did: {marker}");
        assert_eq!(reseal_dev_sealed_secrets(&inner.conn, REAL).unwrap(), 0, "a second sweep is a no-op");
    }

    #[test]
    fn meta_round_trips_and_the_later_write_wins() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(store.get_meta(crate::store::APPROVER_KEYRING_META).unwrap().is_none());

        store.put_meta(crate::store::APPROVER_KEYRING_META, r#"{"keys":[]}"#).unwrap();
        assert_eq!(
            store.get_meta(crate::store::APPROVER_KEYRING_META).unwrap().as_deref(),
            Some(r#"{"keys":[]}"#)
        );

        store.put_meta(crate::store::APPROVER_KEYRING_META, r#"{"keys":["a"]}"#).unwrap();
        assert_eq!(
            store.get_meta(crate::store::APPROVER_KEYRING_META).unwrap().as_deref(),
            Some(r#"{"keys":["a"]}"#),
            "a key holds one value, not a history"
        );
    }

    /// A hold as the enforcement loop records one, with a status the test chooses.
    fn approval(id: &str, status: &str) -> PendingApproval {
        PendingApproval {
            id: id.into(),
            session_id: "sess_demo".into(),
            capability: "github.pull_requests.create".into(),
            resource: "github_acme".into(),
            message: "Approve?".into(),
            status: status.into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({ "owner": "synthetic" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: 0,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        }
    }

    /// An agent polling its approval reads the row without its params, its result served from the row's own bytes: the same fields and the same result text a whole read gives, from this store or from one in memory, and no result where there is none.
    #[test]
    fn an_approvals_outcome_is_read_without_its_params() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut row = approval("appr_out", "approved");
        row.params = serde_json::json!({ "n": vec![1e15; 1000], "s": "é\"\\\n" }).into();
        row.result = Some(permaura_core::JsonText::from_value(&serde_json::json!({ "number": 1, "title": "a \"quoted\" é" })));
        row.result_status = Some(201);
        row.risk = Some(permaura_core::RiskTier::Medium);
        row.action_description = Some("Create a pull request".into());
        row.expires_at = Some(7);
        store.put_approval(row).unwrap();
        let whole = store.get_approval("appr_out").unwrap().unwrap();
        let read = store.get_approval_outcome("appr_out").unwrap().unwrap();
        for outcome in [read, crate::store::ApprovalOutcome::of(whole.clone())] {
            assert_eq!((outcome.id.as_str(), outcome.session_id.as_str(), outcome.status.as_str(), outcome.message.as_str()), ("appr_out", "sess_demo", "approved", "Approve?"));
            assert_eq!((outcome.result_status, outcome.expires_at, outcome.action_description.as_deref()), (Some(201), Some(7), Some("Create a pull request")));
            assert_eq!(outcome.risk_label(), whole.risk_label());
            assert_eq!(outcome.result.as_deref(), Some(whole.result.as_ref().unwrap().get().as_bytes()));
        }
        store.put_approval(approval("appr_none", "pending")).unwrap();
        assert!(store.get_approval_outcome("appr_none").unwrap().unwrap().result.is_none());
        assert!(store.get_approval_outcome("appr_missing").unwrap().is_none());
    }

    /// The cap the in-memory store has carried since long before this one, on the store that
    /// actually ships. Without it a flood of relayed `requires_approval` calls grows the table
    /// without bound, and on a hosted worker each one is also a full snapshot upload of a database
    /// that never shrinks, because no hold expires.
    #[test]
    fn a_flood_of_held_approvals_is_refused_at_the_cap() {
        let store = SqliteStore::open_in_memory().unwrap();
        for i in 0..crate::store::MAX_PENDING_APPROVALS {
            store.put_approval(approval(&format!("appr_{i}"), "pending")).unwrap();
        }
        let err = store
            .put_approval(approval("appr_one_too_many", "pending"))
            .expect_err("the cap must refuse");
        match err {
            GatewayError::TooManyRequests { reason, .. } => assert_eq!(reason, "approval_backlog"),
            other => panic!("the cap must refuse with the shared error: {other:?}"),
        }
        // And it refused before writing: the row is not there and the count has not moved.
        assert!(store.get_approval("appr_one_too_many").unwrap().is_none());
        assert_eq!(
            store.list_approvals(Some("pending")).unwrap().len(),
            crate::store::MAX_PENDING_APPROVALS
        );
        assert_eq!(store.count_pending_approvals().unwrap(), crate::store::MAX_PENDING_APPROVALS);
    }

    /// The half that makes the cap survivable: at the ceiling a human can still work through the
    /// queue, because resolving an existing hold is an update and never a new row.
    #[test]
    fn at_the_cap_an_existing_hold_can_still_be_resolved() {
        let store = SqliteStore::open_in_memory().unwrap();
        for i in 0..crate::store::MAX_PENDING_APPROVALS {
            store.put_approval(approval(&format!("appr_{i}"), "pending")).unwrap();
        }
        store
            .set_approval_status("appr_0", "approved")
            .expect("resolving at the cap is how the queue comes down")
            .expect("the hold is there");
        assert_eq!(store.get_approval("appr_0").unwrap().unwrap().status, "approved");
        // A resolved hold is a cached result, not a question waiting on anyone, so it frees a slot.
        store
            .put_approval(approval("appr_next", "pending"))
            .expect("one resolved hold makes room for one new one");
    }

    /// The property the whole single-use guarantee rests on, here against the real primary key: the
    /// second presentation of a ticket is refused. If this returned `true` twice a pairing ticket
    /// would be a reusable bearer for the rest of its TTL.
    #[test]
    fn a_claim_succeeds_once_and_every_replay_is_refused() {
        let store = SqliteStore::open_in_memory().unwrap();
        let exp = crate::store::now_ms() + 60_000;
        assert!(store.claim_once("pair", "jti-1", exp).unwrap());
        assert!(!store.claim_once("pair", "jti-1", exp).unwrap());
        assert!(!store.claim_once("pair", "jti-1", exp).unwrap());
    }

    /// Scopes namespace unrelated token families, so two of them minting the same jti cannot spend
    /// each other's claim.
    #[test]
    fn the_same_jti_in_two_scopes_is_two_claims() {
        let store = SqliteStore::open_in_memory().unwrap();
        let exp = crate::store::now_ms() + 60_000;
        assert!(store.claim_once("pair", "shared-jti", exp).unwrap());
        assert!(store.claim_once("floor", "shared-jti", exp).unwrap());
        assert!(!store.claim_once("pair", "shared-jti", exp).unwrap());
    }

    /// Reading the sessions table must not be the same as holding every session in it. The stored
    /// digest is what the column holds, and presenting it as a bearer once resolved the row.
    #[test]
    fn a_stored_session_digest_is_not_a_bearer() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .put_session(Session {
                class: Default::default(),
                opened_by: None,
                id: "sess_1".into(),
                agent_id: "operator".into(),
                user_id: None,
                device_id: None,
                token: "raw-bearer".into(),
                role: crate::store::SessionRole::Operator,
                created_at: 0,
                revoked: false,
                expires_at: None,
                last_used_at: None,
                actor: None,
            })
            .unwrap();
        let stored = store.get_session("sess_1").unwrap().unwrap();
        assert!(stored.token.starts_with(crate::store::SESSION_HASH_PREFIX), "the row holds a digest");
        assert!(store.session_by_token("raw-bearer").unwrap().is_some(), "the bearer authenticates");
        assert!(store.session_by_token(&stored.token).unwrap().is_none(), "its digest must not");
        // Writing a row back exactly as it was read must keep the bearer working: touch and revoke do this.
        store.put_session(stored.clone()).unwrap();
        assert!(store.session_by_token("raw-bearer").unwrap().is_some());
        assert!(store.revoke_session("sess_1").unwrap());
        assert!(store.session_by_token("raw-bearer").unwrap().unwrap().revoked);
    }

    /// Pruning must release a dead claim and only a dead one: past its token's expiry the claim has
    /// nothing left to protect, but a live one must keep refusing.
    #[test]
    fn a_lapsed_claim_stops_blocking_but_a_live_one_does_not() {
        let store = SqliteStore::open_in_memory().unwrap();
        let now = crate::store::now_ms();
        assert!(store.claim_once("pair", "expired", now - 1).unwrap());
        assert!(store.claim_once("pair", "expired", now + 60_000).unwrap(), "the lapsed row must be pruned");
        assert!(!store.claim_once("pair", "expired", now + 60_000).unwrap(), "and the fresh one must hold");
    }

    /// A store still on the dev constant has nothing to re-seal *to*, and must not rewrite rows.
    #[test]
    fn the_sweep_does_nothing_while_the_active_kek_is_the_dev_constant() {
        use permaura_core::crypto::{self, Cipher};
        use permaura_core::vault::SecretMetadata;

        let store = SqliteStore::open_in_memory().unwrap();
        store
            .put_secret(SecretRecord {
                id: "sec_dev".into(),
                sealed: crypto::seal(Cipher::Aes256Gcm, crate::service::DEV_VAULT_PASSPHRASE, b"hunter2").unwrap(),
                metadata: SecretMetadata::default(),
            })
            .unwrap();
        let inner = store.lock().unwrap();
        assert_eq!(
            reseal_dev_sealed_secrets(&inner.conn, crate::service::DEV_VAULT_PASSPHRASE).unwrap(),
            0
        );
    }

    /// The store holds every sealed credential, so it must not be readable by other accounts on the
    /// machine. It used to inherit the umask and land 0644 on a default macOS install.
    #[cfg(unix)]
    #[test]
    fn the_store_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("permaura-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gateway.db");
        let p = path.to_str().unwrap();

        // Create it wide open first, the way an old install already on disk looks, so this proves the
        // narrowing happens on OPEN and not only at creation.
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _store = SqliteStore::open(p).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the store must be owner-only, got {mode:o}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every pre-migration copy is a second store with the same contents, and the ones written before
    /// the store itself was tightened are still 0644. Boot is the only thing that ever looks at them
    /// again.
    #[cfg(unix)]
    #[test]
    fn old_pre_migration_backups_are_tightened_on_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("permaura-bkperm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gateway.db");
        let p = path.to_str().unwrap();

        let wide = |name: &str| {
            let f = dir.join(name);
            std::fs::write(&f, b"not really a database").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
            f
        };
        let v0 = wide("gateway.db.backup-v0");
        let v3 = wide("gateway.db.backup-v3");
        let unrelated = wide("notes.txt");

        let _store = SqliteStore::open(p).unwrap();
        let mode = |f: &std::path::Path| std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&v0), 0o600, "an old backup must be tightened on boot");
        assert_eq!(mode(&v3), 0o600, "every old backup, not just the first one found");
        assert_eq!(mode(&unrelated), 0o644, "a file that is not a store backup is left alone");

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── audit key custody in `gateway_meta` (the hosted worker's shape) ─────────

    /// A reversible stand-in for a cloud KMS: XOR is symmetric, so wrap and unwrap round-trip.
    struct XorKms;
    #[async_trait::async_trait]
    impl crate::backend::KmsClient for XorKms {
        async fn decrypt(&self, _key_id: &str, ct: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, GatewayError> {
            Ok(zeroize::Zeroizing::new(ct.iter().map(|b| b ^ 0x5A).collect()))
        }
        async fn encrypt(&self, _key_id: &str, pt: &[u8]) -> Result<Vec<u8>, GatewayError> {
            Ok(pt.iter().map(|b| b ^ 0x5A).collect())
        }
    }

    /// The same, but naming the key version it wrapped under, the way GCP KMS does on an encrypt and
    /// never does on a decrypt.
    pub(super) struct VersionedXorKms {
        pub(super) version: String,
        pub(super) encrypts: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl crate::backend::KmsClient for VersionedXorKms {
        async fn decrypt(&self, _key_id: &str, ct: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, GatewayError> {
            Ok(zeroize::Zeroizing::new(ct.iter().map(|b| b ^ 0x5A).collect()))
        }
        async fn encrypt(&self, key_id: &str, pt: &[u8]) -> Result<Vec<u8>, GatewayError> {
            Ok(self.encrypt_versioned(key_id, pt).await?.ciphertext)
        }
        async fn encrypt_versioned(
            &self,
            _key_id: &str,
            pt: &[u8],
        ) -> Result<crate::backend::WrappedKey, GatewayError> {
            self.encrypts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::backend::WrappedKey {
                ciphertext: pt.iter().map(|b| b ^ 0x5A).collect(),
                key_version: Some(self.version.clone()),
            })
        }
    }

    fn stored_key(path: &str) -> String {
        let conn = Connection::open(path).unwrap();
        conn.query_row("SELECT value FROM gateway_meta WHERE key = ?1", [AUDIT_KEY_META], |r| r.get(0))
            .unwrap()
    }

    /// A `kms:v1:` row records the CMK but not the version the ciphertext actually depends on, and a
    /// destroyed version makes that ciphertext unrecoverable. The version can only be learned from a
    /// wrap, so the upgrade is a rewrap of the same key material on the first open under a CMK. The
    /// chain has to survive it untouched, which is the only part that would be expensive to get
    /// wrong.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kms_v1_wrapped_key_still_opens_and_is_rewritten_as_v2() {
        let dir = custody_dir("kms-v2");
        let path = dir.join("gateway.db").to_string_lossy().to_string();
        let version = "projects/p/locations/l/keyRings/r/cryptoKeys/ws-acme/cryptoKeyVersions/3";

        // A store as a gateway that only knew kms:v1 left it.
        {
            let store =
                SqliteStore::open_with_custody(&path, Some(AuditKeyWrap { kms: Arc::new(XorKms), key_id: "cmk".into(), adopt_plaintext: false }))
                    .unwrap();
            store.append_audit(AuditPayload::new("before", "r", "allow")).unwrap();
        }
        assert!(stored_key(&path).starts_with(KMS_WRAP_PREFIX), "the fixture is a v1 row");

        let kms = Arc::new(VersionedXorKms {
            version: version.into(),
            encrypts: std::sync::atomic::AtomicU64::new(0),
        });
        let store = SqliteStore::open_with_custody(
            &path,
            Some(AuditKeyWrap { kms: kms.clone(), key_id: "cmk".into(), adopt_plaintext: false }),
        )
        .unwrap();
        assert_eq!(store.verify_audit().unwrap(), None, "the chain opens under the same key");
        let next = store.append_audit(AuditPayload::new("after", "r", "allow")).unwrap();
        assert_eq!(next.seq, 1, "and continues, rather than forking onto a fresh key");
        drop(store);

        let rewritten = stored_key(&path);
        assert!(rewritten.starts_with(&format!("{KMS_WRAP_V2_PREFIX}{version}:")), "got: {rewritten}");

        // Reopening reads v2 without rewrapping again: the version is already recorded.
        let before = kms.encrypts.load(std::sync::atomic::Ordering::SeqCst);
        let store =
            SqliteStore::open_with_custody(&path, Some(AuditKeyWrap { kms: kms.clone(), key_id: "cmk".into(), adopt_plaintext: false }))
                .unwrap();
        assert_eq!(store.verify_audit().unwrap(), None);
        assert_eq!(store.audit_events(None).unwrap().len(), 2);
        assert_eq!(
            kms.encrypts.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "a v2 row needs no wrap to read"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A KMS that does not name versions leaves the row exactly where it is. v1 is readable forever,
    /// so there is nothing to gain by rewriting it into a v2 that could not name a version anyway.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kms_that_names_no_version_leaves_the_v1_row_alone() {
        let dir = custody_dir("kms-v1-stays");
        let path = dir.join("gateway.db").to_string_lossy().to_string();
        let wrap = || Some(AuditKeyWrap { kms: Arc::new(XorKms) as Arc<dyn crate::backend::KmsClient>, key_id: "cmk".into(), adopt_plaintext: false });

        {
            let store = SqliteStore::open_with_custody(&path, wrap()).unwrap();
            store.append_audit(AuditPayload::new("a", "r", "allow")).unwrap();
        }
        let first = stored_key(&path);
        let store = SqliteStore::open_with_custody(&path, wrap()).unwrap();
        assert_eq!(store.verify_audit().unwrap(), None);
        drop(store);
        assert_eq!(stored_key(&path), first, "the row is untouched");
        assert!(first.starts_with(KMS_WRAP_PREFIX));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The existing refusal has to cover the new format too: a v2 row with no CMK configured is the
    /// same situation as a v1 one, and starting on a fresh key would orphan the history either way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kms_v2_wrapped_key_with_no_cmk_still_refuses_to_start() {
        let dir = custody_dir("kms-v2-nocmk");
        let path = dir.join("gateway.db").to_string_lossy().to_string();
        let kms = Arc::new(VersionedXorKms {
            version: "projects/p/.../cryptoKeyVersions/1".into(),
            encrypts: std::sync::atomic::AtomicU64::new(0),
        });
        {
            let store =
                SqliteStore::open_with_custody(&path, Some(AuditKeyWrap { kms, key_id: "cmk".into(), adopt_plaintext: false })).unwrap();
            store.append_audit(AuditPayload::new("a", "r", "allow")).unwrap();
        }
        assert!(stored_key(&path).starts_with(KMS_WRAP_V2_PREFIX));

        let err = SqliteStore::open_with_custody(&path, None)
            .err()
            .expect("a wrapped key with no CMK must refuse rather than fork the chain");
        assert!(format!("{err}").contains("refusing to start"), "got: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    fn custody_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("permaura-custody-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Sealed audit-key custody in one test: with a CMK the key is ciphertext in the database, no sidecar is
    /// written, a reopen recovers the same key, and a reopen without the CMK refuses rather than
    /// forking the chain onto a fresh one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn meta_custody_wraps_the_audit_key_and_never_writes_a_sidecar() {
        use std::sync::Arc;
        let dir = custody_dir("wrapped");
        let path = dir.join("gateway.db").to_string_lossy().to_string();
        let wrap = || AuditKeyWrap { kms: Arc::new(XorKms), key_id: "test-cmk".into(), adopt_plaintext: false };

        let store = SqliteStore::open_with_custody(&path, Some(wrap())).unwrap();
        assert_eq!(store.audit_custody().backend, "kms");
        assert!(store.audit_custody().separated_from_records);
        let stored = store.get_meta(AUDIT_KEY_META).unwrap().expect("the key is in gateway_meta");
        assert!(stored.starts_with(KMS_WRAP_PREFIX), "the row holds ciphertext, not the key");
        assert!(!std::path::Path::new(&format!("{path}.auditkey")).exists(), "no sidecar in this mode");
        store.append_audit(AuditPayload::new("first", "r", "allow")).unwrap();
        drop(store);

        let reopened = SqliteStore::open_with_custody(&path, Some(wrap())).unwrap();
        assert_eq!(reopened.verify_audit().unwrap(), None, "same key: the chain still verifies");
        drop(reopened);

        let err = SqliteStore::open_with_custody(&path, None)
            .err()
            .expect("a wrapped key with no CMK must be refused");
        assert!(format!("{err}").contains("KMS-wrapped"), "got {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Without a CMK the key is durable but plainly held, and the store says so rather than claiming
    /// a separation it does not have.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn meta_custody_without_a_cmk_reports_database_custody() {
        let dir = custody_dir("plain");
        let path = dir.join("gateway.db").to_string_lossy().to_string();

        let store = SqliteStore::open_with_custody(&path, None).unwrap();
        assert_eq!(store.audit_custody().backend, "database");
        assert!(!store.audit_custody().separated_from_records);
        store.append_audit(AuditPayload::new("first", "r", "allow")).unwrap();
        drop(store);

        // A CMK arriving to find a plaintext key refuses to adopt it by default. Whoever can write
        // the bucket but cannot use the key can plant a key of their own and re-sign a rewritten
        // history under it, and adopting it would wrap the forger's key and report KMS custody.
        let cmk = |adopt_plaintext| {
            Some(AuditKeyWrap { kms: std::sync::Arc::new(XorKms), key_id: "test-cmk".into(), adopt_plaintext })
        };
        let err = SqliteStore::open_with_custody(&path, cmk(false))
            .err()
            .expect("a plaintext key under a CMK must be refused");
        assert!(format!("{err}").contains("PERMAURA_AUDIT_KEY_ADOPT_PLAINTEXT"), "got {err}");
        assert!(!stored_key(&path).starts_with(KMS_WRAP_PREFIX), "the refusal wrapped nothing");

        // The explicit one-time migration upgrades the row in place, and the events written before it
        // still verify; the next open needs no flag.
        let store = SqliteStore::open_with_custody(&path, cmk(true)).unwrap();
        assert_eq!(store.audit_custody().backend, "kms");
        assert_eq!(store.verify_audit().unwrap(), None);
        drop(store);
        let store = SqliteStore::open_with_custody(&path, cmk(false)).unwrap();
        assert_eq!(store.audit_custody().backend, "kms");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The self-hosted path is untouched: a plain `open` still keeps its key in the `0600` sidecar
    /// and reports file custody.
    #[test]
    fn a_plain_open_still_uses_the_sidecar() {
        let dir = custody_dir("sidecar");
        let path = dir.join("gateway.db").to_string_lossy().to_string();

        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.audit_custody().backend, "file");
        assert!(std::path::Path::new(&format!("{path}.auditkey")).exists(), "the sidecar is still written");
        assert!(store.get_meta(AUDIT_KEY_META).unwrap().is_none(), "and nothing lands in gateway_meta");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `VACUUM INTO` produces a standalone database, which is what makes it safe to upload while the
    /// store is live.
    #[test]
    fn a_snapshot_opens_as_a_store_of_its_own() {
        let dir = custody_dir("snapshot");
        let path = dir.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        store.put_agent(Agent::approved("codex-cli", "Codex CLI", 0)).unwrap();

        let out = dir.join("snap.db");
        store.snapshot_to(&out).unwrap();
        // Twice, because VACUUM INTO refuses an existing target and a retry must still work.
        store.snapshot_to(&out).unwrap();

        assert!(store.size_bytes().unwrap() > 0);
        let copy = SqliteStore::open(&out.to_string_lossy()).unwrap();
        assert_eq!(copy.get_agent("codex-cli").unwrap().unwrap().name, "Codex CLI");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_transaction_commits_together_or_not_at_all() {
        let store = SqliteStore::open(":memory:").unwrap();
        let s: &dyn Store = &store;
        let err = s
            .transaction(|s| {
                s.put_agent(Agent::approved("a", "A", 0))?;
                s.put_agent(Agent::approved("b", "B", 0))?;
                Err::<(), _>(GatewayError::BadRequest("changed my mind".into()))
            })
            .unwrap_err();
        assert!(matches!(err, GatewayError::BadRequest(_)), "the closure's own error comes back: {err}");
        assert!(s.list_agents().unwrap().is_empty(), "nothing from the failed unit remains");
        let n = s
            .transaction(|s| {
                s.put_agent(Agent::approved("a", "A", 0))?;
                s.put_agent(Agent::approved("b", "B", 0))?;
                Ok(s.list_agents()?.len())
            })
            .unwrap();
        assert_eq!(n, 2, "reads inside the unit see its own writes");
        assert_eq!(s.list_agents().unwrap().len(), 2, "and they are there afterwards");
    }

    #[test]
    fn another_threads_write_waits_outside_a_transaction() {
        let store = std::sync::Arc::new(SqliteStore::open(":memory:").unwrap());
        let other = store.clone();
        let handle = std::sync::Mutex::new(None);
        let s: &dyn Store = store.as_ref();
        let err = s
            .transaction(|s| {
                s.put_agent(Agent::approved("mine", "A", 0))?;
                *handle.lock().unwrap() =
                    Some(std::thread::spawn(move || other.put_agent(Agent::approved("theirs", "B", 0))));
                std::thread::sleep(std::time::Duration::from_millis(150));
                assert!(s.get_agent("theirs")?.is_none(), "the other thread's write waited outside the unit");
                Err::<(), _>(GatewayError::BadRequest("abandon".into()))
            })
            .unwrap_err();
        assert!(matches!(err, GatewayError::BadRequest(_)));
        handle.into_inner().unwrap().unwrap().join().unwrap().unwrap();
        assert!(s.get_agent("mine").unwrap().is_none(), "the abandoned write is gone");
        assert!(s.get_agent("theirs").unwrap().is_some(), "the other thread's write landed afterwards, on its own");
    }

    #[test]
    fn an_audit_append_inside_a_transaction_is_refused() {
        let store = SqliteStore::open(":memory:").unwrap();
        let s: &dyn Store = &store;
        let err = s
            .transaction(|s| s.append_audit(AuditPayload::new("x", "r", "allow")).map(|_| ()))
            .unwrap_err();
        assert!(err.to_string().contains("inside a store transaction"), "{err}");
        assert!(s.audit_events(None).unwrap().is_empty());
        s.append_audit(AuditPayload::new("x", "r", "allow")).unwrap();
        assert_eq!(s.audit_events(None).unwrap().len(), 1, "outside a unit it works as before");
    }

    /// A second way to wedge one worker: the usage rebuild held the store's lock while it read the archive, and an archive read is a request whose answer needs a runtime worker.
    /// A store call that waited for the lock parked the only worker, so the read never finished and nothing else did either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_caller_waiting_out_a_rebuild_does_not_park_the_only_worker() {
        struct SlowArchive {
            started: Option<std::sync::mpsc::Sender<()>>,
            release: tokio::sync::watch::Receiver<bool>,
        }
        impl Iterator for SlowArchive {
            type Item = Result<AuditEvent, GatewayError>;
            fn next(&mut self) -> Option<Self::Item> {
                if let Some(started) = self.started.take() {
                    let _ = started.send(());
                    let mut release = self.release.clone();
                    crate::store::bridge::block_on(async move {
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
                            _ = release.wait_for(|r| *r) => {}
                        }
                    });
                }
                None
            }
        }

        let store = Arc::new(SqliteStore::open(":memory:").unwrap());
        let (started, started_rx) = std::sync::mpsc::channel();
        let (release, release_rx) = tokio::sync::watch::channel(false);
        let (done, finished) = std::sync::mpsc::channel::<&str>();
        let (s, d) = (store.clone(), done.clone());
        // On a blocking thread, as `POST /v1/grants/rebuild-usage` runs it.
        tokio::task::spawn_blocking(move || {
            s.rebuild_grant_usage(&mut SlowArchive { started: Some(started), release: release_rx })
                .expect("the rebuild completes");
            let _ = d.send("rebuild");
        });
        started_rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the archive read started");
        let (s, d) = (store.clone(), done);
        tokio::spawn(async move {
            s.list_agents().expect("the read answers");
            let _ = d.send("read");
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut answered = Vec::new();
        while answered.len() < 2 {
            match finished.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
                Ok(who) => answered.push(who),
                Err(_) => break,
            }
        }
        release.send_replace(true);
        assert_eq!(answered.len(), 2, "the worker wedged: only {answered:?} answered within 5 s");
    }

    /// `depth` arrays nested inside one another around a string.
    fn nested(depth: usize) -> serde_json::Value {
        (0..depth).fold(serde_json::json!("leaf"), |inner, _| serde_json::json!([inner]))
    }

    fn depth_of(v: &serde_json::Value) -> usize {
        match v {
            serde_json::Value::Array(items) => 1 + items.iter().map(depth_of).max().unwrap_or(0),
            serde_json::Value::Object(map) => 1 + map.values().map(depth_of).max().unwrap_or(0),
            _ => 0,
        }
    }

    /// An upstream body nested 127 levels parses (serde_json's limit is 128), and nested
    /// one level deeper as a row's `result` it used to be written and never read back: every listing
    /// of the approvals table failed from then on.
    #[test]
    fn a_result_nested_127_deep_is_stored_readable() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut settled = approval("appr_deep", "approved");
        settled.result = Some(nested(127).into());
        store.put_approval(settled).unwrap();
        store.put_approval(approval("appr_next", "pending")).unwrap();

        let read = store.get_approval("appr_deep").expect("the row reads back").expect("and is there");
        let result = read.result.expect("the result is kept, cut short").to_value_unbounded();
        assert!(depth_of(&result) <= crate::store::MAX_STORED_RESULT_DEPTH, "depth {}", depth_of(&result));
        assert!(result.to_string().contains("omitted"), "the cut is marked: {result}");
        let listed = store.list_approvals(None).expect("the table still lists");
        assert_eq!(listed.len(), 2);
        assert_eq!(store.list_approvals(Some("pending")).unwrap().len(), 1);
    }

    /// A result bigger than a stored approval keeps is replaced by a marker naming its size.
    #[test]
    fn an_oversized_result_is_stored_as_a_marker() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut settled = approval("appr_big", "approved");
        settled.result = Some(serde_json::json!({ "blob": "x".repeat(crate::store::MAX_STORED_RESULT_BYTES) }).into());
        store.put_approval(settled).unwrap();
        let result = store.get_approval("appr_big").unwrap().unwrap().result.unwrap();
        assert!(result.to_string().len() < 1024, "the body is not stored");
        assert!(result.to_string().contains("omitted"), "{result}");
    }

    /// The SQL status filters pass over a row that is not JSON, and the control-plane listing skips a row it cannot read, as the whole listing always has, so neither takes the hold path, the sweep or boot settlement down.
    #[test]
    fn a_row_nothing_can_read_does_not_fail_the_filtered_reads() {
        let store = SqliteStore::open_in_memory().unwrap();
        let control_plane = |id: &str| {
            let mut a = approval(id, "pending");
            a.session_id = String::new();
            a.resource = crate::store::CONTROL_PLANE_RESOURCE.into();
            a
        };
        store.put_approval(approval("appr_agent", "pending")).unwrap();
        store.put_approval(control_plane("appr_change")).unwrap();
        let mut unreadable = serde_json::to_value(control_plane("appr_unreadable")).unwrap();
        unreadable["required_signatures"] = nested(127);
        let insert = |id: &str, data: String| {
            store.lock().unwrap().conn.execute("INSERT INTO approvals (id, data) VALUES (?1, ?2)", rusqlite::params![id, data]).unwrap();
        };
        insert("appr_unreadable", unreadable.to_string());
        insert("appr_not_json", "{not json".into());

        let pending: Vec<String> = store.list_approvals(Some("pending")).expect("the pending listing").into_iter().map(|a| a.id).collect();
        assert_eq!(pending.len(), 2, "{pending:?}");
        let holds: Vec<String> =
            store.list_pending_control_plane_holds().expect("the control-plane listing").into_iter().map(|a| a.id).collect();
        assert_eq!(holds, vec!["appr_change".to_string()]);
        assert!(store.pending_hold_bytes().expect("the agent hold sum") > 0);
        assert!(store.pending_control_plane_hold_bytes().expect("the control-plane hold sum") > 0);
        assert_eq!(store.count_pending_approvals().expect("the pending count"), 3, "the unreadable hold still counts toward the ceiling");
        store.put_approval(approval("appr_next", "pending")).expect("a new hold is written");
    }

    /// The owners of staged rows come from the two fields the bound reads, never from deserializing every hold, and only pending control-plane holds that name a staged row count.
    #[test]
    fn staging_owners_are_read_without_deserializing_each_hold() {
        let store = SqliteStore::open_in_memory().unwrap();
        let hold = |id: &str, status: &str, staged: Option<&str>, person: Option<&str>| {
            let mut a = approval(id, status);
            a.session_id = String::new();
            a.resource = crate::store::CONTROL_PLANE_RESOURCE.into();
            a.params = staged.map_or(serde_json::json!({ "mutation": "policy" }), |s| serde_json::json!({ "staging_secret_id": s })).into();
            a.requested_by = person.map(|p| crate::store::HoldRequester { person: Some(p.into()), ..Default::default() });
            a
        };
        store.put_approval(hold("appr_mine", "pending", Some("sec:staging:a"), Some("user_a"))).unwrap();
        store.put_approval(hold("appr_nobody", "pending", Some("sec:staging:b"), None)).unwrap();
        store.put_approval(hold("appr_resolved", "approved", Some("sec:staging:c"), Some("user_a"))).unwrap();
        store.put_approval(hold("appr_policy", "pending", None, Some("user_a"))).unwrap();
        let mut agent_call = approval("appr_agent", "pending");
        agent_call.params = serde_json::json!({ "staging_secret_id": "sec:staging:d" }).into();
        store.put_approval(agent_call).unwrap();
        let mut unreadable = serde_json::to_value(hold("appr_unreadable", "pending", Some("sec:staging:e"), Some("user_b"))).unwrap();
        unreadable["required_signatures"] = nested(127);
        let conn = |sql: &str, id: &str, data: String| {
            store.lock().unwrap().conn.execute(sql, rusqlite::params![id, data]).unwrap();
        };
        conn("INSERT INTO approvals (id, data) VALUES (?1, ?2)", "appr_unreadable", unreadable.to_string());
        conn("INSERT INTO approvals (id, data) VALUES (?1, ?2)", "appr_not_json", "{not json".into());
        assert!(
            store.list_approvals(Some("pending")).unwrap().iter().all(|a| a.id != "appr_unreadable"),
            "the listing cannot deserialize that row"
        );

        let mut owners = store.pending_staging_owners().expect("a row that is not JSON does not fail the read");
        owners.sort_by(|a, b| a.0.cmp(&b.0));
        let person = |p: &str| Some(crate::store::HoldRequester { person: Some(p.into()), ..Default::default() });
        assert_eq!(
            owners,
            vec![
                ("sec:staging:a".to_string(), person("user_a")),
                ("sec:staging:b".to_string(), None),
                ("sec:staging:e".to_string(), person("user_b")),
            ],
            "the unreadable hold's row is still charged to its requester, read from the two fields alone"
        );
    }

    /// A result under the size bound whose cut would be over it (a marker is many times the `[]` it replaces) is stored as the size marker, without the cut ever being written.
    #[test]
    fn a_result_whose_cut_would_be_too_large_is_stored_as_a_marker() {
        let store = SqliteStore::open_in_memory().unwrap();
        let depth = crate::store::MAX_STORED_RESULT_DEPTH;
        let siblings = crate::store::MAX_STORED_RESULT_BYTES / 40;
        let text = format!("{}{}{}", "[".repeat(depth), vec!["[]"; siblings].join(","), "]".repeat(depth));
        assert!(text.len() < crate::store::MAX_STORED_RESULT_BYTES);
        let mut settled = approval("appr_wide", "approved");
        settled.result = Some(permaura_core::JsonText::from_string(text).unwrap());
        store.put_approval(settled).unwrap();
        let result = store.get_approval("appr_wide").unwrap().unwrap().result.unwrap().to_value_unbounded();
        assert!(result["omitted"].as_str().is_some_and(|m| m.contains("more than a stored approval keeps")), "{result}");
        assert!(result["bytes"].as_u64().unwrap() > crate::store::MAX_STORED_RESULT_BYTES as u64, "names the cut's size: {result}");
    }

    /// A row already written that this build cannot read (written before the bound, or by anything
    /// else) is skipped by the listing rather than failing it for every row and every status.
    #[test]
    fn an_unreadable_approval_row_is_skipped_not_fatal() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.put_approval(approval("appr_ok", "pending")).unwrap();
        let mut poisoned = serde_json::to_value(approval("appr_poisoned", "approved")).unwrap();
        // A result is kept as its text now, so however deep it nests the row reads; a field read as a type is what can still make a row unreadable.
        poisoned["required_signatures"] = nested(127);
        store
            .lock()
            .unwrap()
            .conn
            .execute(
                "INSERT INTO approvals (id, data) VALUES (?1, ?2)",
                rusqlite::params!["appr_poisoned", poisoned.to_string()],
            )
            .unwrap();

        let listed = store.list_approvals(None).expect("one unreadable row does not fail the listing");
        assert_eq!(listed.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), vec!["appr_ok"]);
        assert_eq!(store.list_approvals(Some("pending")).unwrap().len(), 1);
        assert!(store.get_approval("appr_poisoned").is_err(), "a read of that row by id still says so");
    }
}

/// The boundary record: where a store's hot window starts, and what happens when the events and the
/// boundary disagree about it. Nothing here prunes anything, since the archive writer does not exist
/// yet, so these drive the store into the shapes a prune will produce and check it reads them back.
#[cfg(test)]
mod boundary_tests {
    use super::*;
    use permaura_core::AuditPayload;
    use std::sync::Arc;

    fn dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("permaura-boundary-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The sidecar key, so a test can sign a boundary the way the archive writer will.
    fn audit_key(path: &str) -> SigningKey {
        let bytes = std::fs::read(format!("{path}.auditkey")).expect("the sidecar key");
        SigningKey::from_bytes(&<[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes"))
    }

    fn stored_boundary(path: &str) -> AuditBoundary {
        let conn = Connection::open(path).unwrap();
        let value: String = conn
            .query_row("SELECT value FROM gateway_meta WHERE key = ?1", [AUDIT_BOUNDARY_META], |r| r.get(0))
            .unwrap();
        serde_json::from_str(&value).unwrap()
    }

    fn write_boundary(path: &str, boundary: &AuditBoundary) {
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO gateway_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![AUDIT_BOUNDARY_META, serde_json::to_string(boundary).unwrap()],
        )
        .unwrap();
    }

    /// Everything below `end_seq` leaves the table, and the boundary is re-signed to say so: the
    /// shape slice 9's prune will produce, made by hand so the reader can be tested before the
    /// writer exists.
    fn prune_below(path: &str, end_seq: u64, base_hash: &str) {
        let conn = Connection::open(path).unwrap();
        conn.execute("DELETE FROM audit_events WHERE seq <= ?1", [end_seq as i64]).unwrap();
        drop(conn);
        let boundary =
            AuditBoundary::create(&audit_key(path), 0, end_seq + 1, base_hash, None, super::super::now_ms());
        write_boundary(path, &boundary);
    }

    fn append_n(store: &SqliteStore, n: usize) {
        for i in 0..n {
            store.append_audit(AuditPayload::new(format!("a{i}"), "r", "allow")).unwrap();
        }
    }

    #[test]
    fn a_store_with_no_boundary_row_migrates_to_base_seq_zero() {
        let d = dir("migrate");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        // A store as v5 left it: every table but no boundary row, stamped one version back.
        {
            let conn = Connection::open(&path).unwrap();
            super::super::migrations::run(&conn, Some(&path)).unwrap();
            conn.execute("DELETE FROM gateway_meta WHERE key = ?1", [AUDIT_BOUNDARY_META]).unwrap();
            conn.pragma_update(None, "user_version", 5).unwrap();
        }

        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 2);
        assert_eq!(store.audit_events(None).unwrap()[0].seq, 0);
        assert_eq!(store.verify_audit().unwrap(), None);
        drop(store);

        let conn = Connection::open(&path).unwrap();
        assert_eq!(super::super::migrations::user_version(&conn).unwrap(), super::super::migrations::SCHEMA_VERSION);
        drop(conn);
        assert_eq!(stored_boundary(&path), AuditBoundary::genesis(), "and it means what it always meant");

        std::fs::remove_dir_all(&d).ok();
    }

    /// The load-bearing one for the archive: with a base, the window is only the rows at or above
    /// it, the chain links to the base hash rather than genesis, and the next append continues at
    /// the absolute sequence rather than restarting.
    #[test]
    fn a_pruned_store_continues_the_chain_from_its_base() {
        let d = dir("based");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 10);
        let events = store.audit_events(None).unwrap();
        let base_hash = events[3].hash.clone();
        let head_hash = events[9].hash.clone();
        drop(store);

        prune_below(&path, 3, &base_hash);

        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.audit_boundary().unwrap().unwrap().base_seq, 4);
        let window = store.audit_events(None).unwrap();
        assert_eq!(window.len(), 6, "only the rows at or above the base are the window");
        assert_eq!(window[0].seq, 4);
        assert_eq!(window[0].prev_hash, base_hash, "the oldest held event links to the base hash");
        assert_eq!(window[5].hash, head_hash);
        assert_eq!(store.verify_audit().unwrap(), None, "the window verifies against the base, not genesis");

        let next = store.append_audit(AuditPayload::new("after", "r", "allow")).unwrap();
        assert_eq!(next.seq, 10, "the sequence is absolute, so it continues past the pruned events");
        assert_eq!(next.prev_hash, head_hash);
        assert_eq!(store.verify_audit().unwrap(), None);
        drop(store);

        // And it survives another open, which is the only way a hosted worker ever sees it.
        let reopened = SqliteStore::open(&path).unwrap();
        assert_eq!(reopened.verify_audit().unwrap(), None);
        assert_eq!(reopened.audit_events(Some(1)).unwrap()[0].seq, 10);

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn load_audit_events_reads_only_from_the_boundary() {
        let d = dir("window");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 6);
        let base_hash = store.audit_events(None).unwrap()[1].hash.clone();
        drop(store);

        // The rows below the base are still in the table: the boundary alone decides the window, so
        // an archive writer that publishes before it prunes cannot make the chain read twice.
        let boundary = AuditBoundary::create(&audit_key(&path), 0, 2, &base_hash, None, 1);
        write_boundary(&path, &boundary);

        let store = SqliteStore::open(&path).unwrap();
        let window = store.audit_events(None).unwrap();
        assert_eq!(window.len(), 4);
        assert_eq!(window[0].seq, 2);
        assert_eq!(store.verify_audit().unwrap(), None);

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_hole_below_the_boundary_is_a_hard_failure_not_a_shift() {
        let d = dir("hole");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 6);
        drop(store);

        // A prune that took one event too few: the boundary says 2, the rows start at 3.
        let base_hash = permaura_core::GENESIS_PREV_HASH;
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_events WHERE seq <= 2", []).unwrap();
        drop(conn);
        write_boundary(&path, &AuditBoundary::create(&audit_key(&path), 0, 2, base_hash, None, 1));

        let err = SqliteStore::open(&path).err().expect("a store whose boundary and events disagree must not open");
        assert!(format!("{err}").contains("hole in it"), "got: {err}");

        // A hole in the middle of the window fails the same way.
        write_boundary(&path, &AuditBoundary::genesis());
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_events", []).unwrap();
        drop(conn);
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 5);
        drop(store);
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_events WHERE seq = 2", []).unwrap();
        drop(conn);
        let err = SqliteStore::open(&path).err().expect("a store whose boundary and events disagree must not open");
        assert!(format!("{err}").contains("hole in it"), "got: {err}");

        std::fs::remove_dir_all(&d).ok();
    }

    /// An append whose write fails (here a trigger standing in for `SQLITE_FULL`) must not move the chain, or the next append writes above a hole and the store never opens again.
    #[test]
    fn a_failed_audit_write_leaves_no_hole_for_the_next_open() {
        let d = dir("failed-write");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 3);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER disk_full BEFORE INSERT ON audit_events WHEN NEW.seq = 3 \
             BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
        )
        .unwrap();
        store
            .append_audit(AuditPayload::new("cap.x", "res", "allow"))
            .expect_err("the write the trigger refuses fails the append");
        conn.execute_batch("DROP TRIGGER disk_full;").unwrap();
        drop(conn);
        let next = store.append_audit(AuditPayload::new("cap.x", "res", "allow")).unwrap();
        assert_eq!(next.seq, 3, "the chain stayed where the rows are");
        drop(store);

        let reopened = SqliteStore::open(&path).expect("the store opens after a failed write");
        assert_eq!(reopened.audit_events_from(0, 100).unwrap().len(), 4);
        std::fs::remove_dir_all(&d).ok();
    }

    /// Rewinding a pruned store's boundary to genesis is the obvious way to try to hide a prune, and
    /// it does not work: the window would have to start at seq 0 and those rows are the ones gone.
    #[test]
    fn a_boundary_rewound_to_genesis_cannot_hide_a_prune() {
        let d = dir("rewind");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 6);
        let base_hash = store.audit_events(None).unwrap()[2].hash.clone();
        drop(store);
        prune_below(&path, 2, &base_hash);
        write_boundary(&path, &AuditBoundary::genesis());

        let err = SqliteStore::open(&path).err().expect("a store whose boundary and events disagree must not open");
        assert!(format!("{err}").contains("hole in it"), "got: {err}");

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_tampered_boundary_signature_refuses_to_open() {
        let d = dir("tampered");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 6);
        let base_hash = store.audit_events(None).unwrap()[2].hash.clone();
        drop(store);
        prune_below(&path, 2, &base_hash);

        // The base moved under a signature that covers where it used to be.
        let mut boundary = stored_boundary(&path);
        boundary.base_seq += 1;
        write_boundary(&path, &boundary);
        let err = SqliteStore::open(&path).err().expect("a store whose boundary and events disagree must not open");
        assert!(format!("{err}").contains("does not verify"), "got: {err}");

        // Stripping the signature instead is refused too, because the boundary still claims a base.
        let mut boundary = stored_boundary(&path);
        boundary.signature = String::new();
        write_boundary(&path, &boundary);
        let err = SqliteStore::open(&path).err().expect("a store whose boundary and events disagree must not open");
        assert!(format!("{err}").contains("no signature"), "got: {err}");

        std::fs::remove_dir_all(&d).ok();
    }

    /// The genesis boundary is accepted whatever its signature says, because it claims nothing. A
    /// `VACUUM INTO` copy of a sidecar-custody store opens under a key of its own and depends on it.
    #[test]
    fn a_genesis_boundary_needs_no_signature_to_be_believed() {
        let d = dir("genesis");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 2);
        drop(store);

        let mut boundary = AuditBoundary::create(&SigningKey::generate(&mut rand::rngs::OsRng), 0, 0, permaura_core::GENESIS_PREV_HASH, None, 1);
        boundary.signature = hex_signature_of_the_wrong_key();
        write_boundary(&path, &boundary);

        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.audit_events(None).unwrap().len(), 2);
        assert_eq!(store.verify_audit().unwrap(), None);

        std::fs::remove_dir_all(&d).ok();
    }

    /// The signing-order trap, and the only proof that matters: a store whose epoch has been forked
    /// still opens, which it only does when the re-signed boundary verifies under the key the next
    /// open resolves.
    #[test]
    fn a_forked_epoch_still_verifies_when_the_store_is_reopened() {
        let d = dir("fork");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        append_n(&store, 3);
        assert_eq!(store.audit_epoch().unwrap(), Some(0));
        assert!(store.fork_audit_epoch(1, "hold-test").unwrap(), "the fork moves the epoch");
        assert_eq!(store.audit_epoch().unwrap(), Some(1), "and this process sees it immediately");
        drop(store);

        let stored = stored_boundary(&path);
        assert_eq!(stored.epoch, 1);
        assert!(stored.verify(&audit_key(&path).verifying_key()), "signed under the store's own key");

        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.audit_epoch().unwrap(), Some(1));
        assert_eq!(store.audit_events(None).unwrap().len(), 3, "the window is untouched by a fork");
        assert_eq!(store.verify_audit().unwrap(), None);
        assert_eq!(store.append_audit(AuditPayload::new("after", "r", "allow")).unwrap().seq, 3);

        std::fs::remove_dir_all(&d).ok();
    }

    /// A fork names the epoch it wants rather than asking for one more, so the retry a crashed
    /// reconciliation makes cannot leave two epochs describing one fork.
    #[test]
    fn forking_to_the_epoch_already_in_force_changes_nothing() {
        let d = dir("fork-idempotent");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        assert!(store.fork_audit_epoch(1, "hold-test").unwrap());
        let first = stored_boundary(&path);
        assert!(!store.fork_audit_epoch(1, "hold-test").unwrap(), "asking again is not a second fork");
        assert_eq!(stored_boundary(&path), first, "and it does not even re-sign");

        let err = store.fork_audit_epoch(0, "hold-test").unwrap_err();
        assert!(err.to_string().contains("backwards"), "{err}");
        assert_eq!(store.audit_epoch().unwrap(), Some(1));

        std::fs::remove_dir_all(&d).ok();
    }

    /// A `:memory:` store generates its audit key per process, so a boundary signed under it would
    /// verify exactly once and refuse every later open of those bytes. It refuses rather than
    /// writing one.
    #[test]
    fn a_store_with_no_persisted_audit_key_refuses_to_fork() {
        let store = SqliteStore::open(":memory:").unwrap();
        let err = store.fork_audit_epoch(1, "hold-test").unwrap_err();
        assert!(err.to_string().contains("persisted audit key"), "{err}");
        assert_eq!(store.audit_epoch().unwrap(), Some(0), "and nothing moved");
    }

    /// What reconciliation deletes, deleted: sessions leave rather than being marked, and an
    /// unredeemed enrolment code leaves while a spent marker stays.
    #[test]
    fn a_restore_clears_sessions_and_unconsumed_enrolment_codes() {
        let d = dir("invalidate");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        let store = SqliteStore::open(&path).unwrap();
        for id in ["s1", "s2"] {
            store
                .put_session(crate::store::Session {
                    class: Default::default(),
                    opened_by: None,
                    id: id.into(),
                    agent_id: "a".into(),
                    user_id: None,
                    device_id: None,
                    token: format!("tok-{id}"),
                    role: crate::store::SessionRole::Operator,
                    created_at: 0,
                    revoked: false,
                    expires_at: None,
                    last_used_at: None,
                    actor: None,
                })
                .unwrap();
        }
        let code = |c: &str, used: bool| crate::store::EnrolmentCode {
            code: c.into(),
            label: None,
            created_at: 0,
            expires_at: i64::MAX,
            used,
        };
        store.put_enrolment_code(code("live", false)).unwrap();
        store.put_enrolment_code(code("spent", true)).unwrap();

        assert_eq!(store.delete_live_sessions().unwrap(), 2);
        assert!(store.list_sessions().unwrap().is_empty(), "deleted, not revoked");
        assert_eq!(store.delete_unconsumed_enrolment_codes().unwrap(), 1);
        assert!(
            store.consume_enrolment_code("live", 1).unwrap().is_none(),
            "the unredeemed code is gone"
        );
        assert!(
            store.consume_enrolment_code("spent", 1).unwrap().is_none(),
            "and the spent marker still refuses a second redemption"
        );

        std::fs::remove_dir_all(&d).ok();
    }


    /// Whether a code would redeem is read without redeeming it, on every store, and agrees with the redemption: live until it is used or expires, never for a code nobody minted.
    #[test]
    fn whether_a_code_would_redeem_is_read_without_redeeming_it() {
        let d = std::env::temp_dir().join(format!("pm-redeemable-{}-{}", std::process::id(), crate::service::short_id()));
        std::fs::create_dir_all(&d).unwrap();
        let stores: Vec<Box<dyn Store>> = vec![
            Box::new(crate::store::memory::MemoryStore::new()),
            Box::new(SqliteStore::open(d.join("g.db").to_str().unwrap()).unwrap()),
        ];
        for store in stores {
            let kind = store.kind();
            store
                .put_enrolment_code(crate::store::EnrolmentCode {
                    code: "ENRL-LIVE-0000-0000-0000".into(),
                    label: None,
                    created_at: 0,
                    expires_at: 1_000,
                    used: false,
                })
                .unwrap();
            assert!(store.enrolment_code_redeemable("ENRL-LIVE-0000-0000-0000", 10).unwrap(), "{kind}");
            assert!(store.enrolment_code_redeemable("ENRL-LIVE-0000-0000-0000", 10).unwrap(), "{kind}: asking redeems nothing");
            assert!(!store.enrolment_code_redeemable("ENRL-LIVE-0000-0000-0000", 1_000).unwrap(), "{kind}: expired");
            assert!(!store.enrolment_code_redeemable("ENRL-NONE-0000-0000-0000", 10).unwrap(), "{kind}: never minted");
            let stored = crate::store::bearer_lookup_hash("ENRL-LIVE-0000-0000-0000");
            assert!(!store.enrolment_code_redeemable(&stored, 10).unwrap(), "{kind}: the stored digest is not the code");
            assert_eq!(store.live_enrolment_code_digests(10).unwrap(), vec![stored.clone()], "{kind}: the bearer proof's list agrees");
            assert!(store.live_enrolment_code_digests(1_000).unwrap().is_empty(), "{kind}: expired");
            assert!(store.consume_enrolment_code("ENRL-LIVE-0000-0000-0000", 10).unwrap().is_some(), "{kind}");
            assert!(!store.enrolment_code_redeemable("ENRL-LIVE-0000-0000-0000", 10).unwrap(), "{kind}: spent");
            assert!(store.live_enrolment_code_digests(10).unwrap().is_empty(), "{kind}: spent");
        }
        std::fs::remove_dir_all(&d).ok();
    }

    // ── the materialised grant usage counter ──────────────────────────────────────────────────

    /// A history wide enough that a filter with any one clause wrong would diverge: four period
    /// kinds, events inside and outside every window, decisions that must not charge, a grant id
    /// nothing matches, and events with no agent on them at all.
    ///
    /// Deliberately the same shape as `grant_usage_tests::history` in `service.rs`, which is what
    /// the in-place tally was proved against when it replaced the clone. The point of repeating it
    /// here is that this one goes through real SQL.
    /// File every charge in `events` at the event's own timestamp, then fold, which is what a
    /// rebuild does with a history. Not the rebuild itself: these events are unchained and were never
    /// archived, and the rebuild refuses anything but a chain that ends where the boundary starts.
    fn file_history(store: &SqliteStore, events: &[AuditEvent]) -> u64 {
        let inner = store.lock().unwrap();
        let tx = inner.conn.unchecked_transaction().unwrap();
        let mut filed = 0u64;
        for event in events {
            if let Some(grant_id) = crate::store::charged_grant(event) {
                file_grant_charge(&tx, grant_id, crate::store::charge_agent(&event.payload), event.timestamp)
                    .unwrap();
                filed += 1;
            }
        }
        tx.commit().unwrap();
        compact_grant_usage(&inner.conn, crate::store::now_ms()).unwrap();
        filed
    }

    fn charged_history(now: i64) -> Vec<AuditEvent> {
        let day = 86_400_000i64;
        let mut events: Vec<AuditEvent> = Vec::new();
        let mut push = |ts: i64, decision: &str, grant: Option<&str>, agent: Option<&str>| {
            let mut payload = AuditPayload::new("conn.act", "conn", decision);
            payload.agent_id = agent.map(str::to_string);
            payload.summary = match grant {
                Some(id) => serde_json::json!({ "grant_id": id, "status": 200 }),
                None => serde_json::json!({ "status": 200 }),
            };
            events.push(AuditEvent {
                seq: events.len() as u64,
                timestamp: ts,
                prev_hash: permaura_core::GENESIS_PREV_HASH.to_string(),
                payload,
                hash: String::new(),
                signature: String::new(),
            });
        };
        for (offset, agent) in [(400 * day, "a1"), (40 * day, "a2"), (3 * day, "a1"), (0, "a2")] {
            for g in ["g_total", "g_day", "g_week", "g_month"] {
                push(now - offset, "allow", Some(g), Some(agent));
                push(now - offset, "approved", Some(g), Some(agent));
                push(now - offset, "deny", Some(g), Some(agent));
                push(now - offset, "attempt", Some(g), Some(agent));
                push(now - offset, "error", Some(g), Some(agent));
                push(now - offset, "requires_approval", Some(g), Some(agent));
            }
            push(now - offset, "allow", None, Some(agent));
            push(now - offset, "allow", Some("g_deleted"), Some(agent));
        }
        push(now, "allow", Some("g_total"), None);
        push(now - day, "allow", Some("g_day"), None);
        push(now - day, "allow", Some("g_day"), Some("a1"));
        push(now - 7 * day, "allow", Some("g_week"), Some("a1"));
        events
    }

    /// Every window kind the engine can ask about, against one `now`.
    fn usage_windows(now: i64) -> Vec<(&'static str, i64)> {
        let day = 86_400_000i64;
        vec![
            ("g_total", i64::MIN),
            ("g_day", now - day),
            ("g_week", now - 7 * day),
            ("g_month", now - 30 * day),
            ("g_unused", now - day),
        ]
    }

    /// The load-bearing test for the materialised counter: it and the audit scan it replaced answer identically,
    /// for every grant, every agent and every period kind, over a generated history.
    ///
    /// The comparison is against `tally_grant_usage`, which is the shipped in-place filter, so this
    /// is a differential test against the behaviour in production rather than against a restatement
    /// of the new one.
    #[test]
    fn the_usage_counter_and_an_audit_scan_agree_before_any_prune() {
        // The wall clock rather than a fixed instant: the rebuild folds against `now`, so a history
        // pinned to a date in the past would arrive already folded and the rolling windows would be
        // comparing a compacted table against an uncompacted scan.
        let now = crate::store::now_ms();
        let events = charged_history(now);
        let store = SqliteStore::open_in_memory().unwrap();
        // Filed through `file_grant_charge`, which is the same call a live append uses, at a
        // timestamp the test chose rather than at the clock.
        let filed = file_history(&store, &events);
        assert!(filed > 0, "the generated history must actually charge something");

        for (grant_id, since_ms) in usage_windows(now) {
            let window = crate::store::GrantWindow { grant_id, since_ms };
            let counted = store.read_grant_usage(std::slice::from_ref(&window)).unwrap();
            let scanned = crate::store::tally_grant_usage(std::slice::from_ref(&window), events.iter());
            assert_eq!(
                counted.total(grant_id),
                scanned.total(grant_id),
                "grant total for {grant_id}"
            );
            for agent in ["a1", "a2", "never-seen"] {
                assert_eq!(
                    counted.agent(grant_id, agent),
                    scanned.agent(grant_id, agent),
                    "per-agent count for {grant_id}/{agent}"
                );
            }
        }
    }

    /// The counter is charged by the append itself, so a store driven through its own API reaches
    /// the same answer as a scan of the chain that append produced.
    #[test]
    fn a_charged_append_and_an_audit_scan_agree() {
        let store = SqliteStore::open_in_memory().unwrap();
        for (decision, grant, agent) in [
            ("allow", Some("g1"), Some("a1")),
            ("allow", Some("g1"), Some("a2")),
            ("approved", Some("g1"), Some("a1")),
            ("allow", Some("g2"), None),
            ("deny", Some("g1"), Some("a1")),
            ("allow", None, Some("a1")),
        ] {
            let mut payload = AuditPayload::new("conn.act", "conn", decision);
            payload.agent_id = agent.map(str::to_string);
            if let Some(id) = grant {
                payload.summary = serde_json::json!({ "grant_id": id });
            }
            // Exactly the rule `TerminalEvent::append` applies: an allow or approved carrying a
            // grant id charges, and nothing else does.
            let charge = match (decision, grant) {
                ("allow" | "approved", Some(id)) => Some(crate::store::GrantCharge::new(id)),
                _ => None,
            };
            store.append_audit_charged(payload, charge).unwrap();
        }
        let windows = [
            crate::store::GrantWindow { grant_id: "g1", since_ms: i64::MIN },
            crate::store::GrantWindow { grant_id: "g2", since_ms: i64::MIN },
        ];
        let counted = store.read_grant_usage(&windows).unwrap();
        let scanned = store.count_grant_usage(&windows).unwrap();
        assert_eq!(counted, scanned, "the counter and the chain agree event for event");
        assert_eq!(counted.total("g1"), 3);
        assert_eq!(counted.agent("g1", "a1"), 2);
        assert_eq!(counted.total("g2"), 1, "a charge with no agent counts towards the grant");
        assert_eq!(counted.agent("g2", ""), 0, "and towards no agent");
    }

    /// The security property, as far as commit 1 can state it: a `Period::Total` budget is not a
    /// property of the hot window, so it is unchanged when the events that charged it are not in it.
    ///
    /// The prune that actually removes them arrives with the archive writer, and
    /// `a_total_period_grant_keeps_its_budget_across_a_prune` asserts the same thing through it.
    /// Here the hot window is empty from the start and the whole history is filed straight into the
    /// counter, which is the state a pruned store reopens into.
    #[test]
    fn a_total_period_grant_keeps_its_budget_when_its_events_are_not_in_the_hot_window() {
        let now = crate::store::now_ms();
        let events = charged_history(now);
        let store = SqliteStore::open_in_memory().unwrap();
        file_history(&store, &events);

        let window = crate::store::GrantWindow { grant_id: "g_total", since_ms: i64::MIN };
        let counted = store.read_grant_usage(std::slice::from_ref(&window)).unwrap();
        let scanned = crate::store::tally_grant_usage(std::slice::from_ref(&window), events.iter());
        assert_eq!(counted.total("g_total"), scanned.total("g_total"));
        assert!(counted.total("g_total") > 0);
        assert_eq!(
            store.count_grant_usage(std::slice::from_ref(&window)).unwrap().total("g_total"),
            0,
            "the hot window holds none of them, which is exactly how a scan would widen the grant"
        );
    }

    /// The fold keeps the table proportional to the live windows without changing a single answer:
    /// a row past the detail horizon moves to `period_start = 0`, which every `Total` read counts
    /// and no rolling window can reach.
    #[test]
    fn folding_a_charge_past_its_detail_window_changes_no_answer() {
        let now = crate::store::now_ms();
        let events = charged_history(now);
        let store = SqliteStore::open_in_memory().unwrap();
        // Filed straight rather than through the rebuild, which folds as its last act: the whole
        // point here is to read the table before and after the fold.
        {
            let inner = store.lock().unwrap();
            for event in &events {
                if let Some(grant_id) = crate::store::charged_grant(event) {
                    super::file_grant_charge(
                        &inner.conn,
                        grant_id,
                        crate::store::charge_agent(&event.payload),
                        event.timestamp,
                    )
                    .unwrap();
                }
            }
        }

        let before: Vec<_> = usage_windows(now)
            .into_iter()
            .map(|(g, since)| {
                let w = crate::store::GrantWindow { grant_id: g, since_ms: since };
                store.read_grant_usage(std::slice::from_ref(&w)).unwrap()
            })
            .collect();
        let inner = store.lock().unwrap();
        let folded = super::compact_grant_usage(&inner.conn, now).unwrap();
        drop(inner);
        assert!(folded > 0, "the history reaches 400 days back, so something must fold");

        let after: Vec<_> = usage_windows(now)
            .into_iter()
            .map(|(g, since)| {
                let w = crate::store::GrantWindow { grant_id: g, since_ms: since };
                store.read_grant_usage(std::slice::from_ref(&w)).unwrap()
            })
            .collect();
        assert_eq!(before, after, "folding is a change of storage, never of the count");
    }

    /// The backfill is the one chance to count a history that is still whole, so it has to count all
    /// of it: a store migrated from v6 answers exactly what the same events appended under v7 would.
    #[test]
    fn the_v7_backfill_counts_every_charge_already_in_the_chain() {
        let d = std::env::temp_dir().join(format!(
            "permaura-backfill-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("gateway.db").to_string_lossy().into_owned();

        let events = {
            let store = SqliteStore::open(&path).unwrap();
            for (decision, grant, agent) in [
                ("allow", Some("g1"), Some("a1")),
                ("approved", Some("g1"), Some("a2")),
                ("allow", Some("g1"), None),
                ("deny", Some("g1"), Some("a1")),
                ("allow", Some("g2"), Some("a1")),
            ] {
                let mut payload = AuditPayload::new("conn.act", "conn", decision);
                payload.agent_id = agent.map(str::to_string);
                if let Some(id) = grant {
                    payload.summary = serde_json::json!({ "grant_id": id });
                }
                store.append_audit(payload).unwrap();
            }
            store.audit_events(None).unwrap()
        };

        // Rewind to v6 and drop the counter, which is what a store written by the binary before
        // this one looks like.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("DROP TABLE grant_usage", []).unwrap();
            conn.pragma_update(None, "user_version", 6).unwrap();
        }
        let store = SqliteStore::open(&path).unwrap();
        let windows = [
            crate::store::GrantWindow { grant_id: "g1", since_ms: i64::MIN },
            crate::store::GrantWindow { grant_id: "g2", since_ms: i64::MIN },
        ];
        assert_eq!(
            store.read_grant_usage(&windows).unwrap(),
            crate::store::tally_grant_usage(&windows, events.iter()),
            "the backfill counts every charge the chain already carried"
        );

        std::fs::remove_dir_all(&d).ok();
    }
    // ── the usage rebuild reads history outside the lock ────────────────────────────────────────

    /// Every row of the counter, for comparing two whole tables.
    fn usage_rows(store: &SqliteStore) -> Vec<(String, String, i64, i64)> {
        let inner = store.lock().unwrap();
        let mut stmt = inner
            .conn
            .prepare("SELECT grant_id, agent_id, period_start, count FROM grant_usage ORDER BY 1, 2, 3")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        rows
    }

    /// The archived history the walk is handed, and something to run once it has been read to its end and before the rebuild takes the lock to apply it.
    struct ThenRun<F: FnOnce()> {
        events: std::vec::IntoIter<AuditEvent>,
        then: Option<F>,
    }

    impl<F: FnOnce()> Iterator for ThenRun<F> {
        type Item = Result<AuditEvent, GatewayError>;
        fn next(&mut self) -> Option<Self::Item> {
            match self.events.next() {
                Some(event) => Some(Ok(event)),
                None => {
                    if let Some(then) = self.then.take() {
                        then();
                    }
                    None
                }
            }
        }
    }

    /// Run `f` on another thread and say whether it finished within a second, which it cannot while this thread holds the store's lock.
    fn lands_promptly(f: impl FnOnce() + Send + 'static) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(1)).is_ok()
    }

    fn charge_n(store: &SqliteStore, n: usize) {
        for i in 0..n {
            let grant = ["g_a", "g_b", "g_c"][i % 3];
            let mut payload = AuditPayload::new(format!("cap.{i}"), "conn", "allow");
            payload.agent_id = Some(format!("agent-{}", i % 2));
            payload.summary = serde_json::json!({ "grant_id": grant });
            store.append_audit_charged(payload, Some(crate::store::GrantCharge::new(grant))).unwrap();
        }
    }

    /// A store with `archived` charged events below its base and `hot` above it, and the archived ones to hand the rebuild.
    fn archived_store(tag: &str, archived: usize, hot: usize) -> (std::path::PathBuf, Arc<SqliteStore>, Vec<AuditEvent>) {
        let d = dir(tag);
        let store = Arc::new(SqliteStore::open(&d.join("gateway.db").to_string_lossy()).unwrap());
        charge_n(&store, archived + hot);
        let below = store.audit_events_from(0, archived).unwrap();
        store.prune_audit_to(archived as u64 - 1, &below[archived - 1].hash, "seg-test").unwrap();
        (d, store, below)
    }

    /// The rebuild that walks outside the lock files the same table the rebuild under the lock did, over a history wide enough to fold: the reference is that rebuild's own body (`file_history`), every event filed one by one and then folded.
    #[test]
    fn a_rebuild_walked_outside_the_lock_files_what_the_rebuild_under_it_filed() {
        let d = dir("rebuild-equal");
        let path = d.join("gateway.db").to_string_lossy().to_string();
        drop(SqliteStore::open(&path).unwrap());
        let now = crate::store::now_ms();
        let mut log = permaura_core::AuditLog::with_signing_key(audit_key(&path));
        for event in charged_history(now) {
            log.append_at(event.payload, event.timestamp).unwrap();
        }
        let events = log.events().to_vec();
        {
            let conn = Connection::open(&path).unwrap();
            for event in &events {
                conn.execute(
                    "INSERT INTO audit_events (seq, data) VALUES (?1, ?2)",
                    rusqlite::params![event.seq as i64, serde_json::to_string(event).unwrap()],
                )
                .unwrap();
            }
        }
        let split = events.len() / 2;
        prune_below(&path, split as u64 - 1, &events[split - 1].hash);

        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.audit_len().unwrap(), (events.len() - split) as u64);
        let filed = store
            .rebuild_grant_usage(&mut events[..split].iter().cloned().map(Ok))
            .expect("the rebuild completes");

        let reference = SqliteStore::open_in_memory().unwrap();
        assert_eq!(filed, file_history(&reference, &events), "the same number of charges");
        let rows = usage_rows(&store);
        assert!(rows.iter().any(|r| r.2 == 0), "the history reaches past the detail window, so something folded");
        assert_eq!(rows, usage_rows(&reference), "and the same table, row for row");
        std::fs::remove_dir_all(&d).ok();
    }

    /// An archive pass that prunes while the rebuild reads the archive moves events the walk did not read out of the hot window. They were counted when the walk began, so the rebuild still files every charge exactly once.
    #[test]
    fn a_prune_landing_while_the_rebuild_reads_the_archive_is_counted_once() {
        let (d, store, below) = archived_store("rebuild-prune", 4, 8);
        let live = usage_rows(&store);
        let held = store.audit_events_from(4, 8).unwrap();
        let landed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (s, l, head) = (store.clone(), landed.clone(), held[3].hash.clone());
        let mut walk = ThenRun {
            events: below.into_iter(),
            then: Some(move || {
                let pruned = lands_promptly(move || {
                    s.prune_audit_to(7, &head, "seg-during").unwrap();
                });
                l.store(pruned, std::sync::atomic::Ordering::SeqCst);
            }),
        };

        let filed = store.rebuild_grant_usage(&mut walk).expect("the rebuild completes");
        assert!(landed.load(std::sync::atomic::Ordering::SeqCst), "the prune landed while the rebuild was reading the archive");
        assert_eq!(store.audit_boundary().unwrap().unwrap().base_seq, 8);
        assert_eq!(filed, 12);
        assert_eq!(usage_rows(&store), live, "every charge is filed exactly once");
        std::fs::remove_dir_all(&d).ok();
    }

    /// Events appended while the rebuild reads the archive are charged too, from the hot window, when it applies.
    #[test]
    fn charges_appended_while_the_rebuild_reads_the_archive_are_counted() {
        let (d, store, below) = archived_store("rebuild-append", 4, 8);
        let mut all = below.clone();
        let s = store.clone();
        let appended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let a = appended.clone();
        let mut walk = ThenRun {
            events: below.into_iter(),
            then: Some(move || a.store(lands_promptly(move || charge_n(&s, 5)), std::sync::atomic::Ordering::SeqCst)),
        };

        let filed = store.rebuild_grant_usage(&mut walk).expect("the rebuild completes");
        assert!(appended.load(std::sync::atomic::Ordering::SeqCst), "the appends landed while the rebuild was reading the archive");
        assert_eq!(filed, 17);
        let reference = SqliteStore::open_in_memory().unwrap();
        all.extend(store.audit_events_from(4, 100).unwrap());
        assert_eq!(all.len(), 17);
        file_history(&reference, &all);
        assert_eq!(usage_rows(&store), usage_rows(&reference));
        std::fs::remove_dir_all(&d).ok();
    }

    /// A prune that moves the base past every event the rebuild had counted leaves events nobody read: refused, and the counter left as it was.
    #[test]
    fn a_prune_past_what_the_rebuild_counted_is_refused_and_changes_nothing() {
        let (d, store, below) = archived_store("rebuild-past", 4, 8);
        let s = store.clone();
        let mut walk = ThenRun {
            events: below.into_iter(),
            then: Some(move || {
                lands_promptly(move || {
                    charge_n(&s, 6);
                    let head = s.audit_events_from(13, 1).unwrap()[0].hash.clone();
                    s.prune_audit_to(13, &head, "seg-past").unwrap();
                });
            }),
        };
        let err = store.rebuild_grant_usage(&mut walk).expect_err("the rebuild refuses");
        assert!(err.to_string().contains("archive pass"), "{err}");
        assert_eq!(store.audit_boundary().unwrap().unwrap().base_seq, 14, "the prune did land first");
        let rows = usage_rows(&store);
        assert_eq!(rows.iter().map(|r| r.3).sum::<i64>(), 18, "the live counter is untouched");
        std::fs::remove_dir_all(&d).ok();
    }

    fn hex_signature_of_the_wrong_key() -> String {
        "ab".repeat(64)
    }
}

#[cfg(test)]
mod one_writer_tests {
    use super::*;
    use permaura_core::AuditPayload;

    fn dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permaura-one-writer-{tag}-{}-{}",
            std::process::id(),
            crate::service::short_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn event(action: &str, decision: &str, summary: serde_json::Value) -> AuditPayload {
        let mut payload = AuditPayload::new(action, "synthetic", decision);
        payload.summary = summary;
        payload
    }

    /// Two writers on one file, each with the chain it loaded at open (what a successor and its draining predecessor were): the second writer of a seq is refused, the event already recorded there stands, and the stored chain still verifies with it in place.
    #[test]
    fn a_second_writer_cannot_replace_an_audit_event_already_recorded_at_its_seq() {
        let d = dir("collide");
        let path = d.join("gateway.db");
        let path = path.to_str().unwrap();
        // The unlocked opener, so this pins the table's own refusal whatever the process lock does.
        let predecessor = SqliteStore::open_with(path, KeyCustody::Sidecar).unwrap();
        predecessor
            .append_audit(event("synthetic.action", "attempt", serde_json::json!({ "execution_id": "exe_1", "grant_id": "g1" })))
            .unwrap();
        let successor = SqliteStore::open_with(path, KeyCustody::Sidecar).unwrap();
        let allow = predecessor
            .append_audit_charged(
                event("synthetic.action", "allow", serde_json::json!({ "execution_id": "exe_1", "grant_id": "g1", "status": 200 })),
                Some(crate::store::GrantCharge::new("g1")),
            )
            .unwrap();
        let interrupted = successor.append_audit_charged(
            event(
                "synthetic.action",
                "error",
                serde_json::json!({ "execution_id": "exe_1", "grant_id": "g1", "error_kind": crate::service::INTERRUPTED_ERROR_KIND }),
            ),
            Some(crate::store::GrantCharge::new("g1")),
        );
        let refused = interrupted.expect_err("a seq another writer recorded is never written over");
        assert!(refused.to_string().contains(&format!("seq {}", allow.seq)), "{refused}");
        assert_eq!(successor.audit_events(None).unwrap().len(), 1, "the refused event is not held in memory either");
        drop(predecessor);
        drop(successor);

        let reopened = SqliteStore::open_with(path, KeyCustody::Sidecar).unwrap();
        let rows = reopened.audit_events(None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].payload.decision, "allow", "the finished call's record stands");
        assert_eq!(reopened.verify_audit().unwrap(), None);
        let usage = reopened.read_grant_usage(&[crate::store::GrantWindow { grant_id: "g1", since_ms: 0 }]).unwrap();
        assert_eq!(usage.total("g1"), 1, "the call is charged once");
        std::fs::remove_dir_all(&d).ok();
    }

    /// A store whose sidecar key went missing while its database kept a chain is refused with the key's path, rather than signed onward under a key minted over the old chain; and the missing file is not created.
    #[test]
    fn a_missing_audit_key_beside_a_recorded_chain_is_refused_not_minted_over() {
        let d = dir("lost-key");
        let path = d.join("gateway.db");
        let path = path.to_str().unwrap();
        {
            let store = SqliteStore::open_with(path, KeyCustody::Sidecar).unwrap();
            store.append_audit(event("synthetic.action", "allow", serde_json::json!({}))).unwrap();
            store.append_audit(event("synthetic.action", "allow", serde_json::json!({}))).unwrap();
        }
        let key = format!("{path}.auditkey");
        std::fs::remove_file(&key).unwrap();

        let refused = SqliteStore::open_with(path, KeyCustody::Sidecar).err().expect("the open is refused");
        let message = refused.to_string();
        assert!(message.contains(&key), "the message names the missing file: {message}");
        assert!(!std::path::Path::new(&key).exists(), "no key was minted over the chain");

        // A store with nothing recorded yet still gets a key of its own on its first open.
        let fresh = d.join("fresh.db");
        let fresh = fresh.to_str().unwrap();
        SqliteStore::open_with(fresh, KeyCustody::Sidecar).unwrap();
        assert!(std::path::Path::new(&format!("{fresh}.auditkey")).exists());
        std::fs::remove_dir_all(&d).ok();
    }

    fn hold(id: &str, status: &str) -> PendingApproval {
        PendingApproval {
            id: id.into(),
            session_id: "sess_demo".into(),
            capability: "github.pull_requests.create".into(),
            resource: "github_acme".into(),
            message: "Approve?".into(),
            status: status.into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({ "owner": "synthetic" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: 0,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        }
    }

    /// A settled approval is a record: a write from a stale view (the boot settlement calling it interrupted after the call it held finished) cannot change its status, while the settled status itself can still be written again with more on it.
    #[test]
    fn a_settled_approval_is_never_rewritten_to_another_status() {
        let d = dir("approval");
        let path = d.join("gateway.db");
        let store = SqliteStore::open_with(path.to_str().unwrap(), KeyCustody::Sidecar).unwrap();
        store.put_approval(hold("appr_1", "pending")).unwrap();
        let mut settled = hold("appr_1", "approved");
        settled.result_status = Some(201);
        store.put_approval(settled.clone()).unwrap();

        let refused = store
            .put_approval(hold("appr_1", crate::store::APPROVAL_UNRESOLVED))
            .expect_err("a settled approval keeps its status");
        assert!(refused.to_string().contains("appr_1"), "{refused}");
        assert!(store.put_approval(hold("appr_1", "pending")).is_err(), "nor goes back to pending");
        let row = store.get_approval("appr_1").unwrap().unwrap();
        assert_eq!(row.status, "approved");
        assert_eq!(row.result_status, Some(201));

        settled.result = Some(permaura_core::JsonText::from_value(&serde_json::json!({ "vault_export": "consumed" })));
        store.put_approval(settled).expect("the settled status itself can be written again");
        assert!(store.get_approval("appr_1").unwrap().unwrap().result.is_some());
        std::fs::remove_dir_all(&d).ok();
    }

    /// A new hold is an INSERT, refused over any row already at its id, while a write that keeps a row's status still replaces its other fields: the rule is status-only.
    #[test]
    fn a_new_hold_never_lands_on_an_existing_row() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut first = hold("appr_1", "pending");
        first.message = "the first question".into();
        store.insert_approval(first).unwrap();
        let mut second = hold("appr_1", "pending");
        second.message = "another question".into();
        let refused = store.insert_approval(second.clone()).expect_err("a new hold never writes over one");
        assert!(matches!(refused, GatewayError::Conflict(_)), "{refused}");
        assert_eq!(store.get_approval("appr_1").unwrap().unwrap().message, "the first question");
        store.put_approval(second).expect("an update that keeps the status replaces the other fields");
        assert_eq!(store.get_approval("appr_1").unwrap().unwrap().message, "another question");
    }
}

#[cfg(test)]
mod class6_review_tests {
    use super::*;
    use permaura_core::AuditPayload;

    fn dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permaura-c6-review-{tag}-{}-{}",
            std::process::id(),
            crate::service::short_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A symlink planted where the lock file goes is refused, and the file it points at is neither truncated nor chmodded.
    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_as_the_lock_file_is_refused_and_its_target_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("symlink");
        let db = d.join("gateway.db");
        let victim = d.join("victim.txt");
        std::fs::write(&victim, b"keep me").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&victim, d.join("gateway.db.lock")).unwrap();

        let refused = SqliteStore::open(db.to_str().unwrap()).err().expect("a planted lock symlink is refused");
        assert!(refused.to_string().contains("lock"), "{refused}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me", "the target was not truncated");
        assert_eq!(std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644, "nor chmodded");
        std::fs::remove_dir_all(&d).ok();
    }

    /// A store reached through a second name for its file is the same store, held by one lock.
    #[cfg(unix)]
    #[test]
    fn a_store_opened_through_another_name_for_its_file_shares_its_lock() {
        let d = dir("alias");
        let db = d.join("gateway.db");
        let first = SqliteStore::open(db.to_str().unwrap()).unwrap();
        first.append_audit(AuditPayload::new("synthetic.action", "synthetic", "allow")).unwrap();
        let alias = d.join("alias.db");
        std::os::unix::fs::symlink(&db, &alias).unwrap();
        let refused = SqliteStore::open(alias.to_str().unwrap()).err().expect("the alias reaches the store the first handle holds");
        assert!(refused.to_string().contains("held by"), "refused because it is held, by one lock: {refused}");
        drop(first);
        std::fs::remove_dir_all(&d).ok();
    }

    /// After another writer takes a seq, this store says so where `/health` and the console read it, rather than serving a log it can no longer append to as if nothing were wrong.
    #[test]
    fn a_colliding_append_marks_the_store_degraded() {
        let d = dir("degraded");
        let path = d.join("gateway.db");
        let path = path.to_str().unwrap();
        let mine = SqliteStore::open_with(path, KeyCustody::Sidecar).unwrap();
        let other = SqliteStore::open_with(path, KeyCustody::Sidecar).unwrap();
        other.append_audit(AuditPayload::new("synthetic.action", "synthetic", "allow")).unwrap();
        assert_eq!(<SqliteStore as Store>::degraded(&mine), None);
        mine.append_audit(AuditPayload::new("synthetic.action", "synthetic", "allow")).expect_err("the seq is taken");
        let note = <SqliteStore as Store>::degraded(&mine).expect("the store is reported degraded");
        assert!(note.contains("another") && note.contains("restart"), "{note}");
        std::fs::remove_dir_all(&d).ok();
    }

    /// Only a primary-key collision is reported as another writer; any other refused insert (here a trigger, as a full disk reads) keeps its own message.
    #[test]
    fn a_refused_insert_that_is_not_a_seq_collision_is_not_called_another_writer() {
        let d = dir("not-collision");
        let path = d.join("gateway.db");
        let path = path.to_str().unwrap();
        let store = SqliteStore::open(path).unwrap();
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER refuse BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
        )
        .unwrap();
        let refused = store.append_audit(AuditPayload::new("synthetic.action", "synthetic", "allow")).unwrap_err().to_string();
        assert!(!refused.contains("another writer"), "{refused}");
        assert_eq!(<SqliteStore as Store>::degraded(&store), None, "a refused write is not a second writer");
        drop(conn);
        std::fs::remove_dir_all(&d).ok();
    }

    /// Writing an enrolment code that is already there is refused, so a used code is never revived as unused.
    #[test]
    fn putting_an_enrolment_code_that_exists_never_revives_it() {
        let store = SqliteStore::open_in_memory().unwrap();
        let code = |used: bool| EnrolmentCode { code: "ENRL-SYNTHETIC".into(), label: None, created_at: 0, expires_at: i64::MAX, used };
        store.put_enrolment_code(code(true)).unwrap();
        assert!(store.put_enrolment_code(code(false)).is_err(), "the code is already there");
        assert!(!store.enrolment_code_redeemable("ENRL-SYNTHETIC", 1).unwrap(), "and stays used");
    }
}
