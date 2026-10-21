//! The SQLite [`Store`] made durable for a stateless worker: the database lives in the instance's
//! own memory, and a consistent copy of it is uploaded to object storage before any request that
//! changed state is acknowledged.
//!
//! **What is guaranteed.** A mutation returns `Ok` only after the snapshot carrying it is durable.
//! An instance killed between the local commit and the upload loses that commit, and the client saw
//! a failure or a timeout, never a success: the acknowledgement is what waits.
//!
//! **How two instances stay honest.** Every upload carries the generation it expects to replace. A
//! `412` means another instance has taken ownership of the store, so this one is stale by
//! definition: it exits rather than serving reads from a database that is no longer the truth, and
//! the replacement instance restores the winner's snapshot at boot.
//!
//! **Custody.** The audit signing key goes in `gateway_meta`, KMS-wrapped when a CMK is configured,
//! never in a `{path}.auditkey` sidecar: the sidecar is not part of the snapshot, so a sidecar key
//! would be regenerated at every cold start and fork the audit chain.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use permaura_core::{AuditEvent, AuditPayload, Connection as Conn, Grant, Policy, SealedSecret, SecretRecord};

use crate::backend::AuditKeyWrap;
use crate::connectors::Capability;
use crate::error::GatewayError;
use crate::manifest::InstalledManifest;
use crate::objectstore::{ObjectHead, ObjectStore, PutOutcome};

use std::cell::Cell;
use std::time::{Duration, Instant};

use super::bridge::blocking_section;
use super::sqlite::{SnapshotStamp, SqliteStore};
use super::{Agent, EnrolmentCode, PendingApproval, SecretCustody, Session, Store};

/// The default object name inside the bucket.
pub const DEFAULT_OBJECT: &str = "store.db";

/// The default size the snapshot has to exceed before every upload says so. Chosen against the
/// worker's 512 MiB instance, which has to hold the database, the `VACUUM INTO` copy and the upload
/// buffer at once.
pub const DEFAULT_WARN_BYTES: u64 = 64 * 1024 * 1024;

/// The generation of an object that does not exist yet, and the precondition a first upload sends.
const NO_GENERATION: u64 = 0;

/// The version of the metadata key table. Bumped on any change to what is stamped, so a reader can
/// tell a gateway that stamped a key it does not know from one that stamped nothing at all.
///
/// Still `1` after `pm-gateway-id` joined the table, for the same reason it was `1` when the table
/// was introduced: no released binary stamps any of these keys, so there is no version 1 in the
/// world for a 2 to be distinguished from. The first released version of the table is the one that
/// ships, whatever is in it by then.
const META_VERSION: &str = "1";

/// What a metadata value says when this gateway could not learn it. Never omitted and never
/// defaulted: a reader has to be able to tell "no vault key version was pinned" from "this field
/// did not exist when the snapshot was written".
const META_UNKNOWN: &str = "none";

/// The metadata key carrying an upload's own random id, and the only thing that proves an object
/// was written by this instance.
///
/// Nothing derived from the store's contents can do that job. Two instances of one tenant that
/// restored the same generation hold the same commit sequence and the same audit head, and a
/// mutation that appends no audit event in its own unit leaves both unchanged, so during a rollout
/// both instances routinely compute an identical set of facts over different databases. An instance
/// comparing only those facts would adopt the other's acknowledged generation, upload over it on the
/// next write, and send the rightful owner away stale: "never overwrite a winning revision",
/// defeated through the very path meant to enforce it.
use crate::objectstore::UPLOAD_ID_KEY;

/// How many unanswered uploads this instance remembers, so a later `412` can be recognised as one of
/// its own landings rather than another instance's write.
///
/// An instance cannot accumulate many: the first unanswered outcome quarantines it, and every later
/// attempt is a retry of that same commit unit. The cap is here because an in-memory list on a
/// long-lived process is a memory target whatever the traffic looks like, and dropping the oldest
/// entry costs at worst the stale exit this rule exists to avoid, which is the behaviour that ships
/// today rather than a protection being weakened.
const UNRESOLVED_UPLOAD_MEMORY: usize = 16;

/// The Secret Manager version of the vault KEK this worker is running on, for the stamp.
///
/// A missing one is a warning and not a refusal: the passphrase itself is what reopens a snapshot,
/// and the salt and cost parameters travel inside each sealed record, so an unstamped version
/// degrades the manifest rather than the gateway. Refusing to start over it would take a running
/// tenant down for a provisioning detail.
const VAULT_KEK_VERSION_ENV: &str = "PERMAURA_VAULT_KEK_VERSION";

thread_local! {
    /// How many `run_atomically` scopes the current thread is inside. A mutation inside one commits
    /// locally and leaves the upload to the scope's end, which is how a handler's several writes cost
    /// one upload rather than one each. Thread-local because the scope's closure runs synchronously
    /// on the thread that opened it, and nothing else on that thread can be inside it.
    static BATCH_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// How long after boot a read confirms the object's generation before answering. Cloud Run keeps
/// the previous instance serving until the new one is ready, so the old one can commit after the
/// new one restored; without this the new one answers reads from before those commits until its own
/// first write meets the 412.
pub const FRESH_READ_WINDOW: Duration = Duration::from_secs(60);
/// The least time between two such confirmations: one metadata request a second, not one per read.
pub const FRESH_READ_INTERVAL: Duration = Duration::from_secs(1);

/// An upload this instance sent and never learned the outcome of, kept so that an object holding the
/// store later can be recognised as this instance's own landing.
///
/// The facts travel with the id because they are checked against the object *as it was stamped with
/// that id*, not against whatever the current upload happens to say. Comparing against the current
/// upload would pass for a different reason (the facts rarely move) and would say nothing about the
/// attempt that actually landed.
#[derive(Clone)]
struct UnresolvedUpload {
    /// The value of [`UPLOAD_ID_KEY`] this instance stamped.
    id: String,
    /// `pm-commit-seq` as sent with that id.
    commit_seq: String,
    /// `pm-audit-head-hash` as sent with that id.
    audit_head_hash: String,
}

/// What an object in the bucket turned out to be.
enum Ownership {
    /// Written by one of this instance's own unanswered uploads: the id matches and so do the facts
    /// stamped beside it.
    Ours(u64),
    /// The id is one of this instance's but the facts are not the ones it sent with that id. One of
    /// the two is lying and there is no safe reading of it.
    Contradiction {
        /// What the object says it carries.
        stamped_seq: String,
        /// What the object says its audit head is.
        stamped_head: String,
        /// What was sent with that id.
        sent_seq: String,
        /// The audit head sent with that id.
        sent_head: String,
    },
    /// Another instance's, or carrying nothing that says whose it is.
    NotOurs,
}

struct PersistState {
    /// The generation of the object this instance last agreed with.
    generation: u64,
    /// The highest commit sequence number a completed upload is known to carry.
    persisted_seq: u64,
    /// The store's row-change counter as of the last successful upload. A mutating method that
    /// changed no row leaves this where it was, and re-uploading a byte-identical database costs a
    /// full-size PUT and a round-trip for nothing.
    persisted_changes: u64,
    /// When the last upload failed, so a local commit stands that the bucket does not have. While
    /// set, no new write is accepted until that commit has been carried: a customer must never be
    /// told "failed" about a change that then quietly becomes durable behind a later one.
    dirty_since: Option<Instant>,
    /// Whether the dirty commit is dirty because an upload produced no answer at all, which reads
    /// differently to an upload that definitely failed: the bucket may hold it and this instance
    /// cannot say. Only ever true alongside `dirty_since`.
    outcome_uncertain: bool,
    /// The uploads this instance sent and never learned the outcome of, newest last.
    unresolved: Vec<UnresolvedUpload>,
    /// When the last upload attempt failed and why, while the commit it was carrying is still owed:
    /// what the carry floor measures from and what a write refused inside it is told.
    last_failure: Option<(Instant, String)>,
}

impl PersistState {
    /// Record an upload whose outcome this instance never learned.
    fn remember_unresolved(&mut self, sent: &BTreeMap<String, String>) {
        let Some(id) = sent.get(UPLOAD_ID_KEY) else { return };
        if self.unresolved.iter().any(|u| &u.id == id) {
            return;
        }
        let field = |key: &str| sent.get(key).cloned().unwrap_or_default();
        self.unresolved.push(UnresolvedUpload {
            id: id.clone(),
            commit_seq: field("pm-commit-seq"),
            audit_head_hash: field("pm-audit-head-hash"),
        });
        if self.unresolved.len() > UNRESOLVED_UPLOAD_MEMORY {
            self.unresolved.remove(0);
        }
    }

    /// Record a generation this instance has agreed with, whether by acknowledgement or by proof.
    ///
    /// The one place all six fields move together. Every earlier unanswered upload is forgotten
    /// here: its precondition names a generation the object has now passed, so it can never land.
    fn agreed(&mut self, generation: u64, target: u64, changes: u64) {
        self.generation = generation;
        self.persisted_seq = target;
        self.persisted_changes = changes;
        self.dirty_since = None;
        self.outcome_uncertain = false;
        self.unresolved.clear();
        self.last_failure = None;
    }
}

/// The durability state as of the last time the persist lock was released, for readers that must
/// not wait behind an upload: the dirty-since moment and whether the outcome was unknown.
type Published = Mutex<Option<(Instant, bool)>>;

/// The persist lock, publishing what [`PersistState`] says about durability as it is released, so
/// `degraded` (the console's status poll and `/health`) never waits behind an upload holding it.
struct Locked<'a> {
    state: MutexGuard<'a, PersistState>,
    published: &'a Published,
}

impl Deref for Locked<'_> {
    type Target = PersistState;
    fn deref(&self) -> &PersistState {
        &self.state
    }
}

impl DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut PersistState {
        &mut self.state
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let now = self.state.dirty_since.map(|since| (since, self.state.outcome_uncertain));
        *self.published.lock().unwrap_or_else(|p| p.into_inner()) = now;
    }
}

/// Decide whether `remote`'s stamped metadata says the object was written by one of `unresolved`.
///
/// Ownership is the id and nothing else, because no fact taken from the store can separate two
/// instances that restored the same generation. The commit sequence and the audit head are still
/// compared, as a check that the object really is the upload its id claims to be.
fn ownership(
    unresolved: &[UnresolvedUpload],
    generation: u64,
    remote: &BTreeMap<String, String>,
) -> Ownership {
    let Some(id) = remote.get(UPLOAD_ID_KEY) else { return Ownership::NotOurs };
    let Some(mine) = unresolved.iter().find(|u| &u.id == id) else { return Ownership::NotOurs };
    let stamped = |key: &str| remote.get(key).cloned().unwrap_or_default();
    if stamped("pm-commit-seq") == mine.commit_seq
        && stamped("pm-audit-head-hash") == mine.audit_head_hash
    {
        Ownership::Ours(generation)
    } else {
        Ownership::Contradiction {
            stamped_seq: stamped("pm-commit-seq"),
            stamped_head: stamped("pm-audit-head-hash"),
            sent_seq: mine.commit_seq.clone(),
            sent_head: mine.audit_head_hash.clone(),
        }
    }
}

/// A [`SqliteStore`] whose every mutation is snapshotted to an [`ObjectStore`] before it returns.
pub struct PersistedSqliteStore {
    inner: SqliteStore,
    objects: Arc<dyn ObjectStore>,
    object: String,
    /// Where the snapshot is staged before upload: `{db}.snap`, beside the database.
    snapshot_path: PathBuf,
    state: Mutex<PersistState>,
    published: Published,
    /// Claimed outside the persist lock so a mutator knows its own sequence number before it queues
    /// for the lock, which is what lets a later upload cover an earlier mutation.
    committed: AtomicU64,
    warn_bytes: u64,
    /// What to do when the object storage says another instance owns the store. Production exits;
    /// a test records it, because a test process cannot be allowed to call `exit`.
    on_stale: Box<dyn Fn(&str) + Send + Sync>,
    opened_at: Instant,
    fresh_read_window: Duration,
    /// How long after a failed upload no carrier tries another ([`Self::persist_floored`]).
    carry_floor: Duration,
    last_generation_check: Mutex<Option<Instant>>,
    /// The tenant slug, the control plane's gateway row id and the vault KEK version, read once at
    /// open because none of them changes while the process runs.
    ///
    /// The first two are different things and are stamped separately. The slug is what every hosted
    /// object, IAM condition, checkpoint path and purge is keyed by, and is the only key still
    /// knowable once a worker has been deleted; the row id is what the control plane calls this
    /// gateway. A manifest that named one while the bytes were stamped with the other would not
    /// agree with itself.
    tenant: Option<String>,
    gateway_id: Option<String>,
    vault_kek_version: Option<String>,
    /// The fair-use counter, told about every commit that changed a row and carried in the snapshot
    /// that commit uploads. Unset on a gateway that does not count.
    meter: std::sync::OnceLock<Arc<dyn super::SnapshotMeter>>,
    /// Held exclusively while a [`Store::change_with_record`] body runs and shared by every upload, so
    /// no thread's upload snapshots a change between its commit and its record.
    record_gate: std::sync::RwLock<()>,
}

impl PersistedSqliteStore {
    /// Restore the store from `objects` and open it at `path`.
    ///
    /// A missing object is a fresh worker. A *failed* read never is: starting empty would mint a new
    /// operator identity and present it as a healthy gateway, so an unreachable bucket aborts.
    pub fn open(
        path: &str,
        objects: Arc<dyn ObjectStore>,
        object: &str,
        wrap: Option<AuditKeyWrap>,
    ) -> Result<Self, GatewayError> {
        let generation = match objects.head(object)? {
            Some(generation) => {
                let bytes = objects.get(object, generation)?;
                restore_file(path, &bytes)?;
                tracing::info!(
                    generation,
                    bytes = bytes.len(),
                    "restored the gateway store from {}/{object}",
                    objects.describe()
                );
                generation
            }
            None => {
                // A deleted object answers `head` exactly as an untouched bucket does. Starting fresh
                // over a store that once existed mints a new operator identity and audit key and
                // reports itself healthy, so the tenant's reset is silent; the version history is the
                // only thing that tells the two apart, and a failure to read it is not an answer.
                if objects.has_history(object)? {
                    return Err(GatewayError::Internal(format!(
                        "{d}/{object} has no live object but earlier versions of it exist: this is an established store whose current version is missing, not a fresh worker. Refusing to start empty, which would mint a new operator identity and audit key and present the reset as a healthy gateway. The bucket keeps the earlier versions of {object}: restore the one you want by copying it, by its generation, back to {d}/{object}, then restart the gateway.",
                        d = objects.describe()
                    )));
                }
                tracing::info!("no snapshot in {}/{object} yet: starting a fresh store", objects.describe());
                NO_GENERATION
            }
        };
        let inner = SqliteStore::open_with_custody(path, wrap).map_err(|e| {
            if generation == NO_GENERATION {
                e
            } else {
                GatewayError::Internal(format!(
                    "the snapshot at {}/{object} generation {generation} did not open as a gateway store: {e}",
                    objects.describe()
                ))
            }
        })?;
        // The counter as the store opens, so the migrations and the audit rehydration a restore just
        // ran do not read as an unpersisted change and force an upload of what was just downloaded.
        let changes_at_open = inner.change_count()?;
        let vault_kek_version = non_empty_env(VAULT_KEK_VERSION_ENV);
        if vault_kek_version.is_none() {
            tracing::warn!(
                "{VAULT_KEK_VERSION_ENV} is not set, so every snapshot this worker uploads records no vault \
                 KEK version. The passphrase is what reopens a snapshot, so this weakens the checkpoint \
                 manifest rather than the store: pin the secret mount to an explicit version and set it."
            );
        }
        Ok(PersistedSqliteStore {
            inner,
            objects,
            object: object.to_string(),
            snapshot_path: PathBuf::from(format!("{path}.snap")),
            state: Mutex::new(PersistState {
                generation,
                persisted_seq: 0,
                persisted_changes: changes_at_open,
                dirty_since: None,
                outcome_uncertain: false,
                unresolved: Vec::new(),
                last_failure: None,
            }),
            published: Mutex::new(None),
            committed: AtomicU64::new(0),
            warn_bytes: DEFAULT_WARN_BYTES,
            on_stale: Box::new(|message| {
                tracing::error!("{message}");
                std::process::exit(super::migrations::EXIT_STORE_STALE);
            }),
            opened_at: Instant::now(),
            fresh_read_window: FRESH_READ_WINDOW,
            carry_floor: crate::STORE_CARRY_INTERVAL,
            last_generation_check: Mutex::new(None),
            tenant: non_empty_env(crate::restore::TENANT_ENV),
            gateway_id: non_empty_env("PERMAURA_GATEWAY_ID"),
            vault_kek_version,
            meter: std::sync::OnceLock::new(),
            record_gate: std::sync::RwLock::new(()),
        })
    }

    /// Name the tenant slug and the gateway row id this store stamps on its uploads.
    ///
    /// Both come from the environment at open, and the environment is process-wide while the suite
    /// runs in parallel, so a test that wants a particular stamp names it here rather than setting a
    /// variable every other test would then read.
    pub fn with_identity(mut self, tenant: Option<String>, gateway_id: Option<String>) -> Self {
        self.tenant = tenant;
        self.gateway_id = gateway_id;
        self
    }

    /// The size above which each upload warns. For the env override.
    pub fn with_warn_bytes(mut self, bytes: u64) -> Self {
        self.warn_bytes = bytes;
        self
    }

    /// How long after opening reads confirm the object generation first. Zero switches the check off.
    pub fn with_fresh_read_window(mut self, window: Duration) -> Self {
        self.fresh_read_window = window;
        self
    }

    /// Replace the carry floor, [`crate::STORE_CARRY_INTERVAL`] by default. A test that retries straight after a failure it scripted sets zero.
    pub fn with_carry_floor(mut self, floor: Duration) -> Self {
        self.carry_floor = floor;
        self
    }

    /// Replace what happens when another instance is found to own the store. Production exits the
    /// process; only a test has any business overriding it.
    pub fn with_on_stale(mut self, on_stale: Box<dyn Fn(&str) + Send + Sync>) -> Self {
        self.on_stale = on_stale;
        self
    }

    /// The generation this instance last agreed with. `0` before anything has been written.
    pub fn generation(&self) -> u64 {
        // Recover through a poisoned lock: reporting 0 would be indistinguishable from a store that
        // has never been uploaded, which is the one thing this number is read to tell apart.
        self.state.lock().unwrap_or_else(|p| p.into_inner()).generation
    }

    /// Snapshot and upload the commit that just landed, unless a completed upload already carries it.
    fn persist(&self) -> Result<(), GatewayError> {
        self.persist_floored(true)
    }

    /// [`Self::persist`], and with `floored` refused at once, without an upload, while a commit is owed and the last attempt to carry it failed less than the carry floor ago. Every carrier shares the floor (the tick, a request's carry, a write's carry first): an upload outage then costs one attempt per floor rather than one per caller, and no request, an unauthenticated one included, can drive back-to-back snapshots. The drain's last carry is the one unfloored path, because nothing comes after it.
    fn persist_floored(&self, floored: bool) -> Result<(), GatewayError> {
        let result = self.persist_once(floored);
        if let Err(e) = &result {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.dirty_since.is_some() && !matches!(&state.last_failure, Some((at, _)) if at.elapsed() < self.carry_floor && floored) {
                state.last_failure = Some((Instant::now(), e.to_string()));
            }
        }
        result
    }

    fn persist_once(&self, floored: bool) -> Result<(), GatewayError> {
        let my_seq = self.committed.fetch_add(1, Ordering::SeqCst) + 1;
        // Donate this runtime worker while queueing: a mutator that parks a worker thread on the
        // mutex takes away a thread the in-flight upload needs to finish, which is how one vCPU and
        // two concurrent callers wedged the hosted worker once already.
        blocking_section(|| {
            let _gate = self.record_gate.read().unwrap_or_else(|p| p.into_inner());
            let mut state = Locked {
                state: self
                    .state
                    .lock()
                    .map_err(|_| GatewayError::Internal("persisted store lock poisoned".into()))?,
                published: &self.published,
            };
            if state.persisted_seq >= my_seq {
                return Ok(());
            }
            if floored && state.dirty_since.is_some() {
                if let Some((at, why)) = &state.last_failure {
                    if at.elapsed() < self.carry_floor {
                        return Err(GatewayError::StoreUnavailable(format!(
                            "{why} (the last upload failed {} ms ago, and the next is not tried until {} ms have passed)",
                            at.elapsed().as_millis(),
                            self.carry_floor.as_millis()
                        )));
                    }
                }
            }
            // Read the counter after taking the lock: every sequence number up to this one belongs to
            // a commit that has already landed, so the snapshot below carries all of them.
            let target = self.committed.load(Ordering::SeqCst);
            // Nothing actually changed, so the database on disk is byte-identical to the one already
            // in the bucket. Skipping here is what keeps an idle worker free: the console's status
            // polls reach mutating methods that write no row, and uploading the whole store for each
            // of them costs a PUT and a round-trip per request for no durability at all.
            let changes = self.inner.change_count()?;
            if changes == state.persisted_changes {
                // Logged, because after this change NOT uploading is the common case, and an object
                // whose generation has not moved for an hour should be distinguishable from one whose
                // uploads are quietly failing without reading this source to find out which.
                tracing::debug!(
                    changes,
                    generation = state.generation,
                    "no row changed since the last snapshot: nothing to upload"
                );
                state.persisted_seq = target;
                return Ok(());
            }
            // This upload is happening anyway, so it carries the fair-use count too. Written only
            // here, where rows already changed, so the counter can never be the reason for an upload.
            let changes = self.stamp_meter(changes)?;
            // The stamp comes back from the same held lock that took the copy, so what the metadata
            // says and what the bytes contain cannot be two different moments.
            let stamp = self.inner.snapshot_to(&self.snapshot_path)?;
            let bytes = std::fs::read(&self.snapshot_path).map_err(|e| {
                GatewayError::Internal(format!("read store snapshot {}: {e}", self.snapshot_path.display()))
            })?;
            // The staging copy is as big as the database and the worker's filesystem is its memory,
            // so it goes as soon as it has been read rather than sitting there until the next write.
            let _ = std::fs::remove_file(&self.snapshot_path);
            let metadata = self.upload_metadata(&stamp, target, bytes.len() as u64);
            let outcome =
                match self.objects.put_if_generation(&self.object, &bytes, state.generation, &metadata) {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        // The one line an operator has when a worker's writes start failing: without it the
                        // only trace is the status code on the request row.
                        tracing::error!(
                            error = %e,
                            bytes = bytes.len(),
                            generation = state.generation,
                            "the gateway store snapshot was not uploaded to {}/{}; the local commit stands, new writes are refused until it is carried",
                            self.objects.describe(),
                            self.object
                        );
                        state.dirty_since.get_or_insert_with(Instant::now);
                        state.outcome_uncertain = false;
                        // Remembered although the read-back said it had not landed: a front end can fail a write the backend commits after that read, and the id is then what proves the late landing this instance's own.
                        state.remember_unresolved(&metadata);
                        return Err(GatewayError::StoreUnavailable(match e {
                            GatewayError::Internal(m) => m,
                            other => other.to_string(),
                        }));
                    }
                };
            match outcome {
                PutOutcome::Uncertain => {
                    state.remember_unresolved(&metadata);
                    self.reconcile_uncertain(state, &metadata, target, changes, &bytes)
                }
                PutOutcome::Stored(generation) => {
                    state.agreed(generation, target, changes);
                    let size = bytes.len() as u64;
                    if snapshot_is_oversized(size, self.warn_bytes) {
                        tracing::warn!(
                            bytes = size,
                            warn_above = self.warn_bytes,
                            "the gateway store snapshot is large; the worker holds the database, this copy and the upload buffer at once"
                        );
                    } else {
                        tracing::debug!(bytes = size, generation, "uploaded the gateway store snapshot");
                    }
                    Ok(())
                }
                PutOutcome::Conflict => {
                    self.reconcile_conflict(state, &metadata, target, changes, &bytes)
                }
            }
        })
    }

    /// Take the stale exit a `412` has always meant.
    ///
    /// The lock is released before the handler runs: production exits here, but a test's handler
    /// returns, and it must not come back to a poisoned mutex.
    fn exit_stale(
        &self,
        state: Locked<'_>,
        message: String,
    ) -> Result<(), GatewayError> {
        drop(state);
        (self.on_stale)(&message);
        Err(GatewayError::StoreUnavailable(message))
    }

    /// Decide what a `412` means, now that an upload of this instance's that was never answered may
    /// be the thing holding the object.
    ///
    /// The residual the upload id was introduced for. When an upload and its single retry both go
    /// unanswered and one of them in fact landed, the next `persist()` uploads at the generation
    /// this instance still believes in, meets the 412, and exits announcing that another instance
    /// owns the store while describing its own write. Nothing is lost, because the next boot
    /// restores that same write, but the diagnosis is wrong and two lost responses cost a cold
    /// start.
    ///
    /// The rule is the one the uncertain path already uses, and it is deliberately the only one: the
    /// generation is adopted if and only if the object carries an upload id this instance sent and
    /// never got an answer to, **and** the commit sequence and audit head stamped beside that id are
    /// the ones sent with it. Anything less is the stale exit that ships today. A `head_full` that
    /// fails is not evidence of ownership either, so it takes that same exit: an object nobody could
    /// read has said nothing about who wrote it.
    fn reconcile_conflict(
        &self,
        state: Locked<'_>,
        sent: &BTreeMap<String, String>,
        target: u64,
        changes: u64,
        bytes: &[u8],
    ) -> Result<(), GatewayError> {
        let Some(head) = self.own_unanswered(&state.unresolved) else {
            let ours = state.generation;
            return self.exit_stale(state, stale_message(ours));
        };
        self.carry_over_own_landing(state, head, sent, target, changes, bytes)
    }

    /// Settle an object proven to be one of this instance's own unanswered uploads.
    ///
    /// Only an object carrying THIS snapshot's upload id holds this commit. One carrying an earlier
    /// id holds an older snapshot: agreeing with it would mark every commit made since as durable,
    /// clear the quarantine and let later persists skip the upload because the change count already
    /// matches, and the next boot would restore the older snapshot over an acknowledged revocation
    /// or a terminal audit event. So that generation is adopted and this commit is sent over it.
    fn carry_over_own_landing(
        &self,
        mut state: Locked<'_>,
        head: ObjectHead,
        sent: &BTreeMap<String, String>,
        target: u64,
        changes: u64,
        bytes: &[u8],
    ) -> Result<(), GatewayError> {
        let generation = head.generation;
        if head.metadata.get(UPLOAD_ID_KEY) == sent.get(UPLOAD_ID_KEY) && head.size == bytes.len() as u64 {
            tracing::info!(
                generation,
                previous = state.generation,
                "this snapshot's own upload landed and only its answer was lost; adopting the generation it produced"
            );
            state.agreed(generation, target, changes);
            return Ok(());
        }
        tracing::info!(
            generation,
            previous = state.generation,
            "the object this upload was rejected against is this instance's own upload that went unanswered; adopting the generation it produced and sending this commit over it"
        );
        // The generation alone: the commit itself is still not durable until the re-run below is
        // acknowledged, so nothing that says it is may move yet.
        state.generation = generation;
        match self.objects.put_if_generation(&self.object, bytes, generation, sent) {
            Ok(PutOutcome::Stored(stored)) => {
                state.agreed(stored, target, changes);
                Ok(())
            }
            // One re-run, never a loop: a second rejection means the object moved again while this
            // one was being sent, and that is the case the stale exit is for.
            Ok(PutOutcome::Conflict) => self.exit_stale(state, stale_message(generation)),
            Ok(PutOutcome::Uncertain) => {
                state.remember_unresolved(sent);
                self.reconcile_uncertain(state, sent, target, changes, bytes)
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    generation,
                    "the commit could not be sent over the generation this instance had just adopted; the local commit stands and writes are refused until it is carried"
                );
                state.dirty_since.get_or_insert_with(Instant::now);
                state.outcome_uncertain = false;
                Err(GatewayError::StoreUnavailable(match e {
                    GatewayError::Internal(m) => m,
                    other => other.to_string(),
                }))
            }
        }
    }

    /// The object when it is one of this instance's own unanswered uploads, or `None` on anything
    /// short of that proof.
    ///
    /// With nothing unresolved there is nothing a read could prove, so no request is made and an
    /// ordinary conflict costs exactly what it costs today.
    fn own_unanswered(&self, unresolved: &[UnresolvedUpload]) -> Option<ObjectHead> {
        if unresolved.is_empty() {
            return None;
        }
        let head = match self.objects.head_full(&self.object) {
            Ok(Some(head)) => head,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "the object that rejected this upload could not be read back, so it says nothing about who wrote it; taking the stale exit rather than reading a failure as ownership"
                );
                return None;
            }
        };
        match ownership(unresolved, head.generation, &head.metadata) {
            Ownership::Ours(_) => Some(head),
            Ownership::Contradiction { stamped_seq, stamped_head, sent_seq, sent_head } => {
                tracing::error!(
                    generation = head.generation,
                    stamped_seq,
                    stamped_head,
                    sent_seq,
                    sent_head,
                    "the object that rejected this upload carries one of this instance's upload ids beside facts it never sent with it; refusing to adopt it"
                );
                None
            }
            Ownership::NotOurs => None,
        }
    }

    /// The custom metadata stamped on one upload: everything a reader would otherwise have to open
    /// the database to learn, plus the upload's own id.
    ///
    /// The checkpoint job may never open a tenant database and holds no decrypt authority, so every
    /// fact its manifest needs has to be stamped here or not exist. `stamp` came back from the same
    /// lock that produced the bytes; `target` and `size` are of this upload. A value this gateway
    /// could not learn is stamped [`META_UNKNOWN`] rather than omitted or defaulted.
    ///
    /// Called once per snapshot, which is what gives [`UPLOAD_ID_KEY`] its meaning: the single retry
    /// of an unanswered upload resends this same map, so whichever of the two attempts landed is
    /// recognisably this instance's afterwards.
    fn upload_metadata(&self, stamp: &SnapshotStamp, target: u64, size: u64) -> BTreeMap<String, String> {
        let optional = |value: Option<&str>| value.unwrap_or(META_UNKNOWN).to_string();
        let mut metadata = BTreeMap::new();
        metadata.insert("pm-meta-version".into(), META_VERSION.to_string());
        metadata.insert(UPLOAD_ID_KEY.into(), new_upload_id());
        // Two keys, because they are two facts. `pm-tenant` is the slug every checkpoint path, IAM
        // condition and purge is keyed by, and the only one still knowable once a worker is gone;
        // `pm-gateway-id` is the control plane's row id for the service that wrote these bytes,
        // which is what an operator needs to find the worker while it still exists.
        metadata.insert("pm-tenant".into(), optional(self.tenant.as_deref()));
        metadata.insert("pm-gateway-id".into(), optional(self.gateway_id.as_deref()));
        metadata.insert("pm-gateway-version".into(), env!("CARGO_PKG_VERSION").to_string());
        metadata.insert("pm-schema-version".into(), stamp.schema_version.to_string());
        metadata.insert("pm-commit-seq".into(), target.to_string());
        metadata.insert("pm-taken-at".into(), super::now_ms().to_string());
        metadata.insert("pm-audit-epoch".into(), stamp.epoch.to_string());
        metadata.insert(
            "pm-audit-head-seq".into(),
            stamp.head_seq.map(|s| s.to_string()).unwrap_or_else(|| META_UNKNOWN.to_string()),
        );
        metadata.insert("pm-audit-head-hash".into(), optional(stamp.head_hash.as_deref()));
        metadata.insert("pm-audit-base-seq".into(), stamp.base_seq.to_string());
        metadata.insert("pm-audit-base-hash".into(), stamp.base_hash.clone());
        metadata.insert("pm-audit-segment-head".into(), optional(stamp.segment_head.as_deref()));
        metadata.insert("pm-audit-key-wrap".into(), stamp.audit_key.wrap.to_string());
        metadata.insert("pm-audit-key-version".into(), optional(stamp.audit_key.version.as_deref()));
        metadata.insert("pm-vault-kek-version".into(), optional(self.vault_kek_version.as_deref()));
        // The two floors, so a restore can take `max(restored, retained)` over them
        // without opening a database. The checkpoint job holds no KMS decrypt authority and never
        // opens a tenant store, so anything it cannot read off the object does not exist as far as
        // a manifest is concerned: today `retained.json` carries `approval_floor: null` and
        // `replay_floor_ms: null` for exactly that reason, and a restore of an older snapshot could
        // silently put back a floor the owner had raised.
        //
        // `none` for an absent row, as every other optional stamp here does, and it is the honest
        // answer rather than a default: "no override is stored" and "this gateway did not stamp
        // one" have to stay distinguishable, and only the reader that knows the key can tell them
        // apart at all.
        metadata.insert("pm-approval-floor".into(), optional(stamp.approval_floor.as_deref()));
        metadata.insert(
            "pm-replay-floor-ms".into(),
            stamp.replay_floor_ms.map(|f| f.to_string()).unwrap_or_else(|| META_UNKNOWN.to_string()),
        );
        metadata.insert("pm-store-bytes".into(), size.to_string());
        metadata
    }

    /// Find out whether an upload that produced no response landed, and turn it into one of the
    /// outcomes a caller may be told about.
    ///
    /// Today this case leaves `state.generation` behind the truth whenever the write did land, so
    /// the next upload meets a 412 and the instance exits announcing that another instance owns the
    /// store, while describing its own write. Nothing is lost (the next boot restores that same
    /// write) but the diagnosis is wrong and a transient network blip costs a cold start.
    ///
    /// The rule that makes this safe is that `state.generation` advances on exactly two things: an
    /// acknowledged `Stored(g)`, and a generation proven to be this instance's own here. The proof
    /// is [`UPLOAD_ID_KEY`] and nothing else, because no fact taken from the store can distinguish
    /// two instances that restored the same generation. The commit sequence and the audit head are
    /// still compared, as a check that the object really is the upload the id says it is; an id that
    /// matches alongside facts that do not is a contradiction rather than a close call, so it
    /// refuses and stays quarantined instead of adopting. Metadata with no id, or none at all,
    /// proves nothing and is read as another owner, which is the conservative reading and the only
    /// safe one.
    fn reconcile_uncertain(
        &self,
        mut state: Locked<'_>,
        sent: &BTreeMap<String, String>,
        target: u64,
        changes: u64,
        bytes: &[u8],
    ) -> Result<(), GatewayError> {
        let remote = match self.objects.head_full(&self.object) {
            Ok(head) => head,
            Err(e) => {
                // Never guess. The upload is not resent, because resending a write that did land
                // draws a 412 and convinces this instance it is stale.
                tracing::error!(
                    error = %e,
                    generation = state.generation,
                    "the store upload produced no response and the object could not be read back, so whether it landed is unknown; staying quarantined without resending"
                );
                state.dirty_since.get_or_insert_with(Instant::now);
                state.outcome_uncertain = true;
                return Err(GatewayError::StoreUnavailable(format!(
                    "the last snapshot upload to {}/{} produced no response and the object could not be read back: whether it landed is not known, so this instance is refusing writes and executions until it is",
                    self.objects.describe(),
                    self.object
                )));
            }
        };
        // A missing object reads as generation 0, which is what a first upload expected to replace.
        let ours = state.generation;
        let current = remote.as_ref().map(|head| head.generation).unwrap_or(NO_GENERATION);

        if current < ours {
            // Generations are monotonic per object, so this cannot happen to a store that has not
            // been rolled back underneath the worker. Absorbing it would mean uploading over
            // whatever is really there.
            return Err(GatewayError::Internal(format!(
                "{}/{} is at generation {current} but this instance already agreed with {ours}: an object store generation went backwards, which it cannot do",
                self.objects.describe(),
                self.object
            )));
        }

        if current == ours {
            // The write never landed. One retry, at the same expected generation, because that is
            // still the generation to replace and nothing has moved.
            tracing::info!(
                generation = ours,
                "the store upload produced no response and did not land; retrying once at the same expected generation"
            );
            match self.objects.put_if_generation(&self.object, bytes, ours, sent) {
                Ok(PutOutcome::Stored(generation)) => {
                    state.agreed(generation, target, changes);
                    return Ok(());
                }
                // The 412 this retry can cause itself: the unanswered attempt was still on its way and
                // landed after the read above. Whose write it is gets decided by the id, as for any
                // other conflict with an unanswered upload outstanding.
                Ok(PutOutcome::Conflict) => {
                    return self.reconcile_conflict(state, sent, target, changes, bytes);
                }
                Ok(PutOutcome::Uncertain) | Err(_) => {
                    state.dirty_since.get_or_insert_with(Instant::now);
                    state.outcome_uncertain = true;
                    return Err(GatewayError::StoreUnavailable(format!(
                        "the snapshot upload to {}/{} is still unresolved after a retry; the local commit stands and writes are refused until it is carried",
                        self.objects.describe(),
                        self.object
                    )));
                }
            }
        }

        // Something landed. Whether it is ours is decided by the id this instance put on the bytes,
        // not by anything the bytes happen to say: two instances of one tenant that restored the
        // same generation agree on every fact in here until one of them appends an audit event. The
        // id compared against is any of this instance's still-unanswered uploads, not only the one
        // just sent: when an upload and its retry both go unanswered, the attempt that landed is an
        // earlier one, and recognising only the newest would read this instance's own write as a
        // stranger's.
        let head = remote.unwrap_or_default();
        match ownership(&state.unresolved, current, &head.metadata) {
            Ownership::Ours(_) => return self.carry_over_own_landing(state, head, sent, target, changes, bytes),
            // The id says these are our bytes, so the facts stamped beside it must be the facts we
            // stamped. If they are not, one of the two is lying and there is no safe reading: this
            // is not a close call to resolve in favour of carrying on.
            Ownership::Contradiction { stamped_seq, stamped_head, sent_seq, sent_head } => {
                state.dirty_since.get_or_insert_with(Instant::now);
                state.outcome_uncertain = true;
                let shown = |value: String| if value.is_empty() { META_UNKNOWN.to_string() } else { value };
                return Err(GatewayError::Internal(format!(
                    "{}/{} at generation {current} carries this instance's upload id but not its facts (stamped commit seq {}, audit head {}; this upload was commit seq {}, audit head {}): refusing to adopt it and staying quarantined",
                    self.objects.describe(),
                    self.object,
                    shown(stamped_seq),
                    shown(stamped_head),
                    shown(sent_seq),
                    shown(sent_head),
                )));
            }
            Ownership::NotOurs => {}
        }

        let message = if !head.metadata.contains_key(UPLOAD_ID_KEY) {
            format!(
                "{}/{} moved to generation {current} while this instance's upload went unanswered, and it carries no upload id to say who wrote it; treating it as another instance's and exiting so the next boot restores the newer state",
                self.objects.describe(),
                self.object
            )
        } else {
            format!(
                "{}/{} is at generation {current} and was written by another upload than this instance's ({}): another instance owns the store; exiting so the next boot restores the newer state",
                self.objects.describe(),
                self.object,
                sent.get(UPLOAD_ID_KEY).map(String::as_str).unwrap_or(META_UNKNOWN),
            )
        };
        self.exit_stale(state, message)
    }

    /// On a fresh instance, confirm the bucket still holds the generation this instance restored
    /// before answering a read. A moved generation is handled exactly like the write-side conflict.
    fn check_current(&self) -> Result<(), GatewayError> {
        if self.opened_at.elapsed() > self.fresh_read_window {
            return Ok(());
        }
        // Never under `serial`: on one worker a request made while holding it wedges the instance, and the `state` read below would invert the order `persist` takes the two locks in.
        // `run_atomically` runs this check before it opens the transaction, so the reads inside one are still covered.
        if self.inner.owns_transaction() {
            return Ok(());
        }
        {
            let mut last = self
                .last_generation_check
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if last.is_some_and(|t| t.elapsed() < FRESH_READ_INTERVAL) {
                return Ok(());
            }
            *last = Some(Instant::now());
        }
        // Ask the bucket first, then compare under the state lock. The lock is held for the whole of
        // an upload and the new generation is recorded before it is released, so by the time this
        // comparison runs, any upload this instance had in flight is in `state.generation`. With
        // generations monotonic per object, the bucket being AHEAD of this instance is the only
        // reading that means another owner; behind means the bucket answered before our own upload.
        let current = match blocking_section(|| self.objects.head(&self.object)) {
            Ok(Some(current)) => current,
            Ok(None) => return Ok(()),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not confirm the store generation on a fresh instance; answering from the restored copy"
                );
                return Ok(());
            }
        };
        let (ours, unresolved) = blocking_section(|| {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (state.generation, state.unresolved.clone())
        });
        if current <= ours {
            return Ok(());
        }
        // The write-side proof: a newer object carrying one of this instance's own unanswered uploads is
        // that upload's late landing, which the local copy already holds and the next write adopts.
        if blocking_section(|| self.own_unanswered(&unresolved)).is_some() {
            tracing::info!(
                current,
                ours,
                "the store object is ahead of this instance with one of its own unanswered uploads; answering from the local copy, which holds it"
            );
            return Ok(());
        }
        let message = format!(
            "store is stale on a fresh instance: {}/{} is at generation {current} and this \
             instance is at {ours}; exiting so the next boot restores the newer state",
            self.objects.describe(),
            self.object
        );
        (self.on_stale)(&message);
        Err(GatewayError::StoreUnavailable(message))
    }

    /// Whether a local commit stands that the bucket does not have.
    fn is_dirty(&self) -> bool {
        blocking_section(|| self.state.lock().unwrap_or_else(|p| p.into_inner()).dirty_since.is_some())
    }

    /// Carry the commit whose upload failed before accepting a new write, so at most one write is
    /// ever in limbo and a storage outage never stacks "failed" changes that later become durable.
    fn carry_if_dirty(&self) -> Result<(), GatewayError> {
        if self.is_dirty() {
            self.persist()
        } else {
            Ok(())
        }
    }

    /// Run a mutation and persist it before reporting success.
    fn mutate<T>(&self, f: impl FnOnce(&SqliteStore) -> Result<T, GatewayError>) -> Result<T, GatewayError> {
        let batched = BATCH_DEPTH.with(Cell::get) > 0;
        if !batched {
            self.carry_if_dirty()?;
        }
        let before = if batched { None } else { Some(self.inner.change_count()?) };
        let out = f(&self.inner)?;
        if let Some(before) = before {
            self.note_if_changed(before)?;
            self.persist()?;
        }
        Ok(out)
    }

    /// Tell the meter a unit of work changed something. The counter is connection-wide, so a
    /// concurrent writer can make a unit that wrote nothing look like one that did; that over-counts a
    /// request by one in a race, which a monthly ceiling in the hundreds of thousands does not feel.
    fn note_if_changed(&self, before: u64) -> Result<(), GatewayError> {
        if let Some(meter) = self.meter.get() {
            if self.inner.change_count()? != before {
                meter.note_mutation();
            }
        }
        Ok(())
    }

    /// Write the meter's row if it moved, and return the change count the snapshot now carries.
    fn stamp_meter(&self, changes: u64) -> Result<u64, GatewayError> {
        let Some((key, value)) = self.meter.get().and_then(|m| m.pending_stamp()) else {
            return Ok(changes);
        };
        self.inner.put_meta(key, &value)?;
        if let Some(meter) = self.meter.get() {
            meter.stamped(&value);
        }
        self.inner.change_count()
    }
}

/// The stale exit's message when the object has moved past `generation` to a write that is not ours.
fn stale_message(generation: u64) -> String {
    format!(
        "store snapshot rejected: another instance owns the store (generation moved past \
         {generation}); exiting so the next boot restores the newer state"
    )
}

/// Whether an uploaded snapshot is big enough to warn about. Its own function so the threshold is
/// testable without capturing logs, and so a threshold of zero means "always warn" rather than
/// "never", which a `>=` on an empty file would.
fn snapshot_is_oversized(bytes: u64, warn_above: u64) -> bool {
    bytes > warn_above
}

/// A fresh upload id: 128 bits from the OS, hex. Random rather than derived, because everything
/// derivable from the store is shared by two instances that restored the same generation, and that
/// is exactly the case this has to tell apart.
fn new_upload_id() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let mut out = String::with_capacity(32);
    for b in raw {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// An environment variable that is set to something, treating empty as unset: a Cloud Run service
/// with a variable declared and never filled in would otherwise stamp an empty tenant slug.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Write the restored bytes over the local database, clearing the write-ahead sidecars.
///
/// The snapshot is a `VACUUM INTO` product, so it has no WAL of its own; a `-wal` or `-shm` left
/// from a previous instance would be replayed over it and reintroduce state the snapshot does not
/// have.
fn restore_file(path: &str, bytes: &[u8]) -> Result<(), GatewayError> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| GatewayError::Internal(format!("store dir {}: {e}", parent.display())))?;
        }
    }
    // `replace_secret_file`, not `write_secret_file`: the latter creates with `create_new` and
    // refuses a path that already holds a database, which is every restore but the first.
    permaura_core::replace_secret_file(p, bytes)
        .map_err(|e| GatewayError::Internal(format!("write restored store {path}: {e}")))?;
    for sidecar in [format!("{path}-wal"), format!("{path}-shm")] {
        let _ = std::fs::remove_file(&sidecar);
    }
    Ok(())
}

impl Store for PersistedSqliteStore {
    fn kind(&self) -> &'static str {
        "sqlite+gcs"
    }

    fn degraded(&self) -> Option<String> {
        let (since, uncertain) = (*self.published.lock().unwrap_or_else(|p| p.into_inner()))?;
        // The two are not the same claim and must not read as one. An upload that failed did not
        // land; an upload that went unanswered may have, and an operator deciding whether to promote
        // a retained version needs to know which of those this is.
        let what = if uncertain {
            "produced no response and could not be resolved"
        } else {
            "failed"
        };
        Some(format!(
            "storage unavailable: the last snapshot upload to {}/{} {what} {} s ago; reads are served from this instance, writes and executions are refused until an upload succeeds",
            self.objects.describe(),
            self.object,
            since.elapsed().as_secs()
        ))
    }

    fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError> {
        struct Depth;
        impl Drop for Depth {
            fn drop(&mut self) {
                BATCH_DEPTH.with(|d| d.set(d.get() - 1));
            }
        }
        // Read before the depth moves: an error here must not leave the depth raised with no guard.
        let before = if BATCH_DEPTH.with(Cell::get) == 0 {
            self.carry_if_dirty()?;
            self.check_current()?;
            Some(self.inner.change_count()?)
        } else {
            None
        };
        BATCH_DEPTH.with(|d| d.set(d.get() + 1));
        let out = {
            let _depth = Depth;
            self.inner.transaction(|| f(self))
        };
        out?;
        // A rolled-back scope changed nothing durable, and a nested one leaves the upload to the outer.
        if let Some(before) = before {
            self.note_if_changed(before)?;
            self.persist()?;
        }
        Ok(())
    }

    fn change_with_record(&self, f: &mut dyn FnMut() -> Result<(), GatewayError>) -> Result<(), GatewayError> {
        struct Depth;
        impl Drop for Depth {
            fn drop(&mut self) {
                BATCH_DEPTH.with(|d| d.set(d.get() - 1));
            }
        }
        if BATCH_DEPTH.with(Cell::get) > 0 {
            return f();
        }
        self.carry_if_dirty()?;
        self.check_current()?;
        let before = self.inner.change_count()?;
        BATCH_DEPTH.with(|d| d.set(d.get() + 1));
        let out = {
            let _depth = Depth;
            // Not left to the thread-local depth alone: another request's write on another thread uploads the whole database, this change included.
            let _gate = blocking_section(|| self.record_gate.write().unwrap_or_else(|p| p.into_inner()));
            f()
        };
        // Uploaded whatever `f` got to, as each write would have been on its own; a change whose record
        // was appended is never in a snapshot without it, because no upload on any thread ran between the two.
        self.note_if_changed(before)?;
        let persisted = self.persist();
        out?;
        persisted
    }

    fn attach_meter(&self, meter: Arc<dyn super::SnapshotMeter>) -> bool {
        self.meter.set(meter).is_ok()
    }

    // No generation check: liveness is about this instance answering, and a bucket round trip would make it about the bucket.
    fn liveness_touch(&self) -> Result<bool, GatewayError> {
        self.inner.liveness_touch()
    }

    // ── agents ────────────────────────────────────────────────────────────────
    fn put_agent(&self, agent: Agent) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_agent(agent))
    }
    fn get_agent(&self, id: &str) -> Result<Option<Agent>, GatewayError> {
        self.check_current()?;

        self.inner.get_agent(id)
    }
    fn list_agents(&self) -> Result<Vec<Agent>, GatewayError> {
        self.check_current()?;

        self.inner.list_agents()
    }
    fn delete_agent(&self, id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_agent(id))
    }

    // ── sessions ──────────────────────────────────────────────────────────────
    fn put_session(&self, session: Session) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_session(session))
    }
    fn insert_session(&self, session: Session) -> Result<bool, GatewayError> {
        self.mutate(|s| s.insert_session(session))
    }
    fn touch_session(&self, id: &str, token: &str, now: i64, extend_expiry_to: Option<i64>) -> Result<bool, GatewayError> {
        self.mutate(|s| s.touch_session(id, token, now, extend_expiry_to))
    }
    fn session_by_token(&self, token: &str) -> Result<Option<Session>, GatewayError> {
        self.check_current()?;

        self.inner.session_by_token(token)
    }
    fn get_session(&self, id: &str) -> Result<Option<Session>, GatewayError> {
        self.check_current()?;

        self.inner.get_session(id)
    }
    fn list_sessions(&self) -> Result<Vec<Session>, GatewayError> {
        self.check_current()?;

        self.inner.list_sessions()
    }
    fn revoke_session(&self, id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.revoke_session(id))
    }
    fn expire_session_by(&self, id: &str, at: i64) -> Result<bool, GatewayError> {
        self.mutate(|s| s.expire_session_by(id, at))
    }
    fn delete_session(&self, id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_session(id))
    }
    fn delete_session_if(&self, id: &str, dead: &dyn Fn(&Session) -> bool) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_session_if(id, dead))
    }
    fn delete_live_sessions(&self) -> Result<u64, GatewayError> {
        self.mutate(|s| s.delete_live_sessions())
    }

    // ── connections ───────────────────────────────────────────────────────────
    fn put_connection(&self, connection: Conn) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_connection(connection))
    }
    fn get_connection(&self, id: &str) -> Result<Option<Conn>, GatewayError> {
        self.check_current()?;

        self.inner.get_connection(id)
    }
    fn list_connections(&self) -> Result<Vec<Conn>, GatewayError> {
        self.check_current()?;

        self.inner.list_connections()
    }
    fn delete_connection(&self, id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_connection(id))
    }

    // ── policies ──────────────────────────────────────────────────────────────
    fn put_policy(&self, policy: Policy) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_policy(policy))
    }
    fn get_policy(&self, id: &str) -> Result<Option<Policy>, GatewayError> {
        self.check_current()?;

        self.inner.get_policy(id)
    }
    fn list_policies(&self) -> Result<Vec<Policy>, GatewayError> {
        self.check_current()?;

        self.inner.list_policies()
    }
    fn policies_for_connection(&self, connection_id: &str) -> Result<Vec<Policy>, GatewayError> {
        self.check_current()?;

        self.inner.policies_for_connection(connection_id)
    }
    fn delete_policy(&self, id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_policy(id))
    }

    // ── grants ────────────────────────────────────────────────────────────────
    fn put_grant(&self, grant: Grant) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_grant(grant))
    }
    fn get_grant(&self, grant_id: &str) -> Result<Option<Grant>, GatewayError> {
        self.check_current()?;

        self.inner.get_grant(grant_id)
    }
    fn list_grants(&self) -> Result<Vec<Grant>, GatewayError> {
        self.check_current()?;

        self.inner.list_grants()
    }
    fn update_grant(&self, grant: Grant) -> Result<bool, GatewayError> {
        self.mutate(|s| s.update_grant(grant))
    }
    fn delete_grant(&self, grant_id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_grant(grant_id))
    }

    // ── enrolment codes ───────────────────────────────────────────────────────
    fn put_enrolment_code(&self, code: EnrolmentCode) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_enrolment_code(code))
    }
    fn mint_enrolment_code(&self, code: EnrolmentCode, now_ms: i64, live_max: usize) -> Result<(), GatewayError> {
        self.mutate(|s| s.mint_enrolment_code(code, now_ms, live_max))
    }
    fn consume_enrolment_code(
        &self,
        code: &str,
        now_ms: i64,
    ) -> Result<Option<EnrolmentCode>, GatewayError> {
        self.mutate(|s| s.consume_enrolment_code(code, now_ms))
    }
    fn enrolment_code_redeemable(&self, code: &str, now_ms: i64) -> Result<bool, GatewayError> {
        self.check_current()?;
        self.inner.enrolment_code_redeemable(code, now_ms)
    }
    fn live_enrolment_code_digests(&self, now_ms: i64) -> Result<Vec<String>, GatewayError> {
        self.check_current()?;
        self.inner.live_enrolment_code_digests(now_ms)
    }
    fn delete_unconsumed_enrolment_codes(&self) -> Result<u64, GatewayError> {
        self.mutate(|s| s.delete_unconsumed_enrolment_codes())
    }

    // ── secrets ───────────────────────────────────────────────────────────────
    fn put_secret(&self, record: SecretRecord) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_secret(record))
    }
    fn get_secret(&self, id: &str) -> Result<Option<SecretRecord>, GatewayError> {
        self.check_current()?;

        self.inner.get_secret(id)
    }
    fn put_secret_if_unchanged(&self, id: &str, expected: &SealedSecret, sealed: SealedSecret) -> Result<bool, GatewayError> {
        // Not `mutate`, for the reason the terminal audit event is not: the only caller writes a rotation the provider has already committed to, so it is committed here whatever the bucket is doing and the upload carries it with whatever was waiting.
        if BATCH_DEPTH.with(Cell::get) > 0 {
            return self.inner.put_secret_if_unchanged(id, expected, sealed);
        }
        let before = self.inner.change_count()?;
        let swapped = self.inner.put_secret_if_unchanged(id, expected, sealed)?;
        self.note_if_changed(before)?;
        self.persist().map_err(|e| match e {
            GatewayError::StoreUnavailable(m) => GatewayError::StoreUnavailable(format!(
                "secret '{id}' is written on this instance and is carried by the next snapshot upload that succeeds: {m}"
            )),
            other => other,
        })?;
        Ok(swapped)
    }
    fn list_secret_ids(&self) -> Result<Vec<String>, GatewayError> {
        self.check_current()?;

        self.inner.list_secret_ids()
    }
    fn delete_secret(&self, id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_secret(id))
    }

    // ── secret custody ────────────────────────────────────────────────────────
    fn put_secret_custody(&self, custody: SecretCustody) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_secret_custody(custody))
    }
    fn get_secret_custody(&self, secret_id: &str) -> Result<Option<SecretCustody>, GatewayError> {
        self.check_current()?;

        self.inner.get_secret_custody(secret_id)
    }
    fn list_secret_custody(&self) -> Result<Vec<SecretCustody>, GatewayError> {
        self.check_current()?;

        self.inner.list_secret_custody()
    }
    fn delete_secret_custody(&self, secret_id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_secret_custody(secret_id))
    }

    // ── capabilities ──────────────────────────────────────────────────────────
    fn put_capability(&self, cap: Capability) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_capability(cap))
    }
    fn get_capability(&self, id: &str) -> Result<Option<Capability>, GatewayError> {
        self.check_current()?;

        self.inner.get_capability(id)
    }
    fn list_capabilities(&self) -> Result<Vec<Capability>, GatewayError> {
        self.check_current()?;

        self.inner.list_capabilities()
    }
    fn delete_capability(&self, id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_capability(id))
    }

    // ── approvals ─────────────────────────────────────────────────────────────
    fn insert_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        self.mutate(|s| s.insert_approval(approval))
    }
    fn put_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_approval(approval))
    }
    fn get_approval(&self, id: &str) -> Result<Option<PendingApproval>, GatewayError> {
        self.check_current()?;

        self.inner.get_approval(id)
    }
    fn get_approval_outcome(&self, id: &str) -> Result<Option<super::ApprovalOutcome>, GatewayError> {
        self.check_current()?;
        self.inner.get_approval_outcome(id)
    }
    fn set_approval_status(
        &self,
        id: &str,
        status: &str,
    ) -> Result<Option<PendingApproval>, GatewayError> {
        self.mutate(|s| s.set_approval_status(id, status))
    }
    fn list_approvals(&self, status: Option<&str>) -> Result<Vec<PendingApproval>, GatewayError> {
        self.check_current()?;

        self.inner.list_approvals(status)
    }
    fn count_pending_approvals(&self) -> Result<usize, GatewayError> {
        self.check_current()?;

        self.inner.count_pending_approvals()
    }
    fn pending_staging_owners(&self) -> Result<Vec<(String, Option<super::HoldRequester>)>, GatewayError> {
        self.check_current()?;

        self.inner.pending_staging_owners()
    }

    fn pending_hold_bytes(&self) -> Result<u64, GatewayError> {
        self.check_current()?;
        self.inner.pending_hold_bytes()
    }

    fn capability_bytes(&self) -> Result<u64, GatewayError> {
        self.check_current()?;
        self.inner.capability_bytes()
    }

    fn pending_control_plane_hold_bytes(&self) -> Result<u64, GatewayError> {
        self.check_current()?;
        self.inner.pending_control_plane_hold_bytes()
    }

    fn list_pending_control_plane_holds(&self) -> Result<Vec<PendingApproval>, GatewayError> {
        self.check_current()?;
        self.inner.list_pending_control_plane_holds()
    }

    // ── connector manifests ───────────────────────────────────────────────────
    fn put_connector_manifest(&self, manifest: InstalledManifest) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_connector_manifest(manifest))
    }
    fn get_connector_manifest(&self, id: &str) -> Result<Option<InstalledManifest>, GatewayError> {
        self.check_current()?;

        self.inner.get_connector_manifest(id)
    }
    fn list_connector_manifests(&self) -> Result<Vec<InstalledManifest>, GatewayError> {
        self.check_current()?;

        self.inner.list_connector_manifests()
    }
    fn delete_connector_manifest(&self, id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.delete_connector_manifest(id))
    }

    // ── durable trust state ───────────────────────────────────────────────────
    fn get_meta(&self, key: &str) -> Result<Option<String>, GatewayError> {
        self.check_current()?;

        self.inner.get_meta(key)
    }
    fn put_meta(&self, key: &str, value: &str) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_meta(key, value))
    }
    fn claim_once(&self, scope: &str, jti: &str, expires_at_ms: i64) -> Result<bool, GatewayError> {
        // Persisted whichever way the claim goes: a replay still prunes expired rows, and a claim
        // that is durable only in this instance is not single use across the fleet.
        self.mutate(|s| s.claim_once(scope, jti, expires_at_ms))
    }

    // ── audit log ─────────────────────────────────────────────────────────────
    fn append_audit_charged(
        &self,
        payload: AuditPayload,
        charge: Option<super::GrantCharge>,
    ) -> Result<AuditEvent, GatewayError> {
        self.mutate(|s| s.append_audit_charged(payload, charge))
    }
    fn append_audit_explained(
        &self,
        payload: AuditPayload,
        charge: Option<super::GrantCharge>,
        diagnostic: Option<super::CallDiagnostic>,
    ) -> Result<AuditEvent, GatewayError> {
        // One persist for the event and its explanation, so a failed call costs one snapshot upload
        // and no reader ever sees `"diagnostic": true` before the row it points at exists.
        self.mutate(|s| s.append_audit_explained(payload, charge, diagnostic))
    }
    fn append_audit_terminal(
        &self,
        payload: AuditPayload,
        charge: Option<super::GrantCharge>,
        diagnostic: Option<super::CallDiagnostic>,
    ) -> Result<AuditEvent, GatewayError> {
        // Not `mutate`, whose first step carries a dirty commit and refuses this write when that
        // fails: the execution this closes has already run, so the record is committed here whatever
        // the bucket is doing, and the upload below carries it together with whatever was waiting.
        if BATCH_DEPTH.with(Cell::get) > 0 {
            return self.inner.append_audit_explained(payload, charge, diagnostic);
        }
        let before = self.inner.change_count()?;
        let event = self.inner.append_audit_explained(payload, charge, diagnostic)?;
        self.note_if_changed(before)?;
        self.persist().map_err(|e| match e {
            GatewayError::StoreUnavailable(m) => GatewayError::StoreUnavailable(format!(
                "terminal audit event {} is recorded on this instance and is carried by the next snapshot upload that succeeds: {m}",
                event.seq
            )),
            other => other,
        })?;
        Ok(event)
    }
    fn append_audit_fence(&self, payload: AuditPayload) -> Result<(AuditEvent, Option<GatewayError>), GatewayError> {
        // `mutate`'s steps, kept apart so the caller learns which of them failed: a commit that
        // could not be carried first means nothing was recorded, and an upload that failed after the
        // local commit means the attempt exists here and needs closing.
        if BATCH_DEPTH.with(Cell::get) > 0 {
            return self.inner.append_audit(payload).map(|event| (event, None));
        }
        self.carry_if_dirty()?;
        let before = self.inner.change_count()?;
        let event = self.inner.append_audit(payload)?;
        self.note_if_changed(before)?;
        match self.persist() {
            Ok(()) => Ok((event, None)),
            Err(e) => Ok((event, Some(e))),
        }
    }
    fn carry_pending(&self) -> Result<bool, GatewayError> {
        if !self.is_dirty() {
            return Ok(true);
        }
        self.persist()?;
        Ok(!self.is_dirty())
    }
    fn carry_before_exit(&self) -> Result<bool, GatewayError> {
        if !self.is_dirty() {
            return Ok(true);
        }
        self.persist_floored(false)?;
        Ok(!self.is_dirty())
    }
    fn owes_upload(&self) -> bool {
        self.published.lock().unwrap_or_else(|p| p.into_inner()).is_some()
    }
    fn put_call_diagnostic(&self, diagnostic: super::CallDiagnostic) -> Result<(), GatewayError> {
        self.mutate(|s| s.put_call_diagnostic(diagnostic))
    }
    fn call_diagnostics(&self, from_seq: u64) -> Result<Vec<super::CallDiagnostic>, GatewayError> {
        self.check_current()?;

        self.inner.call_diagnostics(from_seq)
    }
    fn purge_call_diagnostics(&self) -> Result<u64, GatewayError> {
        self.mutate(|s| s.purge_call_diagnostics())
    }
    fn audit_events(&self, limit: Option<usize>) -> Result<Vec<AuditEvent>, GatewayError> {
        self.check_current()?;

        self.inner.audit_events(limit)
    }
    fn audit_events_from(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, GatewayError> {
        self.check_current()?;

        self.inner.audit_events_from(from_seq, limit)
    }
    fn prune_audit_to(
        &self,
        end_seq: u64,
        base_hash: &str,
        segment_head: &str,
    ) -> Result<u64, GatewayError> {
        // Through `mutate`, so the pruned database is uploaded before the prune is reported. A
        // prune that lived only in this instance would be undone by the next cold start restoring
        // the snapshot in the bucket, and the segment would then be published a second time.
        self.mutate(|s| s.prune_audit_to(end_seq, base_hash, segment_head))
    }
    fn seal_audit_segment(
        &self,
        draft: permaura_core::audit::AuditSegmentDraft,
    ) -> Result<permaura_core::audit::AuditSegment, GatewayError> {
        self.inner.seal_audit_segment(draft)
    }
    fn seal_audit_index(
        &self,
        index: permaura_core::audit::AuditArchiveIndex,
        written_at: &str,
    ) -> Result<permaura_core::audit::AuditArchiveIndex, GatewayError> {
        self.inner.seal_audit_index(index, written_at)
    }
    fn audit_verifying_key(&self) -> Result<[u8; 32], GatewayError> {
        self.inner.audit_verifying_key()
    }
    fn audit_rekey(&self) -> Result<Option<permaura_core::audit::AuditRekey>, GatewayError> {
        self.inner.audit_rekey()
    }
    fn audit_len(&self) -> Result<u64, GatewayError> {
        // No `check_current()`, and that is the point rather than an omission. Every other read here
        // confirms this instance still owns the store because it is about to hand a caller tenant
        // state. This one is about how much THIS instance is carrying in memory and in its next
        // snapshot, which is a local fact and is true whether or not another instance has moved on.
        // Confirming it would also put a metadata request on the execution path in front of the
        // fence, for an answer that cannot change what it says.
        self.inner.audit_len()
    }
    fn count_grant_usage(
        &self,
        windows: &[super::GrantWindow<'_>],
    ) -> Result<super::GrantUsageCounts, GatewayError> {
        // `check_current()`, unlike `audit_len`, because this is tenant state read out of the
        // chain: it is exactly the read `audit_events` took here before, and dropping the
        // confirmation would let a stale instance answer from a chain another instance has moved
        // past.
        self.check_current()?;

        self.inner.count_grant_usage(windows)
    }
    fn read_grant_usage(
        &self,
        windows: &[super::GrantWindow<'_>],
    ) -> Result<super::GrantUsageCounts, GatewayError> {
        // `check_current()` for the reason `count_grant_usage` has one: this is the read that
        // authorizes a call, and a stale instance must not spend a budget another instance owns.
        self.check_current()?;

        self.inner.read_grant_usage(windows)
    }
    fn grant_usage_series(
        &self,
        grant_id: &str,
        since_ms: i64,
        bucket_ms: i64,
        buckets: usize,
    ) -> Result<Vec<u64>, GatewayError> {
        self.check_current()?;
        self.inner.grant_usage_series(grant_id, since_ms, bucket_ms, buckets)
    }
    fn rebuild_grant_usage(
        &self,
        archived: &mut dyn Iterator<Item = Result<AuditEvent, GatewayError>>,
    ) -> Result<u64, GatewayError> {
        // The walk fetches every archived segment, so it runs before `mutate` and with the store's
        // lock released. Only the apply is a write, so only it goes through `mutate` and is uploaded
        // before it is reported: a rebuilt counter that lived only in this instance would be lost
        // with it, and the budget would be back to whatever the snapshot in the bucket says.
        let walked = self.inner.walk_grant_usage(archived)?;
        self.mutate(|s| s.apply_grant_usage(walked))
    }
    fn verify_audit(&self) -> Result<Option<u64>, GatewayError> {
        self.check_current()?;

        self.inner.verify_audit()
    }
    fn audit_boundary(&self) -> Result<Option<permaura_core::audit::AuditBoundary>, GatewayError> {
        self.inner.audit_boundary()
    }
    /// Through [`Self::mutate`], so the forked boundary reaches object storage before anything acts
    /// on it. A fork that lived only in this container's filesystem would be undone by the next cold
    /// start, and the epoch would then be describing a fork the chain no longer records.
    fn fork_audit_epoch(&self, epoch: u64, restore_id: &str) -> Result<bool, GatewayError> {
        self.mutate(|s| s.fork_audit_epoch(epoch, restore_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::KmsClient;
    use crate::objectstore::{FailingObjectStore, MemoryObjectStore, ObjectHead};
    use async_trait::async_trait;
    use permaura_core::AuditPayload;

    /// A reversible stand-in for a cloud KMS: XOR is symmetric, so wrap/unwrap round-trip without an
    /// HSM.
    struct XorKms;
    #[async_trait]
    impl KmsClient for XorKms {
        async fn decrypt(&self, _key_id: &str, ct: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, GatewayError> {
            Ok(zeroize::Zeroizing::new(ct.iter().map(|b| b ^ 0x5A).collect()))
        }
        async fn encrypt(&self, _key_id: &str, pt: &[u8]) -> Result<Vec<u8>, GatewayError> {
            Ok(pt.iter().map(|b| b ^ 0x5A).collect())
        }
    }

    fn wrap() -> Option<AuditKeyWrap> {
        Some(AuditKeyWrap { kms: Arc::new(XorKms), key_id: "test-cmk".into(), adopt_plaintext: false })
    }

    /// A private directory for one test, named after it so a failure leaves something identifiable.
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("permaura-persisted-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open(dir: &Path, objects: Arc<dyn ObjectStore>) -> PersistedSqliteStore {
        let path = dir.join("gateway.db");
        PersistedSqliteStore::open(&path.to_string_lossy(), objects, DEFAULT_OBJECT, wrap())
            .unwrap()
            .with_carry_floor(Duration::ZERO)
    }

    /// The conditional write swaps only while the stored envelope is the one the caller read,
    /// keeps the stored metadata, and never brings back a deleted secret.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn put_secret_if_unchanged_swaps_only_the_envelope_it_was_given() {
        let dir = temp_dir("cas");
        let store = open(&dir, Arc::new(MemoryObjectStore::new()));
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

    /// Open the uploaded bytes as an ordinary SQLite store, which is the whole promise of the
    /// snapshot: a complete, standalone database file.
    fn store_from_object(objects: &MemoryObjectStore, dir: &Path, tag: &str) -> super::SqliteStore {
        let generation = objects.head(DEFAULT_OBJECT).unwrap().expect("an object");
        let bytes = objects.get(DEFAULT_OBJECT, generation).unwrap();
        let path = dir.join(format!("copy-{tag}.db"));
        std::fs::write(&path, bytes).unwrap();
        super::SqliteStore::open_with_custody(&path.to_string_lossy(), wrap()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_first_mutation_uploads_a_readable_database_at_generation_one() {
        let dir = temp_dir("fresh");
        let objects = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects.clone());
        store.put_agent(Agent::approved("codex-cli", "Codex CLI", 0)).unwrap();

        assert_eq!(objects.head(DEFAULT_OBJECT).unwrap(), Some(1), "one object, at the first generation");
        assert_eq!(store.generation(), 1);
        let copy = store_from_object(&objects, &dir, "fresh");
        assert_eq!(copy.get_agent("codex-cli").unwrap().unwrap().name, "Codex CLI");
    }

    /// The audit chain has to survive a cold start, which it only does if the signing
    /// key travelled inside the snapshot rather than in a sidecar the instance left behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restored_store_keeps_its_state_and_its_audit_chain() {
        let dir = temp_dir("restore");
        let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        let path = dir.join("gateway.db");
        {
            let store = open(&dir, objects.clone());
            store.put_agent(Agent::approved("agent-a", "A", 0)).unwrap();
            store.append_audit(AuditPayload::new("first", "r", "allow")).unwrap();
            store.append_audit(AuditPayload::new("second", "r", "deny")).unwrap();
        }
        // Everything local is gone, exactly as it is when a Cloud Run instance is replaced.
        for suffix in ["", "-wal", "-shm", ".auditkey", ".snap"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }

        let store = open(&dir, objects);
        assert_eq!(store.list_agents().unwrap().len(), 1, "state came back");
        assert_eq!(store.audit_events(None).unwrap().len(), 2, "the audit rows came back");
        assert_eq!(store.verify_audit().unwrap(), None, "and they verify under the same key");
        assert!(
            !path.with_extension("db.auditkey").exists() && !dir.join("gateway.db.auditkey").exists(),
            "no sidecar key: it would fork the chain at the next cold start"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stale_instance_is_told_it_lost_the_store() {
        let dir_a = temp_dir("conflict-a");
        let dir_b = temp_dir("conflict-b");
        let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        let a = open(&dir_a, objects.clone());
        let stale = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = stale.clone();
        let b = open(&dir_b, objects)
            .with_on_stale(Box::new(move |m| recorder.lock().unwrap().push(m.to_string())));

        a.put_agent(Agent::approved("a", "A", 0)).unwrap();
        let err = b.put_agent(Agent::approved("b", "B", 0)).unwrap_err();

        assert!(format!("{err}").contains("another instance owns the store"), "got {err}");
        assert_eq!(stale.lock().unwrap().len(), 1, "the stale handler ran exactly once");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_mutations_coalesce_into_fewer_uploads_than_writes() {
        const WRITERS: usize = 8;
        let dir = temp_dir("coalesce");
        let objects = Arc::new(MemoryObjectStore::new());
        let store = Arc::new(open(&dir, objects.clone()));

        let mut handles = Vec::new();
        for i in 0..WRITERS {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                store.put_agent(Agent::approved(format!("agent-{i}"), "A", 0)).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let puts = objects.put_count();
        assert!((1..=WRITERS as u64).contains(&puts), "expected 1..={WRITERS} uploads, saw {puts}");
        let copy = store_from_object(&objects, &dir, "coalesce");
        assert_eq!(copy.list_agents().unwrap().len(), WRITERS, "every mutation is in the final object");
    }

    /// After a failed upload, nothing tries another within the carry floor: not the tick or a request's carry, and not a write, which is refused at once with the failure it would meet.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_upload_is_tried_again_inside_the_carry_floor_after_one_failed() {
        struct Failing {
            inner: MemoryObjectStore,
            fail: Mutex<bool>,
            puts: std::sync::atomic::AtomicUsize,
        }
        impl ObjectStore for Failing {
            fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
                self.inner.head(name)
            }
            fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
                self.inner.head_full(name)
            }
            fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
                self.inner.has_history(name)
            }
            fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
                self.inner.get(name, generation)
            }
            fn put_if_generation(
                &self,
                name: &str,
                bytes: &[u8],
                expected: u64,
                metadata: &BTreeMap<String, String>,
            ) -> Result<PutOutcome, GatewayError> {
                self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if *self.fail.lock().unwrap() {
                    return Err(GatewayError::Internal("object store answered 403".into()));
                }
                self.inner.put_if_generation(name, bytes, expected, metadata)
            }
            fn describe(&self) -> String {
                self.inner.describe()
            }
        }
        let dir = temp_dir("c6-carry-floor");
        let objects = Arc::new(Failing { inner: MemoryObjectStore::new(), fail: Mutex::new(false), puts: Default::default() });
        let path = dir.join("store.db");
        let store = PersistedSqliteStore::open(&path.to_string_lossy(), objects.clone(), DEFAULT_OBJECT, wrap())
            .unwrap()
            .with_carry_floor(Duration::from_secs(60));
        store.put_agent(Agent::approved("first", "First", 0)).unwrap();
        *objects.fail.lock().unwrap() = true;
        store.put_agent(Agent::approved("owed", "Owed", 0)).unwrap_err();
        let after_failure = objects.puts.load(std::sync::atomic::Ordering::SeqCst);

        assert!(!store.carry_pending().unwrap_or(false), "still owed");
        let refused = store.put_agent(Agent::approved("next", "Next", 0)).unwrap_err();
        assert!(matches!(refused, GatewayError::StoreUnavailable(_)), "{refused}");
        assert_eq!(
            objects.puts.load(std::sync::atomic::Ordering::SeqCst),
            after_failure,
            "no upload was tried again inside the floor"
        );
    }

    /// On request-based CPU the 2 s carrier gets no CPU between requests, so a commit an upload failure left local is carried on the next request's path, a read included, before that request answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_commit_left_local_is_carried_by_the_next_request_even_a_read() {
        use tower::ServiceExt as _;
        struct FailOnce {
            inner: MemoryObjectStore,
            fail_next: Mutex<bool>,
        }
        impl ObjectStore for FailOnce {
            fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
                self.inner.head(name)
            }
            fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
                self.inner.head_full(name)
            }
            fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
                self.inner.has_history(name)
            }
            fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
                self.inner.get(name, generation)
            }
            fn put_if_generation(
                &self,
                name: &str,
                bytes: &[u8],
                expected: u64,
                metadata: &BTreeMap<String, String>,
            ) -> Result<PutOutcome, GatewayError> {
                if std::mem::take(&mut *self.fail_next.lock().unwrap()) {
                    return Err(GatewayError::Internal("object store unavailable".into()));
                }
                self.inner.put_if_generation(name, bytes, expected, metadata)
            }
            fn describe(&self) -> String {
                self.inner.describe()
            }
        }

        let dir = temp_dir("request-carry");
        let objects = Arc::new(FailOnce { inner: MemoryObjectStore::new(), fail_next: Mutex::new(false) });
        let store = Arc::new(open(&dir, objects.clone()));
        store.put_agent(Agent::approved("first", "First", 0)).unwrap();
        *objects.fail_next.lock().unwrap() = true;
        store.put_agent(Agent::approved("owed", "Owed", 0)).unwrap_err();
        assert!(<PersistedSqliteStore as Store>::degraded(store.as_ref()).is_some(), "the commit is owed");

        let state = crate::AppState::from_parts(store.clone(), Arc::new(crate::connectors::MockHttpClient::new()));
        let app = crate::build_router(state, "127.0.0.1:7376".parse().unwrap());
        // Any read but `/health`, which starts the carry and answers without waiting for it, so a liveness probe never reaches its timeout.
        let read = axum::http::Request::builder().uri("/").body(axum::body::Body::empty()).unwrap();
        let answered = app.oneshot(read).await.unwrap();
        assert!(answered.status().is_success(), "{}", answered.status());

        assert_eq!(<PersistedSqliteStore as Store>::degraded(store.as_ref()), None, "the read carried the owed commit");
        assert!(store_from_object(&objects.inner, &dir, "request-carry").get_agent("owed").unwrap().is_some());
    }

    /// An upload that fails leaves the local commit standing, and the next successful upload carries
    /// it. What the caller saw was an error, so nothing was acknowledged that is not durable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_upload_is_carried_by_the_next_successful_one() {
        struct Flaky {
            inner: MemoryObjectStore,
            fail_next: Mutex<bool>,
        }
        impl ObjectStore for Flaky {
            fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
                self.inner.head(name)
            }
            fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
                self.inner.head_full(name)
            }
            fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
                self.inner.has_history(name)
            }
            fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
                self.inner.get(name, generation)
            }
            fn put_if_generation(
                &self,
                name: &str,
                bytes: &[u8],
                expected: u64,
                metadata: &BTreeMap<String, String>,
            ) -> Result<PutOutcome, GatewayError> {
                let mut fail = self.fail_next.lock().unwrap();
                if *fail {
                    *fail = false;
                    return Err(GatewayError::Internal("object store unavailable".into()));
                }
                self.inner.put_if_generation(name, bytes, expected, metadata)
            }
            fn describe(&self) -> String {
                self.inner.describe()
            }
        }

        let dir = temp_dir("carry");
        let objects = Arc::new(Flaky { inner: MemoryObjectStore::new(), fail_next: Mutex::new(true) });
        let store = open(&dir, objects.clone());

        let err = store.put_agent(Agent::approved("lost-ack", "A", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "the upload failed, and it says so: {err}");
        store.put_agent(Agent::approved("next", "B", 0)).unwrap();

        let generation = objects.head(DEFAULT_OBJECT).unwrap().unwrap();
        let bytes = objects.get(DEFAULT_OBJECT, generation).unwrap();
        let path = dir.join("carried.db");
        std::fs::write(&path, bytes).unwrap();
        let copy = super::SqliteStore::open_with_custody(&path.to_string_lossy(), wrap()).unwrap();
        assert!(copy.get_agent("lost-ack").unwrap().is_some(), "the earlier commit rode the later upload");
        assert!(copy.get_agent("next").unwrap().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreachable_bucket_never_starts_empty() {
        let dir = temp_dir("unreachable");
        let objects: Arc<dyn ObjectStore> =
            Arc::new(FailingObjectStore { reason: "storage.googleapis.com unreachable".into() });
        let err = PersistedSqliteStore::open(
            &dir.join("gateway.db").to_string_lossy(),
            objects,
            DEFAULT_OBJECT,
            wrap(),
        )
        .err()
        .expect("an unreachable object store must not open");
        assert!(format!("{err}").contains("unreachable"), "got {err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_corrupt_snapshot_is_refused_and_names_its_generation() {
        let dir = temp_dir("corrupt");
        let objects = Arc::new(MemoryObjectStore::new());
        {
            let store = open(&dir, objects.clone());
            store.put_agent(Agent::approved("a", "A", 0)).unwrap();
        }
        objects.corrupt(DEFAULT_OBJECT, b"this is not a database".to_vec());
        let path = dir.join("gateway.db");
        std::fs::remove_file(&path).unwrap();

        let err = PersistedSqliteStore::open(
            &path.to_string_lossy(),
            objects.clone(),
            DEFAULT_OBJECT,
            wrap(),
        )
        .err()
        .expect("a corrupt snapshot must not open");
        let message = format!("{err}");
        assert!(message.contains("generation 1"), "the error must name the generation: {message}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_oversized_snapshot_warns_and_still_persists() {
        let dir = temp_dir("oversize");
        let objects = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects.clone()).with_warn_bytes(0);
        store.put_agent(Agent::approved("a", "A", 0)).unwrap();

        let generation = objects.head(DEFAULT_OBJECT).unwrap().expect("the warning does not block the upload");
        let size = objects.get(DEFAULT_OBJECT, generation).unwrap().len() as u64;
        assert!(snapshot_is_oversized(size, 0), "a snapshot of {size} bytes is over a zero threshold");
        assert!(!snapshot_is_oversized(size, DEFAULT_WARN_BYTES), "and well under the shipped one");
    }
    /// A restore must overwrite whatever is already at the path, not refuse because something is there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restore_overwrites_an_existing_local_database() {
        let dir = temp_dir("overwrite");
        let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        {
            let store = open(&dir, objects.clone());
            store.put_agent(Agent::approved("only", "Only", 0)).unwrap();
        }
        // The local file is still there, as it is on any second open in one process.
        let store = open(&dir, objects);
        assert_eq!(store.list_agents().unwrap().len(), 1);
    }

    /// The production object store bridges to async inside a call that is already inside
    /// `blocking_section`, and `MemoryObjectStore` is synchronous, so nothing else here exercises
    /// that nesting. This double does, on the same runtime a hosted worker uses.
    struct AsyncBridgedObjectStore {
        inner: MemoryObjectStore,
    }

    impl AsyncBridgedObjectStore {
        /// Go through the runtime the way `GcsObjectStore` does, so the nesting is real.
        fn bridged<T: Send>(&self, f: impl FnOnce() -> T + Send) -> T {
            super::super::bridge::block_on(async { f() })
        }
    }

    impl ObjectStore for AsyncBridgedObjectStore {
        fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
            self.bridged(|| self.inner.head(name))
        }
        fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
            self.bridged(|| self.inner.head_full(name))
        }
        fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
            self.bridged(|| self.inner.has_history(name))
        }
        fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
            self.bridged(|| self.inner.get(name, generation))
        }
        fn put_if_generation(
            &self,
            name: &str,
            bytes: &[u8],
            expected: u64,
            metadata: &BTreeMap<String, String>,
        ) -> Result<PutOutcome, GatewayError> {
            self.bridged(|| self.inner.put_if_generation(name, bytes, expected, metadata))
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
    }

    /// An object store whose upload only completes when a spawned tokio task is polled.
    ///
    /// This is the shape that wedged the hosted worker. The Postgres
    /// store took a `std::sync::Mutex` on a runtime worker and then awaited a query that only the
    /// spawned connection-driver task could answer; a caller that parks its worker instead of
    /// donating it removes the very thread that driver needs. The store the fleet runs today has no
    /// connection driver, but it has the same structural requirement, because the persist lock is
    /// held across a bridged async upload, so this double supplies the missing half and lets the shape
    /// be tested against the code that actually ships.
    struct DrivenObjectStore {
        inner: MemoryObjectStore,
        driver: tokio::sync::mpsc::UnboundedSender<tokio::sync::oneshot::Sender<()>>,
    }

    impl DrivenObjectStore {
        /// Do the work, then wait for the driver task exactly as the real client waits for its
        /// connection: through the bridge, which donates the worker first.
        fn driven<T>(&self, f: impl FnOnce() -> T) -> T {
            let out = f();
            let (reply, wait) = tokio::sync::oneshot::channel();
            self.driver.send(reply).expect("the driver task is alive");
            super::super::bridge::block_on(async { wait.await.expect("the driver replies") });
            out
        }
    }

    impl ObjectStore for DrivenObjectStore {
        fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
            self.driven(|| self.inner.head(name))
        }
        fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
            self.driven(|| self.inner.head_full(name))
        }
        fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
            self.driven(|| self.inner.has_history(name))
        }
        fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
            self.driven(|| self.inner.get(name, generation))
        }
        fn put_if_generation(
            &self,
            name: &str,
            bytes: &[u8],
            expected: u64,
            metadata: &BTreeMap<String, String>,
        ) -> Result<PutOutcome, GatewayError> {
            self.driven(|| self.inner.put_if_generation(name, bytes, expected, metadata))
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
    }

    /// More concurrent callers than runtime worker threads, all mutating and reading at
    /// once, must all finish, and the gateway must still answer afterwards.
    ///
    /// The requirement was first pinned in `store/postgres.rs`, which went with the Postgres store and took its
    /// regression test (`concurrent_callers_outnumbering_worker_threads_do_not_wedge`) with it. The
    /// name is kept so the requirement is greppable in the tree that replaced it.
    ///
    /// The measured rule from the 2026-08-09 reproduction is exact: the old shape deadlocked as soon
    /// as callers exceeded workers: 1 worker at 2 callers, 2 at 3, 4 at 6. Eight callers on two
    /// workers is four times over that line, and the deadlock was total enough that the
    /// reproduction's own `tokio::time::timeout` never fired, so the bound here is a
    /// `spawn_blocking` join rather than an in-runtime timeout: a wedged runtime cannot be relied on
    /// to run the watchdog that would report it wedged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_callers_outnumbering_worker_threads_do_not_wedge() {
        let dir = temp_dir("wedge");
        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<tokio::sync::oneshot::Sender<()>>();
        // The connection driver's stand-in. It can only answer while the runtime has a worker free
        // to poll it, which is the whole of the bug.
        let driver = tokio::spawn(async move {
            while let Some(reply) = rx.recv().await {
                let _ = reply.send(());
            }
        });
        let objects: Arc<dyn ObjectStore> = Arc::new(DrivenObjectStore {
            inner: MemoryObjectStore::new(),
            driver: tx,
        });
        let store = Arc::new(open(&dir, objects));

        // Eight callers on two workers, half of them mutating and half reading, so the readers
        // contend for the same persist lock the writers hold across the bridged upload.
        let mut callers = Vec::new();
        for i in 0..8 {
            let store = store.clone();
            callers.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    store
                        .put_agent(Agent::approved(format!("a{i}"), "A", 0))
                        .expect("a concurrent mutation completes");
                } else {
                    store.list_agents().expect("a concurrent read completes");
                }
            }));
        }
        for (i, caller) in callers.into_iter().enumerate() {
            caller.await.unwrap_or_else(|e| panic!("caller {i} did not finish: {e}"));
        }

        // A request after them must still answer. A store that survived the burst but came out of it
        // holding a poisoned or never-released lock is wedged just the same, only later.
        store
            .put_agent(Agent::approved("after", "After", 0))
            .expect("the store still serves a mutation");
        assert_eq!(store.list_agents().expect("the store still reads").len(), 5);

        driver.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_object_store_that_bridges_to_async_works_under_the_persist_lock() {
        let dir = temp_dir("bridged");
        let objects: Arc<dyn ObjectStore> =
            Arc::new(AsyncBridgedObjectStore { inner: MemoryObjectStore::new() });
        let store = open(&dir, objects.clone());
        store.put_agent(Agent::approved("a", "A", 0)).unwrap();
        store.put_agent(Agent::approved("b", "B", 0)).unwrap();
        assert_eq!(store.list_agents().unwrap().len(), 2);
        assert!(objects.head(DEFAULT_OBJECT).unwrap().unwrap() >= 1);
    }

    /// The staging copy is as big as the database and the worker's filesystem is its memory, so it
    /// must not still be there once the upload is done.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_staging_snapshot_does_not_outlive_the_upload() {
        let dir = temp_dir("staging");
        let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects);
        store.put_agent(Agent::approved("a", "A", 0)).unwrap();
        assert!(!dir.join("gateway.db.snap").exists(), "the staging copy must be gone after the upload");
    }

    /// Found on a real worker: the console's status polls reach mutating
    /// methods that write no row, and every one of them was uploading the whole database. One tab
    /// drove about 24 full-size PUTs a minute at a store whose contents never changed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_mutation_that_changed_no_row_uploads_nothing() {
        let dir = temp_dir("nochange");
        let objects = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects.clone());

        store.put_agent(Agent::approved("a", "A", 0)).unwrap();
        let after_real_write = objects.put_count();
        assert!(after_real_write >= 1, "a real change still uploads");

        // A replayed one-shot claim: the first spends it, every later one answers false and writes
        // nothing. Only the first may cost an upload.
        assert!(store.claim_once("scope", "jti-1", 9_999_999_999_999).unwrap());
        let after_first_claim = objects.put_count();
        for _ in 0..20 {
            assert!(!store.claim_once("scope", "jti-1", 9_999_999_999_999).unwrap(), "a replay is refused");
        }
        assert_eq!(
            objects.put_count(),
            after_first_claim,
            "twenty refused replays changed no row, so none of them may upload"
        );

        // And the store is still correct: the agent and the spent claim are both in the object.
        let copy = store_from_object(&objects, &dir, "nochange");
        assert!(copy.get_agent("a").unwrap().is_some());
        assert!(!copy.claim_once("scope", "jti-1", 9_999_999_999_999).unwrap(), "the claim was persisted as spent");
    }

    /// The counterpart: a restore must not upload what it just downloaded. The migrations and audit
    /// rehydration that run inside `open` move SQLite's change counter, and reading it at open is
    /// what stops the first mutation after a restore from re-uploading an unchanged database.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restore_does_not_re_upload_what_it_just_read() {
        let dir = temp_dir("restore-quiet");
        let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        let path = dir.join("gateway.db");
        {
            let store = open(&dir, objects.clone());
            store.put_agent(Agent::approved("a", "A", 0)).unwrap();
        }
        for suffix in ["", "-wal", "-shm", ".snap"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        let store = open(&dir, objects.clone());
        assert_eq!(store.list_agents().unwrap().len(), 1, "the restore worked");
        // A refused claim right after a restore must still upload nothing.
        assert!(store.claim_once("s", "j", 9_999_999_999_999).unwrap());
        let baseline = store.generation();
        for _ in 0..5 {
            let _ = store.claim_once("s", "j", 9_999_999_999_999).unwrap();
        }
        assert_eq!(store.generation(), baseline, "refused replays after a restore upload nothing");
    }

    /// The previous instance keeps serving until this one is ready, so it can commit after this one
    /// restored. A read on the fresh instance asks the object store whether the generation moved, and
    /// a moved generation is the same stale verdict the write path reaches through the 412.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fresh_instance_refuses_reads_once_another_instance_has_written() {
        let objects = Arc::new(MemoryObjectStore::new());
        let a = open(&temp_dir("fresh-a"), objects.clone());
        a.put_agent(Agent::approved("first", "A", 0)).unwrap();
        let stale = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = stale.clone();
        let b = open(&temp_dir("fresh-b"), objects.clone())
            .with_on_stale(Box::new(move |m| recorder.lock().unwrap().push(m.to_string())));
        assert_eq!(b.list_agents().unwrap().len(), 1, "b restored a's write and is current");
        a.put_agent(Agent::approved("second", "A", 0)).unwrap();
        std::thread::sleep(FRESH_READ_INTERVAL);
        let err = b.list_agents().unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "{err}");
        let seen = stale.lock().unwrap();
        assert_eq!(seen.len(), 1, "the stale handler ran exactly once");
        assert!(seen[0].contains("stale on a fresh instance"), "{}", seen[0]);
    }

    /// One metadata request an interval, not one per read, and none at all once the window has closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fresh_reads_confirm_the_generation_once_an_interval_and_only_inside_the_window() {
        struct Counting {
            inner: MemoryObjectStore,
            heads: AtomicU64,
        }
        impl ObjectStore for Counting {
            fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
                self.heads.fetch_add(1, Ordering::SeqCst);
                self.inner.head(name)
            }
            fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
                self.heads.fetch_add(1, Ordering::SeqCst);
                self.inner.head_full(name)
            }
            fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
                self.inner.has_history(name)
            }
            fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
                self.inner.get(name, generation)
            }
            fn put_if_generation(
                &self,
                name: &str,
                bytes: &[u8],
                expected: u64,
                metadata: &BTreeMap<String, String>,
            ) -> Result<PutOutcome, GatewayError> {
                self.inner.put_if_generation(name, bytes, expected, metadata)
            }
            fn describe(&self) -> String {
                self.inner.describe()
            }
        }
        let objects = Arc::new(Counting { inner: MemoryObjectStore::new(), heads: AtomicU64::new(0) });
        let store = open(&temp_dir("fresh-rate"), objects.clone());
        let at_open = objects.heads.load(Ordering::SeqCst);
        for _ in 0..5 {
            store.list_agents().unwrap();
        }
        assert_eq!(
            objects.heads.load(Ordering::SeqCst),
            at_open + 1,
            "five reads inside one interval cost one confirmation"
        );

        let closed = open(&temp_dir("fresh-closed"), objects.clone()).with_fresh_read_window(Duration::ZERO);
        let before = objects.heads.load(Ordering::SeqCst);
        for _ in 0..5 {
            closed.list_agents().unwrap();
        }
        assert_eq!(objects.heads.load(Ordering::SeqCst), before, "outside the window reads never ask");
    }

    // ── upload metadata, and the outcome of an upload nobody answered ──────────

    fn head_of(objects: &MemoryObjectStore) -> crate::objectstore::ObjectHead {
        objects.head_full(DEFAULT_OBJECT).unwrap().expect("an object")
    }

    /// The slug and the control plane's row id are two facts and are stamped separately.
    ///
    /// Every hosted object, IAM condition, checkpoint path and purge is keyed by the SLUG, and the
    /// slug is the only key still knowable once a worker has been deleted. Stamping the row id under
    /// `pm-tenant`, which is what happened before `PERMAURA_TENANT` existed, made every checkpoint
    /// manifest's tenant disagree with the stamp on the bytes it described.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_stamp_carries_the_tenant_slug_and_the_gateway_row_id_separately() {
        let dir = temp_dir("identity");
        let objects = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects.clone())
            .with_identity(Some("acme".into()), Some("gw_EFvwlbK7mJPnqZ7SVxFt8".into()));
        store.put_agent(Agent::approved("a", "A", 0)).unwrap();

        let meta = head_of(&objects).metadata;
        assert_eq!(meta["pm-tenant"], "acme", "the slug, which is what the paths are keyed by");
        assert_eq!(meta["pm-gateway-id"], "gw_EFvwlbK7mJPnqZ7SVxFt8");

        // Unset is unknown, as every other stamp here treats it, never a default and never the
        // other of the two standing in for it.
        let bare = temp_dir("identity-bare");
        let bare_objects = Arc::new(MemoryObjectStore::new());
        let bare_store = open(&bare, bare_objects.clone()).with_identity(None, None);
        bare_store.put_agent(Agent::approved("a", "A", 0)).unwrap();
        let bare_meta = head_of(&bare_objects).metadata;
        assert_eq!(bare_meta["pm-tenant"], META_UNKNOWN);
        assert_eq!(bare_meta["pm-gateway-id"], META_UNKNOWN);
    }

    /// Both floors travel with the snapshot, so a restore can take `max(restored, retained)` over
    /// them without opening a database.
    ///
    /// The checkpoint job never opens a tenant store and holds no KMS decrypt authority, so until
    /// these two keys existed `retained.json` carried `approval_floor: null` and
    /// `replay_floor_ms: null` and a restore of an older snapshot could silently put back a floor
    /// its owner had raised.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_stamp_carries_the_approval_floor_and_the_replay_floor() {
        let dir = temp_dir("floors");
        let objects = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects.clone());

        // A store that has never had either floor set says `none` for both, which is a statement
        // and not a default: "no override is stored" has to stay readable as itself.
        store.put_agent(Agent::approved("a", "A", 0)).unwrap();
        let bare = head_of(&objects).metadata;
        assert_eq!(bare["pm-approval-floor"], META_UNKNOWN);
        assert_eq!(bare["pm-replay-floor-ms"], META_UNKNOWN);

        store.put_meta(crate::store::APPROVAL_FLOOR_META, "device_signed").unwrap();
        store.put_meta(crate::store::REPLAY_FLOOR_META, "1758376682117").unwrap();
        store.put_agent(Agent::approved("b", "B", 0)).unwrap();

        let meta = head_of(&objects).metadata;
        assert_eq!(meta["pm-approval-floor"], "device_signed");
        assert_eq!(meta["pm-replay-floor-ms"], "1758376682117");
        // Unchanged, because no released binary stamps any of these keys: there is still no
        // version 1 in the world for a 2 to be distinguished from.
        assert_eq!(meta["pm-meta-version"], META_VERSION);
    }

    /// The manifest is built entirely from this metadata by a job that may never open the database,
    /// so what the metadata says and what the bytes contain have to be the same moment.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_upload_carries_the_metadata_that_describes_its_own_bytes() {
        let dir = temp_dir("metadata");
        let objects = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects.clone());
        store.put_agent(Agent::approved("a", "A", 0)).unwrap();
        store.append_audit(AuditPayload::new("first", "r", "allow")).unwrap();
        store.append_audit(AuditPayload::new("second", "r", "deny")).unwrap();

        let head = head_of(&objects);
        let meta = &head.metadata;
        let copy = store_from_object(&objects, &dir, "metadata");
        let events = copy.audit_events(None).unwrap();
        let chain_head = events.last().expect("the uploaded bytes carry the chain");

        assert_eq!(meta["pm-audit-head-hash"], chain_head.hash, "the stamped head is the bytes' head");
        assert_eq!(meta["pm-audit-head-seq"], chain_head.seq.to_string());
        assert_eq!(meta["pm-audit-base-seq"], "0");
        assert_eq!(meta["pm-audit-base-hash"], permaura_core::GENESIS_PREV_HASH);
        assert_eq!(meta["pm-audit-epoch"], "0");
        assert_eq!(meta["pm-audit-segment-head"], META_UNKNOWN);
        assert_eq!(meta["pm-meta-version"], META_VERSION);
        assert_eq!(meta["pm-gateway-version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(meta["pm-schema-version"], super::super::migrations::SCHEMA_VERSION.to_string());
        assert_eq!(meta["pm-store-bytes"], head.size.to_string());
        // The test CMK does not name versions, so the honest stamp is the v1 wrap and no version.
        assert_eq!(meta["pm-audit-key-wrap"], "kms:v1");
        assert_eq!(meta["pm-audit-key-version"], META_UNKNOWN);
        assert_eq!(meta["pm-vault-kek-version"], META_UNKNOWN, "unset means unknown, never a default");

        let first_id = meta[UPLOAD_ID_KEY].clone();
        assert_eq!(first_id.len(), 32, "the upload id is 128 bits of hex: {first_id}");

        let first_commit: u64 = meta["pm-commit-seq"].parse().expect("a decimal commit seq");
        store.put_agent(Agent::approved("b", "B", 0)).unwrap();
        let next = head_of(&objects).metadata;
        assert!(
            next["pm-commit-seq"].parse::<u64>().unwrap() > first_commit,
            "the commit seq advances with the uploads it describes"
        );
        assert_ne!(next[UPLOAD_ID_KEY], first_id, "and every upload gets its own id");
    }

    /// The race the stamp has to survive: another thread commits and appends while this one is
    /// between its snapshot and its upload. Checking after the fact would only ever catch the last
    /// upload, so every upload is opened and compared as it arrives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_metadata_describes_the_bytes_even_while_other_threads_are_committing() {
        /// One upload as it was sent: its metadata and its bytes.
        type Upload = (BTreeMap<String, String>, Vec<u8>);

        struct CheckEveryUpload {
            inner: MemoryObjectStore,
            /// Every upload as it was sent. Opened and compared after the writers have finished,
            /// because a mutator runs on a plain thread with no runtime under it and opening a store
            /// needs one for the KMS unwrap.
            seen: Mutex<Vec<Upload>>,
        }
        impl ObjectStore for CheckEveryUpload {
            fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
                self.inner.head(name)
            }
            fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
                self.inner.head_full(name)
            }
            fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
                self.inner.has_history(name)
            }
            fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
                self.inner.get(name, generation)
            }
            fn put_if_generation(
                &self,
                name: &str,
                bytes: &[u8],
                expected: u64,
                metadata: &BTreeMap<String, String>,
            ) -> Result<PutOutcome, GatewayError> {
                self.seen.lock().unwrap().push((metadata.clone(), bytes.to_vec()));
                self.inner.put_if_generation(name, bytes, expected, metadata)
            }
            fn describe(&self) -> String {
                self.inner.describe()
            }
        }

        let dir = temp_dir("metadata-race");
        let objects =
            Arc::new(CheckEveryUpload { inner: MemoryObjectStore::new(), seen: Mutex::new(Vec::new()) });
        let store = Arc::new(open(&dir, objects.clone()));
        let mut handles = Vec::new();
        for i in 0..6 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                store.append_audit(AuditPayload::new(format!("e{i}"), "r", "allow")).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        drop(store);

        let seen = objects.seen.lock().unwrap();
        assert!(!seen.is_empty(), "something was uploaded");
        for (n, (metadata, bytes)) in seen.iter().enumerate() {
            let path = dir.join(format!("received-{n}.db"));
            std::fs::write(&path, bytes).unwrap();
            let copy = super::SqliteStore::open_with_custody(&path.to_string_lossy(), wrap()).unwrap();
            let (seq, hash) = match copy.audit_events(None).unwrap().last() {
                Some(event) => (event.seq.to_string(), event.hash.clone()),
                None => (META_UNKNOWN.into(), META_UNKNOWN.into()),
            };
            assert_eq!(metadata["pm-audit-head-seq"], seq, "upload {n} stamped a seq its bytes do not carry");
            assert_eq!(metadata["pm-audit-head-hash"], hash, "upload {n} stamped a head its bytes do not carry");
        }
    }

    /// What one upload did before it stopped answering.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Landing {
        /// Applied exactly as sent: the write won and only the acknowledgement was lost.
        Ours,
        /// Applied by someone else, stamped with their facts.
        Foreign,
        /// Applied by the other instance in a rollout: a different database, but the same commit
        /// sequence and the same audit head, because both restored the same generation and neither
        /// has appended an audit event since. Every fact taken from the store agrees; only the
        /// upload id does not.
        Twin,
        /// Applied by us, but stamped with facts that are not the ones we sent. A contradiction, and
        /// the one case that is neither ours nor another owner's.
        OurIdTheirFacts,
        /// Applied by a gateway from before any of this, which stamped nothing.
        Unstamped,
        /// Never applied: the request was what was lost.
        Nothing,
        /// Not applied yet: the request is still on its way, and lands when the test says so.
        Held,
    }

    /// An object store that applies (or does not apply) an upload and then behaves as though the
    /// response never came back. The whole of section D is about telling those apart afterwards.
    struct LostResponse {
        inner: MemoryObjectStore,
        pending: Mutex<Vec<Landing>>,
        /// Every upload attempted, as `(expected generation, upload id)`, so a test can see what a
        /// retry retried at and which id it carried.
        attempts: Mutex<Vec<(u64, String)>>,
        /// The metadata of the most recent attempt, so a test can build the object another instance
        /// would have written from the facts this one really sent rather than from a guess at them.
        last_metadata: Mutex<BTreeMap<String, String>>,
        head_fails: Mutex<bool>,
        heads: AtomicU64,
        /// An upload taken under [`Landing::Held`]: its expected generation, bytes and metadata.
        held: Mutex<Option<(u64, Vec<u8>, BTreeMap<String, String>)>>,
    }

    impl LostResponse {
        fn new(pending: Vec<Landing>) -> Self {
            LostResponse {
                inner: MemoryObjectStore::new(),
                pending: Mutex::new(pending),
                attempts: Mutex::new(Vec::new()),
                last_metadata: Mutex::new(BTreeMap::new()),
                head_fails: Mutex::new(false),
                heads: AtomicU64::new(0),
                held: Mutex::new(None),
            }
        }

        /// The held upload arrives now, under its own precondition, long after its sender gave up.
        fn land_held(&self) {
            let (expected, bytes, metadata) = self.held.lock().unwrap().take().expect("an upload is held");
            let landed = self.inner.put_if_generation(DEFAULT_OBJECT, &bytes, expected, &metadata).unwrap();
            assert!(matches!(landed, PutOutcome::Stored(_)), "the held upload lands");
        }

        fn attempts(&self) -> Vec<u64> {
            self.attempts.lock().unwrap().iter().map(|(g, _)| *g).collect()
        }

        fn attempt_ids(&self) -> Vec<String> {
            self.attempts.lock().unwrap().iter().map(|(_, id)| id.clone()).collect()
        }

        /// Put an object there that this instance did not write, over whatever generation is
        /// current, bypassing the landing script: the point is a store another party moved on.
        fn foreign_write(&self, metadata: BTreeMap<String, String>) {
            let current = self.inner.head(DEFAULT_OBJECT).unwrap().unwrap_or(0);
            self.inner
                .put_if_generation(DEFAULT_OBJECT, b"another instance's database", current, &metadata)
                .unwrap();
        }
    }

    impl ObjectStore for LostResponse {
        fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
            self.inner.head(name)
        }
        fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
            self.heads.fetch_add(1, Ordering::SeqCst);
            if *self.head_fails.lock().unwrap() {
                return Err(GatewayError::Internal("synthetic: the object could not be read".into()));
            }
            self.inner.head_full(name)
        }
        fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
            self.inner.has_history(name)
        }
        fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
            self.inner.get(name, generation)
        }
        fn put_if_generation(
            &self,
            name: &str,
            bytes: &[u8],
            expected: u64,
            metadata: &BTreeMap<String, String>,
        ) -> Result<PutOutcome, GatewayError> {
            let id = metadata.get(UPLOAD_ID_KEY).cloned().unwrap_or_default();
            self.attempts.lock().unwrap().push((expected, id));
            *self.last_metadata.lock().unwrap() = metadata.clone();
            let landing = {
                let mut pending = self.pending.lock().unwrap();
                if pending.is_empty() {
                    None
                } else {
                    Some(pending.remove(0))
                }
            };
            let Some(landing) = landing else {
                return self.inner.put_if_generation(name, bytes, expected, metadata);
            };
            match landing {
                Landing::Nothing => {}
                Landing::Held => {
                    *self.held.lock().unwrap() = Some((expected, bytes.to_vec(), metadata.clone()));
                }
                Landing::Ours => {
                    self.inner.put_if_generation(name, bytes, expected, metadata)?;
                }
                Landing::Foreign => {
                    let mut theirs = metadata.clone();
                    theirs.insert(UPLOAD_ID_KEY.into(), "aa".repeat(16));
                    theirs.insert("pm-commit-seq".into(), "999999".into());
                    theirs.insert("pm-audit-head-hash".into(), "ff".repeat(32));
                    self.inner.put_if_generation(name, b"another instance's database", expected, &theirs)?;
                }
                Landing::Twin => {
                    // Everything but the id, exactly as the other instance of this tenant would
                    // have stamped it, over a database that is not ours.
                    let mut theirs = metadata.clone();
                    theirs.insert(UPLOAD_ID_KEY.into(), "bb".repeat(16));
                    self.inner.put_if_generation(name, b"the other instance's database", expected, &theirs)?;
                }
                Landing::OurIdTheirFacts => {
                    let mut mixed = metadata.clone();
                    mixed.insert("pm-commit-seq".into(), "999999".into());
                    self.inner.put_if_generation(name, bytes, expected, &mixed)?;
                }
                Landing::Unstamped => {
                    self.inner.put_if_generation(name, bytes, expected, &BTreeMap::new())?;
                }
            }
            Ok(PutOutcome::Uncertain)
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
    }

    fn open_lost(
        dir: &Path,
        objects: Arc<LostResponse>,
    ) -> (PersistedSqliteStore, Arc<Mutex<Vec<String>>>) {
        let stale = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = stale.clone();
        let store = open(dir, objects)
            .with_fresh_read_window(Duration::ZERO)
            .with_on_stale(Box::new(move |m| recorder.lock().unwrap().push(m.to_string())));
        (store, stale)
    }

    /// The live defect. A lost response on a successful upload left the generation stale, so the next
    /// upload met a 412 and the instance exited announcing another owner while describing its own
    /// write. Data was never lost, but the diagnosis was wrong and a network blip cost a cold start.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_response_on_a_successful_upload_reconciles_to_committed() {
        let dir = temp_dir("lost-landed");
        let objects = Arc::new(LostResponse::new(vec![Landing::Ours]));
        let (store, stale) = open_lost(&dir, objects.clone());

        store.put_agent(Agent::approved("a", "A", 0)).unwrap();

        assert!(stale.lock().unwrap().is_empty(), "its own write is not another instance's");
        assert_eq!(store.generation(), objects.head(DEFAULT_OBJECT).unwrap().unwrap());
        assert_eq!(<PersistedSqliteStore as Store>::degraded(&store), None, "and it is not quarantined");
        assert_eq!(objects.attempts().len(), 1, "an upload that landed is never resent");

        // And it carries on: the next write replaces the generation it adopted.
        store.put_agent(Agent::approved("b", "B", 0)).unwrap();
        assert!(stale.lock().unwrap().is_empty());
        let path = dir.join("after.db");
        let generation = objects.head(DEFAULT_OBJECT).unwrap().unwrap();
        std::fs::write(&path, objects.get(DEFAULT_OBJECT, generation).unwrap()).unwrap();
        let copy = super::SqliteStore::open_with_custody(&path.to_string_lossy(), wrap()).unwrap();
        assert!(copy.get_agent("a").unwrap().is_some() && copy.get_agent("b").unwrap().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_response_on_a_failed_upload_reconciles_to_pending() {
        let dir = temp_dir("lost-nothing");
        // The retry goes unanswered too, so the outcome stays pending rather than resolving.
        let objects = Arc::new(LostResponse::new(vec![Landing::Nothing, Landing::Nothing]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let err = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        assert!(stale.lock().unwrap().is_empty(), "nothing landed, so nobody else owns the store");
        assert_eq!(objects.attempts(), vec![0, 0], "the retry goes at the same expected generation");
        let degraded = <PersistedSqliteStore as Store>::degraded(&store).expect("quarantined");
        assert!(degraded.contains("produced no response"), "got: {degraded}");

        // The commit stands locally and the next successful upload carries it, exactly as a definite
        // failure would.
        store.put_agent(Agent::approved("b", "B", 0)).unwrap();
        let copy = store_from_object(&objects.inner, &dir, "lost-nothing");
        assert!(copy.get_agent("a").unwrap().is_some(), "the limbo commit rode the later upload");
        assert!(copy.get_agent("b").unwrap().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_response_where_another_instance_owns_the_store_still_exits() {
        let dir = temp_dir("lost-foreign");
        let objects = Arc::new(LostResponse::new(vec![Landing::Foreign]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let err = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        let seen = stale.lock().unwrap();
        assert_eq!(seen.len(), 1, "the stale handler ran exactly once");
        assert!(seen[0].contains("another instance owns the store"), "{}", seen[0]);
        assert_eq!(store.generation(), 0, "a generation that was not proven ours is never adopted");
    }

    /// The case that makes the upload id necessary, and that a comparison of stored facts gets
    /// wrong. Two instances overlap during a rollout, both restored generation G, and each runs a
    /// mutation that appends no audit event in its own unit, so both stamp the same commit sequence
    /// and the same audit head over different databases. B's upload lands; A's does not, and A's
    /// response is lost. Comparing facts, A would find them all equal, adopt B's generation while
    /// holding a different database, and overwrite B's acknowledged commit on its next write,
    /// sending the rightful owner away stale.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_upload_that_only_shares_this_instances_facts_is_never_adopted() {
        let dir = temp_dir("lost-twin");
        let objects = Arc::new(LostResponse::new(vec![Landing::Twin]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let err = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        let seen = stale.lock().unwrap();
        assert_eq!(seen.len(), 1, "the stale handler ran exactly once");
        assert!(seen[0].contains("another upload than this instance's"), "{}", seen[0]);
        assert_eq!(store.generation(), 0, "matching facts are not a proof, so nothing is adopted");
    }

    /// An id that matches beside facts that do not is a contradiction, not a close call. There is no
    /// safe reading of it, so it refuses without adopting and without declaring another owner.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_upload_id_that_matches_with_facts_that_do_not_refuses_without_adopting() {
        let dir = temp_dir("lost-mixed");
        let objects = Arc::new(LostResponse::new(vec![Landing::OurIdTheirFacts]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let err = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::Internal(_)), "got {err}");
        assert!(format!("{err}").contains("upload id but not its facts"), "got {err}");
        assert!(stale.lock().unwrap().is_empty(), "a contradiction is not a verdict about ownership");
        assert_eq!(store.generation(), 0);
        assert!(<PersistedSqliteStore as Store>::degraded(&store).is_some(), "and it stays quarantined");
    }

    /// One id per snapshot, reused for that snapshot's single retry, so whichever of the two
    /// attempts landed is recognisably this instance's afterwards. A different snapshot gets a
    /// different id.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_retry_of_an_unanswered_upload_reuses_its_upload_id() {
        let dir = temp_dir("lost-id-reuse");
        let objects = Arc::new(LostResponse::new(vec![Landing::Nothing, Landing::Nothing]));
        let (store, _stale) = open_lost(&dir, objects.clone());

        let _ = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        let ids = objects.attempt_ids();
        assert_eq!(ids.len(), 2, "the upload and its one retry");
        assert_eq!(ids[0], ids[1], "the retry carries the id of the bytes it is resending");
        assert_eq!(ids[0].len(), 32, "128 bits of hex");

        store.put_agent(Agent::approved("b", "B", 0)).unwrap();
        let ids = objects.attempt_ids();
        assert_ne!(ids[2], ids[0], "a different snapshot is a different upload");
    }

    /// A version with no metadata proves nothing, so it is read as another owner. Conservative by
    /// design: the alternative is adopting a generation on the strength of it having appeared.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_response_against_an_unstamped_object_exits_rather_than_assuming() {
        let dir = temp_dir("lost-unstamped");
        let objects = Arc::new(LostResponse::new(vec![Landing::Unstamped]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let err = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        let seen = stale.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains("no upload id to say who wrote it"), "{}", seen[0]);
        assert_eq!(store.generation(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreadable_head_after_an_uncertain_upload_stays_quarantined_and_retries_nothing() {
        let dir = temp_dir("lost-blind");
        let objects = Arc::new(LostResponse::new(vec![Landing::Ours]));
        *objects.head_fails.lock().unwrap() = true;
        let (store, stale) = open_lost(&dir, objects.clone());

        let err = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        assert!(stale.lock().unwrap().is_empty(), "an unreadable object is not a verdict about ownership");
        assert_eq!(objects.attempts().len(), 1, "nothing is resent while the outcome is unknown");
        assert_eq!(store.generation(), 0, "and nothing is adopted");
        let degraded = <PersistedSqliteStore as Store>::degraded(&store).expect("quarantined");
        assert!(degraded.contains("produced no response"), "got: {degraded}");
    }

    /// The residual the upload id left open, and the last case in which a 412 is misread.
    ///
    /// An upload and its single retry both go unanswered and one of them lands. The next `persist()`
    /// sends at the generation this instance still believes in, meets the 412, and used to exit
    /// announcing another owner while describing its own write. The object is now read back, the id
    /// on it is one this instance sent and never heard about, and its facts are the ones sent with
    /// that id, so the generation is adopted and the newer commit goes over it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_conflict_against_this_instances_own_lost_upload_adopts_it_and_carries_the_newer_commit() {
        let dir = temp_dir("conflict-own");
        // Nothing lands on the first attempt; the retry lands and its response is lost too.
        let objects = Arc::new(LostResponse::new(vec![Landing::Nothing, Landing::Ours]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let err = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        assert_eq!(store.generation(), 0, "neither attempt was answered, so nothing is agreed yet");
        let landed = objects.inner.head(DEFAULT_OBJECT).unwrap().expect("the retry did land");

        // The next write meets the 412 that used to be read as another instance's.
        store.put_agent(Agent::approved("b", "B", 0)).unwrap();

        assert!(stale.lock().unwrap().is_empty(), "its own landing is not another instance's");
        assert!(store.generation() > landed, "the adopted generation was replaced, not merely taken");
        assert_eq!(store.generation(), objects.inner.head(DEFAULT_OBJECT).unwrap().unwrap());
        assert_eq!(<PersistedSqliteStore as Store>::degraded(&store), None, "and it is not quarantined");
        let copy = store_from_object(&objects.inner, &dir, "conflict-own");
        assert!(copy.get_agent("a").unwrap().is_some(), "the commit in limbo rode the newer upload");
        assert!(copy.get_agent("b").unwrap().is_some(), "and so did the one that carried it");
    }

    /// The case the exit exists for, with an unanswered upload of this instance's outstanding: an
    /// object that really was written by somebody else still exits stale.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_conflict_against_another_instances_write_still_exits_stale() {
        let dir = temp_dir("conflict-foreign");
        let objects = Arc::new(LostResponse::new(vec![Landing::Nothing, Landing::Nothing]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let _ = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        let mut theirs = BTreeMap::new();
        theirs.insert(UPLOAD_ID_KEY.to_string(), "aa".repeat(16));
        objects.foreign_write(theirs);

        let err = store.put_agent(Agent::approved("b", "B", 0)).unwrap_err();

        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        let seen = stale.lock().unwrap();
        assert_eq!(seen.len(), 1, "the stale handler ran exactly once");
        assert!(seen[0].contains("another instance owns the store"), "{}", seen[0]);
        assert_eq!(store.generation(), 0, "nothing was adopted");
    }

    /// The whole reason ownership is the id and nothing else. The object carries exactly the facts
    /// this instance stamped, because the other instance of one tenant stamps the same ones, and a
    /// different id. It is not ours and the exit still fires.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_conflict_against_twin_facts_under_another_id_still_exits_stale() {
        let dir = temp_dir("conflict-twin");
        let objects = Arc::new(LostResponse::new(vec![Landing::Nothing, Landing::Nothing]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let _ = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        let mut theirs = objects.last_metadata.lock().unwrap().clone();
        theirs.insert(UPLOAD_ID_KEY.to_string(), "bb".repeat(16));
        objects.foreign_write(theirs);

        let err = store.put_agent(Agent::approved("b", "B", 0)).unwrap_err();

        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        assert_eq!(stale.lock().unwrap().len(), 1, "matching facts are not a proof");
        assert_eq!(store.generation(), 0);
    }

    /// An object nobody could read has said nothing about who wrote it, so it is not evidence of
    /// ownership: the conflict takes the exit it would have taken without the check at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_conflict_whose_object_cannot_be_read_back_exits_stale() {
        let dir = temp_dir("conflict-blind");
        let objects = Arc::new(LostResponse::new(vec![Landing::Nothing, Landing::Ours]));
        let (store, stale) = open_lost(&dir, objects.clone());

        let _ = store.put_agent(Agent::approved("a", "A", 0)).unwrap_err();
        *objects.head_fails.lock().unwrap() = true;

        let err = store.put_agent(Agent::approved("b", "B", 0)).unwrap_err();

        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        let seen = stale.lock().unwrap();
        assert_eq!(seen.len(), 1, "the stale handler ran exactly once");
        assert!(seen[0].contains("another instance owns the store"), "{}", seen[0]);
        assert_eq!(store.generation(), 0, "an unreadable object never moves the agreed generation");
    }

    /// Stated on its own because it is the rule the rest of this rests on: `state.generation` moves
    /// on an acknowledgement or on proof, and on nothing else.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_expected_generation_is_never_advanced_without_an_acknowledgement_or_a_proof() {
        for landing in [Landing::Foreign, Landing::Twin, Landing::Unstamped] {
            let dir = temp_dir("lost-noadopt");
            let objects = Arc::new(LostResponse::new(vec![landing]));
            let (store, _stale) = open_lost(&dir, objects.clone());
            let before = store.generation();

            let _ = store.put_agent(Agent::approved("a", "A", 0));

            let remote = objects.head(DEFAULT_OBJECT).unwrap().unwrap();
            assert!(remote > before, "the object did move");
            assert_eq!(store.generation(), before, "but this instance did not follow it");
        }
    }

    /// A handler's several writes are one unit: one upload, and nothing durable from a unit that failed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transaction_uploads_once_and_a_failed_one_uploads_nothing() {
        let objects = Arc::new(MemoryObjectStore::new());
        let store = open(&temp_dir("tx"), objects.clone());
        let s: &dyn Store = &store;
        s.transaction(|s| {
            for i in 0..3 {
                s.put_agent(Agent::approved(format!("agent-{i}"), "A", 0))?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(objects.head(DEFAULT_OBJECT).unwrap(), Some(1), "three writes, one generation");
        let err = s
            .transaction(|s| {
                s.put_agent(Agent::approved("doomed", "A", 0))?;
                Err::<(), _>(GatewayError::BadRequest("no".into()))
            })
            .unwrap_err();
        assert!(matches!(err, GatewayError::BadRequest(_)));
        assert_eq!(objects.head(DEFAULT_OBJECT).unwrap(), Some(1), "a failed unit uploads nothing");
        assert!(s.get_agent("doomed").unwrap().is_none());
        assert_eq!(s.list_agents().unwrap().len(), 3);
    }

    // ── the fair-use counter ──────────────────────────────────────────────────

    fn metered(store: &PersistedSqliteStore) -> Arc<crate::fair_use::FairUse> {
        let fair_use = Arc::new(crate::fair_use::FairUse::new(crate::fair_use::FairUseConfig {
            active: true,
            ..Default::default()
        }));
        fair_use.attach(store);
        fair_use
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_fair_use_count_survives_a_restart() {
        let dir = temp_dir("fair-use-restart");
        let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        {
            let store = open(&dir, objects.clone());
            let fair_use = metered(&store);
            for i in 0..3 {
                crate::fair_use::in_request(|| store.put_agent(Agent::approved(&format!("a{i}"), "A", 0)))
                    .unwrap();
            }
            assert_eq!(fair_use.report().mutating_calls, 3);
        }
        let store = open(&dir, objects);
        let fair_use = metered(&store);
        assert_eq!(fair_use.report().mutating_calls, 3, "a cold start or a new revision does not reset the month");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_request_that_changed_a_row_counts() {
        let dir = temp_dir("fair-use-reads");
        let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects);
        let fair_use = metered(&store);
        crate::fair_use::in_request(|| store.list_agents()).unwrap();
        crate::fair_use::in_request(|| store.get_meta("anything")).unwrap();
        crate::fair_use::in_request(|| store.delete_agent("nobody")).unwrap();
        assert_eq!(fair_use.report().mutating_calls, 0, "reads and writes that changed nothing are free");
        crate::fair_use::in_request(|| {
            store.put_agent(Agent::approved("a", "A", 0))?;
            store.put_agent(Agent::approved("b", "B", 0))
        })
        .unwrap();
        assert_eq!(fair_use.report().mutating_calls, 1, "one request, however many writes");
    }

    /// The ceiling exists to bound snapshot uploads, so it must never add one: the count rides the
    /// upload its own request makes, and a request with nothing to upload writes no counter either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_count_rides_an_upload_the_request_makes_anyway() {
        let dir = temp_dir("fair-use-uploads");
        let objects = Arc::new(MemoryObjectStore::new());
        let store = open(&dir, objects.clone());
        let _fair_use = metered(&store);
        for i in 0..4 {
            crate::fair_use::in_request(|| store.put_agent(Agent::approved(&format!("a{i}"), "A", 0))).unwrap();
        }
        assert_eq!(store.generation(), 4, "one upload per mutating request, none for the counter");
        crate::fair_use::in_request(|| store.delete_agent("nobody")).unwrap();
        assert_eq!(store.generation(), 4, "a no-op request uploads nothing, counter included");
        let copy = store_from_object(&objects, &dir, "fair-use");
        let stamp: serde_json::Value =
            serde_json::from_str(&copy.get_meta(crate::fair_use::META_KEY).unwrap().expect("the count is in the snapshot"))
                .unwrap();
        assert_eq!(stamp["mutating_calls"], 4);
    }

    /// The production shape: the request is an async task on a multi-threaded runtime and the store
    /// reaches the count through `block_in_place`, which has to keep the task's scope visible.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_scope_reaches_through_the_blocking_section() {
        let dir = temp_dir("fair-use-async");
        let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
        let store = Arc::new(open(&dir, objects));
        let fair_use = metered(&store);
        let s = store.clone();
        crate::fair_use::in_request_async(async move {
            tokio::task::yield_now().await;
            s.put_agent(Agent::approved("a", "A", 0)).unwrap();
        })
        .await;
        assert_eq!(fair_use.report().mutating_calls, 1);
    }

    // ── An upload that is taken and never answered ─────────────────────────────────────────────

    use crate::objectstore::fake_gcs::{self, FakeGcs, NextPut};
    use crate::objectstore::{put_attempt_timeout, PUT_ATTEMPT_FLOOR};

    /// A store over the Cloud Storage client pointed at the stand-in, with the stale exit recorded
    /// rather than taken, and one write already durable so the next upload replaces a generation.
    fn open_over_fake(dir: &Path, fake: &FakeGcs) -> (Arc<PersistedSqliteStore>, Arc<Mutex<Vec<String>>>) {
        let stale = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = stale.clone();
        let store = open(dir, Arc::new(fake_gcs::client(fake)))
            .with_fresh_read_window(Duration::ZERO)
            .with_on_stale(Box::new(move |m| recorder.lock().unwrap().push(m.to_string())));
        store.put_agent(Agent::approved("first", "First", 0)).unwrap();
        (Arc::new(store), stale)
    }

    /// What the stand-in holds, opened the way a replacement instance would open it.
    fn restored(fake: &FakeGcs, dir: &Path, tag: &str) -> super::SqliteStore {
        let path = dir.join(format!("restored-{tag}.db"));
        std::fs::write(&path, fake.bytes().expect("an object")).unwrap();
        super::SqliteStore::open_with_custody(&path.to_string_lossy(), wrap()).unwrap()
    }

    /// The 9 October stall, end to end through the real client: the write's upload is taken and never
    /// answered. The write used to wait on it for 30 s; it now answers within the attempt's bound plus
    /// one read and one retry, the retry lands on a fresh connection, and the commit is durable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_whose_upload_is_never_answered_answers_within_the_bound_on_a_retry_that_lands() {
        let fake = FakeGcs::start().await;
        let dir = temp_dir("upload-stall");
        let (store, stale) = open_over_fake(&dir, &fake);
        let before = fake.generation().expect("the first write landed");

        fake.script(&[NextPut::Swallow]);
        let started = Instant::now();
        store.put_agent(Agent::approved("held", "Held", 0)).unwrap();
        let took = started.elapsed();

        let bound = put_attempt_timeout(fake.bytes().unwrap().len());
        assert!(took >= PUT_ATTEMPT_FLOOR - Duration::from_millis(50), "the stalled attempt was waited on: {took:?}");
        assert!(took < bound + Duration::from_secs(2), "and the write answered at its bound, not at 30 s: {took:?}");
        let uploads = fake.uploads();
        assert_eq!(uploads.len(), 3, "the first write, the swallowed attempt and its one retry: {uploads:?}");
        assert_eq!(uploads[1].status, None, "the second was never answered");
        assert_eq!(uploads[2].status, Some(200), "the retry landed");
        assert!(uploads[2].connection > uploads[1].connection, "on a connection opened after the stall");
        assert!(fake.generation().unwrap() > before);
        assert_eq!(store.generation(), fake.generation().unwrap(), "the store agrees with what landed");
        assert_eq!(<PersistedSqliteStore as Store>::degraded(store.as_ref()), None);
        assert!(stale.lock().unwrap().is_empty());
        assert!(restored(&fake, &dir, "stall").get_agent("held").unwrap().is_some(), "the commit is in the bucket");
    }

    /// The 412 the retry can cause itself. The unanswered attempt was still on its way, the read said it
    /// had not landed, and it landed before the retry: the retry at the same generation meets a 412.
    /// That used to be the stale exit, a cold start announcing another owner over this instance's own
    /// write. The object carries this snapshot's upload id, so it is adopted, and nothing is sent again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retry_that_meets_its_own_late_landing_adopts_it_rather_than_exiting_stale() {
        let fake = FakeGcs::start().await;
        let dir = temp_dir("late-landing");
        let (store, stale) = open_over_fake(&dir, &fake);

        fake.script(&[NextPut::LandWhenRetried]);
        store.put_agent(Agent::approved("late", "Late", 0)).unwrap();

        let uploads = fake.uploads();
        assert_eq!(
            uploads.iter().map(|u| u.status).collect::<Vec<_>>(),
            vec![Some(200), None, Some(412)],
            "the attempt landed late, its retry met the 412, and nothing was resent after it: {uploads:?}"
        );
        assert!(stale.lock().unwrap().is_empty(), "its own landing is not another instance's: {:?}", stale.lock().unwrap());
        assert_eq!(store.generation(), fake.generation().unwrap(), "the landed generation is adopted");
        assert_eq!(<PersistedSqliteStore as Store>::degraded(store.as_ref()), None, "and nothing is quarantined");
        assert!(restored(&fake, &dir, "late").get_agent("late").unwrap().is_some());

        store.put_agent(Agent::approved("next", "Next", 0)).unwrap();
        assert_eq!(store.generation(), fake.generation().unwrap(), "and the next write replaces it");
    }

    /// Cloud Storage commits an upload and answers 503, the client resends the same bytes, and the resend meets the 412 its own first attempt caused. That 412 used to read as another instance owning the store, and the rightful owner exited. A resent upload may have landed, so the object is checked for this snapshot's upload id and adopted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_upload_applied_but_answered_503_is_adopted_not_read_as_another_owner() {
        let fake = FakeGcs::start().await;
        let dir = temp_dir("resend-applied-503");
        let (store, stale) = open_over_fake(&dir, &fake);

        fake.script(&[NextPut::ApplyAndAnswer(503)]);
        store.put_agent(Agent::approved("applied", "Applied", 0)).expect("a write that landed is answered as one");

        assert!(stale.lock().unwrap().is_empty(), "its own landing is not another instance's: {:?}", stale.lock().unwrap());
        assert_eq!(store.generation(), fake.generation().unwrap(), "the generation it produced is adopted");
        assert_eq!(<PersistedSqliteStore as Store>::degraded(store.as_ref()), None);
        assert!(restored(&fake, &dir, "applied-503").get_agent("applied").unwrap().is_some());
        store.put_agent(Agent::approved("next", "Next", 0)).unwrap();
        assert_eq!(store.generation(), fake.generation().unwrap(), "and the next write stores at the next one");
        assert!(stale.lock().unwrap().is_empty());
    }

    /// The same commit answered 5xx on every attempt: the last answer is an error, but an answered 5xx may have been applied, so it is resolved against the object rather than reported as a write that did not land.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_final_5xx_after_an_applied_attempt_is_resolved_not_reported_failed() {
        let fake = FakeGcs::start().await;
        let dir = temp_dir("resend-final-5xx");
        let (store, stale) = open_over_fake(&dir, &fake);

        fake.script(&[NextPut::ApplyAndAnswer(503), NextPut::Answer(502), NextPut::Answer(503), NextPut::Answer(504)]);
        store.put_agent(Agent::approved("applied", "Applied", 0)).expect("the landed write is adopted");

        assert!(stale.lock().unwrap().is_empty(), "{:?}", stale.lock().unwrap());
        assert_eq!(store.generation(), fake.generation().unwrap());
        assert_eq!(<PersistedSqliteStore as Store>::degraded(store.as_ref()), None);
        assert!(restored(&fake, &dir, "final-5xx").get_agent("applied").unwrap().is_some());
    }

    /// A resent upload the read-back settled as not applied, which the backend then commits late, is still recognised as this instance's own when the next upload meets the 412 it causes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resent_upload_settled_as_not_applied_that_lands_later_is_still_this_instances() {
        let fake = FakeGcs::start().await;
        let dir = temp_dir("c6-land-later");
        let (store, stale) = open_over_fake(&dir, &fake);
        fake.script(&[NextPut::AnswerAndLandLater(503), NextPut::Answer(502), NextPut::Answer(503), NextPut::Answer(504)]);
        store.put_agent(Agent::approved("first-try", "First try", 0)).expect_err("every attempt was answered with an error");
        store.put_agent(Agent::approved("next", "Next", 0)).expect("the next write carries both");
        assert!(stale.lock().unwrap().is_empty(), "its own late landing is not another owner: {:?}", stale.lock().unwrap());
        assert_eq!(store.generation(), fake.generation().unwrap());
        let copy = restored(&fake, &dir, "land-later");
        assert!(copy.get_agent("first-try").unwrap().is_some() && copy.get_agent("next").unwrap().is_some());
    }

    /// The read side of the resent-upload adoption: inside the fresh-read window, a bucket ahead of this instance is checked for one of its own unanswered uploads before it is called another owner's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fresh_read_meeting_its_own_unanswered_landing_is_not_a_stale_exit() {
        let fake = FakeGcs::start().await;
        let dir = temp_dir("resend-fresh-read");
        let stale = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = stale.clone();
        let objects = Arc::new(fake_gcs::client(&fake));
        let store = open(&dir, objects.clone())
            .with_fresh_read_window(Duration::from_secs(600))
            .with_on_stale(Box::new(move |m| recorder.lock().unwrap().push(m.to_string())));
        store.put_agent(Agent::approved("first", "First", 0)).unwrap();
        let ours = store.generation();

        // An upload of this instance's whose answer never came back, landed after the read that resolved it failed.
        let mut sent = BTreeMap::new();
        sent.insert(UPLOAD_ID_KEY.to_string(), new_upload_id());
        sent.insert("pm-commit-seq".to_string(), "7".to_string());
        sent.insert("pm-audit-head-hash".to_string(), "synthetic-head".to_string());
        store.state.lock().unwrap().remember_unresolved(&sent);
        let landed = objects.put_if_generation(DEFAULT_OBJECT, &fake.bytes().unwrap(), ours, &sent).unwrap();
        assert!(matches!(landed, PutOutcome::Stored(g) if g > ours));

        store.get_agent("first").expect("the read is answered");
        assert!(stale.lock().unwrap().is_empty(), "its own landing is not another owner: {:?}", stale.lock().unwrap());

        // A newer object carrying someone else's upload is still the stale exit.
        let mut theirs = sent.clone();
        theirs.insert(UPLOAD_ID_KEY.to_string(), new_upload_id());
        let generation = fake.generation().unwrap();
        objects.put_if_generation(DEFAULT_OBJECT, &fake.bytes().unwrap(), generation, &theirs).unwrap();
        *store.last_generation_check.lock().unwrap() = None;
        assert!(store.get_agent("first").is_err());
        assert_eq!(stale.lock().unwrap().len(), 1, "another owner's object is still the stale exit");
    }

    /// The console's status poll and `/health` read `degraded`, and they waited out the whole stall
    /// with the write that caused it (every `GET /v1/broker` in that minute answered after 3 to 30 s).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_durability_note_answers_while_an_upload_is_in_flight() {
        let fake = FakeGcs::start().await;
        let dir = temp_dir("upload-degraded");
        let (store, _stale) = open_over_fake(&dir, &fake);

        fake.script(&[NextPut::Swallow]);
        let writer = store.clone();
        let write = tokio::task::spawn_blocking(move || writer.put_agent(Agent::approved("w", "W", 0)));
        let waiting = Instant::now();
        while fake.uploads().len() < 2 {
            assert!(waiting.elapsed() < Duration::from_secs(2), "the upload never reached the stand-in");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let asked = Instant::now();
        let note = <PersistedSqliteStore as Store>::degraded(store.as_ref());
        assert!(asked.elapsed() < Duration::from_millis(200), "it answered without waiting: {:?}", asked.elapsed());
        assert_eq!(note, None, "nothing has failed yet");
        write.await.unwrap().unwrap();
    }

    // ── Two instances of one tenant writing the approver keyring ────────────────────────────────

    fn approver_pubkey(seed: u8) -> String {
        use base64::Engine as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes())
    }

    /// One instance of the tenant's worker: its own local database restored from the shared bucket,
    /// its own service and so its own control-plane and keyring locks, with the stale exit recorded.
    fn instance(
        tag: &str,
        fake: &FakeGcs,
    ) -> (crate::service::EnforcementService, Arc<PersistedSqliteStore>, Arc<Mutex<Vec<String>>>) {
        let stale = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = stale.clone();
        let store = Arc::new(
            open(&temp_dir(tag), Arc::new(fake_gcs::client(fake)))
                .with_fresh_read_window(Duration::ZERO)
                .with_on_stale(Box::new(move |m| recorder.lock().unwrap().push(m.to_string()))),
        );
        let service = crate::service::EnforcementService::new(
            store.clone(),
            Arc::new(crate::connectors::MockHttpClient::new()),
        );
        (service, store, stale)
    }

    /// The split keyring as it reaches the hosted store. Two instances restored from one generation each
    /// revoke a different device, and each sees the other's device as still usable, so neither
    /// revocation looks like the last one and neither asks for recovery authority. On a shared row
    /// both would land and the tenant would be left with no trusted device. Here the second upload
    /// carries the generation it restored, meets the precondition and is refused: the bucket keeps
    /// the first revocation and a trusted device, and the second instance is told it lost the store.
    ///
    /// This proves the second writer is refused, not that two instances are safe to run: the refused
    /// instance has already answered reads from a stale keyring, and its revocation is lost rather
    /// than re-decided against the state that won.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_instance_cannot_upload_a_keyring_decided_on_a_generation_another_has_replaced() {
        let fake = FakeGcs::start().await;
        let (a, _a_store, a_stale) = instance("replaced-a", &fake);
        assert!(a.trust_approver_key_durable("device:one", &approver_pubkey(1)).unwrap());
        assert!(a.trust_approver_key_durable("device:two", &approver_pubkey(2)).unwrap());
        let shared = fake.generation().expect("both pairings are in the bucket");

        let (b, b_store, b_stale) = instance("replaced-b", &fake);
        assert_eq!(b_store.generation(), shared, "the second instance restored the same generation");
        assert!(b.approver_key_trusted("device:one") && b.approver_key_trusted("device:two"));
        assert!(!a.revoking_would_empty_keyring("device:one"), "A sees device two as still usable");
        assert!(!b.revoking_would_empty_keyring("device:two"), "B sees device one as still usable");

        a.revoke_approver_key("device:one").expect("the first revocation lands");
        let refused = b.revoke_approver_key("device:two").expect_err("the second must not land");

        assert!(matches!(refused, GatewayError::StoreUnavailable(_)), "got {refused}");
        let told = b_stale.lock().unwrap().clone();
        assert_eq!(told.len(), 1, "the second instance is sent away stale: {told:?}");
        assert!(told[0].contains("another instance owns the store"), "{}", told[0]);
        assert!(a_stale.lock().unwrap().is_empty(), "the instance that won carries on");
        let uploads = fake.uploads();
        assert_eq!(
            uploads.iter().map(|u| u.status).collect::<Vec<_>>(),
            vec![Some(200), Some(200), Some(200), Some(412)],
            "two pairings and A's revocation landed, and B's upload met the precondition: {uploads:?}"
        );

        // What a replacement instance restores is the state that won, with nothing of B's in it.
        let (after, _, _) = instance("replaced-after", &fake);
        assert!(!after.approver_key_trusted("device:one"), "the acknowledged revocation was not overwritten");
        assert!(after.approver_key_trusted("device:two"), "and the tenant still has a trusted device");
        assert!(after.any_device_trusted());
    }

    /// The late-landing adoption a security review traced on 9 October. Upload X and its retry both go
    /// unanswered, and X lands later. Then a commit X does not contain: a revocation that committed
    /// after X's snapshot, and an execution's terminal audit event with its grant charge, which commits
    /// even while the store is quarantined. That persist's upload Y goes unanswered too, and the object
    /// it reads back carries X's id. Agreeing with it as if it held Y marked both commits durable, and
    /// the next boot restored X without them. Y has to be sent over X's generation instead.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_older_upload_landing_late_is_never_taken_for_the_newer_commit() {
        let dir = temp_dir("late-older-landing");
        let objects = Arc::new(LostResponse::new(Vec::new()));
        let (store, stale) = open_lost(&dir, objects.clone());
        let victim = Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_victim".into(),
            agent_id: "agent".into(),
            user_id: None,
            device_id: None,
            token: "tok_victim".into(),
            role: crate::store::SessionRole::Agent,
            created_at: 0,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        };
        store.put_session(victim).unwrap();
        let before = objects.inner.head(DEFAULT_OBJECT).unwrap().unwrap();

        // X: the upload is held on its way and its retry is lost, so X stays unresolved.
        objects.pending.lock().unwrap().extend([Landing::Held, Landing::Nothing, Landing::Nothing]);
        let err = store.put_agent(Agent::approved("x", "X", 0)).unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "got {err}");
        objects.land_held();
        let x_generation = objects.inner.head(DEFAULT_OBJECT).unwrap().unwrap();
        assert!(x_generation > before, "X landed after its sender gave up on it");

        // A revocation that committed after X's snapshot, with its own upload still queued behind this
        // one, and then the terminal event, which commits whatever the bucket is doing. Its upload, Y,
        // goes unanswered.
        assert!(store.inner.revoke_session("sess_victim").unwrap());
        let mut terminal = AuditPayload::new("generic_http.request", "late-landing", "allow");
        terminal.agent_id = Some("agent".into());
        terminal.summary = serde_json::json!({ "grant_id": "gr_late" });
        store.append_audit_terminal(terminal, Some(crate::store::GrantCharge::new("gr_late")), None).unwrap();

        assert!(stale.lock().unwrap().is_empty(), "every object in this story is this instance's own");
        assert_eq!(<PersistedSqliteStore as Store>::degraded(&store), None, "and nothing is left waiting");
        assert!(store.generation() > x_generation, "Y was sent over the generation X produced");

        // What the next boot restores.
        let copy = store_from_object(&objects.inner, &dir, "late-older-landing");
        assert!(copy.get_agent("x").unwrap().is_some());
        assert!(
            copy.get_session("sess_victim").unwrap().expect("the session row").revoked,
            "the revocation survives the restart"
        );
        assert!(
            copy.audit_events(None).unwrap().iter().any(|e| e.payload.resource == "late-landing"),
            "the terminal audit event survives the restart"
        );
        let window = crate::store::GrantWindow { grant_id: "gr_late", since_ms: i64::MIN };
        assert_eq!(
            copy.read_grant_usage(std::slice::from_ref(&window)).unwrap().total("gr_late"),
            1,
            "and so does its grant charge"
        );
    }

    // ── No metadata request while `serial` is held ──────────────────────────────────────────────

    /// An object store whose metadata request, once armed, answers only after a timer the runtime drives, as the real client's answer arrives only through the runtime's I/O driver.
    /// It counts the requests made inside a `run_atomically` scope, whose body runs holding `serial`, and `release` lets every held request go from outside the runtime so a wedge fails the test instead of hanging the suite.
    struct HeldHead {
        inner: MemoryObjectStore,
        armed: std::sync::atomic::AtomicBool,
        latency: Duration,
        started: std::sync::mpsc::Sender<()>,
        release: tokio::sync::watch::Sender<bool>,
        under_serial: AtomicU64,
    }

    impl HeldHead {
        fn new(latency: Duration, started: std::sync::mpsc::Sender<()>) -> Self {
            HeldHead {
                inner: MemoryObjectStore::new(),
                armed: std::sync::atomic::AtomicBool::new(false),
                latency,
                started,
                release: tokio::sync::watch::channel(false).0,
                under_serial: AtomicU64::new(0),
            }
        }

        fn hold(&self) {
            if !self.armed.load(Ordering::SeqCst) {
                return;
            }
            if BATCH_DEPTH.with(Cell::get) > 0 {
                self.under_serial.fetch_add(1, Ordering::SeqCst);
            }
            let _ = self.started.send(());
            let mut released = self.release.subscribe();
            let latency = self.latency;
            super::super::bridge::block_on(async move {
                tokio::select! {
                    _ = tokio::time::sleep(latency) => {}
                    _ = released.wait_for(|r| *r) => {}
                }
            });
        }
    }

    impl ObjectStore for HeldHead {
        fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
            self.hold();
            self.inner.head(name)
        }
        fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
            self.hold();
            self.inner.head_full(name)
        }
        fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
            self.inner.has_history(name)
        }
        fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
            self.inner.get(name, generation)
        }
        fn put_if_generation(
            &self,
            name: &str,
            bytes: &[u8],
            expected: u64,
            metadata: &BTreeMap<String, String>,
        ) -> Result<PutOutcome, GatewayError> {
            self.inner.put_if_generation(name, bytes, expected, metadata)
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
    }

    /// For a minute after a cold start a read first asks the bucket whether the store's generation moved, and a read inside a transaction (an approve reading the agent it approves) asked while holding `serial`.
    /// On one worker the next store call parked the only runtime thread on that mutex, the request's answer needed that thread, and every later request hung.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_read_inside_a_transaction_on_a_fresh_instance_does_not_wedge_one_worker() {
        let (started, started_rx) = std::sync::mpsc::channel();
        let objects = Arc::new(HeldHead::new(Duration::from_millis(300), started));
        let store = Arc::new(open(&temp_dir("fresh-instance"), objects.clone()));
        assert_eq!(store.fresh_read_window, FRESH_READ_WINDOW, "the window a cold start leaves open");
        store.put_agent(Agent::approved("waiting", "Waiting", 0)).unwrap();
        objects.armed.store(true, Ordering::SeqCst);

        // Spawned, not inline: the test body runs on the calling thread, which is not the worker.
        let (done, finished) = std::sync::mpsc::channel::<&str>();
        let (s, d) = (store.clone(), done.clone());
        tokio::spawn(async move {
            s.run_atomically(&mut |s| {
                s.get_agent("waiting")?.expect("the agent");
                Ok(())
            })
            .expect("the transaction commits");
            let _ = d.send("transaction");
        });
        started_rx.recv_timeout(Duration::from_secs(10)).expect("the transaction's metadata request started");
        let (s, d) = (store.clone(), done);
        tokio::spawn(async move {
            s.list_agents().expect("the read answers");
            let _ = d.send("read");
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut answered = Vec::new();
        while answered.len() < 2 {
            match finished.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(who) => answered.push(who),
                Err(_) => break,
            }
        }
        objects.release.send_replace(true);
        assert_eq!(answered.len(), 2, "the worker wedged: only {answered:?} answered within 5 s");
        assert_eq!(
            objects.under_serial.load(Ordering::SeqCst),
            0,
            "a metadata request was made inside a transaction, holding serial"
        );
    }

    /// The guarantee the check exists for still covers a transaction: a fresh instance whose bucket moved refuses the unit of work before any of it runs against the restored copy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transaction_on_a_fresh_instance_is_refused_once_another_instance_has_written() {
        let objects = Arc::new(MemoryObjectStore::new());
        let a = open(&temp_dir("fresh-tx-a"), objects.clone());
        a.put_agent(Agent::approved("first", "A", 0)).unwrap();
        let stale = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = stale.clone();
        let b = open(&temp_dir("fresh-tx-b"), objects.clone())
            .with_on_stale(Box::new(move |m| recorder.lock().unwrap().push(m.to_string())));
        a.put_agent(Agent::approved("second", "A", 0)).unwrap();

        let mut seen = None;
        let err = b
            .run_atomically(&mut |s| {
                seen = Some(s.list_agents()?.len());
                s.put_agent(Agent::approved("from-b", "B", 0))
            })
            .unwrap_err();
        assert!(matches!(err, GatewayError::StoreUnavailable(_)), "{err}");
        assert_eq!(seen, None, "nothing inside the unit read the stale copy");
        let recorded = stale.lock().unwrap();
        assert_eq!(recorded.len(), 1, "the stale handler ran exactly once");
        assert!(recorded[0].contains("stale on a fresh instance"), "{}", recorded[0]);
        assert!(b.inner.get_agent("from-b").unwrap().is_none(), "and nothing it would have written was");
    }

    /// The same wedge under load through the shipped Cloud Storage client over real HTTP: one runtime thread as on a 1 vCPU worker, the fresh-read window open as a cold start leaves it, and callers that read inside transactions, read alone and write, all at once against a bucket 20 ms away.
    /// A plain `#[test]` driving its own runtime, because a wedged runtime cannot run the watchdog that would report it and cannot be dropped either, so it is abandoned instead.
    #[test]
    fn one_worker_under_load_in_the_fresh_read_window_does_not_wedge() {
        const CALLERS: u32 = 6;
        let bucket = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let fake = bucket.block_on(FakeGcs::start());
        fake.set_latency(Duration::from_millis(20));
        let worker = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let stale = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = stale.clone();
        let store = {
            let _in = worker.enter();
            let store = open(&temp_dir("fresh-instance-soak"), Arc::new(fake_gcs::client(&fake)))
                .with_on_stale(Box::new(move |m| recorder.lock().unwrap().push(m.to_string())));
            for t in 0..CALLERS {
                store.put_agent(Agent::approved(format!("t{t}"), "T", 0)).unwrap();
            }
            Arc::new(store)
        };
        assert_eq!(store.fresh_read_window, FRESH_READ_WINDOW);

        let until = Instant::now() + Duration::from_secs(4);
        let (done, finished) = std::sync::mpsc::channel::<Result<u32, String>>();
        for caller in 0..CALLERS {
            let (store, done) = (store.clone(), done.clone());
            worker.spawn(async move {
                let mut ops = 0u32;
                let outcome = loop {
                    if Instant::now() >= until {
                        break Ok(ops);
                    }
                    let id = format!("t{caller}");
                    let step = match caller % 3 {
                        0 => store.run_atomically(&mut |s| {
                            let mut agent = s.get_agent(&id)?.expect("the caller's agent");
                            agent.name = format!("T{ops}");
                            s.put_agent(agent)
                        }),
                        1 => store.list_agents().map(drop),
                        _ => store.put_agent(Agent::approved(format!("w{caller}-{ops}"), "W", 0)),
                    };
                    if let Err(e) = step {
                        break Err(e.to_string());
                    }
                    ops += 1;
                    tokio::task::yield_now().await;
                };
                let _ = done.send(outcome);
            });
        }
        drop(done);

        let deadline = until + Duration::from_secs(10);
        let mut outcomes = Vec::new();
        while outcomes.len() < CALLERS as usize {
            match finished.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(outcome) => outcomes.push(outcome),
                Err(_) => break,
            }
        }
        if outcomes.len() < CALLERS as usize {
            worker.shutdown_background();
            bucket.shutdown_background();
            panic!("one worker wedged in the fresh-read window: {} of {CALLERS} callers finished: {outcomes:?}", outcomes.len());
        }
        for outcome in &outcomes {
            assert!(matches!(outcome, Ok(n) if *n > 0), "every caller made progress: {outcomes:?}");
        }
        {
            let _in = worker.enter();
            store.put_agent(Agent::approved("after", "After", 0)).expect("the store still writes");
            assert!(store.get_agent("after").unwrap().is_some(), "and still reads");
        }
        assert!(stale.lock().unwrap().is_empty(), "one instance, so nothing was ever stale");
        worker.shutdown_timeout(Duration::from_secs(5));
        bucket.shutdown_timeout(Duration::from_secs(5));
    }
}
