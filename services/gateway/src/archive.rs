//! The audit archive: publish the oldest part of the chain as signed, create-only segments, then prune it.
//! In a bucket that grants the runtime create and no overwrite or delete, the gateway cannot change a segment; in a self-run gateway's `<home>/audit-archive`, anything that can write the home can rewrite or delete segments, and the chain and its signatures catch that only against someone who does not also hold the store's key.
//!
//! # Why this exists
//!
//! With the grant-budget clone gone an audit event costs about 4.6 KB resident and the hot ceiling
//! is 65,000 events. An execution writes two of them and a denial writes one, so a busy tenant
//! reaches the ceiling in weeks, and at the ceiling new executions are refused. Nothing prunes, so
//! today that refusal is permanent. This is what makes it temporary.
//!
//! # The invariant the whole module is built around
//!
//! **A row is deleted only after its segment is provably readable somewhere else.** "Provably" is
//! four checks, not one:
//!
//! 1. the `.ndjson` object exists, written create-only so this pass overwrote nothing (a generation precondition in a bucket; on a
//!    local archive, a check under this process's lock that another process, or the owner, can still get around);
//! 2. its `.manifest.json` exists, likewise create-only;
//! 3. the `.ndjson` has been **read back** and hashes to what the manifest says;
//! 4. the segment's index page names it: one signed object per segment, named for the seq it starts
//!    at and written create-only, so the index is only ever appended to and two writers cannot both
//!    think they published the same range. In an epoch an earlier build indexed with one whole-epoch
//!    `index.json`, the first page after it is also appended to that file at the generation read (the
//!    hand-over), so an older writer still running in the same rollout cannot extend it unseen.
//!
//! Only then does the prune run, and the prune and the boundary advance are one store unit
//! ([`Store::prune_audit_to`]): `audit_boundary` never moves independently of its prune.
//!
//! The checks are one routine, [`AuditArchive::run_pass`]'s `prove_segment`, run by a fresh
//! publication and by a pass that resumes one. A resume in particular proves nothing by finding its
//! own head hash in the index: the index names what should be there, and only fetching the manifest
//! and the bytes and walking the events says that it is.
//!
//! # Restores are branches, not a sequence
//!
//! A restore forks the chain into a new epoch, and the fork is recorded in the store's signed
//! boundary as [`AuditFork`]: the parent epoch, the seq where the restored history leaves it, and
//! the restore that did it. A restored store's history is therefore the root epoch up to the first
//! fork, each fork's epoch up to the next, and its own epoch from its last fork. Whatever a parent
//! archived past the point a child left it is the abandoned suffix, kept and counted but never part
//! of the child's history. Verification, export and budget rebuild all read history through
//! [`ArchivedEvents`], which follows exactly that selection and nothing else.
//!
//! An epoch number is claimed in the bucket ([`AuditArchive::claim_epoch`]) rather than read out of
//! the restored database, because two restores of one checkpoint read the same number out of it.
//!
//! # Where it runs
//!
//! Off the execution path, in a task the request does not own, kicked from the same fence that
//! evaluates the audit ceiling. The request never waits for it, and a pass never delays a call.
//! One pass at a time, bounded to [`DEFAULT_BATCH`] events, and the next pass starts only when the
//! previous one has finished, so pending work cannot pile up. A kick runs a pass only once a full
//! batch has accumulated above the hot-window floor, or sooner when the ceiling signals pressure
//! ([`AuditArchive::due`]), so in steady state a segment holds [`DEFAULT_BATCH`] events, and a pass
//! adds one index page whatever the length of the history before it.
//!
//! That placement is only safe because **a crash at any point leaves a consistent store**. Every
//! step is either idempotent or has no effect until the step after it, and the recovery for each is
//! to run the next pass:
//!
//! | Crash point | What is on disk and in the bucket | What the next pass does |
//! | --- | --- | --- |
//! | before anything | nothing written | publishes the batch |
//! | after the `.ndjson` | a segment nothing names; hot store whole | create-only put meets 412, reads the object back, finds identical bytes, carries on |
//! | after the manifest | segment and manifest; not in the index; hot store whole | same, then appends to the index |
//! | after the read-back | as above | same |
//! | after the index update | index names the segment; hot store whole | sees the index ahead of the boundary and prunes to it without republishing |
//! | inside the prune transaction | SQLite rolled it back; hot store whole | as "after the index update" |
//! | after the prune, before the snapshot upload | rows gone locally, bucket still pre-prune | the store is dirty and refuses writes until it carries; a cold start restores the pre-prune snapshot and the pass repeats idempotently |
//! | after the prune and its upload | rows gone, boundary advanced, index names the segment | starts the next batch |
//!
//! The one state that is **not** recoverable by repetition is a different segment already occupying
//! a name, and that is why it refuses loudly rather than overwriting: two chains claiming one
//! namespace is what the epoch in the path exists to prevent, and meeting it anyway means something
//! is wrong that a writer must not paper over.
//!
//! # Backpressure
//!
//! When publication is unavailable the writer backs off and the existing ceiling provides the
//! backpressure. **An audit event is never dropped**: nothing here is on the append path, and
//! a pass that cannot reach the bucket changes nothing at all.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use permaura_core::audit::{
    segment_id, sha256_hex, AuditArchiveIndex, AuditBoundary, AuditFork, AuditIndexEntry,
    AuditSegment, AuditSegmentDraft,
};
use permaura_core::{AuditEvent, AuditPayload};

use crate::error::GatewayError;
use crate::objectstore::{ObjectStore, PutOutcome};
use crate::store::Store;

/// `1` turns the bucket writer on (it also needs a bucket and a tenant slug). Unset, a self-run gateway archives to
/// `<home>/audit-archive` ([`local`]) and a hosted worker publishes and prunes nothing; `0` switches the local writer off too.
pub const ENABLED_ENV: &str = "PERMAURA_AUDIT_ARCHIVE";

/// The bucket segments are published to. Separate from the store bucket on purpose: the tenant
/// runtime needs create-only on its own prefix here and nothing at all on anyone else's.
pub const BUCKET_ENV: &str = "PERMAURA_AUDIT_ARCHIVE_BUCKET";

/// The prefix inside that bucket. Defaults to [`DEFAULT_PREFIX`].
pub const PREFIX_ENV: &str = "PERMAURA_AUDIT_ARCHIVE_PREFIX";

/// How many events one pass publishes. Defaults to [`default_batch`] of the hot-window floor.
pub const BATCH_ENV: &str = "PERMAURA_AUDIT_ARCHIVE_BATCH";

/// How many of the newest events stay in the hot store whatever happens. Defaults to
/// [`DEFAULT_KEEP_HOT`].
pub const KEEP_HOT_ENV: &str = "PERMAURA_AUDIT_ARCHIVE_KEEP_HOT";

/// Events per pass, and the batch a kick waits for above the hot-window floor before it runs one.
/// Bounded so one pass is one upload of a few megabytes and one transaction, and a store with half a
/// million events migrates in a hundred passes rather than one. Must sit well below the hot ceiling's
/// headroom over [`DEFAULT_KEEP_HOT`], or the ceiling's pressure band is what triggers the pass.
pub const DEFAULT_BATCH: usize = 5_000;

/// Events the hot store always keeps. `GET /v1/audit` serves the hot window, so pruning to nothing
/// would leave the console with an empty audit page on a gateway that has recorded everything.
pub const DEFAULT_KEEP_HOT: usize = 5_000;

/// The prefix under the bucket.
pub const DEFAULT_PREFIX: &str = "audit";

/// The least batch [`default_batch`] derives from a low hot-window floor. Every kick comes with an execution's two events (the attempt and its outcome), so a pass that takes one or two never brings a backlog down, and each segment it publishes is held for the whole retention period; a hundred drains a drill worker's backlog within a few dozen calls.
pub const MIN_DEFAULT_BATCH: usize = 100;

/// The batch a writer takes when [`BATCH_ENV`] is not set: [`DEFAULT_BATCH`], or the hot-window floor when that is lower, but never below [`MIN_DEFAULT_BATCH`].
///
/// Lowering `PERMAURA_AUDIT_ARCHIVE_KEEP_HOT` alone is the lever the hosted runbooks give for forcing passes on a drill worker, and before passes were batched it published as soon as the hot store passed the floor. With the batch tied to the floor it still does once as many events again are waiting (1,359 events over a floor of 600 publishes), the window stays near twice the floor at most, and a pass still covers many calls rather than one. A floor of 0 or 1 made the batch 1, so a drill worker published one-event segments and its hot store never drained; below [`MIN_DEFAULT_BATCH`] a pass starts once that many events sit above the floor.
pub fn default_batch(keep_hot: usize) -> usize {
    keep_hot.clamp(MIN_DEFAULT_BATCH, DEFAULT_BATCH)
}

/// Whether the writer is switched on for this process.
pub fn is_enabled() -> bool {
    std::env::var(ENABLED_ENV).map(|v| v.trim() == "1").unwrap_or(false)
}

/// Where a gateway its owner runs keeps its archive, under its home.
pub const LOCAL_DIR: &str = "audit-archive";

/// The tenant namespace of a local archive. A self-run gateway has no slug, and its archive is its own directory.
pub const LOCAL_TENANT: &str = "local";

/// The writer a gateway its owner runs gets with no configuration: the same passes and the same proof before any prune, publishing to `<home>/audit-archive` on its own disk instead of a bucket, so the hot window stays bounded and the ceiling is a bound rather than a wall nothing ever lowers. `None` on a hosted worker, whose archive is its bucket or nothing; on a store that keeps no audit boundary (an in-memory demo), which has nothing to archive from; when no home resolves; and when [`ENABLED_ENV`] is `0`.
pub fn local(hosted: bool, home: Option<std::path::PathBuf>, store: &dyn Store) -> Option<Arc<AuditArchive>> {
    if hosted || std::env::var(ENABLED_ENV).is_ok_and(|v| v.trim() == "0") {
        return None;
    }
    if !store.audit_boundary().is_ok_and(|boundary| boundary.is_some()) {
        return None;
    }
    let dir = home?.join(LOCAL_DIR);
    let archive = AuditArchive::new(Arc::new(crate::objectstore::LocalObjectStore::new(dir.clone())), LOCAL_TENANT);
    match archive.foreign_to(store) {
        Ok(None) => Some(Arc::new(archive)),
        Ok(Some(why)) => {
            let aside = dir.with_file_name(format!("{LOCAL_DIR}.foreign-{}", crate::service::now_ms()));
            match std::fs::rename(&dir, &aside) {
                Ok(()) => {
                    tracing::warn!(
                        moved_to = %aside.display(),
                        "{} belongs to another store ({why}), most likely an earlier install of this gateway; it was moved aside and this store starts a new archive. Delete the moved directory once nothing needs its history",
                        dir.display()
                    );
                    Some(Arc::new(AuditArchive::new(Arc::new(crate::objectstore::LocalObjectStore::new(dir)), LOCAL_TENANT)))
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "{} belongs to another store ({why}) and could not be moved aside, so this gateway archives nothing: delete or move that directory and restart, or executions are refused once the audit window reaches its ceiling",
                        dir.display()
                    );
                    None
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not tell whether {} belongs to this store; archiving to it as before", dir.display());
            Some(Arc::new(archive))
        }
    }
}

fn usize_from_env(key: &str, default: usize, min: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.max(min))
        .unwrap_or(default)
}

/// What one pass did, for the log line and for a test to assert on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassOutcome {
    /// The segment published or adopted, when one was.
    pub segment_id: Option<String>,
    /// How many rows the prune removed.
    pub pruned: u64,
    /// Why the pass ended where it did, for the log.
    pub reason: &'static str,
}

/// The archive writer: a bucket, a tenant namespace, and the rule that a row is deleted only after
/// its segment is provably readable somewhere else.
pub struct AuditArchive {
    objects: Arc<dyn ObjectStore>,
    tenant: String,
    prefix: String,
    batch: usize,
    keep_hot: usize,
    /// One pass at a time. A second kick while a pass is running does nothing rather than queueing,
    /// because the work is "catch up with the hot store" and the next kick will see whatever is
    /// left.
    running: AtomicBool,
    segments: AtomicU64,
    pruned: AtomicU64,
    /// The last failure, for `/health`. A writer that has been unable to publish for an hour is the
    /// thing an operator needs to see before the ceiling starts refusing executions.
    last_error: Mutex<Option<String>>,
    /// The fork this process has already confirmed owns its epoch in the bucket, so the claim is read
    /// once per process rather than once per pass.
    claimed: Mutex<Option<AuditFork>>,
}

/// The chain event recording a store moved out of an epoch another restore holds.
pub const EPOCH_MOVED: &str = "recovery.epoch_moved";

/// How many epoch numbers [`AuditArchive::claim_epoch`] tries before giving up. Each is one or two
/// small reads, and a tenant restored this many times from one generation is not a real case.
const MAX_EPOCH_PROBES: u64 = 1024;

/// The object that reserves a forked epoch's namespace for one restore.
///
/// Unsigned, because it is an allocation and not evidence: what a verifier trusts is the fork in the
/// store's signed boundary and in the epoch's signed index. What this settles is that no two
/// restores publish into one namespace, which the restored database cannot settle because each
/// restore of one checkpoint reads the same epoch out of it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct EpochClaim {
    tenant: String,
    fork: AuditFork,
}

impl AuditArchive {
    /// Build a writer over `objects`, keyed by tenant slug, taking its limits from the environment.
    pub fn new(objects: Arc<dyn ObjectStore>, tenant: impl Into<String>) -> Self {
        let prefix = std::env::var(PREFIX_ENV)
            .ok()
            .map(|v| v.trim().trim_matches('/').to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_PREFIX.to_string());
        let keep_hot = usize_from_env(KEEP_HOT_ENV, DEFAULT_KEEP_HOT, 0);
        Self::with_limits(objects, tenant, prefix, usize_from_env(BATCH_ENV, default_batch(keep_hot), 1), keep_hot)
    }

    /// The same, with every limit named rather than read from the environment.
    ///
    /// The environment is process-global and the suite runs in parallel, so a test that set
    /// `PERMAURA_AUDIT_ARCHIVE_BATCH` would be setting it for every other test at the same time.
    pub fn with_limits(
        objects: Arc<dyn ObjectStore>,
        tenant: impl Into<String>,
        prefix: impl Into<String>,
        batch: usize,
        keep_hot: usize,
    ) -> Self {
        AuditArchive {
            objects,
            tenant: tenant.into(),
            prefix: prefix.into(),
            batch: batch.max(1),
            keep_hot,
            running: AtomicBool::new(false),
            segments: AtomicU64::new(0),
            pruned: AtomicU64::new(0),
            last_error: Mutex::new(None),
            claimed: Mutex::new(None),
        }
    }

    /// Why this archive cannot be `store`'s, when it plainly is not: a store that has never pruned
    /// (epoch 0, base 0) meeting a first index page that does not verify under its key, or that names
    /// a first segment ending on an event this store does not hold. That is a reinstall over an earlier
    /// install's archive, which no pass could ever adopt or append past. A store that
    /// published and stopped before its prune still holds that segment's rows, so it is not foreign.
    pub fn foreign_to(&self, store: &dyn Store) -> Result<Option<&'static str>, GatewayError> {
        let Some(boundary) = store.audit_boundary()? else { return Ok(None) };
        if boundary.epoch != 0 || boundary.base_seq != 0 {
            return Ok(None);
        }
        let first = match self.read_page(0, 0)? {
            Some(page) => page,
            None => match self.read_legacy_index(0)? {
                Some(index) => index,
                None => return Ok(None),
            },
        };
        if !first.verify(&verifying_key(store)?) {
            return Ok(Some("its index does not verify under this store's audit key"));
        }
        let Some(entry) = first.segments.first() else { return Ok(None) };
        let held = store.audit_events_from(entry.end_seq, 1)?;
        match held.first() {
            Some(event) if event.seq == entry.end_seq && event.hash == entry.head_hash => Ok(None),
            _ => Ok(Some("its first segment is not the events this store holds")),
        }
    }

    /// The tenant slug this writer publishes under.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Where a tenant's segments for one epoch live.
    ///
    /// The epoch is in the path, so segments from two chain histories of one tenant never share a
    /// namespace: a restore forks the epoch, and the fork's segment `seg-…-0000…9999` is a
    /// different object from the abandoned generation's segment of the same range.
    pub fn epoch_prefix(&self, epoch: u64) -> String {
        format!("{}/{}/e{epoch:04}", self.prefix, self.tenant)
    }

    fn ndjson_name(&self, epoch: u64, id: &str) -> String {
        format!("{}/{id}.ndjson", self.epoch_prefix(epoch))
    }

    fn manifest_name(&self, epoch: u64, id: &str) -> String {
        format!("{}/{id}.manifest.json", self.epoch_prefix(epoch))
    }

    /// The whole-epoch index a build before index pages rewrote on every pass: read as the start of an epoch's index, and written once more only by the hand-over, which names the first page after it in it too.
    pub fn index_name(&self, epoch: u64) -> String {
        format!("{}/index.json", self.epoch_prefix(epoch))
    }

    /// The index page naming the segment that starts at `base_seq`, which a reader finds from where the previous segment ended.
    pub fn page_name(&self, epoch: u64, base_seq: u64) -> String {
        format!("{}/index/{base_seq:020}.json", self.epoch_prefix(epoch))
    }

    /// The object that reserves a forked epoch for the restore that opened it.
    pub fn claim_name(&self, epoch: u64) -> String {
        format!("{}/fork.json", self.epoch_prefix(epoch))
    }

    /// Counters and the last failure, for the authenticated `/health` block.
    pub fn health_snapshot(&self, pending: u64) -> serde_json::Value {
        serde_json::json!({
            "enabled": true,
            "tenant": self.tenant,
            "batch": self.batch,
            "keep_hot": self.keep_hot,
            "pending": pending,
            "segments": self.segments.load(Ordering::Relaxed),
            "pruned": self.pruned.load(Ordering::Relaxed),
            "last_error": self.last_error.lock().ok().and_then(|e| e.clone()),
        })
    }

    /// How many events are eligible to leave the hot store right now.
    pub fn pending(&self, store: &dyn Store) -> Result<u64, GatewayError> {
        Ok(store.audit_len()?.saturating_sub(self.keep_hot as u64))
    }

    /// Whether a pass is due with `hot_events` in the hot store: a full batch has accumulated above
    /// the hot-window floor, or the ceiling is signalling `pressure` and whatever is above the floor
    /// should go now. Below that a kick is a comparison and nothing else, so steady traffic past the
    /// floor publishes one segment per batch rather than one per call.
    pub fn due(&self, hot_events: u64, pressure: bool) -> bool {
        let eligible = hot_events.saturating_sub(self.keep_hot as u64);
        eligible > 0 && (pressure || eligible >= self.batch as u64)
    }

    /// Run one pass only when one is [`due`](Self::due), for a caller that drives passes itself.
    pub fn run_pass_if_due(&self, store: &dyn Store, pressure: bool) -> Result<PassOutcome, GatewayError> {
        if !self.due(store.audit_len()?, pressure) {
            return Ok(PassOutcome { reason: "below the batch threshold", ..Default::default() });
        }
        self.run_pass(store)
    }

    /// Run one pass in a task the caller does not own, if one is due and not already running.
    ///
    /// Called from the execution fence, which has just read `audit_len` for the ceiling and knows its
    /// band, so the decision costs an atomic and a comparison. The request never awaits the handle:
    /// an archive pass must not be able to delay a call, and a call that goes away must not be able
    /// to cancel a pass halfway through publishing a segment.
    pub fn kick(self: &Arc<Self>, store: Arc<dyn Store>, hot_events: u64, pressure: bool) {
        if !self.due(hot_events, pressure) {
            return;
        }
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let archive = self.clone();
        // `spawn_blocking`, because a pass is a synchronous store call and a synchronous upload.
        // On a runtime worker it would park the thread the upload itself needs.
        tokio::task::spawn_blocking(move || {
            let result = archive.run_pass(store.as_ref());
            archive.running.store(false, Ordering::SeqCst);
            match result {
                Ok(outcome) => {
                    if let Ok(mut slot) = archive.last_error.lock() {
                        *slot = None;
                    }
                    if outcome.segment_id.is_some() || outcome.pruned > 0 {
                        tracing::info!(
                            segment = ?outcome.segment_id,
                            pruned = outcome.pruned,
                            reason = outcome.reason,
                            "audit archive pass"
                        );
                    }
                }
                Err(e) => {
                    // A warning and a backed-off retry, never a refusal: the ceiling is what applies
                    // pressure when the archive cannot keep up, and nothing here may cost a record.
                    tracing::warn!(error = %e, "audit archive pass failed; the hot store keeps everything and the ceiling still applies");
                    if let Ok(mut slot) = archive.last_error.lock() {
                        *slot = Some(e.to_string());
                    }
                }
            }
        });
    }

    /// Publish at most one segment and prune it, or explain why it did neither.
    ///
    /// Synchronous and self-contained, so a test can drive it directly rather than through a task.
    pub fn run_pass(&self, store: &dyn Store) -> Result<PassOutcome, GatewayError> {
        let Some(boundary) = store.audit_boundary()? else {
            return Ok(PassOutcome { reason: "this store keeps no audit boundary", ..Default::default() });
        };
        let epoch = boundary.epoch;
        let vk = verifying_key(store)?;
        let opened_by = boundary.lineage.last().filter(|fork| fork.epoch == epoch);
        if let Some(fork) = opened_by {
            if !self.ensure_claimed(fork)? {
                return self.move_past_a_foreign_claim(store, &boundary, fork);
            }
        }

        // Resume before publishing. An index entry whose segment starts exactly where the hot
        // window does is a pass that published and then died before it pruned. It is adopted only
        // after the same proof a fresh publication makes, against what is in the bucket now: the
        // index saying so is a claim, and the rows it would replace are the only other copy.
        let handover = match self.place(epoch, &boundary, opened_by, &vk)? {
            Placement::Append(legacy) => legacy,
            Placement::Resume(entry) => return self.resume(store, epoch, &boundary, &entry, &vk),
        };

        let hot = store.audit_len()?;
        let eligible = hot.saturating_sub(self.keep_hot as u64);
        if eligible == 0 {
            return Ok(PassOutcome { reason: "nothing past the hot-window floor", ..Default::default() });
        }
        let take = (eligible as usize).min(self.batch);
        let events = store.audit_events_from(boundary.base_seq, take)?;
        if events.is_empty() {
            return Ok(PassOutcome { reason: "the hot window is empty", ..Default::default() });
        }

        let base_seq = events[0].seq;
        let end_seq = events[events.len() - 1].seq;
        if base_seq != boundary.base_seq {
            return Err(GatewayError::Internal(format!(
                "the oldest held event is seq {base_seq} and the boundary says the window starts at {}: refusing to archive a window that does not begin where it claims to",
                boundary.base_seq
            )));
        }
        // The segment is verified as a chain before it is published, under the store's own key.
        // Publishing a run that does not verify would put a break in the archive that nothing could
        // repair, because the rows behind it are about to be deleted.
        let signed_from = signed_from(store)?;
        if let Some(bad) = permaura_core::AuditLog::verify_from_rekeyed(&events, &vk, base_seq, &boundary.base_hash, signed_from) {
            return Err(GatewayError::Internal(format!(
                "event {bad} does not verify against the hot window's own base: refusing to archive a run that is already broken"
            )));
        }

        let bytes = to_ndjson(&events)?;
        let sha = sha256_hex(&bytes);
        let id = segment_id(base_seq, end_seq);
        let manifest = store.seal_audit_segment(AuditSegmentDraft {
            tenant: self.tenant.clone(),
            epoch,
            base_seq,
            end_seq,
            count: events.len() as u64,
            prev_hash: boundary.base_hash.clone(),
            head_hash: events[events.len() - 1].hash.clone(),
            sha256: sha.clone(),
            written_at: rfc3339_now(),
            gateway_version: env!("CARGO_PKG_VERSION").to_string(),
        })?;

        // 1 and 2: create-only, so nothing that already exists is ever overwritten.
        //
        // The bytes decide for the segment, because they are deterministic. The manifest is not: it
        // carries `written_at`, so the manifest a resuming pass builds is never byte-identical to
        // the one its predecessor wrote, and comparing bytes would turn every recovery into the
        // "two histories, one name" refusal. Its **signature** is deterministic, and it covers the
        // range, both linkages and the digest, so a matching signature is the stronger claim: it
        // says the object already there describes exactly the run this pass is publishing.
        self.create_only(&self.ndjson_name(epoch, &id), &bytes, &|existing| existing == bytes)?;
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| GatewayError::Internal(format!("segment manifest: {e}")))?;
        self.create_only(&self.manifest_name(epoch, &id), &manifest_bytes, &|existing| {
            serde_json::from_slice::<AuditSegment>(existing)
                .map(|found| found.signature == manifest.signature)
                .unwrap_or(false)
        })?;

        // 3: read back and prove before the index names it. The contract lists the index update
        // first; doing it after is strictly safer, because an index that names a segment whose bytes
        // are wrong is a claim a verifier would trust, and one that does not yet name a good segment
        // is a claim nobody has made.
        let entry = AuditIndexEntry {
            segment_id: id.clone(),
            base_seq,
            end_seq,
            prev_hash: manifest.prev_hash.clone(),
            head_hash: manifest.head_hash.clone(),
            sha256: sha,
        };
        self.prove_segment(epoch, &entry, &boundary.base_hash, &events, &vk, signed_from)?;

        // The hand-over from a whole-epoch index.json: the first page after it is named in it as well, against the
        // generation this pass read. A build before pages, still running in the same rollout, rewrites that file at the
        // generation it read, so whichever of the two writes second meets a conflict, rather than both succeeding and
        // leaving index.json naming a different segment for these seqs than the page does.
        if let Some((legacy, generation)) = handover {
            if let Some(outcome) = self.hand_over(store, epoch, legacy, generation, &entry)? {
                return Ok(outcome);
            }
        }

        // 4: the segment's own index page, create-only; its signature is deterministic, so a page already there with the same one is this pass's own write whose answer was lost.
        let mut page = AuditArchiveIndex::empty(self.tenant.clone(), epoch);
        page.fork = opened_by.cloned();
        page.segments.push(entry);
        let sealed = store.seal_audit_index(page, &rfc3339_now())?;
        let page_bytes = serde_json::to_vec(&sealed)
            .map_err(|e| GatewayError::Internal(format!("archive index page: {e}")))?;
        match self.objects.put_if_generation(&self.page_name(epoch, base_seq), &page_bytes, 0, &BTreeMap::new())? {
            PutOutcome::Stored(_) => {}
            PutOutcome::Conflict | PutOutcome::Uncertain => match self.read_page(epoch, base_seq) {
                Ok(Some(found)) if found.signature == sealed.signature => {}
                Ok(Some(_)) => {
                    return Ok(PassOutcome {
                        segment_id: Some(id),
                        pruned: 0,
                        reason: "another writer published a different segment at this seq; published nothing further and pruned nothing",
                    });
                }
                Ok(None) | Err(_) => {
                    return Ok(PassOutcome {
                        segment_id: Some(id),
                        pruned: 0,
                        reason: "the index page write went unanswered; pruned nothing until the next pass can read it",
                    });
                }
            },
        }

        // Only now.
        let pruned = store.prune_audit_to(end_seq, &manifest.head_hash, &id)?;
        self.segments.fetch_add(1, Ordering::Relaxed);
        self.pruned.fetch_add(pruned, Ordering::Relaxed);
        Ok(PassOutcome { segment_id: Some(id), pruned, reason: "published and pruned" })
    }

    /// Append `entry` to the whole-epoch index an earlier build left, at the `generation` it was read at. `None` when the index now names it; otherwise the outcome of a pass that publishes no page and prunes nothing, and the next pass reads the index again and adopts or appends.
    fn hand_over(
        &self,
        store: &dyn Store,
        epoch: u64,
        mut legacy: AuditArchiveIndex,
        generation: u64,
        entry: &AuditIndexEntry,
    ) -> Result<Option<PassOutcome>, GatewayError> {
        legacy.segments.push(entry.clone());
        let sealed = store.seal_audit_index(legacy, &rfc3339_now())?;
        let bytes = serde_json::to_vec(&sealed).map_err(|e| GatewayError::Internal(format!("archive index: {e}")))?;
        let reason = match self.objects.put_if_generation(&self.index_name(epoch), &bytes, generation, &BTreeMap::new())? {
            PutOutcome::Stored(_) => return Ok(None),
            PutOutcome::Conflict => "another writer moved the whole-epoch index this pass hands over from; published no page and pruned nothing",
            PutOutcome::Uncertain => "the whole-epoch index update went unanswered; published no page and pruned nothing until the next pass can read it",
        };
        match self.read_legacy_index(epoch) {
            Ok(Some(found)) if found.segments.last() == Some(entry) => Ok(None),
            _ => Ok(Some(PassOutcome { segment_id: Some(entry.segment_id.clone()), pruned: 0, reason })),
        }
    }

    /// Adopt a segment the index names at the hot window's base, published by a pass that did not reach its prune, after the same proof a fresh publication makes.
    fn resume(
        &self,
        store: &dyn Store,
        epoch: u64,
        boundary: &AuditBoundary,
        entry: &AuditIndexEntry,
        vk: &ed25519_dalek::VerifyingKey,
    ) -> Result<PassOutcome, GatewayError> {
        let count = segment_len(entry)?;
        let local = store.audit_events_from(entry.base_seq, count)?;
        self.prove_segment(epoch, entry, &boundary.base_hash, &local, vk, signed_from(store)?)?;
        let pruned = store.prune_audit_to(entry.end_seq, &entry.head_hash, &entry.segment_id)?;
        self.pruned.fetch_add(pruned, Ordering::Relaxed);
        Ok(PassOutcome {
            segment_id: Some(entry.segment_id.clone()),
            pruned,
            reason: "adopted a segment published by a pass that did not reach its prune",
        })
    }

    /// Prove that `entry` is durably and exactly the `local` rows it would let a prune delete.
    ///
    /// The one routine a fresh publication and a resumed one both pass before anything is pruned:
    /// the manifest verifies under this store's key and agrees with the index entry field for field,
    /// the bytes read back hash to what it signed, the events inside chain from `prev_hash` under
    /// the same key and end on the head it names, and they are the rows held here, seq for seq and
    /// hash for hash. Missing, unreadable or mismatched archive data is an error and prunes nothing.
    fn prove_segment(
        &self,
        epoch: u64,
        entry: &AuditIndexEntry,
        prev_hash: &str,
        local: &[AuditEvent],
        vk: &ed25519_dalek::VerifyingKey,
        signed_from: u64,
    ) -> Result<(), GatewayError> {
        let id = &entry.segment_id;
        let refuse = |why: &str| {
            GatewayError::Internal(format!(
                "archive segment {id} (epoch {epoch}) {why}: refusing to prune anything against it"
            ))
        };
        if *id != segment_id(entry.base_seq, entry.end_seq) {
            return Err(refuse("is not named for the range the index gives it"));
        }
        if entry.prev_hash != prev_hash {
            return Err(refuse("does not link to the hash the hot window starts from"));
        }
        let (bytes, manifest) = self.read_segment(epoch, id).map_err(|e| refuse(&format!("cannot be read back ({e})")))?;
        let disagrees = manifest.epoch != epoch
            || manifest.segment_id != *id
            || manifest.base_seq != entry.base_seq
            || manifest.end_seq != entry.end_seq
            || manifest.prev_hash != entry.prev_hash
            || manifest.head_hash != entry.head_hash
            || manifest.sha256 != entry.sha256;
        if !manifest.verify(vk) || disagrees {
            return Err(refuse("has a manifest that is not what was signed for it"));
        }
        let stored_sha = sha256_hex(&bytes);
        if stored_sha != manifest.sha256 {
            return Err(refuse(&format!("read back as {stored_sha} and its manifest says {}", manifest.sha256)));
        }
        let events = from_ndjson(&bytes).map_err(|e| refuse(&format!("is not readable as events ({e})")))?;
        let count = segment_len(entry)?;
        if events.len() != count || manifest.count != count as u64 {
            return Err(refuse("does not hold the number of events its range names"));
        }
        if let Some(bad) = permaura_core::AuditLog::verify_from_rekeyed(&events, vk, entry.base_seq, prev_hash, signed_from) {
            return Err(refuse(&format!("holds event {bad}, which does not verify")));
        }
        if events.last().map(|e| e.hash.as_str()) != Some(entry.head_hash.as_str()) {
            return Err(refuse("does not end on the head its index entry names"));
        }
        let same = local.len() == events.len()
            && local.iter().zip(&events).all(|(held, archived)| held.seq == archived.seq && held.hash == archived.hash);
        if !same {
            return Err(refuse("is not the rows this store holds for that range"));
        }
        Ok(())
    }

    /// Refuse an index this pass would otherwise adopt from or append to: one that does not verify
    /// under this store's key, belongs to another epoch or tenant, names a different fork from the
    /// one that opened this epoch, or is not one contiguous run.
    fn check_index(
        &self,
        index: &AuditArchiveIndex,
        epoch: u64,
        opened_by: Option<&AuditFork>,
        vk: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), GatewayError> {
        let refuse = |why: &str| {
            GatewayError::Internal(format!(
                "the archive index for epoch {epoch} {why}: refusing to adopt, append to or prune against it"
            ))
        };
        if !index.verify(vk) {
            return Err(refuse("does not verify under this store's audit key"));
        }
        if index.epoch != epoch || index.tenant != self.tenant {
            return Err(refuse("belongs to another epoch or tenant"));
        }
        if index.fork.as_ref() != opened_by {
            return Err(refuse("names a different restore fork from the one this store's lineage records"));
        }
        let broken = index.segments.windows(2).any(|w| {
            w[1].base_seq != w[0].end_seq + 1 || w[1].prev_hash != w[0].head_hash
        });
        if broken {
            return Err(refuse("is not one contiguous run of segments"));
        }
        Ok(())
    }

    /// Refuse an index page this pass would adopt or append after unless it verifies under this store's key and names exactly this epoch's segment starting at `at`.
    fn check_page(
        &self,
        page: &AuditArchiveIndex,
        epoch: u64,
        at: u64,
        opened_by: Option<&AuditFork>,
        vk: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), GatewayError> {
        let refuse = |why: &str| {
            GatewayError::Internal(format!(
                "the archive index page for seq {at} in epoch {epoch} {why}: refusing to adopt, append to or prune against it"
            ))
        };
        if !page.verify(vk) {
            return Err(refuse("does not verify under this store's audit key"));
        }
        if page.epoch != epoch || page.tenant != self.tenant {
            return Err(refuse("belongs to another epoch or tenant"));
        }
        if page.fork.as_ref() != opened_by {
            return Err(refuse("names a different restore fork from the one this store's lineage records"));
        }
        if page.segments.len() != 1 || page.segments[0].base_seq != at {
            return Err(refuse("does not name exactly the segment that starts there"));
        }
        Ok(())
    }

    /// Whether this pass resumes a published segment or appends a new one, read from at most two pages so a pass costs the same however long the history is.
    fn place(
        &self,
        epoch: u64,
        boundary: &AuditBoundary,
        opened_by: Option<&AuditFork>,
        vk: &ed25519_dalek::VerifyingKey,
    ) -> Result<Placement, GatewayError> {
        let base = boundary.base_seq;
        if let Some(page) = self.read_page(epoch, base)? {
            self.check_page(&page, epoch, base, opened_by, vk)?;
            return Ok(Placement::Resume(page.segments.into_iter().next().expect("checked: exactly one entry")));
        }
        let epoch_starts = opened_by.map(|fork| fork.base_seq).unwrap_or(0);
        // A page at the tail's seq that names another segment is not the one the store pruned to last (a fenced
        // instance's, during a rollout), so the tail is then read from the whole-epoch index, which named that one.
        let tail_page = match boundary.segment_head.as_deref().and_then(segment_range) {
            Some((tail_base, _)) if base != epoch_starts && tail_base >= epoch_starts => self
                .read_page(epoch, tail_base)?
                .filter(|p| p.segments.first().map(|e| e.segment_id.as_str()) == boundary.segment_head.as_deref())
                .map(|p| (tail_base, p)),
            _ => None,
        };
        let mut legacy = None;
        let tail = match tail_page {
            Some((tail_base, page)) => {
                self.check_page(&page, epoch, tail_base, opened_by, vk)?;
                page.segments.into_iter().next()
            }
            // No page before the window: an epoch that has published nothing, or the hand-over from a build that kept one whole-epoch index.
            None => match self.read_legacy_index_at(epoch)? {
                Some((index, generation)) => {
                    self.check_index(&index, epoch, opened_by, vk)?;
                    let last = match index.segments.last() {
                        Some(last) if last.base_seq == base => return Ok(Placement::Resume(last.clone())),
                        last => last.cloned(),
                    };
                    legacy = Some((index, generation));
                    last
                }
                None => None,
            },
        };
        match tail {
            Some(entry) if entry.end_seq >= base => Err(GatewayError::Internal(format!(
                "the archive index for epoch {epoch} ends at seq {} and the hot window starts at {base}, so the two overlap: refusing to publish anything over a history that already disagrees with itself",
                entry.end_seq
            ))),
            Some(entry) if entry.end_seq + 1 != base || entry.head_hash != boundary.base_hash => Err(GatewayError::Internal(format!(
                "the archive index for epoch {epoch} ends at seq {} and the hot window starts at {base}: refusing to publish past events the index does not name",
                entry.end_seq
            ))),
            Some(_) => Ok(Placement::Append(legacy)),
            None if base == epoch_starts => Ok(Placement::Append(legacy)),
            None => Err(GatewayError::Internal(format!(
                "the archive index for epoch {epoch} names nothing and the hot window starts at seq {base}, not at {epoch_starts} where this epoch begins: refusing to publish past events the index does not name"
            ))),
        }
    }

    /// Reserve the next free epoch after `parent`'s for the restore `restore_id`, and return it.
    ///
    /// The number cannot come from the restored database: every restore of one checkpoint reads the
    /// same epoch out of it, so `epoch + 1` would hand two restores one namespace. The bucket is the
    /// authority a restore cannot roll back, and a create-only claim there is the allocation. A
    /// claim already holding this exact fork is this restore retrying, and is adopted; one holding
    /// any other fork is skipped, as is a namespace an older build published into without a claim.
    pub fn claim_epoch(&self, parent: &AuditBoundary, restore_id: &str) -> Result<u64, GatewayError> {
        let first = parent.epoch + 1;
        for epoch in first..first.saturating_add(MAX_EPOCH_PROBES) {
            let claim = EpochClaim {
                tenant: self.tenant.clone(),
                fork: AuditFork {
                    epoch,
                    parent_epoch: parent.epoch,
                    base_seq: parent.base_seq,
                    base_hash: parent.base_hash.clone(),
                    restore_id: restore_id.to_string(),
                },
            };
            let ours = match self.read_claim(epoch)? {
                Some(found) => found == claim,
                None if self.objects.head(&self.index_name(epoch))?.is_some() => false,
                None => self.put_claim(&claim)?,
            };
            if ours {
                return Ok(epoch);
            }
        }
        Err(GatewayError::Internal(format!(
            "no free audit epoch for tenant {} in {MAX_EPOCH_PROBES} after epoch {}",
            self.tenant, parent.epoch
        )))
    }

    /// Whether this store owns the forked epoch it is about to publish into, claiming it if nothing
    /// has. `false` is a claim for any other fork: another restore's namespace, which nothing here
    /// ever publishes into.
    fn ensure_claimed(&self, fork: &AuditFork) -> Result<bool, GatewayError> {
        if self.claimed.lock().map(|c| c.as_ref() == Some(fork)).unwrap_or(false) {
            return Ok(true);
        }
        let claim = EpochClaim { tenant: self.tenant.clone(), fork: fork.clone() };
        let ours = match self.read_claim(fork.epoch)? {
            Some(found) => found == claim,
            None => self.put_claim(&claim)?,
        };
        if ours {
            if let Ok(mut slot) = self.claimed.lock() {
                *slot = Some(fork.clone());
            }
        }
        Ok(ours)
    }

    /// Move a store out of a forked epoch that another restore holds, into a freshly claimed one.
    ///
    /// Reached by a store forked into a number it never claimed: one forked before reconciliation
    /// waited for its claim, or with no archive configured at the time. It is safe only while none of
    /// the store's history has left the hot window in that epoch, and then it is a new fork with the
    /// stranded epoch as its parent at the same base, so the stranded epoch stays in the signed
    /// lineage as an empty stretch and nothing already signed is renamed. The move is recorded in
    /// the chain. Past that point the claim was replaced after this store published under it, which
    /// no writer did, and it is refused for an operator to restore the claim object.
    fn move_past_a_foreign_claim(
        &self,
        store: &dyn Store,
        boundary: &AuditBoundary,
        fork: &AuditFork,
    ) -> Result<PassOutcome, GatewayError> {
        let ours = |object: &AuditArchiveIndex| object.fork.as_ref() == Some(fork);
        let published_here = self.read_legacy_index(fork.epoch)?.is_some_and(|index| ours(&index))
            || self.read_page(fork.epoch, fork.base_seq)?.is_some_and(|page| ours(&page));
        if boundary.base_seq != fork.base_seq || published_here {
            return Err(GatewayError::Internal(format!(
                "audit epoch {} of tenant {} is claimed by a different restore, and this store (restore {}) has already archived under it: the claim object was replaced after publication, so refusing to publish or move until an operator restores {}",
                fork.epoch,
                self.tenant,
                fork.restore_id,
                self.claim_name(fork.epoch)
            )));
        }
        let epoch = self.claim_epoch(boundary, &fork.restore_id)?;
        store.fork_audit_epoch(epoch, &fork.restore_id)?;
        let mut payload = AuditPayload::new(
            EPOCH_MOVED,
            crate::reconcile::RECOVERY_RESOURCE,
            crate::reconcile::RECOVERY_DECISION,
        );
        payload.summary = serde_json::json!({
            "restore_id": fork.restore_id,
            "from_epoch": fork.epoch,
            "to_epoch": epoch,
            "base_seq": boundary.base_seq,
            "reason": "the epoch this restore forked into is claimed by a different restore",
        });
        store.append_audit(payload)?;
        tracing::warn!(from = fork.epoch, to = epoch, restore = %fork.restore_id, "moved this store's audit history out of an epoch another restore holds");
        Ok(PassOutcome { reason: "moved to a newly claimed epoch; nothing published this pass", ..Default::default() })
    }

    fn read_claim(&self, epoch: u64) -> Result<Option<EpochClaim>, GatewayError> {
        let Some(bytes) = self.get_current(&self.claim_name(epoch))? else { return Ok(None) };
        serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            GatewayError::Internal(format!("the epoch claim at {} is not readable: {e}", self.claim_name(epoch)))
        })
    }

    /// Write a claim create-only; `true` when the claim now in the bucket is this one.
    fn put_claim(&self, claim: &EpochClaim) -> Result<bool, GatewayError> {
        let name = self.claim_name(claim.fork.epoch);
        let bytes = serde_json::to_vec(claim)
            .map_err(|e| GatewayError::Internal(format!("epoch claim: {e}")))?;
        match self.objects.put_if_generation(&name, &bytes, 0, &BTreeMap::new())? {
            PutOutcome::Stored(_) => Ok(true),
            PutOutcome::Conflict | PutOutcome::Uncertain => match self.read_claim(claim.fork.epoch)? {
                Some(found) => Ok(found == *claim),
                None => Err(GatewayError::Internal(format!(
                    "{name} refused a create-only write and then read back as absent: refusing to claim the epoch until the store says the same thing twice"
                ))),
            },
        }
    }

    /// An epoch's index as one unsigned list, the entries [`Self::index_objects`] follows.
    pub fn read_index(&self, epoch: u64) -> Result<AuditArchiveIndex, GatewayError> {
        let start = self.read_claim(epoch)?.map(|claim| claim.fork.base_seq).unwrap_or(0);
        let (entries, objects) = self.follow_index(epoch, start)?;
        let mut index = AuditArchiveIndex::empty(self.tenant.clone(), epoch);
        index.fork = objects.iter().find_map(|object| object.fork.clone());
        index.segments = entries;
        Ok(index)
    }

    /// Every signed object of one epoch's index the history from `start` is read through, in order and unchecked: the whole-epoch index an older build left, when any segment followed is its, then each page followed.
    pub fn index_objects(&self, epoch: u64, start: u64) -> Result<Vec<AuditArchiveIndex>, GatewayError> {
        Ok(self.follow_index(epoch, start)?.1)
    }

    /// One epoch's index from `start` as a walk follows it: at each seq the page there or the whole-epoch index's entry, the page unless only the other has a segment named after it (as [`ArchivedEvents`] chooses during a rollout that ran both builds), until neither names one. The entries in order, and the objects they came from.
    fn follow_index(&self, epoch: u64, start: u64) -> Result<(Vec<AuditIndexEntry>, Vec<AuditArchiveIndex>), GatewayError> {
        let legacy = self.read_legacy_index(epoch)?;
        let named: BTreeMap<u64, AuditIndexEntry> =
            legacy.iter().flat_map(|index| index.segments.iter()).map(|e| (e.base_seq, e.clone())).collect();
        let continues = |entry: &AuditIndexEntry| -> Result<bool, GatewayError> {
            let next = entry.end_seq + 1;
            Ok(named.contains_key(&next) || self.read_page(epoch, next)?.is_some())
        };
        let mut entries = Vec::new();
        let mut pages = Vec::new();
        let mut used_legacy = false;
        let mut at = start;
        loop {
            let page = self.read_page(epoch, at)?.filter(|p| matches!(p.segments.as_slice(), [e] if e.base_seq == at && e.end_seq >= at));
            let old = named.get(&at).filter(|e| e.end_seq >= at);
            let take_page = match (&page, old) {
                (Some(p), Some(l)) if p.segments[0] != *l => continues(&p.segments[0])? || !continues(l)?,
                (Some(_), _) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            let entry = match (page, old) {
                (Some(p), _) if take_page => {
                    let entry = p.segments[0].clone();
                    pages.push(p);
                    entry
                }
                (_, Some(l)) => {
                    used_legacy = true;
                    l.clone()
                }
                _ => break,
            };
            at = entry.end_seq + 1;
            entries.push(entry);
        }
        let mut objects: Vec<AuditArchiveIndex> = legacy.filter(|_| used_legacy).into_iter().collect();
        objects.extend(pages);
        Ok((entries, objects))
    }

    fn read_legacy_index(&self, epoch: u64) -> Result<Option<AuditArchiveIndex>, GatewayError> {
        Ok(self.read_legacy_index_at(epoch)?.map(|(index, _)| index))
    }

    /// [`Self::read_legacy_index`], with the generation it was read at, which the hand-over to pages writes against.
    fn read_legacy_index_at(&self, epoch: u64) -> Result<Option<(AuditArchiveIndex, u64)>, GatewayError> {
        let name = self.index_name(epoch);
        let Some((bytes, generation)) = self.get_current_at(&name)? else { return Ok(None) };
        serde_json::from_slice(&bytes)
            .map(|index| Some((index, generation)))
            .map_err(|e| GatewayError::Internal(format!("the archive index at {name} is not readable: {e}")))
    }

    /// The index page naming the segment that starts at `at`, or `None` when no segment published starts there.
    fn read_page(&self, epoch: u64, at: u64) -> Result<Option<AuditArchiveIndex>, GatewayError> {
        let name = self.page_name(epoch, at);
        let Some(bytes) = self.get_current(&name)? else { return Ok(None) };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| GatewayError::Internal(format!("the archive index page at {name} is not readable: {e}")))
    }

    /// Fetch one segment's bytes and its manifest.
    pub fn read_segment(
        &self,
        epoch: u64,
        id: &str,
    ) -> Result<(Vec<u8>, AuditSegment), GatewayError> {
        let missing = |what: &str| {
            GatewayError::NotFound(format!("the {what} for archive segment {id} (epoch {epoch})"))
        };
        let bytes = self.get_current(&self.ndjson_name(epoch, id))?.ok_or_else(|| missing("bytes"))?;
        let manifest_bytes =
            self.get_current(&self.manifest_name(epoch, id))?.ok_or_else(|| missing("manifest"))?;
        let manifest: AuditSegment = serde_json::from_slice(&manifest_bytes).map_err(|e| {
            GatewayError::Internal(format!("the manifest for segment {id} is not readable: {e}"))
        })?;
        Ok((bytes, manifest))
    }

    /// The current bytes of an object, or `None` when it does not exist.
    ///
    /// Two calls rather than one, because [`ObjectStore::get`] fetches an exact generation so that
    /// metadata read earlier and bytes read now cannot disagree. This build rewrites nothing but the
    /// whole-epoch index, once, at the hand-over to pages, and an older writer may still be rewriting that
    /// index during a rollout, so it can move between the two: a generation that moved is read again
    /// rather than reported unreadable.
    fn get_current(&self, name: &str) -> Result<Option<Vec<u8>>, GatewayError> {
        Ok(self.get_current_at(name)?.map(|(bytes, _)| bytes))
    }

    /// [`Self::get_current`], with the generation the bytes were read at.
    fn get_current_at(&self, name: &str) -> Result<Option<(Vec<u8>, u64)>, GatewayError> {
        let mut attempts = 0;
        loop {
            let Some(generation) = self.objects.head(name)? else { return Ok(None) };
            match self.objects.get(name, generation) {
                Ok(bytes) => return Ok(Some((bytes, generation))),
                Err(e) => {
                    attempts += 1;
                    if attempts >= 3 || self.objects.head(name)? == Some(generation) {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Write `bytes` at `name` only if nothing is there, and accept an existing object **only** when
    /// `same` says it is the one this pass would have written.
    ///
    /// This is what makes a crashed pass safe to repeat. A segment is meant to be immutable: in a bucket the
    /// runtime should be granted create and never delete or overwrite, and a local archive has only this
    /// process writing there by convention, so the only expected way this meets an object is a pass of its
    /// own that got this far, and the only safe reading of an object under the same name that is not the
    /// one being published is that something is wrong.
    fn create_only(
        &self,
        name: &str,
        bytes: &[u8],
        same: &dyn Fn(&[u8]) -> bool,
    ) -> Result<(), GatewayError> {
        match self.objects.put_if_generation(name, bytes, 0, &BTreeMap::new())? {
            PutOutcome::Stored(_) => Ok(()),
            PutOutcome::Conflict | PutOutcome::Uncertain => {
                let existing = self.get_current(name)?.ok_or_else(|| {
                    GatewayError::Internal(format!(
                        "{name} refused a create-only write and then read back as absent: refusing to publish or prune until the store says the same thing twice"
                    ))
                })?;
                if same(&existing) {
                    return Ok(());
                }
                Err(GatewayError::Internal(format!(
                    "{name} already holds {} bytes that are not the {} this pass built: refusing to publish or prune, because two different histories cannot share one segment name",
                    existing.len(),
                    bytes.len()
                )))
            }
        }
    }
}

/// Serialise events as newline-delimited JSON: one event per line, ascending seq, no trailing blank
/// line, UTF-8, no compression at this layer.
pub fn to_ndjson(events: &[AuditEvent]) -> Result<Vec<u8>, GatewayError> {
    let mut out = Vec::new();
    for (idx, event) in events.iter().enumerate() {
        if idx > 0 {
            out.push(b'\n');
        }
        serde_json::to_writer(&mut out, event)
            .map_err(|e| GatewayError::Internal(format!("segment serialisation: {e}")))?;
    }
    Ok(out)
}

/// Read a segment's NDJSON back into events.
pub fn from_ndjson(bytes: &[u8]) -> Result<Vec<AuditEvent>, GatewayError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| GatewayError::Internal(format!("segment is not UTF-8: {e}")))?;
    let mut events = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        events.push(serde_json::from_str::<AuditEvent>(line).map_err(|e| {
            GatewayError::Internal(format!("segment line {} is not an audit event: {e}", n + 1))
        })?);
    }
    Ok(events)
}

fn verifying_key(store: &dyn Store) -> Result<ed25519_dalek::VerifyingKey, GatewayError> {
    permaura_relay::strict_verifying_key(&store.audit_verifying_key()?)
        .map_err(|e| GatewayError::Internal(format!("audit verifying key: {e}")))
}

/// The seq from which an event must carry the store's own signature: zero, unless a recorded rekey says every event below it was signed under a key the store no longer holds.
fn signed_from(store: &dyn Store) -> Result<u64, GatewayError> {
    Ok(store.audit_rekey()?.map_or(0, |rekey| rekey.seq))
}

fn unreadable_page(span: &Span, at: u64, e: GatewayError) -> HistoryBreak {
    HistoryBreak::new(
        at,
        break_kind::UNREADABLE,
        format!("the archive index page for seq {at} in epoch {} could not be read: {e}", span.epoch),
    )
}

/// What a pass does with the hot window's oldest run.
enum Placement {
    /// The index already names a segment starting at the window's base: prove it and prune to it.
    Resume(AuditIndexEntry),
    /// Nothing names it yet, and the index ends exactly where the window starts: publish it. When the index before it
    /// is the whole-epoch `index.json` an earlier build wrote (and read at this generation), the hand-over to pages.
    Append(Option<(AuditArchiveIndex, u64)>),
}

/// The `(base_seq, end_seq)` a segment id names, from [`segment_id`]'s own format.
fn segment_range(id: &str) -> Option<(u64, u64)> {
    let (base, end) = id.strip_prefix("seg-")?.split_once('-')?;
    Some((base.parse().ok()?, end.parse().ok()?))
}

/// How many events an index entry's range holds.
fn segment_len(entry: &AuditIndexEntry) -> Result<usize, GatewayError> {
    entry
        .end_seq
        .checked_sub(entry.base_seq)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| {
            GatewayError::Internal(format!("archive segment {} does not name a usable range", entry.segment_id))
        })
}

/// RFC 3339, UTC, seconds. Descriptive only: nothing verifies against it.
fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

// ── verification and export across the boundary ─────────────────────────────────────────────────

/// Why a cross-boundary verification failed, as a stable label rather than as prose.
///
/// Four of these are the four ways an archive can be wrong, and they are deliberately distinct: an
/// operator meeting "a segment is missing" is looking for a lifecycle rule or a failed publish,
/// while one meeting "a segment was tampered with" is looking at an incident.
pub mod break_kind {
    /// The index names no segment where one has to be, or names one that starts past where the last
    /// one ended.
    pub const MISSING_SEGMENT: &str = "missing_segment";
    /// A segment is present but does not sit where the chain says it does.
    pub const REORDERED_SEGMENT: &str = "reordered_segment";
    /// A segment's bytes, manifest or events do not match what was signed.
    pub const TAMPERED_SEGMENT: &str = "tampered_segment";
    /// The hot store's boundary does not continue from the last segment's tail.
    pub const BOUNDARY_MISMATCH: &str = "boundary_mismatch";
    /// The hot window itself is broken.
    pub const HOT_WINDOW: &str = "hot_window";
    /// The store's restore lineage, or an index's record of the fork that opened its epoch, does not
    /// describe one history: an index from another restore, or a lineage that does not join up.
    pub const LINEAGE_MISMATCH: &str = "lineage_mismatch";
    /// The archive could not be read at all, so nothing is claimed either way.
    pub const UNREADABLE: &str = "unreadable";
    /// The store moved under the walk in a way it could not follow (a restore into another epoch while it ran), so
    /// nothing is claimed either way. Never served in a report: [`super::AuditArchive::verify_full`] walks again, and
    /// answers an error rather than a report when the store keeps moving.
    pub const WINDOW_MOVED: &str = "window_moved";
}

/// What a full walk of archive plus hot window found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// Whether one continuous signed chain was proved from seq 0 to the head.
    pub chain_intact: bool,
    /// The first absolute seq at which the chain breaks, when it does.
    pub first_break: Option<u64>,
    /// Which of the four failures this is, from [`break_kind`].
    pub break_kind: Option<&'static str>,
    /// What went wrong, for a human.
    pub detail: Option<String>,
    /// The first absolute seq the walk covered.
    pub verified_from: u64,
    /// The last absolute seq the walk covered, or `None` for an empty chain.
    pub verified_to: Option<u64>,
    /// How many archive segments were read and checked.
    pub segments: u64,
    /// How many epochs had an index.
    pub epochs: u64,
    /// The epochs the selected history runs through, root first. One for a store never restored.
    pub lineage: Vec<u64>,
    /// Segments an ancestor epoch published past the point this history left it: the abandoned
    /// suffix of an earlier generation, kept as evidence and deliberately not walked.
    pub abandoned: u64,
    /// Segments this epoch's index names at or past the hot window's base: published by a pass that
    /// has not yet pruned, and still covered by the hot window.
    pub pending: u64,
    /// The key every signature in the walk was checked under, which is the store's own. Reported so a
    /// caller holding a pin can tell "verifies" from "verifies under the key this chain began with".
    pub audit_key: [u8; 32],
}

impl VerificationReport {
    fn broken(walk: &ArchivedEvents<'_>, seq: u64, kind: &'static str, detail: impl Into<String>) -> Self {
        VerificationReport {
            chain_intact: false,
            first_break: Some(seq),
            break_kind: Some(kind),
            detail: Some(detail.into()),
            verified_from: 0,
            verified_to: None,
            segments: walk.segments,
            epochs: walk.epochs,
            lineage: walk.lineage.clone(),
            abandoned: walk.abandoned,
            pending: walk.pending,
            audit_key: walk.vk.to_bytes(),
        }
    }

    /// The report as `/v1/audit/verify-full` serves it.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "chain_intact": self.chain_intact,
            "first_break": self.first_break,
            "break_kind": self.break_kind,
            "detail": self.detail,
            "verified_from": self.verified_from,
            "verified_to": self.verified_to,
            "segments": self.segments,
            "epochs": self.epochs,
            "lineage": self.lineage,
            "abandoned": self.abandoned,
            "pending": self.pending,
            "archive_checked": true,
            "audit_key": crate::audit_key::report(&self.audit_key),
        })
    }
}

impl AuditArchive {
    /// Every signed index object of every epoch the selected history runs through, root first, for the
    /// export footer. Abandoned branches are not the history being exported.
    pub fn lineage_indexes(&self, boundary: &AuditBoundary) -> Result<Vec<AuditArchiveIndex>, GatewayError> {
        let spans = lineage_spans(boundary).map_err(|b| GatewayError::Internal(b.detail))?;
        let mut out = Vec::new();
        for span in spans {
            let objects = self.index_objects(span.epoch, span.from)?;
            out.extend(objects.into_iter().filter(|object| !object.segments.is_empty() && object.fork == span.opened_by));
        }
        Ok(out)
    }

    /// Walk the archive and then the hot window, and prove one continuous signed chain.
    ///
    /// Allowed to be slow: it fetches and hashes every segment. What it is not allowed to be is
    /// vague, which is why it reports the first break with its absolute seq and a stable kind rather
    /// than a bare false.
    ///
    /// The archive half is [`ArchivedEvents`], the same reader export and rebuild use, so what this
    /// proves is exactly what they read. Bounded memory throughout: one segment at a time, and the
    /// hot window in batches.
    ///
    /// A store that moves into another epoch while the walk runs (a pass moving it out of an epoch another restore
    /// claimed, then pruning) is walked again from its new boundary, since a broken report would claim something about
    /// a history nobody tampered with; one that is still moving after [`VERIFY_ATTEMPTS`] walks is a `Conflict`, which
    /// claims nothing either way.
    pub fn verify_full(&self, store: &dyn Store) -> Result<VerificationReport, GatewayError> {
        let mut moved = String::new();
        for _ in 0..VERIFY_ATTEMPTS {
            match self.verify_once(store)? {
                Ok(report) => return Ok(report),
                Err(window) => moved = window.detail,
            }
        }
        Err(GatewayError::Conflict(format!(
            "the audit history moved under {VERIFY_ATTEMPTS} full verifications in a row ({moved}): nothing is claimed either way; run the verification again"
        )))
    }

    /// One walk of [`Self::verify_full`]: the report, or the break that says the store moved under it.
    fn verify_once(&self, store: &dyn Store) -> Result<Result<VerificationReport, HistoryBreak>, GatewayError> {
        let mut walk = ArchivedEvents::new(self, store)?;
        for event in walk.by_ref() {
            if event.is_err() {
                break;
            }
        }
        if let Some(b) = walk.broken.clone() {
            return Ok(Ok(VerificationReport::broken(&walk, b.seq, b.kind, b.detail)));
        }
        let vk = walk.vk;
        let boundary = walk.boundary.clone();

        // The hot window, in batches, so a quarter of a million events is still one batch resident.
        let mut expected_hash = boundary.base_hash.clone();
        let mut cursor = boundary.base_seq;
        let mut last = boundary.base_seq.checked_sub(1);
        loop {
            let events = store.audit_events_from(cursor, self.batch)?;
            let moved = events.first().is_some_and(|e| e.seq != cursor);
            if events.is_empty() || moved {
                // An archive pass may have pruned the window on while the archive was being walked. What it pruned it
                // published and proved first, so the events between the walk's base and the new one are in the index
                // now: prove them there and carry on from the new base, rather than reading the window from the old
                // base and reporting the chain broken at the new one.
                let current = store.audit_boundary()?.ok_or_else(|| {
                    GatewayError::Internal("this store keeps no audit boundary, so there is no archived history to read".into())
                })?;
                if current.base_seq > cursor {
                    match walk.follow_prune(&current) {
                        Ok(()) => {}
                        Err(b) if b.kind == break_kind::WINDOW_MOVED => return Ok(Err(b)),
                        Err(b) => return Ok(Ok(VerificationReport::broken(&walk, b.seq, b.kind, b.detail))),
                    }
                    expected_hash = current.base_hash.clone();
                    last = current.base_seq.checked_sub(1);
                    cursor = current.base_seq;
                    continue;
                }
                if events.is_empty() {
                    break;
                }
            }
            if let Some(bad) = permaura_core::AuditLog::verify_from_rekeyed(&events, &vk, cursor, &expected_hash, walk.signed_from) {
                return Ok(Ok(VerificationReport::broken(
                    &walk,
                    bad,
                    break_kind::HOT_WINDOW,
                    format!("event {bad} in the hot window does not verify"),
                )));
            }
            let tail = &events[events.len() - 1];
            expected_hash = tail.hash.clone();
            last = Some(tail.seq);
            cursor = tail.seq + 1;
        }

        Ok(Ok(VerificationReport {
            chain_intact: true,
            first_break: None,
            break_kind: None,
            detail: None,
            verified_from: 0,
            verified_to: last,
            segments: walk.segments,
            epochs: walk.epochs,
            lineage: walk.lineage.clone(),
            abandoned: walk.abandoned,
            pending: walk.pending,
            audit_key: vk.to_bytes(),
        }))
    }
}

/// How many walks [`AuditArchive::verify_full`] makes of a store that keeps moving into another epoch before it answers that it could not tell.
pub const VERIFY_ATTEMPTS: usize = 3;

/// Where a walk of the archive stopped proving anything, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryBreak {
    /// The first absolute seq the walk could not prove.
    pub seq: u64,
    /// Which failure this is, from [`break_kind`].
    pub kind: &'static str,
    /// What went wrong, for a human.
    pub detail: String,
}

impl HistoryBreak {
    fn new(seq: u64, kind: &'static str, detail: impl Into<String>) -> Self {
        HistoryBreak { seq, kind, detail: detail.into() }
    }
}

/// One stretch of the selected history: seqs `from..to` as published in `epoch`, ending on
/// `end_hash`, which is where the next fork (or the hot window) continues from.
#[derive(Debug, Clone)]
struct Span {
    epoch: u64,
    from: u64,
    to: u64,
    end_hash: String,
    opened_by: Option<AuditFork>,
    last: bool,
}

/// The stretches of which epoch make up the history `boundary` describes, root first.
fn lineage_spans(boundary: &AuditBoundary) -> Result<Vec<Span>, HistoryBreak> {
    let refuse = |seq: u64, why: String| HistoryBreak::new(seq, break_kind::LINEAGE_MISMATCH, why);
    let mut epoch = boundary.lineage.first().map(|f| f.parent_epoch).unwrap_or(boundary.epoch);
    let mut from = 0u64;
    let mut opened_by: Option<AuditFork> = None;
    let mut seen = std::collections::BTreeSet::from([epoch]);
    let mut spans = Vec::new();
    for fork in &boundary.lineage {
        if fork.parent_epoch != epoch || fork.base_seq < from || !seen.insert(fork.epoch) {
            return Err(refuse(
                from,
                format!(
                    "the store's lineage forks epoch {} from epoch {} at seq {}, which does not continue the history before it (epoch {epoch} from seq {from})",
                    fork.epoch, fork.parent_epoch, fork.base_seq
                ),
            ));
        }
        spans.push(Span {
            epoch,
            from,
            to: fork.base_seq,
            end_hash: fork.base_hash.clone(),
            opened_by: opened_by.take(),
            last: false,
        });
        epoch = fork.epoch;
        from = fork.base_seq;
        opened_by = Some(fork.clone());
    }
    if epoch != boundary.epoch || boundary.base_seq < from {
        return Err(refuse(
            from,
            format!(
                "the store's lineage ends in epoch {epoch} at seq {from} and its boundary is epoch {} at seq {}",
                boundary.epoch, boundary.base_seq
            ),
        ));
    }
    spans.push(Span {
        epoch,
        from,
        to: boundary.base_seq,
        end_hash: boundary.base_hash.clone(),
        opened_by,
        last: true,
    });
    Ok(spans)
}

/// Every archived event of the store's selected history, proved as it is read, in chain order.
///
/// **The one reader of archived history.** Verification, export and budget rebuild all walk through
/// this, so none of them can accept a history another would refuse. It follows the store's restore
/// lineage rather than every epoch in numeric order, checks each epoch's index signature before
/// trusting anything it names, checks every segment's manifest, digest and events under the store's
/// audit key, and proves that the segments cover seq 0 up to the signed boundary with no hole and no
/// overlap. The walk yields an error, and ends, at the first thing it cannot prove, **including a
/// history that simply stops short**: an iterator that ran out early would read to a caller as a
/// complete one.
///
/// An iterator rather than a `Vec`, because the whole point of the archive is that the events below
/// the base no longer fit anywhere: one segment is resident at a time.
pub struct ArchivedEvents<'a> {
    archive: &'a AuditArchive,
    vk: ed25519_dalek::VerifyingKey,
    /// Events below this seq were signed under a key the store no longer holds ([`signed_from`]).
    signed_from: u64,
    boundary: AuditBoundary,
    spans: std::vec::IntoIter<Span>,
    span: Option<Span>,
    /// The open span's entries from a whole-epoch index a build before pages left, not yet walked or passed over.
    entries: std::collections::VecDeque<AuditIndexEntry>,
    /// Whether the open span reads index pages, and the seq the whole-epoch index stops naming segments at.
    pages_from: Option<u64>,
    /// Whether the open span's epoch has been counted in `epochs`.
    span_counted: bool,
    current: std::vec::IntoIter<AuditEvent>,
    expected_seq: u64,
    expected_hash: String,
    segments: u64,
    epochs: u64,
    lineage: Vec<u64>,
    abandoned: u64,
    pending: u64,
    broken: Option<HistoryBreak>,
    done: bool,
}

impl<'a> ArchivedEvents<'a> {
    /// Walk the archived history of the boundary `store` is running under, checked against its key.
    pub fn new(archive: &'a AuditArchive, store: &dyn Store) -> Result<Self, GatewayError> {
        let boundary = store.audit_boundary()?.ok_or_else(|| {
            GatewayError::Internal(
                "this store keeps no audit boundary, so there is no archived history to read".into(),
            )
        })?;
        let mut walk = Self::for_boundary(archive, boundary, verifying_key(store)?);
        walk.signed_from = signed_from(store)?;
        Ok(walk)
    }

    /// The same, for a boundary already read, so a caller that goes on to read the hot window
    /// starts it exactly where this walk ends.
    pub fn for_boundary(
        archive: &'a AuditArchive,
        boundary: AuditBoundary,
        vk: ed25519_dalek::VerifyingKey,
    ) -> Self {
        let (spans, broken) = match lineage_spans(&boundary) {
            Ok(spans) => (spans, None),
            Err(b) => (Vec::new(), Some(b)),
        };
        ArchivedEvents {
            archive,
            vk,
            signed_from: 0,
            boundary,
            spans: spans.into_iter(),
            span: None,
            entries: std::collections::VecDeque::new(),
            pages_from: None,
            span_counted: false,
            current: Vec::new().into_iter(),
            expected_seq: 0,
            expected_hash: permaura_core::GENESIS_PREV_HASH.to_string(),
            segments: 0,
            epochs: 0,
            lineage: Vec::new(),
            abandoned: 0,
            pending: 0,
            broken,
            done: false,
        }
    }

    /// The boundary this walk proves coverage up to.
    pub fn boundary(&self) -> &AuditBoundary {
        &self.boundary
    }

    /// Extend a finished walk up to `current`, a boundary an archive pass moved on while the walk ran.
    ///
    /// The pass published and proved the segments it pruned before it pruned them, so they are in this epoch's
    /// index now; this proves them under the same checks a first reading of the index gets and continues the chain
    /// from where the walk left it. Only a prune can be followed: a restore mid-walk changes the epoch or the lineage,
    /// and that is reported as [`break_kind::WINDOW_MOVED`], which claims nothing either way.
    pub fn follow_prune(&mut self, current: &AuditBoundary) -> Result<(), HistoryBreak> {
        let from = self.expected_seq;
        if !self.done || self.broken.is_some() {
            return Err(HistoryBreak::new(from, break_kind::WINDOW_MOVED, "the archive walk did not finish, so the moved window cannot be followed; run the verification again"));
        }
        if current.epoch != self.boundary.epoch || current.lineage != self.boundary.lineage {
            return Err(HistoryBreak::new(
                from,
                break_kind::WINDOW_MOVED,
                format!(
                    "the store was restored into epoch {} while the walk ran in epoch {}: nothing is claimed either way; run the verification again",
                    current.epoch, self.boundary.epoch
                ),
            ));
        }
        if current.base_seq < from {
            return Err(HistoryBreak::new(
                current.base_seq,
                break_kind::BOUNDARY_MISMATCH,
                format!("the hot store's boundary moved back to seq {} from {from}, which no archive pass does", current.base_seq),
            ));
        }
        let span = Span {
            epoch: current.epoch,
            from,
            to: current.base_seq,
            end_hash: current.base_hash.clone(),
            opened_by: current.lineage.last().filter(|fork| fork.epoch == current.epoch).cloned(),
            last: true,
        };
        // The whole-epoch index as well as the pages: the pass that pruned may have adopted a segment only it names.
        let legacy = self.archive.read_legacy_index(span.epoch).map_err(|e| {
            HistoryBreak::new(from, break_kind::UNREADABLE, format!("the archive index for epoch {} could not be read: {e}", span.epoch))
        })?;
        self.entries.clear();
        if let Some(index) = legacy.filter(|index| index.segments.iter().any(|e| e.base_seq >= from && e.base_seq < span.to)) {
            if !index.verify(&self.vk) || index.epoch != span.epoch {
                return Err(HistoryBreak::new(
                    from,
                    break_kind::TAMPERED_SEGMENT,
                    format!("the archive index for epoch {} does not verify under this chain's audit key", span.epoch),
                ));
            }
            if index.fork != span.opened_by {
                return Err(HistoryBreak::new(
                    from,
                    break_kind::LINEAGE_MISMATCH,
                    format!("the archive index for epoch {} records a different restore fork from the one this store's lineage names", span.epoch),
                ));
            }
            self.entries = index.segments.into_iter().filter(|e| e.base_seq >= from && e.base_seq < span.to).collect();
        }
        self.pages_from = Some(from);
        let mut followed = 0;
        while self.expected_seq < span.to {
            let at = self.expected_seq;
            let entry = self.next_entry(&span)?.ok_or_else(|| {
                HistoryBreak::new(at, break_kind::MISSING_SEGMENT, format!("nothing in the archive covers seq {at}, which a pass pruned while the walk ran"))
            })?;
            self.open_segment(&span, &entry)?;
            followed += 1;
        }
        self.pending = self.pending.saturating_sub(followed);
        self.close_span(&span)?;
        self.boundary = current.clone();
        Ok(())
    }

    /// Where the walk stopped proving anything, once it has.
    pub fn broken(&self) -> Option<&HistoryBreak> {
        self.broken.as_ref()
    }

    fn fail(&mut self, b: HistoryBreak) -> Option<Result<AuditEvent, GatewayError>> {
        let err = GatewayError::Internal(format!("archived audit history, seq {}: {} ({})", b.seq, b.detail, b.kind));
        self.broken = Some(b);
        self.done = true;
        Some(Err(err))
    }

    /// Read and check the whole-epoch index an older build may have left, queue its entries inside `span`, and set the walk to read pages from where it ends.
    fn open_span(&mut self, span: &Span) -> Result<(), HistoryBreak> {
        self.lineage.push(span.epoch);
        self.entries.clear();
        self.pages_from = None;
        self.span_counted = false;
        let legacy = match self.archive.read_legacy_index(span.epoch) {
            Ok(found) => found.filter(|index| !index.segments.is_empty()),
            // An empty stretch needs nothing from its index, so an unreadable one proves nothing
            // missing.
            Err(_) if span.from == span.to => return Ok(()),
            Err(e) => {
                return Err(HistoryBreak::new(
                    span.from,
                    break_kind::UNREADABLE,
                    format!("the archive index for epoch {} could not be read: {e}", span.epoch),
                ))
            }
        };
        let first_page = legacy.as_ref().and_then(|index| index.segments.last()).map_or(span.from, |e| e.end_seq + 1);
        if span.from == span.to {
            // Nothing of this history lives in an empty stretch, so its index is counted when it is
            // this lineage's and otherwise left alone: an epoch a restore moved out of because
            // another restore holds it keeps that other restore's index.
            let mut counted = false;
            let mut beyond = 0;
            if let Some(index) = &legacy {
                if index.verify(&self.vk) && index.epoch == span.epoch && index.fork == span.opened_by {
                    counted = true;
                    beyond += index.segments.iter().filter(|e| e.base_seq >= span.to).count() as u64;
                }
            }
            let pages = self.count_pages(span, first_page.max(span.to));
            if counted || pages > 0 {
                self.epochs += 1;
                self.span_counted = true;
            }
            self.add_beyond(span, beyond + pages);
            return Ok(());
        }
        self.pages_from = Some(first_page);
        let Some(index) = legacy else { return Ok(()) };
        self.epochs += 1;
        self.span_counted = true;
        // The index is checked before anything it names, because it is the only statement that a
        // segment *should* be there: an unsigned index cannot make a missing segment detectable.
        if !index.verify(&self.vk) || index.epoch != span.epoch {
            return Err(HistoryBreak::new(
                span.from,
                break_kind::TAMPERED_SEGMENT,
                format!("the archive index for epoch {} does not verify under this chain's audit key", span.epoch),
            ));
        }
        if index.fork != span.opened_by {
            return Err(HistoryBreak::new(
                span.from,
                break_kind::LINEAGE_MISMATCH,
                format!(
                    "the archive index for epoch {} records a different restore fork from the one this store's lineage names",
                    span.epoch
                ),
            ));
        }
        // Ordering is checked over the whole list before any entry is walked, because the two
        // failures look alike one entry at a time: a segment out of place presents as a gap at the
        // position it left, and an operator told "something is missing" would go looking for a
        // lifecycle rule rather than at the list in front of them.
        if let Some(pair) = index.segments.windows(2).find(|w| w[1].base_seq <= w[0].base_seq) {
            return Err(HistoryBreak::new(
                pair[1].base_seq,
                break_kind::REORDERED_SEGMENT,
                format!(
                    "the index for epoch {} lists segment {} after {}, which does not ascend",
                    span.epoch, pair[1].segment_id, pair[0].segment_id
                ),
            ));
        }
        let (selected, beyond): (Vec<_>, Vec<_>) = index.segments.into_iter().partition(|e| e.base_seq < span.to);
        self.add_beyond(span, beyond.len() as u64);
        self.entries = selected.into();
        Ok(())
    }

    /// The next entry the open span needs: the page for the seq the walk has reached or the whole-epoch index's entry for it, and when both name a segment there and disagree, [`Self::continues`] decides; `None` when the span is covered or nothing names the next segment, which [`Self::close_span`] judges.
    ///
    /// Both can name one during a rollout: a build before pages, still running beside this one, appends its own segment for seqs a page already covers to `index.json`, or the reverse. Neither is evidence against the chain, both being signed under its key, and the one the history continues from is the one the store's boundary was moved along. An entry of the whole-epoch index that is not where the walk is goes to [`Self::open_segment`], which says whether it is a gap or an overlap.
    fn next_entry(&mut self, span: &Span) -> Result<Option<AuditIndexEntry>, HistoryBreak> {
        let at = self.expected_seq;
        let behind = self.entries.front().is_some_and(|e| e.base_seq < at);
        if self.pages_from.is_none() || at >= span.to || behind {
            return Ok(self.entries.pop_front());
        }
        let page = match self.archive.read_page(span.epoch, at).map_err(|e| unreadable_page(span, at, e))? {
            Some(page) => Some(self.checked_page(span, at, page)?),
            None => None,
        };
        let legacy = self.entries.front().filter(|e| e.base_seq == at).cloned();
        let chosen = match (page, legacy) {
            (Some(page), Some(legacy)) if page != legacy && !self.continues(span, &page) && self.continues(span, &legacy) => {
                self.entries.pop_front();
                legacy
            }
            (Some(page), _) => {
                while self.entries.front().is_some_and(|e| e.base_seq <= page.end_seq) {
                    self.entries.pop_front();
                }
                page
            }
            (None, Some(_)) => self.entries.pop_front().expect("peeked"),
            (None, None) if !self.entries.is_empty() => return Ok(self.entries.pop_front()),
            (None, None) => {
                if span.last && self.pages_resume_past(span, at) {
                    return Err(HistoryBreak::new(
                        at,
                        break_kind::MISSING_SEGMENT,
                        format!("nothing in the archive covers seq {at}: the index has no page for it and has pages after it"),
                    ));
                }
                return Ok(None);
            }
        };
        if !self.span_counted {
            self.epochs += 1;
            self.span_counted = true;
        }
        Ok(Some(chosen))
    }

    /// Whether the history goes on from `entry` inside `span`: it ends where the span does, or a page or a whole-epoch index entry names the segment after it.
    fn continues(&self, span: &Span, entry: &AuditIndexEntry) -> bool {
        let next = entry.end_seq + 1;
        entry.end_seq < span.to
            && (next == span.to
                || self.entries.iter().any(|e| e.base_seq == next)
                || matches!(self.archive.read_page(span.epoch, next), Ok(Some(_))))
    }

    /// Whether the page of the newest segment the store pruned is there past `at`, making a missing page at `at` a hole in the index rather than an index that ends early.
    fn pages_resume_past(&self, span: &Span, at: u64) -> bool {
        let Some((head_base, _)) = self.boundary.segment_head.as_deref().and_then(segment_range) else { return false };
        head_base > at && head_base < span.to && matches!(self.archive.read_page(span.epoch, head_base), Ok(Some(_)))
    }

    /// The entry of the page the walk reached at `at`, once it verifies under this chain's key and names the span's epoch, fork and the segment starting there.
    fn checked_page(&self, span: &Span, at: u64, page: AuditArchiveIndex) -> Result<AuditIndexEntry, HistoryBreak> {
        if !page.verify(&self.vk) || page.epoch != span.epoch || page.segments.len() != 1 {
            return Err(HistoryBreak::new(
                at,
                break_kind::TAMPERED_SEGMENT,
                format!("the archive index page for seq {at} in epoch {} does not verify under this chain's audit key", span.epoch),
            ));
        }
        if page.fork != span.opened_by {
            return Err(HistoryBreak::new(
                at,
                break_kind::LINEAGE_MISMATCH,
                format!(
                    "the archive index page for seq {at} in epoch {} records a different restore fork from the one this store's lineage names",
                    span.epoch
                ),
            ));
        }
        let entry = page.segments.into_iter().next().expect("checked: exactly one entry");
        if entry.base_seq != at {
            return Err(HistoryBreak::new(
                at,
                break_kind::REORDERED_SEGMENT,
                format!(
                    "the archive index page for seq {at} in epoch {} names segment {}, which starts at seq {}",
                    span.epoch, entry.segment_id, entry.base_seq
                ),
            ));
        }
        Ok(entry)
    }

    /// How many pages of `span`'s epoch run on from `from`, each verified, up to the first missing or bad one.
    fn count_pages(&self, span: &Span, from: u64) -> u64 {
        let mut at = from;
        let mut counted = 0;
        while let Ok(Some(page)) = self.archive.read_page(span.epoch, at) {
            match self.checked_page(span, at, page) {
                Ok(entry) if entry.end_seq >= at => {
                    at = entry.end_seq + 1;
                    counted += 1;
                }
                _ => break,
            }
        }
        counted
    }

    /// Count segments an epoch published past where this history leaves it: pending in the last span, abandoned in any other.
    fn add_beyond(&mut self, span: &Span, n: u64) {
        if span.last {
            self.pending += n;
        } else {
            self.abandoned += n;
        }
    }

    /// Fetch one segment and prove it continues the history exactly where the walk is.
    fn open_segment(&mut self, span: &Span, entry: &AuditIndexEntry) -> Result<Vec<AuditEvent>, HistoryBreak> {
        let id = &entry.segment_id;
        if entry.base_seq > self.expected_seq {
            return Err(HistoryBreak::new(
                self.expected_seq,
                break_kind::MISSING_SEGMENT,
                format!(
                    "nothing in the archive covers seq {}: the next segment the index names starts at {}",
                    self.expected_seq, entry.base_seq
                ),
            ));
        }
        if entry.base_seq < self.expected_seq || entry.prev_hash != self.expected_hash {
            return Err(HistoryBreak::new(
                entry.base_seq,
                break_kind::REORDERED_SEGMENT,
                format!(
                    "segment {id} starts at seq {} linking to {}, and the chain is at seq {} linking to {}",
                    entry.base_seq, entry.prev_hash, self.expected_seq, self.expected_hash
                ),
            ));
        }
        if entry.end_seq >= span.to {
            return Err(HistoryBreak::new(
                entry.base_seq,
                break_kind::REORDERED_SEGMENT,
                format!("segment {id} runs past seq {}, where this history leaves epoch {}", span.to, span.epoch),
            ));
        }
        let tampered = |seq: u64, why: String| HistoryBreak::new(seq, break_kind::TAMPERED_SEGMENT, why);
        let (bytes, manifest) = self.archive.read_segment(span.epoch, id).map_err(|e| {
            HistoryBreak::new(
                entry.base_seq,
                break_kind::MISSING_SEGMENT,
                format!("segment {id} is named by the index and could not be read: {e}"),
            )
        })?;
        let disagrees = manifest.epoch != span.epoch
            || manifest.base_seq != entry.base_seq
            || manifest.end_seq != entry.end_seq
            || manifest.prev_hash != entry.prev_hash
            || manifest.head_hash != entry.head_hash
            || manifest.sha256 != entry.sha256;
        if !manifest.verify(&self.vk) || disagrees || sha256_hex(&bytes) != manifest.sha256 {
            return Err(tampered(entry.base_seq, format!("segment {id} does not match what was signed for it")));
        }
        let events = from_ndjson(&bytes)
            .map_err(|e| tampered(entry.base_seq, format!("segment {id} is not readable as events: {e}")))?;
        if let Some(bad) = permaura_core::AuditLog::verify_from_rekeyed(&events, &self.vk, entry.base_seq, &entry.prev_hash, self.signed_from) {
            return Err(tampered(bad, format!("event {bad} inside segment {id} does not verify")));
        }
        let complete = segment_len(entry).map(|n| n == events.len()).unwrap_or(false);
        if !complete || events.last().map(|e| e.hash.as_str()) != Some(entry.head_hash.as_str()) {
            return Err(tampered(entry.end_seq, format!("segment {id} does not end at the head its manifest names")));
        }
        self.expected_seq = entry.end_seq + 1;
        self.expected_hash = entry.head_hash.clone();
        self.segments += 1;
        Ok(events)
    }

    /// Where a span stops, the next one (or the hot window) has to start.
    fn close_span(&self, span: &Span) -> Result<(), HistoryBreak> {
        if self.expected_seq == span.to && self.expected_hash == span.end_hash {
            return Ok(());
        }
        if span.last {
            // A boundary that names a different base or a different hash is the tell for an archive
            // and a store that are not each other's.
            return Err(HistoryBreak::new(
                self.expected_seq.min(span.to),
                break_kind::BOUNDARY_MISMATCH,
                format!(
                    "the archive ends at seq {} linking to {} and the hot store's boundary starts at seq {} linking to {}",
                    self.expected_seq, self.expected_hash, span.to, span.end_hash
                ),
            ));
        }
        if self.expected_seq < span.to {
            return Err(HistoryBreak::new(
                self.expected_seq,
                break_kind::MISSING_SEGMENT,
                format!(
                    "nothing in epoch {} covers seq {}, and this history does not leave that epoch until seq {}",
                    span.epoch, self.expected_seq, span.to
                ),
            ));
        }
        Err(HistoryBreak::new(
            span.to,
            break_kind::LINEAGE_MISMATCH,
            format!(
                "epoch {} ends on {} at seq {} and the restore fork that leaves it says it continues from {}",
                span.epoch, self.expected_hash, span.to, span.end_hash
            ),
        ))
    }
}

impl Iterator for ArchivedEvents<'_> {
    type Item = Result<AuditEvent, GatewayError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if let Some(b) = self.broken.clone() {
            return self.fail(b);
        }
        loop {
            if let Some(event) = self.current.next() {
                return Some(Ok(event));
            }
            if let Some(span) = self.span.clone() {
                let entry = match self.next_entry(&span) {
                    Ok(entry) => entry,
                    Err(b) => return self.fail(b),
                };
                if let Some(entry) = entry {
                    match self.open_segment(&span, &entry) {
                        Ok(events) => self.current = events.into_iter(),
                        Err(b) => return self.fail(b),
                    }
                    continue;
                }
                self.span = None;
                if let Err(b) = self.close_span(&span) {
                    return self.fail(b);
                }
                if let Some(first_page) = self.pages_from {
                    let beyond = self.count_pages(&span, first_page.max(span.to));
                    self.add_beyond(&span, beyond);
                }
            }
            let Some(span) = self.spans.next() else {
                self.done = true;
                return None;
            };
            if let Err(b) = self.open_span(&span) {
                return self.fail(b);
            }
            self.span = Some(span);
        }
    }
}
