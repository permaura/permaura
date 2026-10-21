//! Restore reconciliation: what a worker does the first time it opens a promoted snapshot.
//!
//! [`crate::restore`] owns the execution **hold**, which is the flag that stops a restored worker
//! acting. This module owns what happens behind that flag: the invalidation, lifting the hold once everything is reviewed, the audit
//! records, and the `needs_review` list that keeps a restored authority from acting after the hold
//! is lifted.
//!
//! **The trigger.** Layer 2's boot read says `held` or `reconciling` **and** the document names a
//! checkpoint and a hold id ([`crate::restore::RestoreTrigger`]). An ordinary cold start cannot
//! satisfy that three times over: a worker with no `PERMAURA_HOLD_BUCKET` has no layer 2 at all, a
//! provisioned worker reads `state: "open"`, and the object provisioning writes carries no
//! checkpoint id even if its state were misread. The hold id is the fourth guard and the one that
//! needs a row: a restored worker scales to zero and cold-starts repeatedly, so the hold id it
//! reconciled is recorded and a boot whose hold id matches resumes the list rather than re-running
//! the invalidation.
//!
//! **The bootstrap problem, and the answer.** Every live session is deleted (only revocation
//! tombstones, which can never authenticate, are kept) and every device is unconfirmed, so nothing
//! inside the restored database can authorize a confirmation. The authority is the OAuth operator
//! subject: a permaura.com token whose `sub` equals `PERMAURA_OWNER_SUB`. That
//! fact lives entirely outside the tenant database, so a promoted snapshot cannot restore it,
//! rewrite it or forge it. Three legs follow from that and each is tested:
//!
//! - a restored **device key** proves nothing, because confirmation is not a device operation at all
//!   and no device key enters the check;
//! - a restored **session bearer** cannot do it, because the invalidation deletes every live session before
//!   the list is built (a kept revocation tombstone cannot authenticate) and the routes require the
//!   OAuth path rather than a session;
//! - a restored **recovery code** cannot do it, because the replay floor refuses any code set issued
//!   at or before it.
//!
//! **The residual, stated rather than discovered.** A self-hosted gateway has no Authorization
//! Server and no `PERMAURA_OWNER_SUB`, so it has no confirmation authority of this kind. It also has
//! no hold bucket and therefore never reconciles, so the two absences line up exactly; the routes
//! answer 403 saying so rather than pretending to be available.

use std::collections::BTreeSet;

use permaura_core::AuditPayload;
use serde::{Deserialize, Serialize};

use crate::error::GatewayError;
use crate::service::{ApprovalFloor, EnforcementService};
use crate::store::{Store, APPROVAL_FLOOR_META};

/// The `gateway_meta` key holding the reconciliation record.
///
/// One row rather than a table, for the reason [`crate::store::APPROVER_KEYRING_META`] is one: the
/// document is small, it is read and written whole, and a table would have to be added to every
/// store implementation and migrated into every existing database for state that exists only on a
/// tenant that has been restored.
pub const RECONCILIATION_META: &str = "reconciliation";

/// The only record format there has been.
pub const RECONCILIATION_VERSION: u32 = 1;

/// The audit action prefix every record in this module shares.
const RECOVERY_RESTORED: &str = "recovery.restored";
const RECOVERY_INVALIDATED: &str = "recovery.invalidated";
const RECOVERY_NEEDS_REVIEW: &str = "recovery.needs_review";
const RECOVERY_RECONCILED: &str = "recovery.reconciled";

/// The resource every recovery event names. The tenant slug is already on the hold object and in
/// `pm-tenant`; what this says is which part of the gateway wrote the record.
pub(crate) const RECOVERY_RESOURCE: &str = "recovery";

/// The decision every recovery event carries.
///
/// Deliberately not `allow`: these are records of something that happened rather than verdicts on a
/// request, and `allow` is the value [`crate::store::tally_grant_usage`] charges a grant's budget
/// against. Nothing here carries a grant id, so it would not in fact charge one, but a decision
/// vocabulary that only works because of a second field is one waiting to go wrong.
pub(crate) const RECOVERY_DECISION: &str = "recorded";

/// The status a pending approval is moved to by the invalidation, with `restore` as its reason.
const DENIED: &str = "denied";

/// Why a pending approval was denied by reconciliation rather than by a human.
pub const DENIED_BY_RESTORE: &str = "restore";

// ── The record ───────────────────────────────────────────────────────────────────────────────────

/// Which kind of restored authority an item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKind {
    /// A paired approver device key.
    Device,
    /// A grant binding a policy to agents.
    Grant,
    /// A configured integration instance.
    Connection,
    /// A sealed credential.
    Secret,
    /// A registered agent.
    Agent,
}

impl ReviewKind {
    /// The wire spelling, which is also what a route accepts.
    pub fn as_str(self) -> &'static str {
        match self {
            ReviewKind::Device => "device",
            ReviewKind::Grant => "grant",
            ReviewKind::Connection => "connection",
            ReviewKind::Secret => "secret",
            ReviewKind::Agent => "agent",
        }
    }

    /// Parse the wire spelling.
    ///
    /// Named `parse` rather than `from_str` so it is not mistaken for the standard trait, which
    /// this is not: an unknown kind is `None` rather than an error type nobody would read.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "device" => Some(ReviewKind::Device),
            "grant" => Some(ReviewKind::Grant),
            "connection" => Some(ReviewKind::Connection),
            "secret" => Some(ReviewKind::Secret),
            "agent" => Some(ReviewKind::Agent),
            _ => None,
        }
    }
}

/// Where one item stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    /// Restored, and not yet confirmed by the owner. Cannot act.
    NeedsReview,
    /// The owner confirmed it. Acts exactly as it did before the restore.
    Confirmed,
    /// The owner removed it. The underlying object was deleted, and the item is kept so the record
    /// says what was decided rather than going quiet.
    Removed,
}

/// One restored authority awaiting the owner's decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewItem {
    /// Which kind of thing this is.
    pub kind: ReviewKind,
    /// Its id: the grant id, connection id, secret id, agent id, or approver id.
    pub id: String,
    /// A human label where one exists (a connection's or an agent's name), for the console.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Needs review until the owner says otherwise.
    pub status: ReviewStatus,
    /// When the owner decided, unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
    /// Whether this id is absent from the state the restore abandoned, which usually means it was
    /// revoked after the checkpoint.
    ///
    /// **Computed by the hosted restore tool, never here.** The abandoned generation is readable
    /// only from outside this worker, and only sometimes; a gateway that guessed would be
    /// manufacturing exactly the automatic decision a restore must never make. Left
    /// `None` by everything in this repository, and it is a hint to the human even when it is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absent_from_abandoned_state: Option<bool>,
}

impl ReviewItem {
    /// Whether this item is still blocking.
    pub fn is_unreviewed(&self) -> bool {
        matches!(self.status, ReviewStatus::NeedsReview)
    }
}

/// How far reconciliation has got.
///
/// The stage is what makes a crashed reconciliation resumable in the right direction. `Opened` means
/// the invalidation may not have finished, so a boot that meets it runs the invalidation again.
/// Every step of it is idempotent, and the epoch fork names the epoch it must land on rather than
/// incrementing, so the retry cannot fork twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The record exists and the invalidation has not been seen through.
    Opened,
    /// Invalidated; the owner is working through the list.
    Reviewing,
    /// `recovery.reconciled` is in the chain. The restoration authority may clear the hold.
    Closed,
}

/// The reconciliation a restore opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationRecord {
    /// [`RECONCILIATION_VERSION`].
    pub version: u32,
    /// The hold id this reconciliation belongs to, and the idempotency key across cold starts.
    pub hold_id: String,
    /// The checkpoint whose bytes were promoted.
    pub checkpoint_id: String,
    /// How far this has got.
    pub stage: Stage,
    /// The epoch the fork must land on. Recorded **before** the fork, so a crash between the two
    /// leaves a retry that asks for the same number rather than one that forks again.
    pub epoch_target: Option<u64>,
    /// Unix ms the record was opened.
    pub opened_at: i64,
    /// Unix ms `recovery.reconciled` was appended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<i64>,
    /// Who closed it: the OAuth operator subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<String>,
    /// Every restored authority, and where it stands.
    #[serde(default)]
    pub items: Vec<ReviewItem>,
    /// What this restore could not establish, in the owner's words rather than a log line's.
    ///
    /// This is where a missing or null retained floor is said out loud, and it is carried into the
    /// review response as well as into `recovery.restored`, because the console is where an owner
    /// would otherwise never learn that no pre-restore token was killed.
    #[serde(default)]
    pub notes: Vec<String>,
    /// The replay floor now in force. Always set once the invalidation has run: the restore instant
    /// is in the maximum, so there is always something to raise to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_floor_ms: Option<i64>,
    /// Which of the three inputs the floor came from: [`FloorSource`], as its string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_floor_source: Option<String>,
    /// The approval floor now in force, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_floor: Option<String>,
    /// Records the abandoned chain lost, or `None` when it could not be computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_events: Option<i64>,
}

impl ReconciliationRecord {
    /// Whether this item is restored authority that has not been confirmed.
    ///
    /// A closed reconciliation blocks nothing: closing requires every item to have been decided, and
    /// an item this record has never heard of was created after the restore and was therefore
    /// created by somebody the owner had already let in.
    pub fn blocks(&self, kind: ReviewKind, id: &str) -> bool {
        if matches!(self.stage, Stage::Closed) {
            return false;
        }
        self.items
            .iter()
            .any(|i| i.kind == kind && i.id == id && i.is_unreviewed())
    }

    /// How many items are still blocking.
    pub fn unreviewed(&self) -> usize {
        self.items.iter().filter(|i| i.is_unreviewed()).count()
    }

    /// The `/health` projection: the state of the reconciliation and nothing that names a grant, a
    /// device, a connection or a secret.
    pub fn health_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "state": match self.stage {
                Stage::Opened => "opened",
                Stage::Reviewing => "reviewing",
                Stage::Closed => "closed",
            },
            "hold_id": self.hold_id,
            "items": self.items.len(),
            "unreviewed": self.unreviewed(),
        })
    }
}

/// Read the reconciliation record, or `None` when this gateway has never been restored.
///
/// An unreadable record is an **error** rather than `None`, on the same judgement
/// [`crate::store::Store::get_meta`]'s doc makes about the approver keyring: answering "no
/// reconciliation" for a row nobody could parse would let every restored grant, device and
/// connection act again, which is the fail-open direction and the exact thing this record exists to
/// prevent.
pub fn load(store: &dyn Store) -> Result<Option<ReconciliationRecord>, GatewayError> {
    let Some(raw) = store.get_meta(RECONCILIATION_META)? else { return Ok(None) };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&raw).map(Some).map_err(|e| {
        GatewayError::Internal(format!(
            "the {RECONCILIATION_META} row cannot be read ({e}): refusing to treat an unreadable reconciliation as no reconciliation, which would let every restored authority act again"
        ))
    })
}

/// Write the record back.
pub fn save(store: &dyn Store, record: &ReconciliationRecord) -> Result<(), GatewayError> {
    let value = serde_json::to_string(record)
        .map_err(|e| GatewayError::Internal(format!("the reconciliation record will not serialise: {e}")))?;
    store.put_meta(RECONCILIATION_META, &value)
}

// ── The retained record, and its three kinds of nothing ──────────────────────────────────────────

/// One field of `retained.json`, and which nothing it is when it is not a value.
///
/// The three are genuinely different and must not be collapsed. `checkpoint-job.sh` writes `null`
/// for metadata no gateway stamped, carries the literal string `none` through when a gateway looked
/// and there was nothing there, and turns an all-digit value into a JSON number. A reader that read
/// all three as "absent" would treat "this chain was empty" and "nobody has ever told me" as the
/// same fact, and only one of them is a reason to say nothing was preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Retained<T> {
    /// A value a gateway stamped.
    Known(T),
    /// The literal `none`: a gateway looked and there was nothing there.
    Nothing,
    /// `null`, or the key is absent: no gateway stamped this at all.
    Unstamped,
    /// Present, and not a shape this build can read.
    Unreadable(String),
    /// The retained record itself could not be read, so whatever it says is unknown.
    RecordUnread,
}

impl<T> Retained<T> {
    /// The value, when there is one.
    pub fn known(self) -> Option<T> {
        match self {
            Retained::Known(v) => Some(v),
            _ => None,
        }
    }

    /// One phrase naming which nothing this is, for a note the owner reads.
    pub fn why_nothing(&self) -> &'static str {
        match self {
            Retained::Known(_) => "a value",
            Retained::Nothing => "the literal 'none': a gateway looked and there was nothing there",
            Retained::Unstamped => "null or absent: no gateway ever stamped it",
            Retained::Unreadable(_) => "present, and not a shape this gateway can read",
            Retained::RecordUnread => "unknown: the retained record could not be read",
        }
    }
}

/// A field of the retained block, or [`Retained::RecordUnread`] for every field when the record itself could not be read.
fn stated<T>(field: Retained<T>, record_unread: bool) -> Retained<T> {
    if record_unread {
        Retained::RecordUnread
    } else {
        field
    }
}

/// The `retained` block of `retained.json`, whatever shape the object arrived in.
fn retained_block(retained: Option<&serde_json::Value>) -> Option<&serde_json::Value> {
    retained?.get("retained")
}

/// One field of the retained block as a millisecond / sequence integer.
///
/// Accepts a JSON number and a numeric string, because `checkpoint-job.sh` passes Cloud Storage's
/// custom metadata through and that has no type but string; the follow-up in progress on the hosted
/// side turns all-digit values into JSON numbers, and both shapes are read here so the gateway does
/// not have to land in step with it.
pub fn retained_i64(block: Option<&serde_json::Value>, key: &str) -> Retained<i64> {
    match block.and_then(|b| b.get(key)) {
        None | Some(serde_json::Value::Null) => Retained::Unstamped,
        Some(serde_json::Value::Number(n)) => match n.as_i64() {
            Some(v) => Retained::Known(v),
            None => Retained::Unreadable(n.to_string()),
        },
        Some(serde_json::Value::String(s)) if s.trim() == "none" => Retained::Nothing,
        Some(serde_json::Value::String(s)) => match s.trim().parse::<i64>() {
            Ok(v) => Retained::Known(v),
            Err(_) => Retained::Unreadable(s.clone()),
        },
        Some(other) => Retained::Unreadable(other.to_string()),
    }
}

/// One field of the retained block as a string, with the same three nothings.
pub fn retained_str(block: Option<&serde_json::Value>, key: &str) -> Retained<String> {
    match block.and_then(|b| b.get(key)) {
        None | Some(serde_json::Value::Null) => Retained::Unstamped,
        Some(serde_json::Value::String(s)) if s.trim() == "none" => Retained::Nothing,
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Retained::Unstamped,
        Some(serde_json::Value::String(s)) => Retained::Known(s.trim().to_string()),
        Some(other) => Retained::Unreadable(other.to_string()),
    }
}

// ── The boot path ────────────────────────────────────────────────────────────────────────────────

/// Keep retrying a reconciliation that failed at boot, in the background, until it runs.
///
/// A failure leaves the tenant held, so nothing is at risk while this waits. What it restores is
/// progress: a claim bucket that was unreachable at boot would otherwise be retried only by the next
/// cold start, and a warm worker can go days without one. [`run_at_boot`] is idempotent and changes
/// nothing when it fails before claiming, so running it again later is running it at boot, late.
pub fn retry_in_background(service: std::sync::Arc<EnforcementService>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
    handle.spawn_blocking(move || {
        let mut wait = std::time::Duration::from_secs(30);
        loop {
            std::thread::sleep(wait);
            match run_at_boot(&service) {
                Ok(_) => {
                    tracing::info!("the reconciliation that could not run at boot has now run");
                    return;
                }
                Err(e) => {
                    wait = (wait * 2).min(std::time::Duration::from_secs(600));
                    tracing::warn!(error = %e, retry_in_secs = wait.as_secs(), "this restore still cannot reconcile; execution stays held");
                }
            }
        }
    });
}

/// Reconcile a restored database, if this boot is one.
///
/// Called once at startup, before anything serves a request. Returns the record when this worker is
/// in a reconciliation and `None` when it is an ordinary cold start.
///
/// **A failure here leaves the tenant held**, which is the safe direction and the reason this can
/// report rather than abort: the hold that triggered reconciliation is still `held` or
/// `reconciling`, so nothing executes, and the next cold start finds the same trigger and tries
/// again.
pub fn run_at_boot(service: &EnforcementService) -> Result<Option<ReconciliationRecord>, GatewayError> {
    let Some(trigger) = service.execution_hold().and_then(|h| h.restore_trigger().cloned()) else {
        return Ok(None);
    };
    let store = service.store().clone();
    let retained = service.execution_hold().and_then(|h| h.retained().cloned());
    let existing = load(store.as_ref())?;

    let mut record = match existing {
        // The same restore, already past its invalidation: resume the list rather than re-running
        // anything. This is every cold start of a restored worker after the first.
        Some(record) if record.hold_id == trigger.hold_id && !matches!(record.stage, Stage::Opened) => {
            tracing::info!(
                hold_id = %record.hold_id,
                unreviewed = record.unreviewed(),
                "resuming the reconciliation this worker already opened for this restore"
            );
            return Ok(Some(record));
        }
        // The same restore whose invalidation did not finish. Everything below is idempotent, so it
        // is run again from the top.
        Some(record) if record.hold_id == trigger.hold_id => record,
        // A different hold id, or nothing at all: a restore this worker has not seen.
        _ => {
            let epoch_target = match store.audit_boundary()? {
                None => None,
                // Claimed in the archive bucket, which a restore cannot roll back. The restored
                // database's own epoch is the same for every restore of one checkpoint, so `epoch + 1`
                // alone would hand two restores one archive namespace. Nothing is recorded, forked or
                // appended until the claim is held: a guessed number would put this restore's first
                // events in a namespace another restore may own. The tenant stays held meanwhile, and
                // the claim is retried by [`retry_in_background`] and by every cold start.
                Some(boundary) => match service.audit_archive() {
                    Some(archive) => Some(archive.claim_epoch(&boundary, &trigger.hold_id).map_err(|e| {
                        GatewayError::Internal(format!(
                            "this restore could not claim an audit epoch in the archive ({e}): nothing has been reconciled, execution stays held, and the claim is retried"
                        ))
                    })?),
                    None => Some(boundary.epoch + 1),
                },
            };
            ReconciliationRecord {
                version: RECONCILIATION_VERSION,
                hold_id: trigger.hold_id.clone(),
                checkpoint_id: trigger.checkpoint_id.clone(),
                stage: Stage::Opened,
                epoch_target,
                opened_at: crate::store::now_ms(),
                closed_at: None,
                closed_by: None,
                items: Vec::new(),
                notes: Vec::new(),
                replay_floor_ms: None,
                replay_floor_source: None,
                approval_floor: None,
                gap_events: None,
            }
        }
    };
    record.stage = Stage::Opened;
    record.notes.clear();
    save(store.as_ref(), &record)?;

    // The fork, before the first event of the restored chain is appended, so every record this
    // reconciliation writes is already in the new epoch.
    if let Some(epoch) = record.epoch_target {
        match store.fork_audit_epoch(epoch, &record.hold_id) {
            Ok(true) => tracing::warn!(epoch, "the audit chain has forked: this database is a restore of an older generation, and the sequence numbers below this point were also spent by a generation that has been abandoned"),
            Ok(false) => {}
            Err(e) => {
                // Loud, and not fatal. The epoch keeps two forks' archive segments out of one
                // namespace, and nothing is archived yet; refusing to reconcile over it would leave
                // a tenant held with no way forward for a record no reader consults today.
                tracing::error!(error = %e, epoch, "could not fork the audit epoch; reconciliation continues and the fork is recorded in the chain");
                record.notes.push(format!(
                    "the audit boundary's epoch could not be moved to {epoch}: {e}"
                ));
            }
        }
    } else {
        record
            .notes
            .push("this store keeps no audit boundary, so the fork is recorded in the chain only".into());
    }

    let block = retained_block(retained.as_ref());
    let retained_read = service.execution_hold().and_then(|h| h.retained_read().cloned());
    let record_unread = retained_read.as_ref().is_some_and(|r| r.record_unreadable);
    append_restored(store.as_ref(), &trigger, block, retained_read.as_ref(), &mut record)?;
    let counts = invalidate(store.as_ref(), service, block, record_unread, &mut record)?;
    append_invalidated(store.as_ref(), &counts, &record)?;

    record.items = build_review_list(store.as_ref(), service)?;
    record.stage = Stage::Reviewing;
    save(store.as_ref(), &record)?;
    append_needs_review(store.as_ref(), &record)?;

    tracing::warn!(
        hold_id = %record.hold_id,
        checkpoint_id = %record.checkpoint_id,
        items = record.items.len(),
        "this database was restored from a checkpoint: every live session is gone, every pending approval is denied, and no restored device, grant, connection, secret or agent can act until its owner confirms it"
    );
    Ok(Some(record))
}

/// What the invalidation actually removed, for `recovery.invalidated`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct InvalidationCounts {
    sessions: u64,
    approvals: u64,
    enrolment_codes: u64,
}

/// Where the replay floor now in force came from.
///
/// Reported in `recovery.invalidated` and in the review response, because "this restore floored the
/// one-time ledger at its own instant" and "this restore carried a floor forward from the state it
/// abandoned" are different facts about the same number, and an operator reading the chain should
/// not have to infer which one happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorSource {
    /// `retained.json` carried a floor and it was the highest of the three.
    Retained,
    /// The restored snapshot's own `gateway_meta` row was the highest.
    Restored,
    /// The instant this reconciliation ran, which is the answer on every restore that has nothing
    /// higher to take, and, until the hosted scripts stamp `pm-replay-floor-ms`, on every restore.
    RestoreTime,
}

impl FloorSource {
    /// The value written into the chain and the review response.
    pub fn as_str(self) -> &'static str {
        match self {
            FloorSource::Retained => "retained",
            FloorSource::Restored => "restored",
            FloorSource::RestoreTime => "restore_time",
        }
    }
}

/// The invalidation, as one unit where the store can give one.
///
/// Atomic where the store allows, and correct when it does not: every step is idempotent, so a
/// partial run that crashes is finished by the next boot rather than left half-applied.
///
/// The **replay floor is inside the unit** with the rows. A restore that deleted every session,
/// denied every approval and dropped every enrolment code but left the one-time ledger unfloored is
/// exactly the half-invalidation this step exists to prevent, and there is no reason for the two to
/// be able to disagree. Re-running it cannot lower the floor, because the write takes a maximum.
///
/// The **approval floor stays outside** it, because it is written through
/// [`EnforcementService::set_approval_floor`], which also updates the service's in-memory floor,
/// and taking it inside would put a service-level mutation inside a store transaction. That method
/// checks no authority and appends no audit event of its own; `recovery.invalidated` records the
/// floor now in force.
fn invalidate(
    store: &dyn Store,
    service: &EnforcementService,
    retained: Option<&serde_json::Value>,
    record_unread: bool,
    record: &mut ReconciliationRecord,
) -> Result<InvalidationCounts, GatewayError> {
    // Read once, outside, so a retry inside the transaction cannot move the floor between attempts.
    let restore_time = crate::store::now_ms();
    let (counts, floor, source, note) = store.transaction(|s| {
        let sessions = s.delete_live_sessions()?;
        let mut approvals = 0u64;
        for mut approval in s.list_approvals(Some("pending"))? {
            // A resolution this process is running ends the row itself. Every other row is claimed before it is denied, so a resolution that starts after this list fails at its claim instead of finishing over the denial; a claim already spent (by the snapshot's own resolution) leaves nothing that can resolve the row, so it is denied all the same.
            if service.executions().is_resolving(&approval.id) {
                continue;
            }
            if !s.claim_once("approval-resolution", &approval.id, i64::MAX)? && service.executions().is_resolving(&approval.id) {
                continue;
            }
            approval.status = DENIED.to_string();
            approval.resolution_reason = Some(DENIED_BY_RESTORE.to_string());
            s.put_approval(approval)?;
            approvals += 1;
        }
        let enrolment_codes = s.delete_unconsumed_enrolment_codes()?;
        let (floor, source, note) = raise_replay_floor_from(s, retained, record_unread, restore_time)?;
        Ok((InvalidationCounts { sessions, approvals, enrolment_codes }, floor, source, note))
    })?;

    record.replay_floor_ms = Some(floor);
    record.replay_floor_source = Some(source.as_str().to_string());
    if let Some(note) = note {
        tracing::warn!("{note}");
        record.notes.push(note);
    }
    record.approval_floor = Some(raise_approval_floor_from(service, retained, record_unread, record)?);
    Ok(counts)
}

/// The replay floor: `max(restored floor, retained floor, the instant this reconciliation runs)`.
///
/// The restore instant is in the maximum because of what a restore *is*. The `one_time_claims` table
/// was rolled back with the database, so every one-time token alive at this moment was issued
/// against a ledger that no longer exists, and this gateway cannot say of any of them whether it has
/// already been spent. Nothing issued before the restore may be claimed after it. Nothing legitimate
/// is lost beyond a ceremony that was mid-flight: tokens are minted again above the floor, and the
/// owner repeats the step-up they were half way through.
///
/// Two floors it deliberately is **not**:
///
/// - **the checkpoint's own instant.** A token issued between the checkpoint and the restore would
///   survive it, and that window is precisely where the rolled-back claims live.
/// - **anything derived from another stamp** (`pre_restore_commit_seq`, `pm-taken-at`). Restore forbids
///   inventing a floor from a number that is sitting nearby and means something else.
///
/// The retained floor stays in the maximum even though the restore instant dominates it in every
/// ordinary run: a clock that went backwards, or a retained record refreshed by a worker whose clock
/// ran ahead, must not be able to lower the floor.
fn raise_replay_floor_from(
    store: &dyn Store,
    retained: Option<&serde_json::Value>,
    record_unread: bool,
    restore_time: i64,
) -> Result<(i64, FloorSource, Option<String>), GatewayError> {
    let stated = stated(retained_i64(retained, "replay_floor_ms"), record_unread);
    let mut floor = restore_time;
    let mut source = FloorSource::RestoreTime;
    if let Some(ms) = crate::restore::replay_floor(store)? {
        if ms >= floor {
            floor = ms;
            source = FloorSource::Restored;
        }
    }
    if let Retained::Known(ms) = stated {
        if ms >= floor {
            floor = ms;
            source = FloorSource::Retained;
        }
    }
    let note = match &stated {
        Retained::Known(_) => None,
        Retained::RecordUnread => Some(format!(
            "the retained record could not be read, so the replay floor it carried is unknown; the floor is the instant this restore reconciled ({floor}), which refuses every step-up ticket, pairing ticket, recovery code and approval claim issued before the restore"
        )),
        other => Some(format!(
            "the retained record carried no replay floor ({}), so the floor is the instant this restore reconciled ({floor}) rather than anything the checkpoint job stamped. Every step-up ticket, pairing ticket, recovery code and approval claim issued before that instant is refused, which is the outcome a retained floor would also have produced; what is missing is `pm-replay-floor-ms` in the hosted lane's `write_retained`, and until it lands a recovery code set issued before a restore has to be reissued after one.",
            other.why_nothing()
        )),
    };
    Ok((crate::restore::raise_replay_floor(store, floor)?, source, note))
}

/// The approval floor: `max(restored, retained)`, and never lowered.
///
/// `device_signed` outranks `approve`, so the maximum is "device_signed if either says so". The one
/// write this makes is the raise; a retained `approve` against a restored `approve` writes nothing
/// at all, because writing an explicit `approve` where the database held no override would turn the
/// absence of a setting into the deliberate opt-down that
/// [`EnforcementService::set_approval_floor`] treats as a trust-root decision.
fn raise_approval_floor_from(
    service: &EnforcementService,
    retained: Option<&serde_json::Value>,
    record_unread: bool,
    record: &mut ReconciliationRecord,
) -> Result<String, GatewayError> {
    let store = service.store();
    let restored = store
        .get_meta(APPROVAL_FLOOR_META)?
        .and_then(|v| ApprovalFloor::from_str(&v));
    let stated = stated(retained_str(retained, "approval_floor"), record_unread);
    let retained_floor = match &stated {
        Retained::Known(raw) => match ApprovalFloor::from_str(raw) {
            Some(f) => Some(f),
            None => {
                let note = format!(
                    "the retained record's approval floor reads '{raw}', which this gateway does not recognise; the restored floor has been kept and nothing was lowered"
                );
                tracing::error!("{note}");
                record.notes.push(note);
                None
            }
        },
        // Unknown is not empty: the owner may have raised the floor after the snapshot, and a restore can raise the floor but never lower it.
        Retained::RecordUnread => {
            let note = "the retained record could not be read, so the approval floor it carried is unknown: raised to device_signed, because a restore can raise the floor and never lower it; the owner can lower it again once the restore is confirmed".to_string();
            tracing::warn!("{note}");
            record.notes.push(note);
            Some(ApprovalFloor::DeviceSigned)
        }
        other => {
            let note = format!(
                "the retained record carried no approval floor ({}), so the floor is whatever the restored snapshot held. A floor its owner raised after the checkpoint has NOT been preserved.",
                other.why_nothing()
            );
            tracing::warn!("{note}");
            record.notes.push(note);
            None
        }
    };
    let raise = matches!(retained_floor, Some(ApprovalFloor::DeviceSigned))
        && !matches!(restored, Some(ApprovalFloor::DeviceSigned));
    if raise {
        service.set_approval_floor(Some(ApprovalFloor::DeviceSigned))?;
        tracing::warn!("the retained record's approval floor is device_signed and the restored snapshot's was not: raised, because a restore can raise the floor and can never lower it");
        return Ok(ApprovalFloor::DeviceSigned.as_str().to_string());
    }
    Ok(restored
        .or(retained_floor)
        .map(|f| f.as_str().to_string())
        .unwrap_or_else(|| service.approval_floor().as_str().to_string()))
}

/// The review list: everything in the restored snapshot that can act, listed and unconfirmed.
///
/// The journal replay is skipped: restore ships with no revocation journal, so this list covers
/// everything. That is strictly safe, because nothing acts until the owner
/// confirms it, and it is why this list is the whole restored estate rather than the part a journal
/// could not account for.
fn build_review_list(
    store: &dyn Store,
    service: &EnforcementService,
) -> Result<Vec<ReviewItem>, GatewayError> {
    let item = |kind: ReviewKind, id: String, label: Option<String>| ReviewItem {
        kind,
        id,
        label,
        status: ReviewStatus::NeedsReview,
        decided_at: None,
        absent_from_abandoned_state: None,
    };
    let mut items = Vec::new();
    // Devices come from the keyring rather than the device registry: a key reaches the keyring
    // through pairing alone, while a row reaches the registry only when push registration succeeds,
    // so a Watch or a simulator would be trusted and invisible.
    for (approver, _, revoked) in service.approver_keyring_snapshot().entries() {
        if !revoked {
            items.push(item(ReviewKind::Device, approver.to_string(), None));
        }
    }
    for grant in store.list_grants()? {
        items.push(item(ReviewKind::Grant, grant.grant_id.clone(), Some(grant.policy_ids.join(", "))));
    }
    for connection in store.list_connections()? {
        items.push(item(ReviewKind::Connection, connection.id.clone(), Some(connection.name.clone())));
    }
    for id in store.list_secret_ids()? {
        items.push(item(ReviewKind::Secret, id, None));
    }
    for agent in store.list_agents()? {
        items.push(item(ReviewKind::Agent, agent.id.clone(), Some(agent.name.clone())));
    }
    Ok(items)
}

// ── The audit records ────────────────────────────────────────────────────────────────────────────

/// `recovery.restored`: the fork record.
///
/// A restore reuses sequence numbers the abandoned chain already spent, so an auditor comparing the
/// Cloud Logging anchors against the live chain will find two different events at one seq. That has
/// to be explicit rather than discovered, which is the whole job of this event.
///
/// `gap_events` is the honest number of records lost, and `unknown` when it cannot be computed: a
/// zero would be a claim that nothing was lost.
fn append_restored(
    store: &dyn Store,
    trigger: &crate::restore::RestoreTrigger,
    retained: Option<&serde_json::Value>,
    retained_read: Option<&crate::restore::RetainedRead>,
    record: &mut ReconciliationRecord,
) -> Result<(), GatewayError> {
    let read = retained_read.cloned();
    if let Some(problem) = read.as_ref().and_then(|r| r.problem.clone()) {
        record.notes.push(problem);
    }
    if let Some(read) = read.as_ref().filter(|r| r.chosen == crate::restore::RETAINED_NEWEST && r.generation.is_some()) {
        let note = format!(
            "the hold pins no generation of the retained record, so the newest ({}) was read; a checkpoint taken since the promotion may have rewritten it from the restored state",
            read.generation.unwrap_or_default()
        );
        tracing::warn!("{note}");
        record.notes.push(note);
    }
    let head = store.audit_events(Some(1))?.pop();
    let restored_head_seq = head.as_ref().map(|e| e.seq);
    let record_unread = read.as_ref().is_some_and(|r| r.record_unreadable);
    let abandoned_head_seq = stated(retained_i64(retained, "pre_restore_audit_head_seq"), record_unread);
    let abandoned_epoch = stated(retained_i64(retained, "pre_restore_audit_epoch"), record_unread);
    let abandoned_head_hash = stated(retained_str(retained, "pre_restore_audit_head_hash"), record_unread);
    let gap_events = match (&abandoned_head_seq, restored_head_seq) {
        (Retained::Known(abandoned), Some(restored)) => Some(abandoned - restored as i64),
        // An abandoned head with nothing restored below it: the whole chain is the gap, and the
        // count is the head's seq plus one because sequence numbers start at zero.
        (Retained::Known(abandoned), None) => Some(abandoned + 1),
        _ => None,
    };
    record.gap_events = gap_events;
    if gap_events.is_none() {
        let note = format!(
            "how many audit records the abandoned generation held beyond this one is UNKNOWN ({}), so the size of the gap in this tenant's history cannot be stated",
            abandoned_head_seq.why_nothing()
        );
        tracing::error!("{note}");
        record.notes.push(note);
    }
    // Stated only when both ends of it are known: the retained record's own refresh time, and the
    // timestamp of the newest event the restored chain actually holds. It is the wall time the
    // abandoned generation covered beyond this one, which is the number an owner asks for first.
    let gap_ms = retained_refreshed_at_ms(retained)
        .and_then(|refreshed| head.as_ref().map(|e| refreshed - e.timestamp));
    let payload = AuditPayload {
        summary: serde_json::json!({
            "checkpoint_id": trigger.checkpoint_id,
            "hold_id": trigger.hold_id,
            "source_generation": trigger.retained_ref.as_ref().and_then(|r| r.generation.clone()),
            // What was actually read, which is what every number below came from.
            "retained_generation": read.as_ref().and_then(|r| r.generation).map(|g| g.to_string()),
            "retained_chosen": read.as_ref().map(|r| r.chosen),
            "restored_head_seq": restored_head_seq,
            "restored_head_hash": head.as_ref().map(|e| e.hash.clone()),
            "abandoned_head_seq": stamp_json(&abandoned_head_seq),
            "abandoned_head_hash": stamp_json(&abandoned_head_hash),
            "abandoned_epoch": stamp_json(&abandoned_epoch),
            "epoch": record.epoch_target,
            "gap_events": gap_events.map(serde_json::Value::from).unwrap_or(serde_json::Value::String("unknown".into())),
            "gap_ms": gap_ms,
            "notes": record.notes,
        }),
        ..AuditPayload::new(RECOVERY_RESTORED, RECOVERY_RESOURCE, RECOVERY_DECISION)
    };
    store.append_audit(payload)?;
    Ok(())
}

/// When the checkpoint job last refreshed the retained record, as unix ms, when it said.
fn retained_refreshed_at_ms(retained: Option<&serde_json::Value>) -> Option<i64> {
    let raw = retained_str(retained, "refreshed_at").known()?;
    // `YYYY-MM-DDTHH:MM:SSZ`, which is what `date -u +%Y-%m-%dT%H:%M:%SZ` writes.
    let digits: Vec<i64> = raw
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<i64>().unwrap_or(0))
        .collect();
    let [y, mo, d, h, mi, s] = digits.get(..6)? else { return None };
    // Days since the unix epoch, by the civil-from-days algorithm, so no date library is needed for
    // one timestamp on one path.
    let (y, mo) = (if *mo <= 2 { y - 1 } else { *y }, *mo);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400) + h * 3_600 + mi * 60 + s) * 1000)
}

/// A retained field as JSON: the value, the string `none`, or `null`, keeping the three nothings
/// distinguishable in the chain exactly as they are in the object.
fn stamp_json<T: Clone + Into<serde_json::Value>>(stamp: &Retained<T>) -> serde_json::Value {
    match stamp {
        Retained::Known(v) => v.clone().into(),
        Retained::Nothing => serde_json::Value::String("none".into()),
        Retained::Unstamped => serde_json::Value::Null,
        Retained::Unreadable(raw) => serde_json::json!({ "unreadable": raw }),
        Retained::RecordUnread => serde_json::json!({ "unreadable": "the retained record could not be read" }),
    }
}

/// `recovery.invalidated`: what the invalidation removed, and the two floors now in force.
fn append_invalidated(
    store: &dyn Store,
    counts: &InvalidationCounts,
    record: &ReconciliationRecord,
) -> Result<(), GatewayError> {
    let payload = AuditPayload {
        summary: serde_json::json!({
            "hold_id": record.hold_id,
            "sessions_deleted": counts.sessions,
            "approvals_denied": counts.approvals,
            "enrolment_codes_deleted": counts.enrolment_codes,
            "denied_reason": DENIED_BY_RESTORE,
            "replay_floor_ms": record.replay_floor_ms,
            // Which of the three inputs the floor came from. Without it a reader cannot tell a floor
            // carried forward from the abandoned state from one this restore set at its own instant,
            // and only the first says the checkpoint job is stamping what it should.
            "replay_floor_source": record.replay_floor_source,
            "approval_floor": record.approval_floor,
        }),
        ..AuditPayload::new(RECOVERY_INVALIDATED, RECOVERY_RESOURCE, RECOVERY_DECISION)
    };
    store.append_audit(payload)?;
    Ok(())
}

/// `recovery.needs_review`: the reconciliation list, ids only.
fn append_needs_review(store: &dyn Store, record: &ReconciliationRecord) -> Result<(), GatewayError> {
    let payload = AuditPayload {
        summary: serde_json::json!({
            "hold_id": record.hold_id,
            "items": record
                .items
                .iter()
                .map(|i| serde_json::json!({ "kind": i.kind.as_str(), "id": i.id }))
                .collect::<Vec<_>>(),
        }),
        ..AuditPayload::new(RECOVERY_NEEDS_REVIEW, RECOVERY_RESOURCE, RECOVERY_DECISION)
    };
    store.append_audit(payload)?;
    Ok(())
}

/// `recovery.reconciled`: the close.
pub(crate) fn append_reconciled(
    store: &dyn Store,
    record: &ReconciliationRecord,
) -> Result<(), GatewayError> {
    let payload = AuditPayload {
        summary: serde_json::json!({
            "hold_id": record.hold_id,
            "checkpoint_id": record.checkpoint_id,
            "reviewed_by": record.closed_by,
            "cleared_at": record.closed_at,
            "items": record.items.len(),
            "removed": record
                .items
                .iter()
                .filter(|i| matches!(i.status, ReviewStatus::Removed))
                .count(),
        }),
        ..AuditPayload::new(RECOVERY_RECONCILED, RECOVERY_RESOURCE, RECOVERY_DECISION)
    };
    store.append_audit(payload)?;
    Ok(())
}

/// One audit record per reconciliation mutation the owner makes.
///
/// `action` is `recovery.confirm`, `recovery.confirm_all` or `recovery.remove`. Confirm-all is its
/// own action rather than N confirmations, because "the owner looked at every one of these" and "the
/// owner accepted all of these at once" are different statements and only one of them is true.
pub(crate) fn append_review_action(
    store: &dyn Store,
    action: &str,
    subject: &str,
    summary: serde_json::Value,
) -> Result<(), GatewayError> {
    let mut map = match summary {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    map.insert("subject".into(), serde_json::json!(subject));
    let payload = AuditPayload {
        summary: serde_json::Value::Object(map),
        ..AuditPayload::new(action, RECOVERY_RESOURCE, RECOVERY_DECISION)
    };
    store.append_audit(payload)?;
    Ok(())
}

/// Every id in a list, deduplicated, for a caller that wants to say what it acted on.
pub(crate) fn ids(items: &[ReviewItem]) -> Vec<String> {
    items
        .iter()
        .map(|i| format!("{}:{}", i.kind.as_str(), i.id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(json: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "hold_version": 1, "tenant": "acme", "retained": json })
    }

    /// The three nothings, kept apart. `checkpoint-job.sh` writes all three and they mean different
    /// things: only `null` says nobody has ever stamped this.
    #[test]
    fn the_three_kinds_of_nothing_in_a_retained_record_stay_distinguishable() {
        let value = block(serde_json::json!({
            "pre_restore_audit_head_seq": "100987",
            "pre_restore_audit_head_hash": "none",
            "pre_restore_commit_seq": 91801,
            "approval_floor": null,
        }));
        let b = retained_block(Some(&value));
        assert_eq!(retained_i64(b, "pre_restore_audit_head_seq"), Retained::Known(100_987));
        assert_eq!(retained_i64(b, "pre_restore_commit_seq"), Retained::Known(91_801));
        assert_eq!(retained_str(b, "pre_restore_audit_head_hash"), Retained::Nothing);
        assert_eq!(retained_str(b, "approval_floor"), Retained::Unstamped);
        assert_eq!(retained_str(b, "revocation_journal_head"), Retained::Unstamped);
        // The string `none` on a numeric field is the same statement, not a parse failure.
        let nothing = block(serde_json::json!({ "replay_floor_ms": "none" }));
        assert_eq!(retained_i64(retained_block(Some(&nothing)), "replay_floor_ms"), Retained::Nothing);
    }

    #[test]
    fn a_retained_field_this_build_cannot_read_is_never_silently_nothing() {
        let value = block(serde_json::json!({ "replay_floor_ms": "17583 76682117" }));
        let read = retained_i64(retained_block(Some(&value)), "replay_floor_ms");
        assert!(matches!(read, Retained::Unreadable(_)), "{read:?}");
        assert_ne!(read, Retained::Unstamped, "an unreadable value is not an absent one");
    }

    #[test]
    fn a_missing_retained_object_reads_as_unstamped_rather_than_as_an_error() {
        assert_eq!(retained_i64(None, "replay_floor_ms"), Retained::Unstamped);
        assert_eq!(retained_str(None, "approval_floor"), Retained::Unstamped);
    }

    #[test]
    fn the_checkpoint_jobs_iso_timestamp_parses_to_milliseconds() {
        let value = block(serde_json::json!({ "refreshed_at": "2026-09-20T14:22:00Z" }));
        assert_eq!(retained_refreshed_at_ms(retained_block(Some(&value))), Some(1_789_914_120_000));
        assert_eq!(retained_refreshed_at_ms(None), None);
    }

    fn pending_hold(id: &str) -> crate::store::PendingApproval {
        crate::store::PendingApproval {
            id: id.into(),
            session_id: "sess_demo".into(),
            capability: "github.pull_requests.create".into(),
            resource: "github_acme".into(),
            message: "Approve?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({}).into(),
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

    /// A restore's invalidation leaves a hold this process is resolving to the resolution, and claims every row it denies, so a resolution that starts after the list fails at its claim instead of finishing over the denial.
    #[test]
    fn invalidation_skips_a_hold_being_resolved_and_claims_the_rows_it_denies() {
        let store: std::sync::Arc<dyn Store> = std::sync::Arc::new(crate::store::memory::MemoryStore::new());
        let service = EnforcementService::new(store.clone(), std::sync::Arc::new(crate::connectors::MockHttpClient::new()));
        store.put_approval(pending_hold("appr_live")).unwrap();
        store.put_approval(pending_hold("appr_idle")).unwrap();
        let _resolving = service.executions().admit(Some("appr_live")).unwrap();
        assert!(store.claim_once("approval-resolution", "appr_live", i64::MAX).unwrap());
        let mut record = ReconciliationRecord {
            version: RECONCILIATION_VERSION,
            hold_id: "hold_1".into(),
            checkpoint_id: "cp_1".into(),
            stage: Stage::Opened,
            epoch_target: None,
            opened_at: 0,
            closed_at: None,
            closed_by: None,
            items: Vec::new(),
            notes: Vec::new(),
            replay_floor_ms: None,
            replay_floor_source: None,
            approval_floor: None,
            gap_events: None,
        };
        invalidate(store.as_ref(), &service, None, false, &mut record).unwrap();
        assert_eq!(store.get_approval("appr_live").unwrap().unwrap().status, "pending", "the resolution in flight ends it");
        assert_eq!(store.get_approval("appr_idle").unwrap().unwrap().status, DENIED);
        assert!(
            !store.claim_once("approval-resolution", "appr_idle", i64::MAX).unwrap(),
            "the denied row's claim is spent, so no resolution can finish over the denial"
        );
    }

    /// A closed reconciliation blocks nothing, and an item created after the restore was created by
    /// somebody the owner had already let in.
    #[test]
    fn only_an_unreviewed_item_of_an_open_reconciliation_blocks() {
        let mut record = ReconciliationRecord {
            version: RECONCILIATION_VERSION,
            hold_id: "hold_1".into(),
            checkpoint_id: "cp_1".into(),
            stage: Stage::Reviewing,
            epoch_target: Some(1),
            opened_at: 0,
            closed_at: None,
            closed_by: None,
            items: vec![
                ReviewItem {
                    kind: ReviewKind::Grant,
                    id: "g1".into(),
                    label: None,
                    status: ReviewStatus::NeedsReview,
                    decided_at: None,
                    absent_from_abandoned_state: None,
                },
                ReviewItem {
                    kind: ReviewKind::Grant,
                    id: "g2".into(),
                    label: None,
                    status: ReviewStatus::Confirmed,
                    decided_at: Some(1),
                    absent_from_abandoned_state: None,
                },
            ],
            notes: Vec::new(),
            replay_floor_ms: None,
            replay_floor_source: None,
            approval_floor: None,
            gap_events: None,
        };
        assert!(record.blocks(ReviewKind::Grant, "g1"));
        assert!(!record.blocks(ReviewKind::Grant, "g2"), "confirmed acts again");
        assert!(!record.blocks(ReviewKind::Grant, "g3"), "created after the restore");
        assert!(!record.blocks(ReviewKind::Connection, "g1"), "the kind is part of the identity");
        assert_eq!(record.unreviewed(), 1);
        record.stage = Stage::Closed;
        assert!(!record.blocks(ReviewKind::Grant, "g1"), "a closed reconciliation blocks nothing");
    }
}
