//! The execution hold: the per-tenant flag that stops a worker acting on restored authority.
//!
//! Not to be confused with [`crate::recovery`], which owns *recovery authority* (recovery codes,
//! recovery tickets, the second factor behind lowering the approval floor). Nothing here touches it.
//! A **restore** is the promotion of an older snapshot into a tenant's store bucket, and the flag
//! that gates it is the **execution hold**.
//!
//! **Why it lives outside the database.** A promoted snapshot restores every row the database held
//! when its checkpoint was taken, so a hold kept inside it would be rolled back by the very
//! promotion it exists to gate. The hold therefore lives in two places a snapshot cannot reach, and
//! both must read open for execution to proceed:
//!
//! - **Layer 1, deployment.** `PERMAURA_EXECUTION_HOLD=<hold-id>` as a Cloud Run environment
//!   variable. Setting or clearing it needs `run.services.update`, which no tenant runtime has. Read
//!   once at process start; cost zero.
//! - **Layer 2, the hold object.** `holds/<tenant>/state.json` in the **checkpoint bucket**, named
//!   by `PERMAURA_HOLD_BUCKET`. The runtime can read that one prefix and nothing else, so a
//!   compromised runtime cannot clear its own hold, which layer 1 alone does not prevent.
//!
//! `<tenant>` is the slug in [`TENANT_ENV`], never the control plane's gateway row id. See that
//! constant for why the difference is a safety property rather than naming taste.
//!
//! **Fail closed, and the disagreement is a signal.** If the layers disagree the hold wins and the
//! gateway says so loudly: an object that says held beside an environment that says open is the
//! signature of a deploy that dropped the variable, and the reverse is a hold that was lifted in one
//! layer only.
//!
//! **What it stops** is execution: an agent invoke, the release of a held call, a vault export and
//! every other request that sends a stored credential
//! ([`crate::service::EnforcementService::send_with_credential`]). Operator-initiated outbound
//! requests that use no stored credential (an OAuth connect code exchange, OpenAPI or WordPress
//! discovery) and notifications are not held. Reads keep working, because an owner has to be able
//! to inspect the restored state in order to reconcile it, and control-plane mutations keep
//! working, because reconciliation *is* a sequence of control-plane mutations.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::GatewayError;
use crate::objectstore::ObjectStore;

/// Layer 1: the deployment flag. Any non-empty value is a hold, and the value is the hold id.
pub const EXECUTION_HOLD_ENV: &str = "PERMAURA_EXECUTION_HOLD";

/// The bucket holding `holds/<tenant>/`. Unset means there is no layer 2 at all: self-hosted
/// gateways have no checkpoint bucket, and neither did the hosted workers that predate the backup
/// project. Provisioning sets it once that project exists, and from then on an absent hold object is
/// a refusal rather than an open.
pub const HOLD_BUCKET_ENV: &str = "PERMAURA_HOLD_BUCKET";

/// How long a cached hold state is believed on the execution path before it is checked again.
pub const HOLD_RECHECK_INTERVAL_ENV: &str = "PERMAURA_HOLD_RECHECK_MS";

/// The tenant **slug**, which is what every hosted object, IAM condition, checkpoint path, manifest
/// and purge is keyed by, and the only key still knowable once a worker has been deleted.
///
/// Deliberately **not** `PERMAURA_GATEWAY_ID`, which on a hosted worker carries the control plane's
/// gateway ROW id (`gw_…`) and means something else entirely. A worker that addressed its hold by
/// the row id would read a prefix its IAM condition does not cover, take a 403 at boot and refuse to
/// start, and every checkpoint manifest's tenant would disagree with the stamp on the bytes it
/// describes.
///
/// There is no fallback from one to the other, on purpose: falling back is exactly the silent
/// wrong-prefix read this variable exists to prevent, and it would fail in the direction that looks
/// like it worked.
pub const TENANT_ENV: &str = "PERMAURA_TENANT";

/// The default recheck interval. One metadata request a minute on a busy instance, and nothing at
/// all on an idle one, which is what keeps scale-to-zero intact.
pub const DEFAULT_RECHECK_INTERVAL: Duration = Duration::from_secs(60);

/// The narrowest and widest recheck interval accepted. Below a second the check is a load generator
/// against the bucket; above ten minutes it is not a control any more, because a hold set during a
/// live incident would not bind for the length of the incident.
const RECHECK_INTERVAL_BOUNDS: (Duration, Duration) =
    (Duration::from_secs(1), Duration::from_secs(600));

/// The hold document version this build understands. A reader that meets a version it does not know
/// refuses the object rather than parsing it best-effort, which for a hold means refusing execution.
const HOLD_VERSION: u64 = 1;

/// The one state under which execution proceeds. `held` and `reconciling` are the other two the
/// contract names, and anything else is a value this build does not know, which is also not open.
const STATE_OPEN: &str = "open";

/// The hold object for `tenant`, written only by the restoration authority.
pub fn hold_object(tenant: &str) -> String {
    format!("holds/{tenant}/state.json")
}

// ── The replay floor ─────────────────────────────────────────────────────────────────────────────

/// The replay floor, or `None` when this gateway has never been restored.
///
/// A read that *fails* is an error rather than `None`, for the same reason
/// [`crate::store::Store::get_meta`]'s doc gives: answering "no floor" for a read nobody could make
/// would turn an unreadable floor into no floor at all, which is the fail-open direction. An
/// unparseable value is the same judgement: somebody wrote something this build cannot act on, and
/// the safe reading of that is not "act as though nothing was written".
pub fn replay_floor(store: &dyn crate::store::Store) -> Result<Option<i64>, GatewayError> {
    let Some(raw) = store.get_meta(crate::store::REPLAY_FLOOR_META)? else { return Ok(None) };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    raw.parse::<i64>().map(Some).map_err(|e| {
        GatewayError::Internal(format!(
            "{} holds '{raw}', which is not a millisecond instant ({e}); refusing to treat an unreadable replay floor as no floor",
            crate::store::REPLAY_FLOOR_META
        ))
    })
}

/// Raise the replay floor to `at_least`, never lower. Returns the floor now in force.
///
/// The maximum is taken here rather than at the call site so there is exactly one place that could
/// get the direction wrong. A restore raises it to
/// `max(restored floor, retained floor, the instant reconciliation runs)`. See
/// [`crate::reconcile`]'s `raise_replay_floor_from` for why the restore instant is in there.
/// Nothing else writes it.
pub fn raise_replay_floor(
    store: &dyn crate::store::Store,
    at_least: i64,
) -> Result<i64, GatewayError> {
    let floor = replay_floor(store)?.unwrap_or(i64::MIN).max(at_least);
    store.put_meta(crate::store::REPLAY_FLOOR_META, &floor.to_string())?;
    Ok(floor)
}

/// Refuse a one-time token that was issued at or before the replay floor.
///
/// Called by every [`crate::store::Store::claim_once`] consumer that spends a presented token,
/// immediately before the claim, because the claim is exactly the check a restore invalidated (the
/// hold-expiry sweep and the retirement of a stranded hold also claim `approval-resolution`, but
/// only deny or expire, so they skip it). The five of them are:
///
/// | Token | Issuance time it presents |
/// | --- | --- |
/// | Step-up / pairing ticket (`spend_pairing_ticket`) | the ticket's `auth_time` |
/// | Recovery ticket (`spend_recovery_ticket`) | the ticket's `auth_time` |
/// | Recovery code claim (`recovery::consume`) | the code set's `issued_at` |
/// | Approval resolution (`resolve_approval`) | the approval's `created_at` |
/// | Vault export claim (`claim_vault_export`) | the approval's `created_at` |
///
/// For step-up, pairing and recovery tickets the issuance time presented is the ticket's
/// `auth_time`, which is at or before its `iat`.
///
/// At or before, not strictly before: a token minted in the same millisecond as the abandoned
/// generation's last write is one this gateway cannot vouch for either.
///
/// With no floor set this is a `get_meta` and nothing else, and none of these paths is a hot one:
/// a step-up, a pairing, a recovery and an approval are all human-paced.
pub fn refuse_if_replayed_across_a_restore(
    store: &dyn crate::store::Store,
    issued_at_ms: i64,
    what: &str,
) -> Result<(), GatewayError> {
    let Some(floor) = replay_floor(store)? else { return Ok(()) };
    if issued_at_ms > floor {
        return Ok(());
    }
    tracing::warn!(
        issued_at_ms,
        floor,
        "refusing a {what} issued at or before this gateway's replay floor: it predates a restore, so the single-use ledger cannot say whether it has already been spent"
    );
    Err(GatewayError::Unauthorized(format!(
        "this {what} was issued before this gateway was restored from a checkpoint, so it cannot be spent; obtain a fresh one"
    )))
}

/// The retained record for `tenant`, written only by the checkpoint job on every successful
/// checkpoint. Read here at boot for the reconciliation slice; a missing one is never a hold.
pub fn retained_object(tenant: &str) -> String {
    format!("holds/{tenant}/retained.json")
}

/// Why execution is refused, and the only three facts a caller is told.
///
/// Deliberately three strings and nothing else: the hold object also carries who set it and which
/// checkpoint is being promoted, and neither belongs in a response to an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    /// The hold id, as the restoration authority minted it, or `unknown` when the object named none.
    pub hold_id: String,
    /// The state that refused: `held`, `reconciling`, `unreadable`, or whatever the object said.
    pub state: String,
    /// One sentence saying which layer refused and why.
    pub reason: String,
}

impl Held {
    fn new(hold_id: impl Into<String>, state: impl Into<String>, reason: impl Into<String>) -> Self {
        Held { hold_id: hold_id.into(), state: state.into(), reason: reason.into() }
    }

    /// The error a refused caller gets: HTTP 423, or the JSON-RPC equivalent over MCP.
    pub fn as_error(&self) -> GatewayError {
        GatewayError::ExecutionHeld {
            hold_id: self.hold_id.clone(),
            state: self.state.clone(),
            reason: self.reason.clone(),
        }
    }
}

/// What the hold object said, once it has been read and parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Layer2State {
    /// An explicit `{"state":"open"}` object. The only reading that permits execution.
    Open,
    /// Anything else the bucket answered with, including a missing object and one this build cannot
    /// parse. All of them refuse, and each says which it was.
    Refused(Held),
}

/// The layer-2 reader: the bucket, the object, and which tenant the object has to name.
struct HoldObject {
    objects: Arc<dyn ObjectStore>,
    object: String,
    tenant: String,
}

/// The cached answer and what it took to get it.
struct Cached {
    state: Layer2State,
    /// The object generation the cached state was parsed from. `0` when there was no object.
    generation: u64,
    /// When the last read was *attempted*, successful or not: the interval throttles attempts, not
    /// successes, or an unreachable bucket would be asked on every execution.
    attempted_at: Instant,
    /// When reads started failing, cleared by the first that succeeds. The grace period runs from
    /// here.
    failing_since: Option<Instant>,
    /// Whether `state` is the refusal this gateway put in place because the object stayed
    /// unreadable, rather than anything the object said. `generation` still names the last version
    /// actually read, so an unchanged generation on the next successful check says nothing about
    /// whether to keep it: the next check reads the body instead.
    synthetic: bool,
}

/// The two layers, the cache in front of layer 2, and the retained record read at boot.
pub struct ExecutionHold {
    /// Layer 1, read once at process start. `Some` means held, whatever layer 2 says.
    env_hold: Option<String>,
    /// Layer 2, or `None` when no bucket is configured.
    layer2: Option<HoldObject>,
    cached: Mutex<Cached>,
    recheck_interval: Duration,
    /// `holds/<tenant>/retained.json` as read at boot, for the reconciliation slice. `None` when
    /// there is no layer 2, when the object is absent, or when it could not be read or parsed: a
    /// missing retained record is never a hold, it only means reconciliation will have no
    /// independent account of the tenant's pre-restore authority.
    retained: Option<serde_json::Value>,
    /// Which version of the retained record `retained` is, and why that one. `None` with no layer 2.
    retained_read: Option<RetainedRead>,
    /// What the boot read said about a restore in progress, if anything. Boot only: see
    /// [`RestoreTrigger`].
    restore_trigger: Option<RestoreTrigger>,
}

impl ExecutionHold {
    /// Build a hold with layer 1 only: no bucket is configured, so there is nothing to read.
    ///
    /// This is every self-hosted gateway and every hosted worker provisioned before the backup
    /// project existed.
    pub fn env_only(env_hold: Option<String>) -> Self {
        ExecutionHold {
            env_hold: env_hold.filter(|v| !v.trim().is_empty()),
            layer2: None,
            cached: Mutex::new(Cached {
                state: Layer2State::Open,
                generation: 0,
                attempted_at: Instant::now(),
                failing_since: None,
                synthetic: false,
            }),
            recheck_interval: DEFAULT_RECHECK_INTERVAL,
            retained: None,
            retained_read: None,
            restore_trigger: None,
        }
    }

    /// Build both layers and take the boot read, which is the only unconditional one.
    ///
    /// An error reaching the object aborts: an unreachable hold bucket is exactly the shape of
    /// `an_unreachable_bucket_never_starts_empty`, and a worker that cannot tell whether it is held
    /// must not decide that it is not. A *missing* object is not an error, it is an answer, and the
    /// answer refuses execution while leaving the gateway up so its owner can reconcile it.
    pub fn open(
        env_hold: Option<String>,
        objects: Arc<dyn ObjectStore>,
        tenant: &str,
        recheck_interval: Duration,
    ) -> Result<Self, GatewayError> {
        let layer2 = HoldObject {
            objects,
            object: hold_object(tenant),
            tenant: tenant.to_string(),
        };
        let (state, generation, restore_trigger) = layer2.read()?;
        let env_hold = env_hold.filter(|v| !v.trim().is_empty());
        match &state {
            Layer2State::Open => tracing::info!(
                object = %layer2.object,
                generation,
                "the execution hold object reads open"
            ),
            Layer2State::Refused(held) => tracing::warn!(
                object = %layer2.object,
                generation,
                hold_id = %held.hold_id,
                state = %held.state,
                "this tenant is HELD: execution is refused and only reads and control-plane mutations answer. {}",
                held.reason
            ),
        }
        warn_on_disagreement(env_hold.as_deref(), &state);
        let pinned = restore_trigger.as_ref().and_then(|t| t.retained_ref.as_ref());
        let (retained, retained_read) = layer2.read_retained(pinned);
        Ok(ExecutionHold {
            env_hold,
            layer2: Some(layer2),
            cached: Mutex::new(Cached {
                state,
                generation,
                attempted_at: Instant::now(),
                failing_since: None,
                synthetic: false,
            }),
            recheck_interval: clamp_interval(recheck_interval),
            retained,
            retained_read: Some(retained_read),
            restore_trigger,
        })
    }

    /// The retained record as it was at boot, for the reconciliation slice. `None` means there was
    /// none to read, which is a weaker restore rather than a hold.
    pub fn retained(&self) -> Option<&serde_json::Value> {
        self.retained.as_ref()
    }

    /// Which version of the retained record [`Self::retained`] is, and why that one.
    pub fn retained_read(&self) -> Option<&RetainedRead> {
        self.retained_read.as_ref()
    }

    /// The restore this worker booted into, if it booted into one.
    ///
    /// `None` on every ordinary cold start, which is what [`crate::reconcile`] keys off. Taken from
    /// the boot read and never from a later recheck: reconciliation is the first act on a restored
    /// database, and a trigger noticed an hour into a process's life would be describing a database
    /// that has been serving all along.
    pub fn restore_trigger(&self) -> Option<&RestoreTrigger> {
        self.restore_trigger.as_ref()
    }

    /// Refuse the caller when either layer is not open, rechecking layer 2 at most once an interval.
    ///
    /// The **only** thing that triggers a read, and it is called only from the execution paths, so
    /// nothing on a read path can wake an idle instance.
    pub fn refuse_if_held(&self) -> Result<(), GatewayError> {
        match self.evaluate(true) {
            Some(held) => Err(held.as_error()),
            None => Ok(()),
        }
    }

    /// What the last read said, without taking another one. What `/health` reports.
    pub fn cached(&self) -> Option<Held> {
        self.evaluate(false)
    }

    /// Whether this gateway has a hold configured at all. `/health` reports `null` rather than
    /// `open` when it does not, so a gateway that has never been told about holds is not read as one
    /// that has and is running free.
    pub fn is_configured(&self) -> bool {
        self.env_hold.is_some() || self.layer2.is_some()
    }

    /// Combine the two layers, optionally refreshing layer 2 first.
    ///
    /// Layer 2 is consulted even when layer 1 already refuses, because the disagreement between them
    /// is the signal worth having: it costs at most one metadata request an interval, and without it
    /// a hold lifted in one layer only is invisible until somebody goes looking. The disagreement is
    /// reported where the layer-2 state is *read*, not here, because layer 1 never changes: logging
    /// it per call would put one line on every refused request, and a held tenant being retried is
    /// exactly when that turns into a logging bill.
    ///
    /// Layer 2 wins when both refuse, because it is the one a compromised runtime cannot clear.
    fn evaluate(&self, may_recheck: bool) -> Option<Held> {
        self.layer2_state(may_recheck).or_else(|| {
            self.env_hold.as_ref().map(|id| {
                Held::new(
                    id,
                    "held",
                    format!("{EXECUTION_HOLD_ENV} is set on this deployment, so execution is refused until it is cleared"),
                )
            })
        })
    }

    /// Layer 2's answer, refreshed when it is stale and this is an execution path.
    ///
    /// The read happens with the lock released, and a caller claims the next recheck before making
    /// it. Waiting on a `std::sync::Mutex` parks a runtime worker without donating it, which on one
    /// vCPU is how the hosted store wedged once already, and holding this one across a metadata
    /// request would park every concurrent execution behind it for the length of that request.
    fn layer2_state(&self, may_recheck: bool) -> Option<Held> {
        let layer2 = self.layer2.as_ref()?;
        if may_recheck {
            if let Some(known) = self.claim_recheck() {
                let outcome = Self::read_for_recheck(layer2, known);
                self.apply_recheck(outcome);
            }
        }
        match &self.lock().state {
            Layer2State::Open => None,
            Layer2State::Refused(held) => Some(held.clone()),
        }
    }

    /// The cached state, under a lock taken with this worker released from the runtime's pool.
    fn lock(&self) -> std::sync::MutexGuard<'_, Cached> {
        crate::store::bridge::blocking_section(|| {
            self.cached.lock().unwrap_or_else(|p| p.into_inner())
        })
    }

    /// Claim the next recheck when one is due, answering with the generation the cached state was
    /// parsed from, or `None` when the cached state came from no read at all and the body has to be
    /// read whatever the generation.
    ///
    /// The attempt is marked before the read rather than after it, so a burst of executions produces
    /// one request rather than one each, and the callers that did not win answer from the state they
    /// already have instead of queueing behind the one that did. Attempts are throttled whether they
    /// succeed or fail, so an unreachable bucket costs one request an interval rather than one per
    /// execution.
    fn claim_recheck(&self) -> Option<Option<u64>> {
        let mut cached = self.lock();
        if cached.attempted_at.elapsed() < self.recheck_interval {
            return None;
        }
        cached.attempted_at = Instant::now();
        Some((!cached.synthetic).then_some(cached.generation))
    }

    /// One recheck, with no lock held: the cheap generation-only `head`, and the body only when the
    /// generation moved or nothing is known. `Ok(None)` means it has not moved.
    fn read_for_recheck(
        layer2: &HoldObject,
        known: Option<u64>,
    ) -> Result<Option<(Layer2State, u64)>, GatewayError> {
        match layer2.objects.head(&layer2.object)? {
            Some(generation) if Some(generation) == known => Ok(None),
            // The trigger is dropped on purpose: reconciliation keys off the boot read alone.
            _ => layer2.read().map(|(state, generation, _)| Some((state, generation))),
        }
    }

    /// Fold a recheck's outcome back into the cache.
    ///
    /// **What a failed recheck does, and why.** A read that fails leaves the last known state in
    /// place and starts a grace period of exactly one further interval. If the last known state was
    /// *held*, nothing changes and nothing ever will: a hold is never lifted by a failure to read
    /// it. If the last known state was *open*, the first failure is absorbed, because a single Cloud
    /// Storage blip must not take a working tenant down, and a failure still standing one interval
    /// later refuses execution, because at that point nobody can say whether this tenant is held.
    /// That refusal is the gateway's own rather than the object's, so it is marked as such and the
    /// first read that succeeds replaces it with what the object says, even at an unchanged
    /// generation; otherwise an outage that ended would keep refusing until the process restarts.
    fn apply_recheck(&self, outcome: Result<Option<(Layer2State, u64)>, GatewayError>) {
        let (state, generation) = match outcome {
            Ok(Some(read)) => read,
            Ok(None) => {
                self.lock().failing_since = None;
                return;
            }
            Err(e) => {
                let mut cached = self.lock();
                self.recheck_failed(&mut cached, &e);
                return;
            }
        };
        let mut cached = self.lock();
        let was_unreadable = std::mem::replace(&mut cached.synthetic, false);
        if was_unreadable {
            tracing::warn!(
                generation,
                "the execution hold object is readable again: the refusal that stood while it could not be read is replaced by what it says"
            );
        }
        if state != cached.state {
            match &state {
                Layer2State::Open => tracing::warn!(
                    generation,
                    "the execution hold has been lifted: the hold object now reads open"
                ),
                Layer2State::Refused(held) => tracing::warn!(
                    generation,
                    hold_id = %held.hold_id,
                    state = %held.state,
                    "this tenant is now HELD: execution is refused from here. {}",
                    held.reason
                ),
            }
            warn_on_disagreement(self.env_hold.as_deref(), &state);
        }
        cached.state = state;
        cached.generation = generation;
        cached.failing_since = None;
    }

    /// Apply the grace period to a recheck that could not read the object.
    fn recheck_failed(&self, cached: &mut Cached, error: &GatewayError) {
        let since = *cached.failing_since.get_or_insert_with(Instant::now);
        if matches!(cached.state, Layer2State::Refused(_)) {
            tracing::warn!(error = %error, "the execution hold object could not be re-read; this tenant was already held, so it stays held");
            return;
        }
        if since.elapsed() < self.recheck_interval {
            tracing::warn!(error = %error, "the execution hold object could not be re-read; the last read said open, so execution continues for one more interval");
            return;
        }
        tracing::error!(
            error = %error,
            "the execution hold object has been unreadable for longer than one recheck interval: refusing execution, because an unreadable hold is indistinguishable from a hold"
        );
        cached.state = Layer2State::Refused(Held::new(
            "unknown",
            "unreadable",
            "the hold object could not be read for longer than one recheck interval, and an unreadable hold is indistinguishable from a hold",
        ));
        cached.synthetic = true;
    }
}

impl HoldObject {
    /// Fetch and parse the hold object.
    ///
    /// Two requests, not one: the contract calls for a `head_full` at boot, and `head_full` carries
    /// the generation and the stamped metadata but not the body, which is where the state lives. So
    /// the generation is read first and the body is fetched at exactly that generation, which also
    /// means the state and the generation cached beside it cannot come from two different versions.
    fn read(&self) -> Result<(Layer2State, u64, Option<RestoreTrigger>), GatewayError> {
        let Some(generation) = self.objects.head(&self.object)? else {
            // Reached the bucket and there is nothing there. Not an error, and not an open either:
            // once a bucket is configured, provisioning writes an explicit open object, so an absent
            // one means either that it never did or that somebody removed it.
            return Ok((
                Layer2State::Refused(Held::new(
                    "unknown",
                    "absent",
                    format!(
                        "{} names a hold bucket but it holds no {}, and only an explicit open state permits execution",
                        HOLD_BUCKET_ENV, self.object
                    ),
                )),
                0,
                None,
            ));
        };
        let bytes = self.objects.get(&self.object, generation)?;
        let (state, trigger) = self.parse(&bytes);
        Ok((state, generation, trigger))
    }

    /// Read the retained record at boot. Every failure is a warning: it is the reconciliation
    /// slice's input, not a gate, and refusing to start over a missing one would take a healthy
    /// tenant down for a record nothing has asked for yet.
    ///
    /// **The generation the hold pins, when it pins one, and never the newest instead.** The
    /// checkpoint job rewrites this object from whatever the store holds, and after a promotion that
    /// is the older, restored snapshot, so the newest version can describe the restored state rather
    /// than the abandoned one. A pinned generation that cannot be read leaves the restore
    /// with no retained record, which reconciliation already treats as a weaker restore and says so;
    /// substituting the newest would be the defect itself. The newest is read only when the hold pins
    /// nothing, which is also every ordinary boot.
    fn read_retained(&self, pinned: Option<&RetainedRef>) -> (Option<serde_json::Value>, RetainedRead) {
        let object = retained_object(&self.tenant);
        let pin = pinned.and_then(|r| r.generation.as_deref().map(str::trim).filter(|g| !g.is_empty()).map(|g| (r, g)));
        if let Some((reference, raw)) = pin {
            let refuse = |problem: String, record_unreadable: bool| {
                tracing::error!("{problem}");
                (None, RetainedRead { chosen: RETAINED_PINNED, generation: None, problem: Some(problem), record_unreadable })
            };
            if let Some(named) = reference.object.as_deref().filter(|o| *o != object) {
                return refuse(format!(
                    "the hold pins {named}, which is not this tenant's {object}, so this restore has no retained record"
                ), true);
            }
            let Ok(generation) = raw.parse::<u64>() else {
                return refuse(format!(
                    "the hold pins {object} at generation '{raw}', which is not a generation, so this restore has no retained record"
                ), true);
            };
            // No stored version has generation 0: restore-tenant.sh writes it when it could read no retained record.
            if generation == 0 {
                return refuse(format!(
                    "the restore that set this hold could read no {object} when it was planned, so this restore has no retained record; any version there now was written after the plan and may describe the restored state"
                ), false);
            }
            return match self.parse_retained(&object, generation) {
                Ok(value) => (
                    Some(value),
                    RetainedRead { chosen: RETAINED_PINNED, generation: Some(generation), problem: None, record_unreadable: false },
                ),
                Err(e) => refuse(format!(
                    "the hold pins {object} at generation {generation}, and that generation could not be read ({e}). The newest version is not used in its place, because a checkpoint since the promotion may have rewritten it from the restored state, so this restore has no retained record"
                ), true),
            };
        }
        let unread = |problem: Option<String>| {
            let record_unreadable = problem.is_some();
            (None, RetainedRead { chosen: RETAINED_NEWEST, generation: None, problem, record_unreadable })
        };
        let generation = match self.objects.head(&object) {
            Ok(Some(generation)) => generation,
            Ok(None) => {
                tracing::info!(
                    "{object} does not exist yet: this tenant has no independent account of its pre-restore authority, so a restore would need every device, grant, connection, secret and agent re-authorised by its owner"
                );
                return unread(None);
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not read {object}; carrying on, because a missing retained record is not a hold");
                return unread(Some(format!("{object} could not be read ({e})")));
            }
        };
        match self.parse_retained(&object, generation) {
            Ok(value) => (
                Some(value),
                RetainedRead { chosen: RETAINED_NEWEST, generation: Some(generation), problem: None, record_unreadable: false },
            ),
            Err(e) => {
                tracing::warn!(error = %e, "carrying on without {object}");
                unread(Some(e))
            }
        }
    }

    /// One version of the retained record, fetched and parsed.
    fn parse_retained(&self, object: &str, generation: u64) -> Result<serde_json::Value, String> {
        let bytes = self
            .objects
            .get(object, generation)
            .map_err(|e| format!("could not fetch {object} at generation {generation}: {e}"))?;
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| format!("{object} at generation {generation} is not readable JSON: {e}"))
    }

    /// Turn the object's bytes into a state. Everything that is not an explicit, current-version,
    /// this-tenant `open` refuses.
    fn parse(&self, bytes: &[u8]) -> (Layer2State, Option<RestoreTrigger>) {
        let unreadable = |why: String| {
            (Layer2State::Refused(Held::new("unknown", "unreadable", why)), None)
        };
        let document: HoldDocument = match serde_json::from_slice(bytes) {
            Ok(document) => document,
            Err(e) => {
                return unreadable(format!(
                    "the hold object could not be read as a hold document ({e}), and an unreadable hold is indistinguishable from a hold"
                ))
            }
        };
        // A version this build does not know is refused rather than parsed hopefully: a hold is read
        // exactly when somebody is about to act on it. A document carrying no version at all is
        // accepted, because the smallest legal open object is `{"state":"open"}`.
        if document.hold_version.is_some_and(|v| v != HOLD_VERSION) {
            return unreadable(format!(
                "the hold object is version {} and this gateway understands version {HOLD_VERSION}",
                document.hold_version.unwrap_or_default()
            ));
        }
        // The path already names the tenant, so this catches an object copied or restored from
        // somewhere else rather than an addressing mistake. Treated as unreadable, because a hold
        // that describes another workspace has said nothing about this one.
        if let Some(named) = document.tenant.as_deref().filter(|t| !t.is_empty()) {
            if named != self.tenant {
                return unreadable(format!(
                    "the hold object names tenant '{named}' and this gateway is '{}'",
                    self.tenant
                ));
            }
        } else {
            tracing::warn!("{} names no tenant; accepting it for this gateway", self.object);
        }
        let trigger = document.restore_trigger();
        let state = document.state.as_deref().unwrap_or("absent");
        if state == STATE_OPEN {
            return (Layer2State::Open, trigger);
        }
        let held = Held::new(
            document.hold_id.clone().filter(|id| !id.is_empty()).unwrap_or_else(|| "unknown".into()),
            state,
            document
                .reason
                .clone()
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| "this tenant is held by its hold object".into()),
        );
        (Layer2State::Refused(held), trigger)
    }
}

/// The fields of `holds/<tenant>/state.json` this gateway reads. Everything else the restoration
/// authority writes (`set_at`, `set_by`) is for the human and is deliberately not parsed here.
#[derive(serde::Deserialize)]
struct HoldDocument {
    hold_version: Option<u64>,
    tenant: Option<String>,
    state: Option<String>,
    hold_id: Option<String>,
    reason: Option<String>,
    /// The checkpoint this hold is promoting. Present only on a hold a restore wrote: the object
    /// provisioning writes has `state: "open"` and no checkpoint id at all, which is the second of
    /// the four guards that keep an ordinary cold start from reconciling.
    checkpoint_id: Option<String>,
    /// Which generation of `retained.json` the restore was planned against. Widened onto the
    /// document rather than onto [`Held`], which is a response body.
    retained_ref: Option<RetainedRef>,
}

/// The `retained_ref` block `restore-tenant.sh` writes: the account the restore was **planned
/// against**, rather than whatever a later checkpoint leaves behind.
///
/// Every field is optional because the script writes `null` for a generation or a timestamp it
/// could not read, and a restore planned against no retained record at all is a weaker restore
/// rather than a malformed one.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RetainedRef {
    /// The object name, e.g. `holds/acme/retained.json`.
    #[serde(default)]
    pub object: Option<String>,
    /// Its generation at planning time, as Cloud Storage reported it.
    #[serde(default)]
    pub generation: Option<String>,
    /// When the checkpoint job last refreshed it, ISO-8601.
    #[serde(default)]
    pub refreshed_at: Option<String>,
}

/// [`RetainedRead::chosen`] when the hold pinned a generation.
pub const RETAINED_PINNED: &str = "pinned";
/// [`RetainedRead::chosen`] when the hold pinned none and the newest version was read.
pub const RETAINED_NEWEST: &str = "newest";

/// Which version of `retained.json` the boot read, recorded in `recovery.restored` so an auditor can
/// tell the record a restore was planned against from whatever a later checkpoint left behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedRead {
    /// [`RETAINED_PINNED`] or [`RETAINED_NEWEST`].
    pub chosen: &'static str,
    /// The generation actually read, or `None` when nothing was.
    pub generation: Option<u64>,
    /// Why nothing could be read, in a sentence an owner can act on, when that is worth saying.
    pub problem: Option<String>,
    /// A record the restore was planned against exists, or may, and could not be read: what it says is unknown, which is not the same as a record that says nothing.
    pub record_unreadable: bool,
}

/// What a hold object says about a restore in progress: the four facts reconciliation needs, and
/// nothing a caller is ever shown.
///
/// Produced **only** from the boot read. Reconciliation is the first act on a restored database, so
/// a trigger observed on some later recheck would be describing a database this process has already
/// been serving from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreTrigger {
    /// The hold id the restoration authority minted. The idempotency key: a restored worker cold
    /// starts repeatedly, and reconciliation runs once per restore rather than once per boot.
    pub hold_id: String,
    /// `held` or `reconciling`.
    pub state: String,
    /// The checkpoint whose bytes were promoted.
    pub checkpoint_id: String,
    /// The retained record the restore was planned against, when the hold names one.
    pub retained_ref: Option<RetainedRef>,
}

impl HoldDocument {
    /// The restore trigger this document carries, or `None` when it is not a restore.
    ///
    /// **Both halves are required.** The state must be one this build knows as a restore in
    /// progress, and the document must name a checkpoint. An ordinary cold start cannot satisfy
    /// either: a provisioned worker reads `state: "open"`, and the object provisioning writes
    /// carries no checkpoint id even if its state were misread. A worker with no hold bucket has no
    /// layer 2 at all and never gets this far.
    ///
    /// A hold with no id is refused as a trigger even when everything else fits, because the id is
    /// what makes reconciliation run once per restore: without one, every cold start of the same
    /// restored worker would look like a new restore and re-run the invalidation.
    fn restore_trigger(&self) -> Option<RestoreTrigger> {
        let state = self.state.as_deref()?.trim();
        if !matches!(state, "held" | "reconciling") {
            return None;
        }
        let checkpoint_id = self.checkpoint_id.as_deref().map(str::trim).filter(|v| !v.is_empty())?;
        let hold_id = self.hold_id.as_deref().map(str::trim).filter(|v| !v.is_empty())?;
        Some(RestoreTrigger {
            hold_id: hold_id.to_string(),
            state: state.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
            retained_ref: self.retained_ref.clone(),
        })
    }
}

/// Say so when the two layers do not agree, which they should not be able to.
///
/// A restore sets both, and clearing one is the last step of a reconciliation that clears the other,
/// so either direction means a step was missed. Called where layer 2 is read (boot, and each time
/// its state changes) rather than on every evaluation: layer 1 cannot change while the process runs,
/// so per-call logging would only put one line on each refused request, and a held tenant being
/// retried is exactly when that turns into a logging bill.
fn warn_on_disagreement(env_hold: Option<&str>, state: &Layer2State) {
    match (env_hold, state) {
        (None, Layer2State::Refused(held)) => tracing::error!(
            hold_id = %held.hold_id,
            state = %held.state,
            "the hold object says this tenant is held and {EXECUTION_HOLD_ENV} is not set: the hold wins, and a deployment that dropped the variable is the usual cause"
        ),
        (Some(id), Layer2State::Open) => tracing::error!(
            hold_id = %id,
            "{EXECUTION_HOLD_ENV} holds this tenant and its hold object reads open: the hold wins, and a lift that cleared one layer and not the other is the usual cause"
        ),
        _ => {}
    }
}

/// Keep a configured interval inside [`RECHECK_INTERVAL_BOUNDS`].
fn clamp_interval(interval: Duration) -> Duration {
    interval.clamp(RECHECK_INTERVAL_BOUNDS.0, RECHECK_INTERVAL_BOUNDS.1)
}

/// The recheck interval from the environment. An unparseable value takes the default rather than
/// refusing to boot: a typo in one variable must not be why a gateway will not start, which is the
/// line every knob in [`crate::limits`] already takes.
pub fn recheck_interval_from_env() -> Duration {
    let Some(raw) = non_empty_env(HOLD_RECHECK_INTERVAL_ENV) else {
        return DEFAULT_RECHECK_INTERVAL;
    };
    match raw.parse::<u64>() {
        Ok(ms) => clamp_interval(Duration::from_millis(ms)),
        Err(e) => {
            tracing::warn!(error = %e, value = %raw, "{HOLD_RECHECK_INTERVAL_ENV} is not a millisecond count; keeping the default");
            DEFAULT_RECHECK_INTERVAL
        }
    }
}

/// Build the process's execution hold from the environment, or abort.
///
/// Returns `None` only when nothing about holds is configured at all, which is every local gateway.
/// A configured bucket with no tenant slug, or one that cannot be reached, ends the process: both
/// mean this worker cannot tell whether it is held, and a worker in that position must not decide
/// that it is not.
pub fn from_env() -> Option<Arc<ExecutionHold>> {
    let env_hold = non_empty_env(EXECUTION_HOLD_ENV);
    let (bucket, tenant) = match layer_two_addressing(
        non_empty_env(HOLD_BUCKET_ENV),
        non_empty_env(TENANT_ENV),
    ) {
        Ok(Some(addressing)) => addressing,
        Ok(None) => return env_hold.map(|id| Arc::new(ExecutionHold::env_only(Some(id)))),
        Err(message) => {
            tracing::error!("{message}");
            std::process::exit(1);
        }
    };
    let objects = crate::backend::shared_gcp_token_source()
        .ok_or_else(|| {
            GatewayError::Internal(format!(
                "{HOLD_BUCKET_ENV} is set but the workload token for Google's endpoints could not be minted"
            ))
        })
        .and_then(|token| crate::objectstore::GcsObjectStore::new(&bucket, token));
    let hold = objects.and_then(|objects| {
        ExecutionHold::open(env_hold, Arc::new(objects), &tenant, recheck_interval_from_env())
    });
    match hold {
        Ok(hold) => Some(Arc::new(hold)),
        Err(e) => {
            tracing::error!(
                error = %e,
                bucket = %bucket,
                tenant = %tenant,
                "the execution hold object could not be read at boot: refusing to start, because a worker that cannot tell whether it is held must not decide that it is not"
            );
            std::process::exit(1);
        }
    }
}

/// Resolve layer 2's address: the bucket and the tenant slug, or the reason there is none.
///
/// `Ok(None)` means nothing about layer 2 is configured, which is every local gateway. `Err` means
/// a bucket was named and the slug was not, and the caller ends the process: a worker in that
/// position cannot tell whether it is held, and a worker that cannot tell must not decide that it
/// is not.
///
/// Split out of [`from_env`] so the rule is testable without setting a process-wide variable in a
/// suite that runs in parallel, and the signature is itself the statement that there is no
/// fallback, because there is nowhere in it for a gateway row id to arrive.
fn layer_two_addressing(
    bucket: Option<String>,
    tenant: Option<String>,
) -> Result<Option<(String, String)>, String> {
    let Some(bucket) = bucket else {
        return Ok(None);
    };
    match tenant {
        Some(tenant) => Ok(Some((bucket, tenant))),
        None => Err(format!(
            "{HOLD_BUCKET_ENV} is set but {TENANT_ENV} is not, so this worker cannot address its own hold object: refusing to start rather than executing without knowing whether it is held. {TENANT_ENV} is the tenant SLUG that every hold object, IAM condition and checkpoint path is keyed by, and it is not the control plane's gateway row id"
        )),
    }
}

/// An environment variable set to something, treating empty as unset, so a provisioning template
/// with a variable declared and never filled in does not select a mode.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The `/health` projection: the state and the hold id, and nothing else.
///
/// Deliberately not the reason or `set_by`: `/health` is read by the console and by the hosted
/// fleet check, and the reason names the checkpoint a restore is promoting, which is operational
/// detail rather than something a status document should carry.
pub fn health_snapshot(hold: Option<&Arc<ExecutionHold>>) -> serde_json::Value {
    let Some(hold) = hold.filter(|h| h.is_configured()) else {
        return serde_json::Value::Null;
    };
    match hold.cached() {
        Some(held) => serde_json::json!({ "state": held.state, "hold_id": held.hold_id }),
        None => serde_json::json!({ "state": STATE_OPEN }),
    }
}

/// Build the JSON body of a hold object, for tests and for anything that has to write one.
///
/// Here rather than in a test file so the shape the gateway parses and the shape anything in this
/// repository writes cannot drift apart. The hosted scripts are the real writer; this is the
/// contract they are held to.
pub fn hold_document(tenant: &str, state: &str, hold_id: &str, reason: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "hold_version": HOLD_VERSION,
        "tenant": tenant,
        "state": state,
        "hold_id": hold_id,
        "reason": reason,
    }))
    .unwrap_or_default()
}

/// Metadata for a hold object written by a test double. Empty, because nothing reads the hold
/// object's stamped metadata: its body is the whole of it.
pub fn hold_metadata() -> BTreeMap<String, String> {
    BTreeMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objectstore::MemoryObjectStore;
    use crate::store::Store as _;

    /// A bucket named with no slug to address inside it is a worker that cannot find its own hold
    /// object, so it refuses to start rather than execute without knowing whether it is held.
    ///
    /// The row id is not consulted and cannot be: [`layer_two_addressing`] has nowhere for one to
    /// arrive. That is the point. A fallback would read `holds/gw_…/state.json`, a prefix no IAM
    /// condition covers, and a 403 at boot would look like a permissions bug rather than the wrong
    /// key.
    #[test]
    fn a_hold_bucket_with_no_tenant_slug_refuses_to_start() {
        let refused = layer_two_addressing(Some("permaura-checkpoints".into()), None)
            .expect_err("a bucket with no slug cannot be addressed");
        assert!(refused.contains(TENANT_ENV), "the message must name the right variable: {refused}");
        assert!(
            refused.contains("gateway row id"),
            "and must say which variable it is NOT: {refused}"
        );
    }

    #[test]
    fn no_hold_bucket_is_no_layer_two_at_all() {
        assert_eq!(layer_two_addressing(None, None).unwrap(), None);
        // A slug on its own is every local gateway that happens to know its own name.
        assert_eq!(layer_two_addressing(None, Some("acme".into())).unwrap(), None);
    }

    #[test]
    fn a_bucket_and_a_slug_address_the_tenants_own_prefix() {
        let (bucket, tenant) =
            layer_two_addressing(Some("permaura-checkpoints".into()), Some("acme".into()))
                .unwrap()
                .expect("both halves are configured");
        assert_eq!(bucket, "permaura-checkpoints");
        assert_eq!(hold_object(&tenant), "holds/acme/state.json");
        assert_eq!(retained_object(&tenant), "holds/acme/retained.json");
    }

    fn bucket_with(tenant: &str, body: Vec<u8>) -> Arc<MemoryObjectStore> {
        let objects = Arc::new(MemoryObjectStore::new());
        objects
            .put_if_generation(&hold_object(tenant), &body, 0, &hold_metadata())
            .unwrap();
        objects
    }

    fn open(objects: Arc<dyn ObjectStore>, env: Option<&str>) -> ExecutionHold {
        ExecutionHold::open(
            env.map(String::from),
            objects,
            "acme",
            Duration::from_millis(10),
        )
        .expect("the hold object reads")
    }

    #[test]
    fn an_explicit_open_object_permits_execution() {
        let objects = bucket_with("acme", br#"{"state":"open"}"#.to_vec());
        assert!(open(objects, None).refuse_if_held().is_ok());
    }

    #[test]
    fn a_configured_bucket_with_no_object_refuses() {
        let hold = open(Arc::new(MemoryObjectStore::new()), None);
        let err = hold.refuse_if_held().unwrap_err();
        assert!(matches!(err, GatewayError::ExecutionHeld { .. }), "got {err}");
        assert_eq!(hold.cached().unwrap().state, "absent");
    }

    #[test]
    fn an_unparseable_object_refuses() {
        let objects = bucket_with("acme", b"not json at all".to_vec());
        assert_eq!(open(objects, None).cached().unwrap().state, "unreadable");
    }

    #[test]
    fn an_object_naming_another_tenant_is_treated_as_unreadable() {
        let objects = bucket_with("acme", hold_document("other", "open", "h1", "not ours"));
        let held = open(objects, None).cached().expect("refused");
        assert_eq!(held.state, "unreadable");
        assert!(held.reason.contains("names tenant 'other'"), "{}", held.reason);
    }

    #[test]
    fn a_version_this_build_does_not_know_is_refused() {
        let body = br#"{"hold_version":99,"tenant":"acme","state":"open"}"#.to_vec();
        assert_eq!(open(bucket_with("acme", body), None).cached().unwrap().state, "unreadable");
    }

    #[test]
    fn the_object_wins_over_an_environment_that_says_open() {
        let objects = bucket_with("acme", hold_document("acme", "held", "hold_1", "a restore"));
        let held = open(objects, None).cached().expect("refused");
        assert_eq!(held.state, "held");
        assert_eq!(held.hold_id, "hold_1");
    }

    #[test]
    fn the_environment_holds_on_its_own_with_no_bucket_configured() {
        let hold = ExecutionHold::env_only(Some("hold_env".into()));
        let held = hold.cached().expect("refused");
        assert_eq!(held.hold_id, "hold_env");
        assert!(hold.is_configured());
    }

    #[test]
    fn nothing_configured_is_not_a_hold_and_reports_nothing() {
        let hold = ExecutionHold::env_only(None);
        assert!(hold.refuse_if_held().is_ok());
        assert!(!hold.is_configured());
        assert_eq!(health_snapshot(Some(&Arc::new(hold))), serde_json::Value::Null);
    }

    #[test]
    fn an_empty_environment_value_is_not_a_hold() {
        assert!(ExecutionHold::env_only(Some("   ".into())).refuse_if_held().is_ok());
    }

    #[test]
    fn the_recheck_interval_is_clamped_at_both_ends() {
        assert_eq!(clamp_interval(Duration::from_millis(1)), RECHECK_INTERVAL_BOUNDS.0);
        assert_eq!(clamp_interval(Duration::from_secs(9999)), RECHECK_INTERVAL_BOUNDS.1);
        assert_eq!(clamp_interval(Duration::from_secs(30)), Duration::from_secs(30));
    }

    // ── The replay floor ─────────────────────────────────────────────────────────────────────

    /// With no floor row, nothing about a one-time token changes. This is every gateway that has
    /// never been restored, which today is all of them.
    #[test]
    fn with_no_replay_floor_every_one_time_token_is_accepted_exactly_as_before() {
        let store = crate::store::memory::MemoryStore::new();
        assert_eq!(replay_floor(&store).unwrap(), None);
        for issued_at in [i64::MIN, 0, 1, 1_758_376_682_117, i64::MAX] {
            assert!(
                refuse_if_replayed_across_a_restore(&store, issued_at, "ticket").is_ok(),
                "issued_at {issued_at} must pass with no floor"
            );
        }
        // An empty row reads the same as no row, matching how a cleared approval-floor override is
        // recorded: the store has no delete, so "absent" is written as the empty string.
        store.put_meta(crate::store::REPLAY_FLOOR_META, "").unwrap();
        assert_eq!(replay_floor(&store).unwrap(), None);
        assert!(refuse_if_replayed_across_a_restore(&store, 1, "ticket").is_ok());
    }

    /// At or before, not strictly before: a token minted in the same millisecond as the abandoned
    /// generation's last write is one nobody can vouch for either.
    #[test]
    fn a_token_issued_at_or_before_the_replay_floor_is_refused() {
        let store = crate::store::memory::MemoryStore::new();
        let floor = 1_758_376_682_117i64;
        assert_eq!(raise_replay_floor(&store, floor).unwrap(), floor);

        for issued_at in [floor - 1, floor] {
            let err = refuse_if_replayed_across_a_restore(&store, issued_at, "step-up ticket")
                .expect_err("a token from before the restore cannot be spent");
            assert!(matches!(err, GatewayError::Unauthorized(_)), "got {err}");
            assert!(
                err.to_string().contains("restored from a checkpoint"),
                "the refusal must say why: {err}"
            );
        }
        assert!(refuse_if_replayed_across_a_restore(&store, floor + 1, "step-up ticket").is_ok());
    }

    /// The floor is raised and never lowered, and the maximum lives in one place so no call site
    /// can get the direction wrong.
    #[test]
    fn the_replay_floor_is_never_lowered() {
        let store = crate::store::memory::MemoryStore::new();
        assert_eq!(raise_replay_floor(&store, 5_000).unwrap(), 5_000);
        assert_eq!(raise_replay_floor(&store, 9_000).unwrap(), 9_000);
        assert_eq!(raise_replay_floor(&store, 1).unwrap(), 9_000, "a lower restore cannot lower it");
        assert_eq!(replay_floor(&store).unwrap(), Some(9_000));
    }

    /// An unreadable floor is not no floor. Answering `None` for a value this build cannot parse
    /// would turn somebody's typo into an open gate, which is the one direction that matters.
    #[test]
    fn an_unparseable_replay_floor_is_an_error_and_never_an_open_gate() {
        let store = crate::store::memory::MemoryStore::new();
        store.put_meta(crate::store::REPLAY_FLOOR_META, "yesterday").unwrap();
        assert!(replay_floor(&store).is_err());
        assert!(
            refuse_if_replayed_across_a_restore(&store, i64::MAX, "ticket").is_err(),
            "a token must not pass a floor nobody could read"
        );
    }

    #[test]
    fn health_reports_the_state_and_the_id_and_no_more() {
        let objects = bucket_with("acme", hold_document("acme", "reconciling", "hold_2", "secret-ish"));
        let hold = Arc::new(open(objects, None));
        let snapshot = health_snapshot(Some(&hold));
        assert_eq!(snapshot["state"], "reconciling");
        assert_eq!(snapshot["hold_id"], "hold_2");
        assert!(snapshot.get("reason").is_none(), "the reason is not a health field");
    }
}
