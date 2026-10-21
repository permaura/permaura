//! The worker dial-out client.
//!
//! A worker (the `permaura start` gateway process, when `PERMAURA_RELAY_URL`,
//! `PERMAURA_WORKER_ID` and `PERMAURA_WORKER_ORG` are set; see [`spawn_from_env`]) dials the
//! control plane's
//! `GET /v1/relay`, completes the [`run_worker_handshake`] (signing the server's challenge with
//! its enrolled key), then runs [`run_worker`]: it heartbeats and, for each relayed
//! [`InvokeRequest`], runs the **local** [`EnforcementService::invoke`] via [`handle_invoke`] and
//! returns only the redacted result. The secret is resolved and used solely on this worker:
//! it never crosses the wire. All logic runs over the [`RelayTransport`] trait, so the handshake
//! and invoke handling are tested over an in-memory transport.

pub mod approver;
pub mod keystore;
pub mod ws_client;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ed25519_dalek::SigningKey;
use rand::Rng;

use permaura_core::{Decision, ExecutionLocation};
use permaura_relay::{
    hello_preimage, request_hash, sign, ApprovalRequest,
    ApprovalResult, ChallengeRequest, Envelope, Frame, Heartbeat, Hello, InvokeRequest,
    InvokeResult, JobLedger, ProtocolVersion, RelayError, RelayOutcome, RelayTransport, Signed,
};

use crate::relay::approver::ApproverKeyring;
use crate::service::{EnforcementService, InvokeOutcome, SignedApprovalOutcome};
use crate::store::{Session, SessionRole};

/// How long a held approval stays resolvable before the worker abandons it (unix-ms TTL). A
/// relayed `ApprovalResult` that arrives after this is refused as stale (fail-closed).
/// **Zero means no expiry**, and is the default. A hold that dies on a timer is worse than one that
/// waits: the approval stayed in the pending list after expiring, so the prompt sat there refusing
/// every press with no way for the operator to tell why. Until the timeout is a setting the operator
/// chooses, waiting is the honest behaviour: the request stays held either way.
pub const APPROVAL_TTL_MS: i64 = 0;

/// Whether holds expire at all. Every TTL comparison must go through this, or a zero TTL reads as
/// "everything is already stale" and refuses instantly, the exact inversion of what it means.
pub fn approvals_expire() -> bool {
    APPROVAL_TTL_MS > 0
}

/// The absolute unix-ms moment a hold created at `created_at` is abandoned, or `None` when holds
/// do not expire at all.
///
/// Called once, when the approval is held, and the answer is stored on the row: a later change to
/// [`APPROVAL_TTL_MS`] must not move the deadline under a human who is already looking at it.
pub fn hold_expiry(created_at: i64) -> Option<i64> {
    approvals_expire().then(|| created_at + APPROVAL_TTL_MS)
}

/// Worker heartbeat cadence (must stay under the hub's miss budget).
pub const WORKER_HEARTBEAT_MS: u64 = 15_000;

/// Identity + key for a worker dial-out session.
pub struct WorkerConfig {
    /// The enrolled worker id.
    pub worker_id: String,
    /// The worker's org.
    pub org_id: String,
    /// The worker's ed25519 signing key (its public half is `Worker.pubkey`).
    pub signing_key: SigningKey,
}

/// The worker side of the relay handshake: `ChallengeRequest → recv Challenge → sign+send Hello
/// → recv AuthAck`. The Hello signature is over the server-issued challenge bound to the
/// connection, so only the holder of the worker key can complete it.
pub async fn run_worker_handshake(
    transport: &mut dyn RelayTransport,
    config: &WorkerConfig,
) -> Result<(), RelayError> {
    transport
        .send(Envelope::new(
            0,
            now_ms(),
            Frame::ChallengeRequest(ChallengeRequest {
                worker_id: config.worker_id.clone(),
                max_version: ProtocolVersion::CURRENT,
            }),
        ))
        .await?;

    let chal = match transport.recv().await?.frame {
        Frame::Challenge(c) => c,
        Frame::Error(e) => return Err(RelayError::protocol(format!("relay error: {}", e.message))),
        _ => return Err(RelayError::protocol("expected challenge")),
    };

    let preimage = hello_preimage(
        &config.worker_id,
        &config.org_id,
        &chal.challenge,
        &chal.connection_id,
        ProtocolVersion::CURRENT,
    );
    let sig = sign(&config.signing_key, &preimage);
    let hello = Hello {
        worker_id: config.worker_id.clone(),
        org_id: config.org_id.clone(),
        challenge: chal.challenge,
        connection_id: chal.connection_id,
        max_version: ProtocolVersion::CURRENT,
        platform: std::env::consts::OS.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        host_attestation: None,
    };
    transport
        .send(Envelope::new(0, now_ms(), Frame::Hello(Signed::new(hello, sig))))
        .await?;

    match transport.recv().await?.frame {
        Frame::AuthAck(ack) => {
            if !ProtocolVersion::SUPPORTED.contains(&ack.version) {
                return Err(RelayError::protocol("control plane negotiated an unsupported version"));
            }
            Ok(())
        }
        Frame::Error(e) => Err(RelayError::protocol(format!("relay rejected handshake: {}", e.message))),
        _ => Err(RelayError::protocol("expected auth_ack")),
    }
}

/// The local id of the session a relayed invoke runs as: the control plane's session id, in a namespace
/// no session this gateway issues is ever given.
pub fn relayed_session_id(cp_session_id: &str) -> String {
    format!("relay:{cp_session_id}")
}

/// Run a relayed [`InvokeRequest`] through the LOCAL enforcement service and build the redacted
/// [`InvokeResult`]. The worker recomputes `request_hash` and refuses a mismatch (a control plane
/// must not be able to alter the params after hashing). The secret is resolved and used only
/// inside `invoke`; no secret ever appears in the result.
pub async fn handle_invoke(
    service: &EnforcementService,
    worker_org: &str,
    mut req: InvokeRequest,
) -> InvokeResult {
    // Refuse a control plane that altered the params after hashing.
    if request_hash(&req.capability, &req.params) != req.request_hash {
        return denied(req.job_id, "request_hash mismatch: refusing relayed invoke");
    }
    // Tenant binding: refuse a relayed invoke for a different org than this worker serves.
    if req.session_ctx.org_id != worker_org {
        return denied(req.job_id, "org mismatch: refusing cross-org relayed invoke");
    }
    // Staleness: refuse a job already past its deadline rather than running it late.
    if now_ms() > req.deadline_ms {
        return denied(req.job_id, "deadline exceeded: refusing stale relayed invoke");
    }

    // Map the relayed identity onto a worker-local Session (identity only, no bearer crosses the
    // wire). The worker re-runs the full policy authoritatively against its own grants. The id the
    // control plane chose is namespaced so it can never name, or overwrite, a session this gateway
    // issued, and the token is random and handed to nobody, so the row authenticates nothing.
    let p = &req.session_ctx.principal;
    let session = Session {
        class: Default::default(),
        opened_by: None,
        id: relayed_session_id(&req.session_ctx.cp_session_id),
        agent_id: p.agent.clone().unwrap_or_else(|| "relay".to_string()),
        user_id: p.user.clone(),
        device_id: p.device.clone(),
        token: crate::oauth_connect::random_token(),
        // A relayed remote agent identity: invoke-only, never the control plane.
        role: SessionRole::Agent,
        created_at: now_ms(),
        revoked: false,
        // Identity-only (nobody holds the token); the cap keeps it consistent with every other agent
        // session rather than leaving an immortal row behind.
        expires_at: Some(now_ms() + crate::store::AGENT_SESSION_TTL_MS),
        last_used_at: None,
        actor: None,
    };
    // Persist the relayed session so a RequiresApproval outcome can later be resolved
    // (resolve_approval looks the session up by id), refreshing it on every relayed invoke but never
    // over a revocation. The read and the write are one unit so a revocation cannot land between them
    // and be written back over.
    let revoked = service.store().transaction(|store| {
        let mut session = session.clone();
        match store.get_session(&session.id)? {
            Some(row) if row.revoked => return Ok(true),
            // A refresh is the same identity, so the row keeps its creation time.
            Some(row) => session.created_at = row.created_at,
            None => {}
        }
        store.put_session(session)?;
        Ok(false)
    });
    match revoked {
        Ok(false) => {}
        Ok(true) => return denied(req.job_id, "session has been revoked"),
        Err(e) => return denied(req.job_id, &format!("relayed invoke failed: {e}")),
    }

    // A relayed job is remote by construction, and the frame's own field is outside `request_hash`.
    let params = crate::memory::AgentParams::uncharged(std::mem::take(&mut req.params));
    let outcome = service
        .invoke_admitted(&session, &req.capability, params, req.reason.as_deref(), ExecutionLocation::RemoteAllowed)
        .await;

    let mapped = match outcome {
        // The view-growth room is held while the view's text is, until it has been framed.
        Ok(InvokeOutcome::Allowed { decision, result, status, room: _room }) => match framed_result(service, &result).await {
            Ok(result) => RelayOutcome::Allowed { decision, result, http_status: status },
            Err(why) => RelayOutcome::Denied { decision: Decision::deny(why) },
        },
        Ok(InvokeOutcome::RequiresApproval { decision, approval }) => RelayOutcome::RequiresApproval {
            decision,
            risk: approval.risk_label(),
            approval_id: approval.id,
            message: approval.message,
            expires_at: approval.expires_at,
            action_description: approval.action_description,
        },
        Ok(InvokeOutcome::Denied { decision }) => RelayOutcome::Denied { decision },
        Err(e) => RelayOutcome::Denied {
            decision: Decision::deny(format!("relayed invoke failed: {e}")),
        },
    };
    InvokeResult { job_id: req.job_id, outcome: mapped }
}

/// Verify a relayed [`ApprovalResult`] and, only if it checks out, run the held call and return
/// the terminal [`InvokeResult`] to push on the original job. Returns `None` (after logging) on ANY
/// failure: an approval the worker cannot independently verify is never honored.
///
/// The trust anchor is `keyring`: the device key is resolved from the worker's LOCAL keyring by
/// `approver` id, never from the frame, so the control plane (which only relays these bytes)
/// can neither forge the signature nor swap in a key it controls.
pub async fn handle_approval_result(
    service: &EnforcementService,
    keyring: &ApproverKeyring,
    result: ApprovalResult,
) -> Option<InvokeResult> {
    // One verifier for both transports: signature (against the local trusted key), freshness, held
    // approval exists + pending + unexpired, request_hash re-bind, and separation of duty. Only on
    // Verified do we run the held call, and only locally on this worker.
    let outcome = {
        let _room = match service.display_room_for_signed(&result).await {
            Ok(room) => room,
            Err(e) => {
                tracing::warn!(approval = %result.approval_id, error = %e, "no room to render what the approver was shown; the relayed job stays open");
                return None;
            }
        };
        service.verify_signed_approval(keyring, &result)
    };
    match outcome {
        SignedApprovalOutcome::Refused(why) => {
            tracing::warn!(approval = %result.approval_id, reason = %why, "device-signed approval refused");
            None
        }
        SignedApprovalOutcome::AlreadyResolved(pending) => {
            // Idempotent re-delivery: surface its terminal outcome so the job still resolves.
            terminal_from_pending(service, &result.job_id, &pending).await
        }
        SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => {
            // A valid signature, recorded, but the two-person rule still wants another device.
            // The relayed job stays open (no terminal outcome) until the last signature lands.
            tracing::info!(
                approval = %result.approval_id,
                approver = %result.approver,
                collected,
                required,
                "device-signed approval recorded; awaiting more signatures"
            );
            None
        }
        SignedApprovalOutcome::Verified => {
            let (resolved, claimed) = service
                .resolve_approval_reaching_claim(&result.approval_id, result.approve, "device_signed", Some(&result.approver))
                .await;
            let resolved = match resolved {
                Ok(p) => p,
                // A refusal short of the claim (no room, a draining gateway, a pause) leaves the approval approvable again, so the job stays open with it rather than ending as a denial of a call that can still run.
                Err(e) if !claimed => {
                    tracing::warn!(approval = %result.approval_id, error = %e, "the held call was refused before its claim; its relayed job stays open");
                    return None;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "resolving the held call failed");
                    return Some(InvokeResult {
                        job_id: result.job_id,
                        outcome: RelayOutcome::Denied {
                            decision: Decision::deny(format!("approved call failed: {e}")),
                        },
                    });
                }
            };
            terminal_from_pending(service, &result.job_id, &resolved).await
        }
    }
}

/// A result as a relay frame carries it. The frame type holds a tree, so the result is built into one by the metered parse under the worker's memory budget; a result the budget cannot hold is reported as a refusal on the relay, never as its raw text.
/// The budget's charge ends with this call, while the frame and the job ledger keep the tree: the relay is outside the hosted request path.
async fn framed_result(service: &EnforcementService, result: &permaura_core::JsonText) -> Result<serde_json::Value, String> {
    service
        .memory()
        .parse(result.get().as_bytes(), 1)
        .await
        .map(|(value, _charge)| value)
        .map_err(|e| format!("the call ran, but its result could not be relayed: {e}"))
}

/// Build the terminal relay outcome from a resolved (`approved`/`denied`) approval.
async fn terminal_from_pending(
    service: &EnforcementService,
    job_id: &str,
    pending: &crate::store::PendingApproval,
) -> Option<InvokeResult> {
    let outcome = match pending.status.as_str() {
        "approved" => match (&pending.result, pending.result_status) {
            (Some(result), Some(status)) => match framed_result(service, result).await {
                Ok(result) => RelayOutcome::Allowed {
                    decision: Decision::allow("approved by human"),
                    result,
                    http_status: status,
                },
                Err(why) => RelayOutcome::Denied { decision: Decision::deny(why) },
            },
            _ => RelayOutcome::Denied {
                decision: Decision::deny("approved but produced no result"),
            },
        },
        "denied" => RelayOutcome::Denied {
            decision: Decision::deny(match pending.resolution_reason.as_deref() {
                Some(reason) => format!("the gateway refused the held call ({reason})"),
                None => "approval denied by the approver".to_string(),
            }),
        },
        _ => return None,
    };
    Some(InvokeResult { job_id: job_id.to_string(), outcome })
}

/// Run the full worker session over `transport`: handshake, then a heartbeat + dispatch loop.
/// Returns when the connection drops or a `Revoke` ends it (the caller reconnects).
pub async fn run_worker(
    transport: &mut dyn RelayTransport,
    service: &EnforcementService,
    config: &WorkerConfig,
    ledger: &mut JobLedger,
) -> Result<(), RelayError> {
    run_worker_handshake(transport, config).await?;

    let mut seq: u64 = 0;
    let mut heartbeat = tokio::time::interval(Duration::from_millis(WORKER_HEARTBEAT_MS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                seq += 1;
                transport.send(Envelope::new(
                    seq, now_ms(),
                    Frame::Heartbeat(Heartbeat { at: now_ms(), inflight: 0, serving: None }),
                )).await?;
            }
            incoming = transport.recv() => {
                let env = incoming?;
                match env.frame {
                    Frame::InvokeRequest(req) => {
                        let job_id = req.job_id.clone();
                        // Idempotency: a re-delivered job returns its cached result, not a re-run.
                        if let Ok(Some(cached)) = ledger.check(&job_id, now_ms()) {
                            let result = cached.clone();
                            seq += 1;
                            transport.send(Envelope::new(seq, now_ms(), Frame::InvokeResult(result))).await?;
                            continue;
                        }
                        let _ = ledger.mark_inflight(&job_id, now_ms());
                        // Captured before `req` is consumed, needed for the ApprovalRequest below.
                        let capability = req.capability.clone();
                        let req_hash = req.request_hash.clone();
                        let result = handle_invoke(service, &config.org_id, req).await;
                        ledger.complete(job_id.clone(), result.clone(), now_ms());
                        // A held call: note its approval id before the result is moved into the send.
                        let held = if let RelayOutcome::RequiresApproval {
                            approval_id,
                            message,
                            expires_at,
                            risk,
                            action_description,
                            ..
                        } = &result.outcome
                        {
                            Some((
                                approval_id.clone(),
                                message.clone(),
                                *expires_at,
                                risk.clone(),
                                action_description.clone(),
                            ))
                        } else {
                            None
                        };
                        seq += 1;
                        transport.send(Envelope::new(seq, now_ms(), Frame::InvokeResult(result))).await?;
                        // If the call was held for human approval, emit an ApprovalRequest so the CP
                        // can push to the approver's phone. The worker holds the call until a
                        // device-signed ApprovalResult returns; the secret is never resolved yet.
                        if let Some((approval_id, message, expires_at, risk, action_description)) = held {
                            let resource = capability
                                .split('.')
                                .next()
                                .filter(|s| !s.is_empty())
                                .unwrap_or(&capability)
                                .to_string();
                            seq += 1;
                            transport.send(Envelope::new(seq, now_ms(), Frame::ApprovalRequest(ApprovalRequest {
                                job_id,
                                approval_id,
                                capability,
                                resource,
                                message,
                                request_hash: req_hash,
                                // The deadline captured on the held row, not one recomputed here:
                                // the phone reading this frame and the console reading the REST row
                                // are looking at the same approval and must see the same moment.
                                expires_at,
                                risk,
                                action_description,
                            }))).await?;
                        }
                    }
                    Frame::ApprovalResult(result) => {
                        // A device-signed approval came back down the relay. Verify it locally against
                        // the service's shared keyring (a point-in-time snapshot, so no lock is held
                        // across the resolve) and, only if it checks out, run the held call.
                        let keyring = service.approver_keyring_snapshot();
                        if let Some(terminal) = handle_approval_result(service, &keyring, result).await {
                            ledger.complete(terminal.job_id.clone(), terminal.clone(), now_ms());
                            seq += 1;
                            transport.send(Envelope::new(seq, now_ms(), Frame::InvokeResult(terminal))).await?;
                        }
                    }
                    Frame::Revoke(_signed) => {
                        // Signed-Revoke verification against a pinned CP relay key is a tracked
                        // follow-up. Until then an UNVERIFIABLE Revoke is ignored, so a forged frame
                        // cannot kill the worker.
                        tracing::warn!("received Revoke; signed-revoke handling not yet wired: ignoring");
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Resolve when graceful shutdown is requested. With no shutdown channel (the loop runs forever)
/// this never resolves, so the `select!` arm it guards is inert. A dropped sender also counts as
/// shutdown, so a lost supervisor never wedges the worker.
async fn wait_shutdown(shutdown: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match shutdown {
        Some(rx) => {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    return; // sender dropped: treat as shutdown
                }
            }
        }
        None => std::future::pending::<()>().await,
    }
}

/// Dial the relay and run the worker session, reconnecting with capped exponential backoff on drop.
/// Runs until the process exits or `shutdown` fires. On shutdown it sends a `Close(Going)` frame so
/// the control plane sees an orderly departure (and can drop this worker's routing immediately)
/// rather than a dead socket it must time out.
pub async fn run_relay_worker_loop(
    relay_url: String,
    service: Arc<EnforcementService>,
    config: WorkerConfig,
    mut shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) {
    // The job ledger persists ACROSS reconnects so a re-delivered job_id is not re-run: the
    // "refund never runs twice" guarantee survives a drop+retry, not just one connection.
    let mut ledger = JobLedger::new(1024, 5 * 60 * 1000);
    let mut backoff = Duration::from_secs(1);
    loop {
        // Don't dial (or re-dial) once shutdown has been requested.
        if shutdown.as_ref().map(|s| *s.borrow()).unwrap_or(false) {
            return;
        }
        match ws_client::WsClientTransport::connect(&relay_url).await {
            Ok(mut transport) => {
                tracing::info!(worker = %config.worker_id, "relay connected");
                let started = std::time::Instant::now();
                // We own `transport` here, so a shutdown mid-session lets us close it cleanly. The
                // flag (rather than closing inside the select arm) keeps the borrow checker happy:
                // the `run_worker` future's `&mut transport` is released when the select completes.
                let shutting_down = tokio::select! {
                    r = run_worker(&mut transport, &service, &config, &mut ledger) => {
                        if let Err(e) = r {
                            tracing::warn!(error = %e, "relay worker session ended");
                        }
                        false
                    }
                    _ = wait_shutdown(&mut shutdown) => true,
                };
                if shutting_down {
                    let _ = transport.close(permaura_relay::CloseCode::Going).await;
                    tracing::info!(worker = %config.worker_id, "relay closed cleanly for shutdown");
                    return;
                }
                // Reset the backoff only if the session actually ran for a while, so an
                // accept-then-immediately-drop server cannot cause a tight reconnect spin.
                if started.elapsed() >= Duration::from_secs(30) {
                    backoff = Duration::from_secs(1);
                }
            }
            Err(e) => tracing::warn!(error = %e, "relay dial failed; backing off"),
        }
        let jitter = Duration::from_millis(rand::thread_rng().gen_range(0..500));
        tokio::select! {
            _ = tokio::time::sleep(backoff + jitter) => {}
            _ = wait_shutdown(&mut shutdown) => return,
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// If `PERMAURA_RELAY_URL` + `PERMAURA_WORKER_ID` + `PERMAURA_WORKER_ORG` are set, load the worker
/// key (from `PERMAURA_WORKER_KEY`, default `~/.permaura/worker.key`) and spawn the dial-out loop.
/// Returns the task handle, or `None` if relay mode is not configured. `shutdown` (a `watch` set to
/// `true` on graceful stop) makes the loop close its WS cleanly instead of being aborted mid-flight.
pub fn spawn_from_env(
    service: Arc<EnforcementService>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) -> Option<tokio::task::JoinHandle<()>> {
    let url = std::env::var("PERMAURA_RELAY_URL").ok()?;
    let worker_id = std::env::var("PERMAURA_WORKER_ID").ok()?;
    let org_id = std::env::var("PERMAURA_WORKER_ORG").ok()?;
    let key_path = match std::env::var("PERMAURA_WORKER_KEY") {
        Ok(p) => p,
        Err(_) => match default_key_path() {
            Some(p) => p,
            None => {
                tracing::error!("relay configured but no PERMAURA_HOME or home directory to place the worker key: refusing to write it to a relative path; set PERMAURA_HOME or PERMAURA_WORKER_KEY. Relay disabled.");
                return None;
            }
        },
    };
    let signing_key = match keystore::FileKeystore::new(&key_path).load_or_create() {
        Ok(k) => {
            tracing::info!(
                pubkey = %keystore::FileKeystore::public_key_b64(&k),
                "worker relay key loaded (register this pubkey at enrollment)"
            );
            k
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to load worker key; relay mode disabled");
            return None;
        }
    };
    // Approver device keys are provisioned worker-locally (PERMAURA_APPROVER_KEYS + local pairing),
    // never by the CP. The service owns the shared keyring; an empty one fails closed: relayed
    // high-risk capabilities can be triggered but never approved.
    if service.approver_keyring_snapshot().is_empty() {
        tracing::warn!(
            "no approver device keys enrolled (PERMAURA_APPROVER_KEYS or local pairing): relayed capabilities that require approval cannot be resolved"
        );
    }
    let config = WorkerConfig { worker_id, org_id, signing_key };
    Some(tokio::spawn(run_relay_worker_loop(url, service, config, shutdown)))
}

/// Build a redacted `Denied` result with a reason (for relay-side refusals: hash/org/deadline).
fn denied(job_id: String, reason: &str) -> InvokeResult {
    InvokeResult {
        job_id,
        outcome: RelayOutcome::Denied {
            decision: Decision::deny(reason),
        },
    }
}

/// `~/.permaura/worker.key`. `None` when no home resolves: the relay then refuses to start rather
/// than write the worker signing key to a relative path.
fn default_key_path() -> Option<String> {
    permaura_core::permaura_path("worker.key").map(|p| p.display().to_string())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod shutdown_tests {
    use super::wait_shutdown;
    use std::time::Duration;

    // No channel → the guard never resolves, so the select arm it protects stays inert and the
    // forever-loop keeps running.
    #[tokio::test]
    async fn wait_shutdown_none_is_inert() {
        let mut none: Option<tokio::sync::watch::Receiver<bool>> = None;
        let elapsed = tokio::time::timeout(Duration::from_millis(150), wait_shutdown(&mut none)).await;
        assert!(elapsed.is_err(), "wait_shutdown(None) must never resolve");
    }

    // Already-true → resolves immediately (shutdown requested before the loop reached the guard).
    #[tokio::test]
    async fn wait_shutdown_already_true_resolves() {
        let (tx, rx) = tokio::sync::watch::channel(true);
        let mut rx = Some(rx);
        tokio::time::timeout(Duration::from_millis(150), wait_shutdown(&mut rx))
            .await
            .expect("must resolve when the value is already true");
        drop(tx);
    }

    // Becomes true → resolves after the sender flips it.
    #[tokio::test]
    async fn wait_shutdown_on_change_resolves() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut rx = Some(rx);
        let waiter = tokio::spawn(async move { wait_shutdown(&mut rx).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "must still be waiting before the flip");
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_millis(150), waiter)
            .await
            .expect("must resolve after the value flips")
            .unwrap();
    }

    // A dropped sender counts as shutdown, so a lost supervisor can't wedge the worker forever.
    #[tokio::test]
    async fn wait_shutdown_dropped_sender_resolves() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut rx = Some(rx);
        drop(tx);
        tokio::time::timeout(Duration::from_millis(150), wait_shutdown(&mut rx))
            .await
            .expect("a dropped sender must be treated as shutdown");
    }
}
