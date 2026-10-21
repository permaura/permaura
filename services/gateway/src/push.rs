//! Enrolled approval devices + best-effort push notifications via Expo.
//!
//! An enrolled device (the operator's phone) carries the Expo push token used to notify it when an
//! action needs approval, plus (for display) the approver public key it would sign with. When an
//! approval is created, a gateway that is its own push sender fires a push to every non-revoked
//! device that registered a token, so the human can approve from the lock screen; when
//! [`crate::announce`] is configured the gateway holds no tokens and the control plane sends
//! instead (see below). Best-effort: failures are logged and never block the enforcement loop, and
//! delivery still depends on the app's APNs / Expo push credentials being configured.
//!
//! The registry is held in memory and mirrored to a `gateway_meta` row, so it survives a restart.
//! It used to be memory only, on the reasoning that the phone re-enrols on launch and a restart
//! therefore self-heals. That is true of availability and false of security: while the registry was
//! empty every approval hold announced itself to nobody, and the delayed-recovery path that has since
//! been removed treated "every paired device has been told" as a guarantee. Push delivery is still
//! best effort and still guarantees nothing, but a restart is no longer a way to arrange silence.
//!
//! A GATEWAY HOLDS A PUSH TOKEN ONLY WHEN IT IS THE SENDER. Expo's send
//! endpoint authenticates nobody, so a token is the entire credential for notifying that handset, and
//! a gateway that keeps one is a party who can be impersonated to its owner's phone. When
//! [`crate::announce`] is configured the control plane sends instead, from a server that can hold an
//! Expo credential, so this registry refuses to keep a token at all: [`DeviceRegistry::upsert`],
//! [`DeviceRegistry::register`] and the restore path all drop it, and [`DeviceRegistry::tokens`]
//! comes back empty. The device rows stay, because they carry the approver identity the console
//! displays and the pairing flow reads, which is a different thing and is not an address.
//!
//! SECURITY: the `approver_pubkey` recorded here is **NOT trusted** for verifying a device-signed
//! approval. A signing key is trusted only through `PERMAURA_APPROVER_KEYS` or the approver pairing
//! route (see [`crate::relay::approver`]): loopback-only on a self-run gateway and, on a hosted
//! worker, a step-up ticket for the first device and a trusted device's co-signature for every
//! later one.
//! This registry is for naming, push fan-out and display, and for finding the key a device
//! revocation untrusts.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// The `gateway_meta` key the registry is mirrored to.
pub const DEVICES_META: &str = "push_devices";

/// Expo's push endpoint.
const EXPO_PUSH_URL: &str = "https://exp.host/--/api/v2/push/send";

/// One enrolled approval device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Gateway-assigned device id (`device_<rand>`).
    pub id: String,
    /// Human-friendly device name shown in the console.
    pub name: String,
    /// Platform hint, `"ios"` / `"android"`.
    pub platform: Option<String>,
    /// The Expo push token. Never serialized in listings (see `list_devices` in rest), which is why
    /// [`DeviceRegistry::snapshot`] persists through [`StoredDevice`] rather than through this type.
    #[serde(skip_serializing)]
    pub push_token: Option<String>,
    /// The approver id this device would sign as (e.g. `device:sam-iphone`): shown in the
    /// console, and the trusted key a revocation of this device untrusts.
    pub approver_id: Option<String>,
    /// base64 ed25519 public key the device would sign approvals with. RECORDED, NOT TRUSTED for
    /// verification: a key is trusted only through the approver keyring (see relay::approver).
    pub approver_pubkey: Option<String>,
    /// Unix-ms enrolment time (0 for a legacy bare-token registration).
    pub enrolled_at: i64,
    /// True once revoked (a lost/rotated phone); revoked devices get no pushes and aren't trusted.
    pub revoked: bool,
}

/// A device as it is written to `gateway_meta`.
///
/// A separate type only because [`Device`] carries `#[serde(skip_serializing)]` on the push token so
/// the console listing cannot leak it, and a persisted registry with no push tokens in it would be
/// exactly the empty-notification state this persistence exists to prevent.
#[derive(Serialize, Deserialize)]
struct StoredDevice {
    id: String,
    name: String,
    platform: Option<String>,
    push_token: Option<String>,
    approver_id: Option<String>,
    approver_pubkey: Option<String>,
    enrolled_at: i64,
    revoked: bool,
}

/// Registry of the enrolled phone(s): in memory for reads, mirrored to `gateway_meta` by the service.
pub struct DeviceRegistry {
    devices: RwLock<Vec<Device>>,
    /// Whether this gateway may keep a push address at all. True only when it is the sender.
    ///
    /// Held as state rather than checked at each call site so there is one place to be wrong about
    /// it. Every way a token could enter (enrol, the legacy bare-token route, a snapshot written by
    /// an older build) goes through this flag, and none of them can be added later without meeting it.
    holds_push_tokens: AtomicBool,
}

impl Default for DeviceRegistry {
    /// A gateway that has not said otherwise is its own sender and keeps its tokens.
    fn default() -> Self {
        DeviceRegistry::new(true)
    }
}

impl DeviceRegistry {
    /// Build a registry, saying whether this gateway is the party that sends notifications.
    ///
    /// `false` when [`crate::announce`] is configured: the control plane sends, so an address here
    /// would be a credential kept for nothing. See the module docs.
    pub fn new(holds_push_tokens: bool) -> Self {
        DeviceRegistry {
            devices: RwLock::new(Vec::new()),
            holds_push_tokens: AtomicBool::new(holds_push_tokens),
        }
    }

    /// Whether this gateway keeps push addresses. False means the control plane is the sender.
    pub fn holds_push_tokens(&self) -> bool {
        self.holds_push_tokens.load(Ordering::SeqCst)
    }

    /// Change whether this gateway is the sender, for a gateway that starts or stops announcing while
    /// it runs. Handing the job to the control plane drops every address held, under the same lock
    /// that admits new ones, so none can slip in between. Returns true when an address was dropped,
    /// so the caller can rewrite the stored row.
    pub fn set_holds_push_tokens(&self, holds: bool) -> bool {
        let mut devices = self.devices.write().expect("device registry lock not poisoned");
        self.holds_push_tokens.store(holds, Ordering::SeqCst);
        if holds {
            return false;
        }
        let mut dropped = false;
        for d in devices.iter_mut() {
            dropped |= d.push_token.take().is_some();
        }
        dropped
    }

    /// The whole registry as JSON, for the service to write to `gateway_meta` after every mutation.
    pub fn snapshot(&self) -> Result<String, serde_json::Error> {
        let devices = self.devices.read().expect("device registry lock not poisoned");
        let stored: Vec<StoredDevice> = devices
            .iter()
            .map(|d| StoredDevice {
                id: d.id.clone(),
                name: d.name.clone(),
                platform: d.platform.clone(),
                push_token: d.push_token.clone(),
                approver_id: d.approver_id.clone(),
                approver_pubkey: d.approver_pubkey.clone(),
                enrolled_at: d.enrolled_at,
                revoked: d.revoked,
            })
            .collect();
        serde_json::to_string(&stored)
    }

    /// Replace the registry with a persisted snapshot. Called once, at construction. A snapshot that
    /// will not parse is dropped rather than propagated: the registry drives notifications and
    /// nothing else, so refusing to start over it would trade a degraded announcement for no gateway.
    ///
    /// Returns true when a token was dropped on the way in, so the caller can rewrite the stored row
    /// and stop the old address surviving another restart. A snapshot written before this gateway
    /// started announcing still carries addresses; reading one is the only way they can arrive now.
    pub fn restore(&self, json: &str) -> bool {
        let Ok(stored) = serde_json::from_str::<Vec<StoredDevice>>(json) else {
            tracing::warn!("the persisted push registry is not readable; starting with none");
            return false;
        };
        let mut dropped = false;
        let mut devices = self.devices.write().expect("device registry lock not poisoned");
        *devices = stored
            .into_iter()
            .map(|d| {
                let push_token = if self.holds_push_tokens() {
                    d.push_token
                } else {
                    dropped |= d.push_token.is_some();
                    None
                };
                Device {
                    id: d.id,
                    name: d.name,
                    platform: d.platform,
                    push_token,
                    approver_id: d.approver_id,
                    approver_pubkey: d.approver_pubkey,
                    enrolled_at: d.enrolled_at,
                    revoked: d.revoked,
                }
            })
            .collect();
        dropped
    }

    /// Whether a non-revoked device already signs as `approver_id`. The question
    /// `POST /v1/devices/enroll` has to ask before it lets an operator bearer replace an entry.
    pub fn has_approver(&self, approver_id: &str) -> bool {
        self.devices
            .read()
            .expect("device registry lock not poisoned")
            .iter()
            .any(|d| !d.revoked && d.approver_id.as_deref() == Some(approver_id))
    }

    /// Enroll (or replace) a device. Drops any existing entry sharing the same id, push token, or
    /// approver id, so a phone re-enrolling on launch updates in place rather than duplicating.
    ///
    /// The push token is discarded entirely when this gateway is not the sender. An old app build
    /// still sends one and a caller can always be persuaded to; neither should be able to put an
    /// address back into a store that has no business holding it.
    pub fn upsert(&self, mut device: Device) {
        let mut devices = self.devices.write().expect("device registry lock not poisoned");
        if !self.holds_push_tokens() {
            device.push_token = None;
        }
        devices.retain(|d| {
            d.id != device.id
                && (device.push_token.is_none() || d.push_token != device.push_token)
                && (device.approver_id.is_none() || d.approver_id != device.approver_id)
        });
        devices.push(device);
    }

    /// Legacy `POST /v1/devices/push-token`: register a bare Expo token as an unnamed device. A
    /// token already present (named or bare) is left as-is.
    ///
    /// A whole no-op when this gateway is not the sender. The route stays and still answers, because
    /// an older app build calling it should not see an error for something that is no longer its job;
    /// what it must not do is leave the address behind.
    pub fn register(&self, token: String) {
        if !self.holds_push_tokens() {
            return;
        }
        let token = token.trim().to_string();
        if token.is_empty() {
            return;
        }
        {
            let devices = self.devices.read().expect("device registry lock not poisoned");
            if devices.iter().any(|d| d.push_token.as_deref() == Some(token.as_str())) {
                return;
            }
        }
        let suffix: String = token.chars().rev().take(6).collect::<String>().chars().rev().collect();
        self.upsert(Device {
            id: format!("device_anon_{suffix}"),
            name: "Phone".to_string(),
            platform: None,
            push_token: Some(token),
            approver_id: None,
            approver_pubkey: None,
            enrolled_at: 0,
            revoked: false,
        });
    }

    /// A snapshot of every device (revoked included; the console shows + can prune them).
    pub fn list(&self) -> Vec<Device> {
        self.devices.read().expect("device registry lock not poisoned").clone()
    }

    /// The most recently enrolled non-revoked device that signs as `approver_id`, if any, for the
    /// device name shown beside an approval or a key change. Pairing does not read the pubkey
    /// recorded here: it verifies the possession proof in the pairing request itself.
    pub fn find_by_approver(&self, approver_id: &str) -> Option<Device> {
        self.devices
            .read()
            .expect("device registry lock not poisoned")
            .iter()
            .rev()
            .find(|d| !d.revoked && d.approver_id.as_deref() == Some(approver_id))
            .cloned()
    }

    /// The device id that signs as `approver_id` (non-revoked), for wiring a device revocation
    /// through to its trusted key.
    pub fn approver_for_device(&self, device_id: &str) -> Option<String> {
        self.devices
            .read()
            .expect("device registry lock not poisoned")
            .iter()
            .find(|d| d.id == device_id)
            .and_then(|d| d.approver_id.clone())
    }

    /// Mark a device revoked (a lost/rotated phone). Returns false if no such device.
    pub fn revoke(&self, id: &str) -> bool {
        let mut devices = self.devices.write().expect("device registry lock not poisoned");
        match devices.iter_mut().find(|d| d.id == id) {
            Some(d) => {
                d.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Non-revoked devices' Expo push tokens, for the approval notification fan-out.
    pub fn tokens(&self) -> Vec<String> {
        self.devices
            .read()
            .expect("device registry lock not poisoned")
            .iter()
            .filter(|d| !d.revoked)
            .filter_map(|d| d.push_token.clone())
            .collect()
    }
}

/// The notification category the phone registers Review and Deny against. Must match
/// `APPROVAL_CATEGORY` in the app's `lib/push.ts`; there is no shared type across that boundary.
pub const APPROVAL_CATEGORY: &str = "permaura.approval";

/// What every approval push says, whoever sends it.
///
/// The notification is a doorbell, not a message. See [`send_expo_push`] for why the text is fixed
/// rather than describing the action.
const APPROVAL_TITLE: &str = "Permaura";
const APPROVAL_BODY: &str = "An approval needs you";
/// The after-the-fact `notify` rung, which is not a decision and must not read like one.
const EXECUTED_BODY: &str = "An action ran unattended";
/// An agent has enrolled and can do nothing until somebody approves it.
const AGENT_BODY: &str = "A new agent is waiting";

/// Which of the fixed notifications to ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushKind {
    /// Something is held and waiting for a human.
    ApprovalRequested,
    /// A `notify`-rung action already ran. Nothing to decide.
    Executed,
    /// An agent enrolled and is sitting Pending. A decision, but on a different screen.
    AgentPending,
}

impl PushKind {
    fn body(self) -> &'static str {
        match self {
            PushKind::ApprovalRequested => APPROVAL_BODY,
            PushKind::Executed => EXECUTED_BODY,
            PushKind::AgentPending => AGENT_BODY,
        }
    }

    /// The `data.type` the app routes on. An agent lands on the Agents screen, not on an approval
    /// card it would fetch and be told does not exist.
    fn route(self) -> &'static str {
        match self {
            PushKind::AgentPending => "agent",
            _ => "approval",
        }
    }

    /// Whether the notification may carry the Review/Deny actions and ride above a Focus.
    ///
    /// Only a held approval. The category would put a Deny button on a notification whose screen
    /// cannot deny anything, and the `notify` rung has already run. An agent waits indefinitely, so
    /// it does not need the interruption level that an expiring decision does.
    fn decidable(self) -> bool {
        matches!(self, PushKind::ApprovalRequested)
    }
}

/// Fire a push to every registered token via Expo's push API. Best-effort: never returns
/// an error to the caller, logs problems, and is meant to be `tokio::spawn`ed (detached)
/// from the enforcement loop so it never delays the agent's response.
///
/// THE TEXT IS FIXED, AND THAT IS THE SECURITY PROPERTY.
///
/// Expo's send endpoint takes no sender authentication, so possession of an `ExponentPushToken[…]`
/// is the entire credential, and a gateway that sends its own pushes (one with no
/// [`crate::announce`] link configured) holds one for every phone enrolled with it, because it must
/// in order to notify them. Anyone who can read that gateway's store can deliver a notification to
/// those phones.
///
/// What they can deliver is what this function decides: the wire carries one of three fixed
/// sentences plus an id, so a stolen token buys a doorbell with no content to lie with, rather than
/// a Focus-bypassing, Permaura-branded banner with Review and Deny buttons that could say anything.
/// The phone fills in who and what from its own authenticated fetch before it renders the card; the
/// notification is never the source of that detail.
///
/// This bounds the exposure for a gateway that is its own sender rather than closing it. A gateway
/// with announce configured holds no push token at all (see [`DeviceRegistry::holds_push_tokens`]),
/// and the control plane, which can hold an Expo credential, sends instead.
pub async fn send_expo_push(tokens: Vec<String>, kind: PushKind, approval_id: String) {
    if tokens.is_empty() {
        return;
    }
    let messages = push_messages(&tokens, kind, &approval_id);

    let client = match reqwest::Client::builder().build() {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!("push: failed to build http client: {e}");
            return;
        }
    };

    match client
        .post(EXPO_PUSH_URL)
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .json(&messages)
        .send()
        .await
    {
        Ok(resp) => tracing::debug!(
            status = resp.status().as_u16(),
            devices = tokens.len(),
            "push: approval notification sent"
        ),
        Err(e) => tracing::warn!("push: send failed (best-effort): {e}"),
    }
}

/// Build the Expo message bodies. Pure, so the one thing that matters about them (that they carry
/// no detail of the action) is testable without a network.
fn push_messages(tokens: &[String], kind: PushKind, approval_id: &str) -> Vec<serde_json::Value> {
    tokens
        .iter()
        .map(|to| {
            let mut msg = serde_json::json!({
                "to": to,
                "title": APPROVAL_TITLE,
                "body": kind.body(),
                "sound": "default",
                "priority": "high",
                "data": { "type": kind.route(), "approval_id": approval_id },
            });
            if kind.decidable() {
                let m = msg.as_object_mut().expect("push message is an object");
                // The notification category the phone registers its Review and Deny actions
                // against. Without it the actions exist in the app but can never appear on a
                // notification. Additive: a client that does not know the category ignores it.
                m.insert("categoryId".into(), serde_json::json!(APPROVAL_CATEGORY));
                // An approval expires. Queued behind a Focus it is simply missed, which is the one
                // outcome this notification exists to prevent.
                m.insert("interruptionLevel".into(), serde_json::json!("time-sensitive"));
            }
            msg
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything a caller could pass that must NOT reach the wire. The send
    /// is unauthenticated, so whatever is in the body is
    /// what a stolen push token lets somebody else say.
    #[test]
    fn a_push_carries_no_detail_of_the_action() {
        let tokens = vec!["ExponentPushToken[aaaa]".to_string()];
        for kind in [PushKind::ApprovalRequested, PushKind::Executed, PushKind::AgentPending] {
            let body = serde_json::to_string(&push_messages(&tokens, kind, "appr_secret1")).unwrap();
            // The id is deliberately present: it is the handle the app fetches the real card by,
            // and it names nothing on its own.
            assert!(body.contains("appr_secret1"));
            // Nothing else about the action may be. These are the values the call sites used to
            // interpolate: the approval's message, the capability, and the connection.
            for leaked in ["stripe.refunds.create", "conn_stripe_prod", "Refund GBP 42.00"] {
                assert!(!body.contains(leaked), "{kind:?} leaked {leaked}");
            }
            // By key, not just by value: a future edit that adds one of these fields fails here even
            // if whatever it puts in them looks harmless in this fixture.
            let msgs = push_messages(&tokens, kind, "appr_secret1");
            let data = msgs[0]["data"].as_object().expect("data");
            for forbidden in ["params", "message", "resource", "capability", "result"] {
                assert!(!data.contains_key(forbidden), "{kind:?} grew a {forbidden} field");
            }
            assert_eq!(
                data.keys().collect::<Vec<_>>(),
                vec!["approval_id", "type"],
                "the payload is an id and a routing hint, and adding to it is the thing to notice"
            );
        }
    }

    /// The two fixed sentences, and the fact that they are fixed. A future edit that reaches for a
    /// caller-supplied string has to delete this test to do it.
    #[test]
    fn the_body_is_one_of_two_fixed_sentences() {
        let tokens = vec!["ExponentPushToken[aaaa]".to_string()];
        let held = push_messages(&tokens, PushKind::ApprovalRequested, "a");
        assert_eq!(held[0]["title"], APPROVAL_TITLE);
        assert_eq!(held[0]["body"], APPROVAL_BODY);
        let ran = push_messages(&tokens, PushKind::Executed, "");
        assert_eq!(ran[0]["body"], EXECUTED_BODY);
        // An after-the-fact notice must not read as a decision that is still open.
        assert_ne!(ran[0]["body"], held[0]["body"]);
    }

    fn phone(token: &str) -> Device {
        Device {
            id: "device_1".into(),
            name: "iPhone".into(),
            platform: Some("ios".into()),
            push_token: Some(token.into()),
            approver_id: Some("device:sam-iphone".into()),
            approver_pubkey: Some("AAAA".into()),
            enrolled_at: 1,
            revoked: false,
        }
    }

    /// The push-token regression: a gateway whose notifications are sent
    /// by the control plane must not hold an address at all, whatever anybody hands it.
    ///
    /// Every way a token can arrive is exercised, because the hole is not one route: it is the
    /// registry being willing to keep one. An old app build still sends `push_token` on enrol, the
    /// legacy bare-token route still exists, and a snapshot written before announcing was switched on
    /// still carries addresses from then.
    #[test]
    fn a_gateway_that_does_not_send_keeps_no_push_address() {
        let reg = DeviceRegistry::new(false);

        reg.upsert(phone("ExponentPushToken[enrolled]"));
        reg.register("ExponentPushToken[bare]".into());
        let dropped = reg.restore(
            r#"[{"id":"device_old","name":"iPhone","platform":"ios",
                 "push_token":"ExponentPushToken[persisted]","approver_id":"device:old",
                 "approver_pubkey":null,"enrolled_at":1,"revoked":false}]"#,
        );

        assert!(dropped, "a restore that drops an address must say so, or the row survives a restart");
        assert!(reg.tokens().is_empty(), "the fan-out list is the whole exposure");
        let snapshot = reg.snapshot().expect("snapshot");
        for address in ["ExponentPushToken[enrolled]", "ExponentPushToken[bare]", "ExponentPushToken[persisted]"] {
            assert!(!snapshot.contains(address), "the persisted registry kept {address}");
        }
        // The device rows themselves stay: the approver identity is what the console shows and the
        // pairing flow reads, and it is not an address.
        assert_eq!(reg.list().len(), 1);
        assert_eq!(reg.list()[0].approver_id.as_deref(), Some("device:old"));
    }

    /// The other half of the same rule, so the flag cannot be read as "never hold one". A self-run
    /// gateway that announces to nobody is still the only party who can notify its operator, and
    /// taking the address away there would take the notification away with it.
    #[test]
    fn a_gateway_that_does_send_still_keeps_the_address_it_needs() {
        let reg = DeviceRegistry::new(true);
        reg.upsert(phone("ExponentPushToken[mine]"));
        assert_eq!(reg.tokens(), vec!["ExponentPushToken[mine]".to_string()]);
        assert!(!reg.restore(
            r#"[{"id":"d","name":"n","platform":null,"push_token":"ExponentPushToken[kept]",
                 "approver_id":null,"approver_pubkey":null,"enrolled_at":0,"revoked":false}]"#
        ));
        assert_eq!(reg.tokens(), vec!["ExponentPushToken[kept]".to_string()]);
    }

    /// A self-run gateway linked while it runs becomes an announcing one without a restart, so the
    /// addresses it was holding as the sender have to go at that moment, and new ones stay out.
    #[test]
    fn handing_the_job_to_the_control_plane_drops_the_addresses_already_held() {
        let reg = DeviceRegistry::new(true);
        reg.upsert(phone("ExponentPushToken[held]"));

        assert!(reg.set_holds_push_tokens(false), "dropping an address must say so");
        assert!(reg.tokens().is_empty());
        assert!(!reg.snapshot().expect("snapshot").contains("ExponentPushToken[held]"));
        assert_eq!(reg.list().len(), 1, "the device itself stays; only its address goes");

        reg.register("ExponentPushToken[late]".into());
        assert!(reg.tokens().is_empty(), "an address arriving after the switch is refused");

        // Unlinking hands the job back, and from then on an address is worth keeping again.
        assert!(!reg.set_holds_push_tokens(true));
        reg.upsert(phone("ExponentPushToken[again]"));
        assert_eq!(reg.tokens(), vec!["ExponentPushToken[again]".to_string()]);
    }

    /// One message per device, each addressed to its own token and to no other.
    #[test]
    fn every_registered_device_gets_its_own_message() {
        let tokens = vec![
            "ExponentPushToken[aaaa]".to_string(),
            "ExponentPushToken[bbbb]".to_string(),
        ];
        let msgs = push_messages(&tokens, PushKind::ApprovalRequested, "a");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["to"], tokens[0]);
        assert_eq!(msgs[1]["to"], tokens[1]);
    }
}
