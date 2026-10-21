//! The gateway as an OAuth 2.0 **Resource Server**.
//!
//! When the gateway has a public URL (`PERMAURA_PUBLIC_URL`, set once it is reachable via a
//! tunnel or a hosted address), it speaks the MCP Authorization spec (2025-06-18): it
//! validates **access-token JWTs minted by permaura.com** (the Authorization Server) *offline*
//! against the AS's JWKS, so a remote MCP client (ChatGPT / Claude) authenticates once at
//! permaura.com and then talks **directly** to the gateway: the control plane never sees the
//! traffic.
//!
//! ## Design choices
//! - **EdDSA (Ed25519) only**, verified with the `ed25519-dalek` + `base64` already in the
//!   gateway: no new crypto backend, no C toolchain. Better Auth's `jwt()` plugin signs with
//!   EdDSA by default, so this matches our AS. (RS256 can be added later via `jsonwebtoken`.)
//! - **Audience-bound:** a token is accepted only if its `aud` is *this* gateway's canonical
//!   MCP URL or one listed in `PERMAURA_PUBLIC_URL_ALIASES` (RFC 8707), so a token minted for
//!   another gateway is rejected.
//! - **Offline + cached:** the JWKS is fetched in the background and cached; verification is
//!   synchronous against the cache (keeps `authenticate()` sync), and a cache miss wakes the
//!   refresher early (rate-limited on the clock alone, so an unauthenticated caller cannot use it
//!   to amplify traffic at the AS), so the client's retry succeeds after key rotation or after a
//!   cold start that raced an unreachable AS.
//!
//! The same machinery also verifies **step-up tickets** ([`OAuthRs::verify_ticket`]): a second,
//! short-lived token class the AS mints only after a fresh re-authentication. A hosted gateway
//! (Mode C, a per-tenant Cloud Run worker) has no loopback client, so the "a human is physically
//! at this machine" signal that guards device enrolment on a local gateway does not exist there;
//! a ticket replaces it for pairing, revocation and lowering the approval floor. A self-run gateway
//! that is an OAuth resource server also accepts tickets for recovery, for revoking a device from
//! off its machine, and for issuing recovery codes from off its machine. Tickets are bound to a
//! per-endpoint audience rather than the MCP resource, so an access token and a ticket are
//! structurally non-interchangeable.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

/// URL-safe base64 without padding: the JOSE encoding for JWT segments and JWK values.
fn b64url(input: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input.as_bytes())
        .map_err(|e| format!("base64url: {e}"))
}

/// Static configuration for the RS, derived from env. Absent (`None`) for a pure-local gateway,
/// which then accepts only its own opaque tokens (no OAuth).
#[derive(Debug, Clone)]
pub struct RsConfig {
    /// The gateway's public base URL, e.g. `https://g-abc.permaura.com`.
    pub public_url: String,
    /// The canonical MCP resource URI = `{public_url}/mcp`. A token's `aud` must equal this, or one
    /// of [`Self::public_url_aliases`].
    pub mcp_resource: String,
    /// Other public URLs whose audiences are still honoured, from `PERMAURA_PUBLIC_URL_ALIASES`.
    ///
    /// Accepted, never advertised: discovery keeps naming [`Self::mcp_resource`] alone, so new tokens
    /// are always minted for the canonical name and an alias only ever drains. It exists so a gateway
    /// can be MOVED to a new hostname without invalidating tokens agents already hold. Point
    /// `PERMAURA_PUBLIC_URL` at the new name, list the old one here, and both verify until the old
    /// name is retired. Without it a rename is a hard cutover that 401s every connected agent until
    /// each re-runs its OAuth flow, which for an unattended agent is not a recovery at all.
    pub public_url_aliases: Vec<String>,
    /// The Authorization Server issuer, e.g. `https://permaura.com`.
    pub issuer: String,
    /// Where to fetch the AS signing keys (JWKS).
    pub jwks_uri: String,
    /// The paired operator's user id (`sub` of the tokens this gateway accepts). The RS only runs on
    /// a **publicly-reachable** gateway (it is built only when `PERMAURA_PUBLIC_URL` is set), whose
    /// MCP audience is discoverable (DNS / CT logs), so a valid-audience token alone is NOT proof of
    /// authorisation by this gateway's operator. A token is accepted only if its `sub` equals this.
    /// If unset, the gateway **fails closed** (rejects every remote token) rather than silently
    /// dropping tenant isolation on a public host. The web tunnel-provisioning path always sets it
    /// (`PERMAURA_OWNER_SUB`); `None` only happens via misconfiguration or a hand-run gateway.
    ///
    /// The pin at boot. The live binding is [`OAuthRs::owner_sub`]: when the organization's owner changes, permaura.com names the new one in the answer to this gateway's check-in and the RS moves to it.
    pub owner_sub: Option<String>,
}

impl RsConfig {
    /// Build from env. Returns `None` (RS disabled) when `PERMAURA_PUBLIC_URL` is unset.
    ///
    /// Does NOT check the scheme. [`validate_public_url`] does, at startup, so a bad value stops the
    /// boot instead of arriving here as a half-built resource server.
    pub fn from_env() -> Option<Self> {
        let public_url = std::env::var("PERMAURA_PUBLIC_URL")
            .ok()
            .map(|s| s.trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())?;
        // Better Auth's oauth-provider issuer is `{baseURL}/api/auth`, so the gateway must match
        // it (the JWT `iss` claim carries this exact value). JWKS hangs off the same base.
        let issuer = std::env::var("PERMAURA_AS_ISSUER")
            .unwrap_or_else(|_| "https://permaura.com/api/auth".to_string())
            .trim_end_matches('/')
            .to_string();
        let jwks_uri =
            std::env::var("PERMAURA_AS_JWKS").unwrap_or_else(|_| format!("{issuer}/jwks"));
        let owner_sub = std::env::var("PERMAURA_OWNER_SUB")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        // Comma- or whitespace-separated. A hostname that equals the canonical one is dropped rather
        // than duplicated, so a redeploy that lists the current name is a no-op instead of a config
        // that verifies the same audience twice.
        let public_url_aliases = parse_public_url_aliases(
            &std::env::var("PERMAURA_PUBLIC_URL_ALIASES").unwrap_or_default(),
            &public_url,
        );
        Some(RsConfig {
            mcp_resource: format!("{public_url}/mcp"),
            public_url,
            public_url_aliases,
            issuer,
            jwks_uri,
            owner_sub,
        })
    }

    /// Every MCP resource URI a token may be addressed to: the canonical one, then any alias.
    pub fn accepted_mcp_resources(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(1 + self.public_url_aliases.len());
        out.push(self.mcp_resource.clone());
        out.extend(self.public_url_aliases.iter().map(|u| format!("{u}/mcp")));
        out
    }

    /// Every audience a pairing ticket for `path` may carry. Same aliasing rule as the MCP resource:
    /// a ticket minted against the old hostname stays spendable across a rename, and the ticket's
    /// audience is still pinned to ONE route so it cannot be presented as an access token.
    pub fn accepted_ticket_audiences(&self, path: &str) -> Vec<String> {
        let mut out = Vec::with_capacity(1 + self.public_url_aliases.len());
        out.push(format!("{}{path}", self.public_url));
        out.extend(
            self.public_url_aliases
                .iter()
                .map(|u| format!("{u}{path}")),
        );
        out
    }
}

/// Refuse a public URL this gateway has no business serving.
///
/// The gateway cannot terminate TLS (it has no inbound TLS dependency at all, only outbound
/// rustls), so `PERMAURA_PUBLIC_URL` never describes something this process encrypts. It describes what a *proxy or tunnel in front of it* is publishing. If
/// that is `http://`, then every remote agent's bearer token, and every response the gateway
/// gives it, crosses the internet in the clear.
    ///
/// Refusing is the only honest answer, and refusing at boot rather than per-request is what makes
/// it useful: a gateway that started, reported healthy, and then leaked tokens is the failure this
/// prevents. The console has always rejected a non-https BYO URL, so nothing that went through the
/// documented path is affected; what this closes is the hand-run gateway that never touched it.
    ///
/// `PERMAURA_ALLOW_INSECURE_PUBLIC_URL=1` opts back out, matching `PERMAURA_ALLOW_INSECURE_VAULT`
/// in [`crate::service::vault_passphrase`], for a throwaway box someone is poking at, and it says
/// so on every boot rather than once.
pub fn validate_public_url() -> Result<(), String> {
    let Some(public_url) = std::env::var("PERMAURA_PUBLIC_URL")
        .ok()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
    else {
        return Ok(());
    };
    check_scheme(&public_url)
}

fn check_scheme(public_url: &str) -> Result<(), String> {
    if public_url.starts_with("https://") {
        return Ok(());
    }
    if crate::service::truthy_env("PERMAURA_ALLOW_INSECURE_PUBLIC_URL") {
        tracing::error!(
            public_url,
            "INSECURE: this gateway is advertising a non-https public URL because \
             PERMAURA_ALLOW_INSECURE_PUBLIC_URL is set. Every remote agent's bearer token and every \
             response crosses the network in the clear. Never do this with real credentials."
        );
        return Ok(());
    }
    Err(format!(
        "PERMAURA_PUBLIC_URL is {public_url}, which is not https. The gateway cannot terminate TLS \
         itself, so this address is whatever your tunnel or reverse proxy publishes: over plain \
         http every remote agent's token and every response travel in the clear. Put a \
         TLS-terminating proxy or tunnel in front and give its https address here. To override on a \
         throwaway install, set PERMAURA_ALLOW_INSECURE_PUBLIC_URL=1."
    ))
}

/// The validated claims we care about from an access-token JWT.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    /// The OAuth subject: the **end user** who consented (the operator's account id), NOT the agent.
    pub sub: String,
    /// The authorized party (`azp`): the per-client DCR id. THIS is the agent identity: each MCP
    /// client (ChatGPT / Claude / Cursor) self-registers separately, so `azp` distinguishes them
    /// even when the same operator consented for all of them. `None` only for tokens that omit it.
    pub azp: Option<String>,
    /// A display name for the agent (the registered client name), if the AS included one.
    pub name: Option<String>,
    /// The token's space-delimited `scope`, when present. Carries the operator grant: a token minted
    /// server-side by the console for its own use asks for [`OPERATOR_SCOPE`], which the authorize
    /// flow can never issue, so an agent's token cannot claim it. See [`VerifiedClaims::is_operator`].
    pub scope: Option<String>,
    /// The workspace member acting behind `sub`, from the same `act_sub`/`act_name`/`act_role` claims a pairing ticket uses, plus the console's signed `vault_export` claim.
    /// This is an actor claim, not the addressing pin `sub` is, and two authorization decisions read it: `actor.sub` and `actor.vault_export` decide whether a remote caller may change where a stored credential goes (`rest::may_move_a_credential`), and `actor.sub` becomes the requester of a held change, so that member's own devices cannot confirm it alone (`rest::requester_of`).
    /// Both narrow what the token's `sub` (the owner, on every console token) allows; neither widens it. `actor.name` and `actor.role` are recorded for the audit chain and authorize nothing: the owner-or-admin standing checks read [`PairingTicket::actor_role`] off a step-up ticket instead.
    /// Absent means "not named", never "the owner". See [`crate::store::SessionActor`].
    pub actor: Option<crate::store::SessionActor>,
}

/// The scope that marks a token as the CONSOLE acting as the operator, rather than an agent acting on
/// the operator's behalf. Deliberately absent from the AS's requestable-scope list: it is only ever
/// minted server-to-server, so no client, self-registered or otherwise, can request it.
pub const OPERATOR_SCOPE: &str = "permaura:operator";

/// The scope an MCP client asks for when it signs in to act as an agent, and the one the consent page describes as access to the gateway. A token without it was consented for identity only ("sign in with Permaura"), so it opens no agent session.
pub const MCP_SCOPE: &str = "mcp";

/// The refusal [`OAuthRs::verify`] gives a token that passed every check but its expiry. See [`OAuthRs::lapsed`].
pub const TOKEN_EXPIRED: &str = "token expired";

/// The refusal every token gets once [`OAuthRs::withdraw`] has run.
pub const REMOTE_ACCESS_OFF: &str = "remote access was turned off on this gateway; it accepts no permaura.com token until it restarts with remote access on";

impl VerifiedClaims {
    /// Whether the space-delimited `scope` names `scope` exactly.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope
            .as_deref()
            .is_some_and(|s| s.split_whitespace().any(|tok| tok == scope))
    }

    /// Whether this token may act as an agent: it carries [`MCP_SCOPE`].
    pub fn is_agent(&self) -> bool {
        self.has_scope(MCP_SCOPE)
    }

    /// Whether this token grants the operator/control plane. Exact token match on a space-delimited
    /// scope string, never a substring test, which `permaura:operator-readonly` would satisfy.
    pub fn is_operator(&self) -> bool {
        self.has_scope(OPERATOR_SCOPE)
    }
}

/// What a step-up ticket authorises. Each variant is a *different token class*, not a flag
/// on one class: it fixes both the `purpose` claim the AS must set and the audience the ticket is
/// minted for, so a ticket that would re-open bearer approvals can never be spent enrolling a key
/// (or the reverse) even if a future AS change gets the `purpose` claim wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketPurpose {
    /// Enrol a device signing key: `POST /v1/approver-keys/pair`.
    ApproverPair,
    /// Lower the approval floor, re-opening bearer-tier resolutions: the lowering branch of
    /// `PUT /v1/approval-floor`. Raising the floor is fail-safe and needs no ticket.
    ApprovalFloorLower,
    /// Revoke one approver key, bound to its approver id: every revocation made away from a self-run gateway's own machine, except one that would empty a self-run keyring, which a [`TicketPurpose::Recovery`] ticket may carry instead.
    ApproverRevoke,
    /// Recover a SELF-RUN gateway whose trusted device is gone: the lowering branch of
    /// `PUT /v1/approval-floor` and the revocation that empties the keyring, on a gateway that is an
    /// OAuth resource server.
    ///
    /// One purpose for both controls rather than two, because on a self-run gateway they are one
    /// decision. Hosted keeps [`TicketPurpose::ApprovalFloorLower`] and
    /// [`TicketPurpose::ApproverRevoke`] separate because there the ticket is the ORDINARY
    /// authority for each control and they are reached independently; here it is the recovery
    /// authority for the single situation "the device is gone", and splitting it would make an owner
    /// re-authenticate twice to walk one path.
    ///
    /// It exists because the alternative was a timer. A delayed path that completed on its own gave
    /// the operator bearer everything it needed: notification delivery is best effort, so an attacker
    /// holding the bearer could silence the announcement and simply wait. A clock is not an
    /// authority. This is one the bearer does not carry.
    Recovery,
    /// Issue a fresh recovery code set on a SELF-RUN gateway from anywhere but its own machine:
    /// `POST /v1/recovery-codes`. Required beside the device signature (or current code) the route
    /// already takes, because a new set voids the one on paper and hands over the floor's recovery
    /// authority. Never bound to an approver: the signature in the same request names the device.
    RecoveryCodesIssue,
}

impl TicketPurpose {
    /// The exact value the ticket's `purpose` claim must carry.
    pub fn claim(self) -> &'static str {
        match self {
            TicketPurpose::ApproverPair => "approver-pair",
            TicketPurpose::ApprovalFloorLower => "approval-floor-lower",
            TicketPurpose::ApproverRevoke => "approver-revoke",
            TicketPurpose::Recovery => "recovery",
            TicketPurpose::RecoveryCodesIssue => "recovery-codes-issue",
        }
    }

    /// The single-use ledger scope the caller spends the ticket's `jti` under. Namespaced per
    /// purpose so a jti spent for one purpose cannot mark a different purpose's ticket as spent,
    /// and so neither can collide with any other single-use key in the same store.
    pub fn scope(self) -> &'static str {
        match self {
            TicketPurpose::ApproverPair => "ticket:approver-pair",
            TicketPurpose::ApprovalFloorLower => "ticket:approval-floor-lower",
            TicketPurpose::ApproverRevoke => "ticket:approver-revoke",
            TicketPurpose::Recovery => "ticket:recovery",
            TicketPurpose::RecoveryCodesIssue => "ticket:recovery-codes-issue",
        }
    }

    /// The path appended to this gateway's public URL to form the ticket's required audience.
    /// Deliberately the endpoint's own path: audience binding, not claim inspection, is what keeps
    /// an operator access token and a ticket in disjoint universes.
    ///
    /// [`TicketPurpose::ApproverRevoke`] is the one whose path names the ACTION rather than a
    /// route, because two routes can perform it (`DELETE /v1/approver-keys/:id` and
    /// `DELETE /v1/devices/:id`, which revokes the device's approver key on the way past). Binding it
    /// to either route's path would mint a ticket that only one of them accepted, and the audience
    /// would then be describing where the request arrived rather than what it is allowed to do.
    pub fn audience_path(self) -> &'static str {
        match self {
            TicketPurpose::ApproverPair => "/v1/approver-keys/pair",
            TicketPurpose::ApprovalFloorLower => "/v1/approval-floor",
            TicketPurpose::ApproverRevoke => "/v1/approver-keys/revoke",
            // The recovery resource itself, not either control, because one ticket authorises both.
            TicketPurpose::Recovery => "/v1/recovery",
            TicketPurpose::RecoveryCodesIssue => "/v1/recovery-codes",
        }
    }

    /// Whether the ticket must assert two factors (the password and one of [`RECOVERY_SECOND_FACTORS`], or two different [`PASSWORDLESS_RECOVERY_FACTORS`], or one of them and `backup`) rather than one of [`SIGN_IN_METHODS`]: the recovery of a self-run gateway whose device is gone, and the issuing of the code set that carries that recovery authority.
    pub fn needs_two_factors(self) -> bool {
        matches!(self, TicketPurpose::Recovery | TicketPurpose::RecoveryCodesIssue)
    }

    fn weak_step_up_reason(self) -> &'static str {
        if self.needs_two_factors() {
            "ticket does not assert the password and a second factor, two different strong methods, or one strong method and a backup code"
        } else {
            "ticket does not assert a password, passkey or phone approval"
        }
    }
}

/// A verified step-up pairing ticket. Everything here has been checked against the AS's signature;
/// what it means is bounded by the doc on [`OAuthRs::verify_ticket`]. Read that before treating
/// any of it as evidence about a human.
#[derive(Debug, Clone)]
pub struct PairingTicket {
    /// The ticket's unique id. The caller MUST spend it (`Store::claim_once` under
    /// [`TicketPurpose::scope`]) before acting, or the ticket is replayable for its whole TTL.
    pub jti: String,
    /// The account this worker belongs to, already checked to equal this gateway's bound owner.
    ///
    /// This is an ADDRESSING claim, not an actor claim. It answers "which worker may this ticket be
    /// spent on", which is why it is pinned against `PERMAURA_OWNER_SUB`. It says nothing whatever
    /// about who was at the keyboard: on a team account any member the org has given `device.manage`
    /// to can obtain a ticket for their organisation's worker, and every one of those tickets carries
    /// the same `sub`. Read [`PairingTicket::actor_sub`] for the human.
    pub sub: String,
    /// When the AS asserts the *actor* re-authenticated (unix seconds).
    pub auth_time: i64,
    /// The authentication methods the AS asserts the actor used, for the audit record.
    pub amr: Vec<String>,
    /// The principal the AS asserts actually completed that re-authentication (the org member who
    /// stepped up), which on a team account is frequently not [`PairingTicket::sub`].
    ///
    /// `None` means the AS did not name one (a permaura.com older than the claim). It emphatically
    /// does NOT mean the owner acted, and nothing downstream may render it that way: an audit record
    /// that silently attributes an enrolment to the owner is precisely the confusion the record
    /// exists to prevent, since the owner's notification email is the detection control for an
    /// enrolment they did not perform.
    pub actor_sub: Option<String>,
    /// The actor's display name, when the AS supplies one. A convenience for whoever reads the audit
    /// chain later and nothing more: it is a label the account holder sets on themselves, so it is
    /// not evidence of identity and must never be matched on. [`PairingTicket::actor_sub`] is the
    /// identifier. Truncated on the way in: see [`MAX_ACTOR_NAME_LEN`].
    pub actor_name: Option<String>,
    /// The organization role the AS says entitled the actor to this ticket, `"owner"` or `"admin"`,
    /// read when it was minted. A self-run gateway reads it on `recovery` tickets, accepting a
    /// re-authentication that is not its owner's own only from someone who currently holds one of
    /// those roles. A hosted worker reads it for the changes that set or clear its trust root, which
    /// take the same standing: pairing the first trusted device, replacing a key another person
    /// holds, a floor change while no device is trusted, and a revocation that would leave no trusted
    /// approver. Any other value is dropped to `None`, so it can never widen what is accepted.
    pub actor_role: Option<String>,
    /// Whether an `approver-revoke` ticket's signed `remove_alone` claim is `true`: permaura.com minted it for the owner or for a member holding `device.remove.any`, whose removal of any device is an admin action that applies at once rather than waiting for somebody else's device. Always `false` on every other purpose, and when the claim is absent or not `true`.
    pub remove_alone: bool,
}

/// How stale the AS's asserted re-authentication may be.
const STEP_UP_MAX_AGE_SECS: i64 = 300;

/// How far ahead of the gateway the AS's clock may run before an `auth_time` in the future is read
/// as a forgery rather than skew. Small on purpose: a large tolerance here silently widens
/// [`STEP_UP_MAX_AGE_SECS`], because a ticket claiming a future `auth_time` stays fresh for longer.
const STEP_UP_MAX_SKEW_SECS: i64 = 60;

/// The `amr` values that each re-prove sign-in on their own: the account password, a passkey, or the account approver (the phone's hardware key), which permaura.com names `new-device` until it is a day old. A step-up ticket must name at least one. An allowlist, because something the browser already had (a session cookie, a remembered device) proves nothing about the moment the ticket was minted, and an emailed, authenticator or backup code alone is a second step, not a sign-in.
const SIGN_IN_METHODS: [&str; 4] = ["pwd", "passkey", "device", "new-device"];

/// The `amr` values that count as the second factor beside `pwd` on a recovery ticket ([`TicketPurpose::needs_two_factors`]). Recovery stays the strongest path, so a lost-device takeover needs two independent proofs even though a step-up takes one. `new-device` is left out because a phone is registered on one method, so in its first day it would be a second factor that one method minted.
const RECOVERY_SECOND_FACTORS: [&str; 5] = ["passkey", "device", "totp", "otp", "backup"];

/// The strong methods an account with no password proves two different ones of, or one of and a backup code, on a recovery ticket in place of the password and a second factor, as permaura.com's two-factor rule does. `new-device` is not one, for the reason it is not a second factor.
const PASSWORDLESS_RECOVERY_FACTORS: [&str; 3] = ["passkey", "device", "totp"];

/// How much of the actor's display name is kept. The name is set by the account holder on
/// themselves, so it is attacker-influenced text that ends up in a hash-chained audit record and in
/// an email; truncating bounds what one member can write into another's evidence. Truncated rather
/// than rejected because the name is decorative: refusing a ticket over a long display name would
/// block a legitimate enrolment for a cosmetic reason.
const MAX_ACTOR_NAME_LEN: usize = 96;

/// The longest actor id kept. A permaura.com user id is far shorter; this only bounds what a malformed
/// token could copy into every audit event it touches.
const MAX_ACTOR_SUB_LEN: usize = 128;

/// What a ticket must additionally be pinned to, beyond its purpose and audience.
#[derive(Debug, Clone, Copy)]
pub enum TicketBinding<'a> {
    /// Purpose and audience are the whole authorisation: the action has no per-object parameters
    /// worth pinning (lowering the approval floor is one such action: there is only one floor).
    None,
    /// The ticket authorises enrolling exactly this approver id carrying exactly this public-key
    /// fingerprint, and nothing else. Without this pinning a ticket would authorise "an enrolment",
    /// so anyone who intercepted one could swap in a key of their own before it was spent.
    ApproverKey {
        /// The approver id the request is enrolling, which the ticket's own claim must equal.
        approver_id: &'a str,
        /// [`crate::service::key_fingerprint`] of the key being enrolled. The fingerprint rather
        /// than the key so the AS can bind a ticket without the request body having to round-trip
        /// through it, and so the two sides cannot disagree about padding or encoding.
        pubkey_fp: &'a str,
    },
    /// The ticket authorises revoking exactly this approver id.
    ApproverId {
        /// The approver id being revoked, which the ticket's own claim must equal.
        approver_id: &'a str,
    },
}

/// Why [`OAuthRs::verify_ticket`] refused a ticket.
#[derive(Debug)]
pub struct TicketRejected {
    /// What was wrong, for the caller's error message.
    pub reason: String,
    /// The ticket verified as far as its binding, which names a different approver id or key than the request.
    pub unbound: bool,
    /// Set only when everything else held and the re-authentication fell short, so the caller can record what the AS asserted.
    pub weak_step_up: Option<Box<WeakStepUp>>,
}

/// The claims of a ticket refused for its `amr`, kept for the audit record.
#[derive(Debug)]
pub struct WeakStepUp {
    /// The ticket's id, if it carried one.
    pub jti: Option<String>,
    /// The methods the AS asserted.
    pub amr: Vec<String>,
    /// Who the AS says stepped up.
    pub actor_sub: Option<String>,
    /// Their display name as the AS supplied it.
    pub actor_name: Option<String>,
}

impl std::fmt::Display for TicketRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl From<String> for TicketRejected {
    fn from(reason: String) -> Self {
        TicketRejected { reason, unbound: false, weak_step_up: None }
    }
}

impl From<&str> for TicketRejected {
    fn from(reason: &str) -> Self {
        reason.to_string().into()
    }
}

/// A ticket's `purpose` claim, read WITHOUT verifying the ticket. Routing only: whichever path it picks verifies the ticket in full.
pub fn unverified_ticket_purpose(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let claims: serde_json::Value = serde_json::from_slice(&b64url(payload).ok()?).ok()?;
    claims.get("purpose")?.as_str().map(str::to_string)
}

/// Wire shape of one JWK (Ed25519 / OKP) from the AS JWKS.
#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    kid: String,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: String,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: String,
    exp: i64,
    /// `aud` may be a string or an array of strings.
    #[serde(default)]
    aud: serde_json::Value,
    /// The authorized party: the per-client DCR id (Better Auth's oauth-provider sets this on the
    /// access token; `sub` is the consenting end user, not the client).
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    name: Option<String>,
    /// The registered client's display name, when the AS is configured to surface it.
    #[serde(default)]
    client_name: Option<String>,
    /// Space-delimited OAuth scopes. Only the console's server-minted tokens carry
    /// [`OPERATOR_SCOPE`]; agent tokens from the authorize flow cannot.
    #[serde(default)]
    scope: Option<String>,
    /// The JWT id. Access tokens do not carry one; a step-up ticket must, because the jti is the
    /// only handle the gateway has for spending it exactly once.
    #[serde(default)]
    jti: Option<String>,
    /// What a step-up ticket authorises (see [`TicketPurpose`]). Absent on access tokens.
    #[serde(default)]
    purpose: Option<String>,
    /// The one approver id an `approver-pair` ticket may enrol or an `approver-revoke` ticket may revoke.
    #[serde(default)]
    approver_id: Option<String>,
    /// The fingerprint of the one public key an `approver-pair` ticket may enrol.
    #[serde(default)]
    pubkey_fp: Option<String>,
    /// The authentication methods the AS asserts the user completed for this ticket (RFC 8176).
    #[serde(default)]
    amr: Vec<String>,
    /// When the AS says that authentication happened (unix seconds). Bounded by
    /// [`STEP_UP_MAX_AGE_SECS`] so a ticket cannot be minted off a months-old session.
    #[serde(default)]
    auth_time: Option<i64>,
    /// The principal who actually performed the step-up, when `sub` is not them. Optional so a
    /// permaura.com that predates the claim keeps working against a newer gateway; see
    /// [`PairingTicket::actor_sub`] for why absent must never be read as "the owner".
    #[serde(default)]
    act_sub: Option<String>,
    /// That principal's display name, if the AS supplies one. Self-set, therefore not evidence.
    #[serde(default)]
    act_name: Option<String>,
    /// The organization role behind `act_sub`. See [`PairingTicket::actor_role`].
    #[serde(default)]
    act_role: Option<String>,
    /// On a console operator token: permaura.com says the acting member holds the Export the vault capability. Read only as exactly `true`; a role never implies it.
    #[serde(default)]
    vault_export: Option<bool>,
    /// On an `approver-revoke` ticket: permaura.com says the actor may remove any device alone (the owner, or a holder of `device.remove.any`). See [`PairingTicket::remove_alone`].
    #[serde(default)]
    remove_alone: Option<bool>,
}

/// The shortest interval between two ON-DEMAND JWKS refetches, whatever the volume of unknown-`kid`
/// misses. This number is the entire anti-DoS property of [`OAuthRs::request_jwks_refetch`]: the
/// gate is on the CLOCK, never on the number or the identity of the misses, so a caller presenting
/// ten thousand tokens with random `kid`s produces at most one fetch in this window, exactly what
/// the periodic-only design produced, only sooner.
const JWKS_ONDEMAND_MIN_INTERVAL_SECS: i64 = 30;

/// The Resource Server: config + a cached set of the AS's Ed25519 verifying keys by `kid`.
pub struct OAuthRs {
    config: RsConfig,
    /// The operator this RS accepts tokens for, starting as [`RsConfig::owner_sub`] and moved by [`OAuthRs::repin_owner`] when permaura.com names a new owner at a check-in.
    owner: RwLock<Option<String>>,
    keys: RwLock<HashMap<String, VerifyingKey>>,
    http: reqwest::Client,
    /// Wakes the [`OAuthRs::spawn_refresh`] task early. The refresher owns the `Arc<Self>` a spawn
    /// needs; verification does not, and cannot await in any case, so the miss signals across rather
    /// than fetching inline.
    refresh_now: tokio::sync::Notify,
    /// Unix seconds of the last on-demand refetch this process asked for. The rate gate.
    last_ondemand_secs: std::sync::atomic::AtomicI64,
    /// Set by [`OAuthRs::withdraw`]: no token verifies from then until the process ends.
    withdrawn: std::sync::atomic::AtomicBool,
}

impl OAuthRs {
    /// Build the RS. The key cache starts empty; call [`OAuthRs::spawn_refresh`] to populate it
    /// and keep it fresh.
    pub fn new(config: RsConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap_or_default();
        OAuthRs {
            owner: RwLock::new(config.owner_sub.clone()),
            config,
            keys: RwLock::new(HashMap::new()),
            http,
            refresh_now: tokio::sync::Notify::new(),
            last_ondemand_secs: std::sync::atomic::AtomicI64::new(i64::MIN),
            withdrawn: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Refuse every token, access token and ticket alike, for the rest of this process: `permaura remote disable` turning remote access off in a running gateway. A restart builds the resource server again only if the public URL is still configured.
    pub fn withdraw(&self) {
        self.withdrawn.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether [`Self::withdraw`] has run.
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The static config (used by the metadata endpoints). The owner it names is the boot-time pin; the live one is [`Self::owner_sub`].
    pub fn config(&self) -> &RsConfig {
        &self.config
    }

    /// The operator whose tokens this RS accepts now. A poisoned lock reads as no owner, which fails closed.
    pub fn owner_sub(&self) -> Option<String> {
        self.owner.read().ok().and_then(|o| o.clone())
    }

    /// Bind this RS to `sub`. Returns the owner it replaced (`Some(None)` when there was none) when the binding moved, and `None` when `sub` was already the owner.
    pub fn repin_owner(&self, sub: &str) -> Option<Option<String>> {
        let mut owner = self.owner.write().unwrap_or_else(|e| e.into_inner());
        if owner.as_deref() == Some(sub) {
            return None;
        }
        Some(owner.replace(sub.to_string()))
    }

    /// Whether the key cache holds at least one signing key, i.e. the JWKS fetch has landed and this
    /// RS can verify a token at all.
    ///
    /// A verify failure while this is `false` is "cannot check yet" (the fetch is still in flight on a
    /// cold or just-scaled-up worker), not "will not check this" (a bearer that is genuinely no good).
    /// The caller uses it to answer the first with a retryable status instead of a 401. Reads the same
    /// cache [`Self::verify`] does; a poisoned lock (a panic while `refresh` held the write guard,
    /// which its one assignment cannot cause) reads as not-ready, the conservative answer.
    pub fn verifier_ready(&self) -> bool {
        self.keys.read().map(|k| !k.is_empty()).unwrap_or(false)
    }

    /// Fetch the AS JWKS and replace the key cache. Best-effort; logs on failure.
    pub async fn refresh(&self) {
        match self.fetch_keys().await {
            Ok(map) => {
                if let Ok(mut guard) = self.keys.write() {
                    *guard = map;
                }
            }
            Err(e) => tracing::warn!(error = %e, jwks_uri = %self.config.jwks_uri, "JWKS refresh failed"),
        }
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, VerifyingKey>, String> {
        let set: JwkSet = self
            .http
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("jwks fetch: {e}"))?
            .json()
            .await
            .map_err(|e| format!("jwks parse: {e}"))?;
        let mut map = HashMap::new();
        for jwk in set.keys {
            if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
                continue; // EdDSA-only for now.
            }
            let Ok(bytes) = b64url(&jwk.x) else { continue };
            let Ok(arr): Result<[u8; 32], _> = bytes.try_into() else { continue };
            if let Ok(vk) = permaura_relay::strict_verifying_key(&arr) {
                map.insert(jwk.kid, vk);
            }
        }
        Ok(map)
    }

    /// Spawn a background task that refreshes the JWKS at startup, every `interval` after that, and
    /// whenever [`OAuthRs::request_jwks_refetch`] lets a cache miss through the rate gate.
    ///
    /// The on-demand wake is what makes a cold start survivable. A Mode C worker fetches once at
    /// boot; if permaura.com is briefly unreachable at that moment the cache stays EMPTY, and with
    /// only the ticker every token is refused for up to `interval`, five minutes of a tenant's
    /// worker answering `unknown signing key (kid)`, which reads like a key-rotation fault and is
    /// nothing of the sort. The recovery is now bounded by
    /// [`JWKS_ONDEMAND_MIN_INTERVAL_SECS`] instead.
    pub fn spawn_refresh(self: &Arc<Self>, interval: Duration) {
        let this = self.clone();
        tokio::spawn(async move {
            this.refresh().await;
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // consume the immediate first tick (we just refreshed)
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = this.refresh_now.notified() => {}
                }
                this.refresh().await;
            }
        });
    }

    /// Verify an access-token JWT and return its claims, or an error string. Synchronous: reads
    /// the cached keys. On an unknown `kid` it notes the miss for the next scheduled JWKS refresh
    /// (so the client's retry can succeed after key rotation) and fails this attempt.
    pub fn verify(&self, token: &str, now_secs: i64) -> Result<VerifiedClaims, String> {
        let claims =
            self.verify_signed_claims(token, &self.config.accepted_mcp_resources(), now_secs)?;
        Ok(VerifiedClaims {
            sub: claims.sub,
            azp: claims.azp,
            // Prefer an explicit display name, else the registered client name.
            name: claims.name.or(claims.client_name),
            scope: claims.scope,
            actor: actor_sub(claims.act_sub).map(|sub| crate::store::SessionActor {
                sub,
                name: actor_name(claims.act_name),
                role: actor_role(claims.act_role),
                vault_export: claims.vault_export.filter(|held| *held),
            }),
        })
    }

    /// Every check that holds for EVERY token this gateway trusts, whatever its class: three JWS
    /// segments, EdDSA over a key from the AS's JWKS, the AS's own `iss`, unexpired, minted for
    /// `expected_aud`, and issued to this gateway's bound operator, failing closed when no owner
    /// is bound at all.
    ///
    /// The audience is a parameter rather than the MCP resource constant because one AS signing key
    /// mints several token classes for this gateway (MCP access tokens, and the step-up tickets of
    /// [`OAuthRs::verify_ticket`]). Giving each class its own audience is what makes them
    /// non-interchangeable: a caller cannot present an access token where a ticket is demanded, and
    /// the check is a string equality on a claim the AS controls rather than an inference from the
    /// claims that happen to be present.
    ///
    /// It is a SET rather than one string only to survive a hostname change (see
    /// [`RsConfig::public_url_aliases`]). Every entry is still one exact string equality, and the
    /// classes stay disjoint because the caller passes the audiences of a single class.
    fn verify_signed_claims(
        &self,
        token: &str,
        expected_auds: &[String],
        now_secs: i64,
    ) -> Result<JwtClaims, String> {
        if self.is_withdrawn() {
            return Err(REMOTE_ACCESS_OFF.into());
        }
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("not a JWS".into());
        }
        let header: JwtHeader = serde_json::from_slice(&b64url(parts[0])?)
            .map_err(|e| format!("header: {e}"))?;
        if header.alg != "EdDSA" {
            return Err(format!("unsupported alg {}", header.alg));
        }

        // Select the key by kid (or the sole key if the token omits kid).
        let vk = {
            let keys = self.keys.read().map_err(|_| "key cache poisoned".to_string())?;
            let found = if header.kid.is_empty() {
                keys.values().next().copied()
            } else {
                keys.get(&header.kid).copied()
            };
            match found {
                Some(k) => k,
                None => {
                    self.note_unknown_kid();
                    return Err("unknown signing key (kid)".into());
                }
            }
        };

        // Verify the signature over "header.payload".
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = b64url(parts[2])?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "bad signature length".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify_strict(signing_input.as_bytes(), &sig)
            .map_err(|_| "signature mismatch".to_string())?;

        // Validate the claims.
        let claims: JwtClaims =
            serde_json::from_slice(&b64url(parts[1])?).map_err(|e| format!("claims: {e}"))?;
        if claims.iss.trim_end_matches('/') != self.config.issuer {
            return Err(format!("issuer mismatch: {}", claims.iss));
        }
        if !expected_auds
            .iter()
            .any(|want| aud_contains(&claims.aud, want))
        {
            return Err("audience mismatch: token not minted for this gateway".into());
        }
        // Tenant isolation. The RS only runs on a publicly-reachable gateway, whose MCP hostname is
        // discoverable (DNS/CT logs), so a valid-audience token is not proof of authorisation by THIS
        // gateway's operator. Accept only the paired owner's tokens, and FAIL CLOSED if no owner is
        // bound at all, since an unbound public RS would otherwise accept any operator's
        // audience-correct token. The web tunnel-provisioning path always sets PERMAURA_OWNER_SUB;
        // this guards a misconfigured or hand-run gateway.
        match self.owner_sub() {
            Some(owner) if claims.sub == owner => {}
            Some(_) => return Err("token subject is not this gateway's operator".into()),
            None => {
                return Err(
                    "gateway has no operator binding (PERMAURA_OWNER_SUB unset): refusing remote tokens".into(),
                )
            }
        }
        // Last, after the audience and the owner, so that this reason is only ever given for a token that was this gateway's own caller's: admission control answers it with a 401 ahead of every bucket, and a stranger's expired token for another gateway must not earn that.
        if claims.exp <= now_secs {
            return Err(TOKEN_EXPIRED.into());
        }
        Ok(claims)
    }

    /// Whether `token` is this gateway's own caller's token that has merely expired: signed by the AS, for this audience, for the bound owner, and past `exp`. The one refusal an agent needs to hear as a 401 rather than share a bucket with strangers, since a 401 is what makes an MCP client refresh.
    pub fn lapsed(&self, token: &str, now_secs: i64) -> bool {
        matches!(self.verify(token, now_secs), Err(reason) if reason == TOKEN_EXPIRED)
    }

    /// Verify a **step-up ticket** for one [`TicketPurpose`]: the anchor that lets a hosted gateway
    /// (Mode C) enrol a device-signed approver at all, where a local gateway would instead require
    /// the caller to be on loopback, and the authority behind the other purposes' controls.
    ///
    /// Understand precisely what this does and does not establish. The gateway **cannot verify that
    /// a human re-authenticated.** It verifies that the Authorization Server *asserted* that one
    /// did, recently, under a signature the gateway already trusts for every other token. If
    /// permaura.com is compromised, tickets are forgeable, and no check in this function will say
    /// so. That is not a gap to be patched here: on a hosted worker the AS is the tenant's only
    /// channel to the worker at all, so an AS-asserted fresh re-auth is the strongest honest
    /// guarantee available for the FIRST device. Every subsequent enrolment must additionally be
    /// co-signed by hardware already trusted by this worker, which the control plane has never held
    /// a key for, so a ticket alone cannot join a device to a keyring that still holds a usable key.
    /// That does not bound an AS compromise: tickets also lower the approval floor, revoke approver
    /// keys (at once when the ticket names the owner as actor or carries `remove_alone`),
    /// carry a self-run recovery and issue recovery codes, so a forged ticket can empty a hosted
    /// worker's keyring and a second one can then enrol the attacker's device as the first. Do not
    /// read this function as cryptographic proof of a human.
    ///
    /// On top of [`OAuthRs::verify_signed_claims`] against the purpose's own audience, the ticket
    /// must: name that same `purpose`; match the supplied [`TicketBinding`] exactly; assert an
    /// `auth_time` within [`STEP_UP_MAX_AGE_SECS`] (and not implausibly in the future); name at least
    /// one of [`SIGN_IN_METHODS`] (the password, a passkey or the phone) in `amr`, or for a recovery purpose ([`TicketPurpose::needs_two_factors`]) the password and one of [`RECOVERY_SECOND_FACTORS`], two different [`PASSWORDLESS_RECOVERY_FACTORS`], or one of them and `backup`; and carry a `jti`. A ticket with no `jti` cannot be
    /// spent single-use by the caller and would therefore be replayable for its whole TTL, so it is
    /// refused here rather than accepted and left unspendable.
    ///
    /// Verification alone does NOT consume the ticket. The caller must spend the returned `jti` via
    /// the store's single-use ledger under [`TicketPurpose::scope`] *before* performing the action;
    /// on a multi-instance hosted worker only that shared claim makes "single use" true.
    ///
    /// **`sub` is not the actor.** It names the worker's owner, which is what the ticket is pinned
    /// against, and on a team account the member who re-authenticated is very often somebody else.
    /// The actor arrives separately in `act_sub` and is surfaced as [`PairingTicket::actor_sub`],
    /// unvalidated beyond trimming because the gateway has no roster to check an org's membership
    /// against: the AS is the only party that can know it, and the same signature that carries
    /// `auth_time` and `amr` carries this. Absent means "not named", never "the owner".
    pub fn verify_ticket(
        &self,
        token: &str,
        purpose: TicketPurpose,
        bind: TicketBinding<'_>,
        now_secs: i64,
    ) -> Result<PairingTicket, TicketRejected> {
        let expected_auds = self.config.accepted_ticket_audiences(purpose.audience_path());
        let claims = self.verify_signed_claims(token, &expected_auds, now_secs)?;

        if claims.purpose.as_deref() != Some(purpose.claim()) {
            return Err(format!(
                "ticket purpose mismatch: expected {}, got {}",
                purpose.claim(),
                claims.purpose.as_deref().unwrap_or("none")
            )
            .into());
        }

        let unbound = |reason: &str| TicketRejected { reason: reason.into(), unbound: true, weak_step_up: None };
        match bind {
            TicketBinding::None => {}
            TicketBinding::ApproverKey { approver_id, pubkey_fp } => {
                if claims.approver_id.as_deref() != Some(approver_id) {
                    return Err(unbound("ticket is not bound to this approver id"));
                }
                if claims.pubkey_fp.as_deref() != Some(pubkey_fp) {
                    return Err(unbound("ticket is not bound to this public key"));
                }
            }
            TicketBinding::ApproverId { approver_id } => {
                if claims.approver_id.as_deref() != Some(approver_id) {
                    return Err(unbound("ticket is not bound to this approver id"));
                }
            }
        }

        let auth_time = claims
            .auth_time
            .ok_or_else(|| "ticket asserts no auth_time: cannot judge re-authentication".to_string())?;
        let age = now_secs - auth_time;
        if age > STEP_UP_MAX_AGE_SECS {
            return Err(format!("re-authentication is stale ({age}s old)").into());
        }
        if age < -STEP_UP_MAX_SKEW_SECS {
            return Err("ticket asserts a future auth_time".into());
        }

        let asserts = |method: &str| claims.amr.iter().any(|m| m == method);
        let enough = if purpose.needs_two_factors() {
            let strong = PASSWORDLESS_RECOVERY_FACTORS.iter().filter(|f| asserts(f)).count();
            (asserts("pwd") && RECOVERY_SECOND_FACTORS.iter().any(|f| asserts(f))) || strong >= 2 || (strong == 1 && asserts("backup"))
        } else {
            SIGN_IN_METHODS.iter().any(|f| asserts(f))
        };
        if !enough {
            return Err(TicketRejected {
                reason: purpose.weak_step_up_reason().into(),
                unbound: false,
                weak_step_up: Some(Box::new(WeakStepUp {
                    jti: claims.jti.filter(|j| !j.trim().is_empty()),
                    amr: claims.amr,
                    actor_sub: actor_sub(claims.act_sub),
                    actor_name: actor_name(claims.act_name),
                })),
            });
        }

        let jti = claims
            .jti
            .filter(|j| !j.trim().is_empty())
            .ok_or("ticket has no jti: it could not be limited to a single use")?;

        Ok(PairingTicket {
            jti,
            sub: claims.sub,
            auth_time,
            amr: claims.amr,
            actor_sub: actor_sub(claims.act_sub),
            actor_name: actor_name(claims.act_name),
            actor_role: actor_role(claims.act_role),
            remove_alone: purpose == TicketPurpose::ApproverRevoke && claims.remove_alone == Some(true),
        })
    }

    /// Note a cache miss and, at most once every [`JWKS_ONDEMAND_MIN_INTERVAL_SECS`], ask the
    /// refresher task to fetch the JWKS now rather than at its next tick.
    ///
    /// **The anti-DoS property this used to get by doing nothing, and how it is kept.** Verification
    /// runs before any authentication has succeeded, so a miss is an UNAUTHENTICATED signal: fetching
    /// per miss would let anyone who can reach the gateway drive one outbound request at the AS per
    /// token they invent, with the gateway as the amplifier. The gate is therefore on the clock and
    /// on nothing else (not on the `kid`, not on the caller, not on a counter), so the worst an
    /// attacker achieves by presenting unlimited garbage is the one fetch per window that a single
    /// honest miss would already have caused. There is no input they control that changes the rate.
    ///
    /// The signal is a [`tokio::sync::Notify`] rather than an inline fetch because this call sits in
    /// a synchronous path (`authenticate` is sync by design, so the whole request path is not
    /// infected by an await for a cache read) and because the refresher already holds the `Arc<Self>`
    /// a spawn would need. THIS attempt still fails: the caller retries, and the retry finds the key.
    fn note_unknown_kid(&self) {
        if self.request_jwks_refetch(now_secs()) {
            tracing::debug!("JWT verify: unknown kid: refetching the JWKS now");
        } else {
            tracing::debug!("JWT verify: unknown kid: a refetch is already rate-limited, awaiting it");
        }
    }

    /// The rate gate itself, taking `now_secs` so its timing is testable without sleeping.
    ///
    /// Returns whether THIS miss was the one allowed through the window. The compare-and-exchange is
    /// what makes concurrent misses collapse to a single fetch: every loser sees the winner's stamp
    /// and gives up rather than retrying.
    pub fn request_jwks_refetch(&self, now_secs: i64) -> bool {
        use std::sync::atomic::Ordering;
        let last = self.last_ondemand_secs.load(Ordering::Relaxed);
        if last != i64::MIN && now_secs.saturating_sub(last) < JWKS_ONDEMAND_MIN_INTERVAL_SECS {
            return false;
        }
        if self
            .last_ondemand_secs
            .compare_exchange(last, now_secs, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        self.refresh_now.notify_one();
        true
    }
}

/// Unix seconds now. Used only by the JWKS rate gate; every verification path is handed the time by
/// its caller so a test can pin it.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A claim that is present and says something. A whitespace-only `act_sub` would otherwise read as
/// "the AS named an actor" while identifying nobody, which is worse than an honest absence.
/// An actor id as the audit chain may record it: trimmed, stripped like a name, and capped.
fn actor_sub(value: Option<String>) -> Option<String> {
    non_empty(value.map(|v| printable(&v))).map(|v| truncate_chars(&v, MAX_ACTOR_SUB_LEN))
}

/// An actor's organization role, only when it is one a recovery may rest on.
fn actor_role(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_ascii_lowercase()).filter(|v| v == "owner" || v == "admin")
}

/// An actor's display name as the audit chain may record it.
///
/// Self-chosen text on its way into a permanent, signed record that terminals and apps render, so
/// control, bidirectional-override and zero-width characters go: they can rewrite a terminal view,
/// reverse the text around them, or make two different names look identical.
fn actor_name(value: Option<String>) -> Option<String> {
    let cleaned = value.map(|v| printable(&v).split_whitespace().collect::<Vec<_>>().join(" "));
    non_empty(cleaned).map(|v| truncate_chars(&v, MAX_ACTOR_NAME_LEN))
}

fn printable(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
        })
        .collect()
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Truncate to `max` CHARACTERS, never bytes: slicing a multi-byte name mid-codepoint would panic.
fn truncate_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

/// Parse `PERMAURA_PUBLIC_URL_ALIASES` into normalised public URLs.
///
/// Comma- or whitespace-separated, trailing slashes stripped, blanks dropped. An entry equal to the
/// canonical URL is dropped rather than duplicated, so a deploy that lists the current hostname among
/// its aliases is a no-op instead of a config that verifies the same audience twice.
fn parse_public_url_aliases(raw: &str, canonical: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for candidate in raw.split([',', ' ', '\t', '\n', '\r']) {
        let url = candidate.trim().trim_end_matches('/');
        if url.is_empty() || url == canonical || out.iter().any(|u| u == url) {
            continue;
        }
        out.push(url.to_string());
    }
    out
}

/// True if `aud` (a JSON string or array of strings) contains `want`.
fn aud_contains(aud: &serde_json::Value, want: &str) -> bool {
    match aud {
        serde_json::Value::String(s) => s == want,
        serde_json::Value::Array(items) => items.iter().any(|v| v.as_str() == Some(want)),
        _ => false,
    }
}

#[cfg(test)]
mod scheme_tests {
    use super::check_scheme;

    /// The whole point: the gateway does not terminate TLS, so a non-https public URL means a proxy
    /// publishing this gateway in the clear. Refused, and the message has to say what to do instead:
    /// a bare "invalid" would leave someone guessing at a config they cannot see the danger in.
    #[test]
    fn a_plain_http_public_url_is_refused_with_the_fix_in_the_message() {
        let err = check_scheme("http://gw.example.com").expect_err("http must not be accepted");
        assert!(err.contains("not https"), "unexpected: {err}");
        assert!(err.contains("TLS-terminating proxy"), "the message must name the fix: {err}");
        assert!(
            err.contains("PERMAURA_ALLOW_INSECURE_PUBLIC_URL"),
            "the message must name the override: {err}"
        );
    }

    #[test]
    fn https_is_accepted() {
        assert!(check_scheme("https://gw.example.com").is_ok());
    }

    /// Anything that is not https is refused, not just http: a scheme this gateway cannot reason
    /// about is not a reason to assume it is safe.
    #[test]
    fn a_scheme_that_is_neither_is_still_refused() {
        for u in ["ws://gw.example.com", "gw.example.com", "ftp://gw.example.com"] {
            assert!(check_scheme(u).is_err(), "{u} should be refused");
        }
    }

    /// `https` must be the scheme, not merely present. Guards the naive `contains` implementation.
    #[test]
    fn https_elsewhere_in_the_url_does_not_count() {
        assert!(check_scheme("http://evil.example/?next=https://gw.example.com").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn enc(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn mint_jwt(sk: &SigningKey, kid: &str, claims: serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "EdDSA", "kid": kid, "typ": "JWT" });
        let h = enc(serde_json::to_string(&header).unwrap().as_bytes());
        let p = enc(serde_json::to_string(&claims).unwrap().as_bytes());
        let signing_input = format!("{h}.{p}");
        let sig = sk.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", enc(&sig.to_bytes()))
    }

    fn rs() -> (OAuthRs, SigningKey) {
        rs_with_aliases(Vec::new())
    }

    /// The same RS, having been MOVED to `g-test.permaura.com` from the listed older hostnames.
    fn rs_with_aliases(public_url_aliases: Vec<String>) -> (OAuthRs, SigningKey) {
        let cfg = RsConfig {
            public_url: "https://g-test.permaura.com".into(),
            mcp_resource: "https://g-test.permaura.com/mcp".into(),
            public_url_aliases,
            issuer: "https://permaura.com".into(),
            jwks_uri: "https://permaura.com/api/auth/jwks".into(),
            owner_sub: None,
        };
        let rs = OAuthRs::new(cfg);
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        rs.keys
            .write()
            .unwrap()
            .insert("k1".into(), sk.verifying_key());
        (rs, sk)
    }

    /// The cold-start signal the retryable path keys off. Before the JWKS lands the RS is NOT ready
    /// and cannot verify even a well-formed, owner-bound token (the only thing missing is the key),
    /// and once the key arrives readiness flips and the very same token verifies. `authenticate`
    /// turns the not-ready state into a 503 rather than a 401 (see the service test).
    #[test]
    fn the_verifier_is_not_ready_until_its_signing_keys_land() {
        let cfg = RsConfig {
            public_url: "https://g-test.permaura.com".into(),
            mcp_resource: "https://g-test.permaura.com/mcp".into(),
            public_url_aliases: Vec::new(),
            issuer: "https://permaura.com".into(),
            jwks_uri: "https://permaura.com/api/auth/jwks".into(),
            owner_sub: Some("operator-owner".into()),
        };
        let rs = OAuthRs::new(cfg);
        assert!(!rs.verifier_ready(), "an RS whose JWKS has not been fetched is not ready");

        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let jwt = mint_jwt(
            &sk,
            "k9",
            serde_json::json!({
                "iss": "https://permaura.com",
                "sub": "operator-owner",
                "aud": "https://g-test.permaura.com/mcp",
                "exp": 9_999_999_999i64,
            }),
        );
        // Cold: the token is fine, the key is simply not here yet.
        assert!(rs.verify(&jwt, 1_000).unwrap_err().contains("unknown signing key"));

        // Warm: the key lands, readiness flips, and the identical token now verifies.
        rs.keys.write().unwrap().insert("k9".into(), sk.verifying_key());
        assert!(rs.verifier_ready());
        assert!(rs.verify(&jwt, 1_000).is_ok(), "the same token verifies once the key is present");
    }

    #[test]
    fn accepts_a_valid_audience_bound_token() {
        let (rs, sk) = rs();
        rs.repin_owner("claude-web"); // a public RS must be owner-bound
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({ "sub": "claude-web", "iss": "https://permaura.com",
                "aud": "https://g-test.permaura.com/mcp", "exp": 9_999_999_999i64, "name": "Claude" }),
        );
        let claims = rs.verify(&jwt, 1_000).expect("valid token");
        assert_eq!(claims.sub, "claude-web");
        assert_eq!(claims.name.as_deref(), Some("Claude"));
    }

    #[test]
    fn azp_and_client_name_are_surfaced() {
        // `sub` is the consenting operator; `azp` is the per-client id; `client_name` is the label.
        let (rs, sk) = rs();
        rs.repin_owner("operator-user-id");
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({ "sub": "operator-user-id", "iss": "https://permaura.com",
                "aud": "https://g-test.permaura.com/mcp", "exp": 9_999_999_999i64,
                "azp": "client-abc", "client_name": "Claude" }),
        );
        let c = rs.verify(&jwt, 1_000).unwrap();
        assert_eq!(c.sub, "operator-user-id");
        assert_eq!(c.azp.as_deref(), Some("client-abc"));
        assert_eq!(c.name.as_deref(), Some("Claude"));
    }

    #[test]
    fn rejects_wrong_audience() {
        let (rs, sk) = rs();
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({ "sub": "x", "iss": "https://permaura.com",
                "aud": "https://other.permaura.com/mcp", "exp": 9_999_999_999i64 }),
        );
        assert!(rs.verify(&jwt, 1_000).unwrap_err().contains("audience"));
    }

    #[test]
    fn rejects_expired_and_bad_issuer_and_bad_sig() {
        let (rs, sk) = rs();
        rs.repin_owner("x");
        let aud = "https://g-test.permaura.com/mcp";
        // expired
        let exp = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"x","iss":"https://permaura.com","aud":aud,"exp":500i64 }));
        assert_eq!(rs.verify(&exp, 1_000).unwrap_err(), TOKEN_EXPIRED);
        assert!(rs.lapsed(&exp, 1_000));
        assert!(!rs.lapsed(&exp, 400), "not lapsed while it is live");
        // wrong issuer
        let iss = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"x","iss":"https://evil.com","aud":aud,"exp":9_999_999_999i64 }));
        assert!(rs.verify(&iss, 1_000).unwrap_err().contains("issuer"));
        // signed by a different key
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let forged = mint_jwt(&other, "k1", serde_json::json!({ "sub":"x","iss":"https://permaura.com","aud":aud,"exp":9_999_999_999i64 }));
        assert!(rs.verify(&forged, 1_000).unwrap_err().contains("signature"));
    }

    /// A JWKS key comes from the network: a small-order one with `R = identity, s = 0` would otherwise sign any token.
    #[test]
    fn a_small_order_jwks_key_verifies_no_token() {
        let (rs, _sk) = rs();
        rs.repin_owner("x");
        let mut identity = [0u8; 32];
        identity[0] = 1;
        rs.keys.write().unwrap().insert("weak".into(), VerifyingKey::from_bytes(&identity).unwrap());
        let header = enc(br#"{"alg":"EdDSA","kid":"weak","typ":"JWT"}"#);
        let claims = enc(br#"{"sub":"x","iss":"https://permaura.com","aud":"https://g-test.permaura.com/mcp","exp":9999999999}"#);
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let jwt = format!("{header}.{claims}.{}", enc(&forged));
        assert!(rs.verify(&jwt, 1_000).is_err(), "a weak key must sign nothing");
    }

    /// "Expired" is said only of this gateway's own caller's token. An expired token for another gateway or another operator is refused for that, so a stranger holding one cannot take the lapsed-token lane past admission control.
    #[test]
    fn an_expired_token_for_another_gateway_or_operator_is_not_merely_lapsed() {
        let (rs, sk) = rs();
        rs.repin_owner("operator-owner");
        let elsewhere = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"operator-owner","iss":"https://permaura.com","aud":"https://other.permaura.com/mcp","exp":500i64 }));
        assert!(rs.verify(&elsewhere, 1_000).unwrap_err().contains("audience"));
        assert!(!rs.lapsed(&elsewhere, 1_000));
        let someone_else = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"operator-stranger","iss":"https://permaura.com","aud":"https://g-test.permaura.com/mcp","exp":500i64 }));
        assert!(rs.verify(&someone_else, 1_000).unwrap_err().contains("operator"));
        assert!(!rs.lapsed(&someone_else, 1_000));
        let forged = mint_jwt(&SigningKey::from_bytes(&[9u8; 32]), "k1", serde_json::json!({ "sub":"operator-owner","iss":"https://permaura.com","aud":"https://g-test.permaura.com/mcp","exp":500i64 }));
        assert!(!rs.lapsed(&forged, 1_000));
        assert!(!rs.lapsed("not.a.jwt", 1_000) && !rs.lapsed("", 1_000));
    }

    /// After an ownership change the AS mints every token for the new owner. The re-pin moves the binding, so the new owner's tokens verify and the old owner's stop, and asking for the owner already bound changes nothing.
    #[test]
    fn a_repin_moves_the_owner_whose_tokens_verify() {
        let (rs, sk) = rs();
        rs.repin_owner("user_old");
        let aud = "https://g-test.permaura.com/mcp";
        let old = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"user_old","iss":"https://permaura.com","aud":aud,"exp":9_999_999_999i64 }));
        let new = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"user_new","iss":"https://permaura.com","aud":aud,"exp":9_999_999_999i64 }));
        assert!(rs.verify(&old, 1_000).is_ok());
        assert!(rs.verify(&new, 1_000).unwrap_err().contains("operator"));
        assert_eq!(rs.repin_owner("user_old"), None, "already the owner");
        assert_eq!(rs.repin_owner("user_new"), Some(Some("user_old".into())));
        assert_eq!(rs.owner_sub().as_deref(), Some("user_new"));
        assert!(rs.verify(&new, 1_000).is_ok());
        assert!(rs.verify(&old, 1_000).unwrap_err().contains("operator"), "the old owner's tokens stop at once");
        assert_eq!(rs.config().owner_sub, None, "the boot-time pin is what it was");
    }

    #[test]
    fn rejects_a_token_from_a_different_operator_when_owner_bound() {
        // Cross-tenant defence: a token correctly minted for THIS gateway's audience but by a
        // different operator (different `sub`) is rejected when the gateway is owner-bound.
        let (rs, sk) = rs();
        rs.repin_owner("operator-owner");
        let aud = "https://g-test.permaura.com/mcp";
        let foreign = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"operator-attacker","iss":"https://permaura.com","aud":aud,"exp":9_999_999_999i64 }));
        assert!(rs.verify(&foreign, 1_000).unwrap_err().contains("operator"));
        // The owner's own token still verifies.
        let own = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"operator-owner","iss":"https://permaura.com","aud":aud,"exp":9_999_999_999i64 }));
        assert_eq!(rs.verify(&own, 1_000).unwrap().sub, "operator-owner");
    }

    #[test]
    fn aud_array_is_accepted() {
        let (rs, sk) = rs();
        rs.repin_owner("x");
        let jwt = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"x","iss":"https://permaura.com",
            "aud":["https://other/mcp","https://g-test.permaura.com/mcp"],"exp":9_999_999_999i64 }));
        assert!(rs.verify(&jwt, 1_000).is_ok());
    }

    #[test]
    fn fails_closed_when_no_owner_is_bound() {
        // A public RS with no operator binding must reject every token (the relay-free remote-access
        // guard): an audience-correct token from any operator is refused, not silently accepted.
        let (rs, sk) = rs(); // rs() leaves owner_sub = None
        let aud = "https://g-test.permaura.com/mcp";
        let jwt = mint_jwt(&sk, "k1", serde_json::json!({ "sub":"anyone","iss":"https://permaura.com","aud":aud,"exp":9_999_999_999i64 }));
        assert!(rs.verify(&jwt, 1_000).unwrap_err().contains("operator binding"));
    }

    /// The console's own token carries the operator scope and is recognised as such.
    #[test]
    fn an_operator_scoped_token_is_marked_operator() {
        let (rs, sk) = rs();
        rs.repin_owner("user_sam");
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({
                "sub": "user_sam", "iss": "https://permaura.com", "exp": 4_102_444_800i64,
                "aud": "https://g-test.permaura.com/mcp", "scope": "permaura:operator",
            }),
        );
        let claims = rs.verify(&jwt, 1_700_000_000).expect("valid");
        assert!(claims.is_operator(), "console token must grant the operator plane");
    }

    /// The escalation that matters: an MCP client's token is minted for the SAME operator and passes
    /// every existing check, so only the scope may separate it from the console. If this ever fails,
    /// any connected agent can drive the control plane.
    #[test]
    fn an_agent_token_for_the_same_operator_is_not_operator() {
        let (rs, sk) = rs();
        rs.repin_owner("user_sam");
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({
                "sub": "user_sam", "iss": "https://permaura.com", "exp": 4_102_444_800i64,
                "aud": "https://g-test.permaura.com/mcp",
                "azp": "client_chatgpt", "scope": "openid profile mcp",
            }),
        );
        let claims = rs.verify(&jwt, 1_700_000_000).expect("valid agent token");
        assert!(!claims.is_operator(), "an agent token must never reach the operator plane");
    }

    /// A token with no scope at all (the shape every token had before this existed) is not the operator, and not an agent either: `is_agent` wants `mcp`.
    #[test]
    fn a_scopeless_token_is_not_operator() {
        let (rs, sk) = rs();
        rs.repin_owner("user_sam");
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({
                "sub": "user_sam", "iss": "https://permaura.com", "exp": 4_102_444_800i64,
                "aud": "https://g-test.permaura.com/mcp",
            }),
        );
        let claims = rs.verify(&jwt, 1_700_000_000).unwrap();
        assert!(!claims.is_operator());
        assert!(!claims.is_agent());
    }

    fn operator_token(sk: &SigningKey, sub: &str, extra: serde_json::Value) -> String {
        let mut claims = serde_json::json!({
            "sub": sub, "iss": "https://permaura.com", "exp": 4_102_444_800i64,
            "aud": "https://g-test.permaura.com/mcp", "scope": OPERATOR_SCOPE,
        });
        claims.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        mint_jwt(sk, "k1", claims)
    }

    /// The console signs `vault_export: true` only for a holder of Export the vault, and the verifier carries
    /// exactly that. Absent, `false` or any other shape is no standing, and a role never stands in for it.
    #[test]
    fn an_operator_token_carries_the_export_standing_only_when_signed_true() {
        let (rs, sk) = rs();
        rs.repin_owner("user_owner");
        let standing_of = |extra: serde_json::Value| {
            rs.verify(&operator_token(&sk, "user_owner", extra), 1_700_000_000).unwrap().actor.and_then(|a| a.vault_export)
        };
        assert_eq!(standing_of(serde_json::json!({ "act_sub": "user_priya", "vault_export": true })), Some(true));
        assert_eq!(standing_of(serde_json::json!({ "act_sub": "user_priya", "act_role": "admin", "vault_export": true })), Some(true));
        for without in [
            serde_json::json!({ "act_sub": "user_priya" }),
            serde_json::json!({ "act_sub": "user_priya", "vault_export": false }),
            serde_json::json!({ "act_sub": "user_priya", "act_role": "admin" }),
            serde_json::json!({ "act_sub": "user_priya", "act_role": "owner" }),
        ] {
            assert_eq!(standing_of(without.clone()), None, "{without}");
        }
        let err = rs
            .verify(&operator_token(&sk, "user_owner", serde_json::json!({ "act_sub": "user_priya", "vault_export": "true" })), 1_700_000_000)
            .expect_err("a claim of the wrong type does not verify");
        assert!(err.contains("claims"), "{err}");
    }

    /// The console names the member acting behind the owner's `sub`, and the verifier carries it.
    #[test]
    fn an_operator_token_carries_the_acting_member() {
        let (rs, sk) = rs();
        rs.repin_owner("user_owner");
        let jwt = operator_token(&sk, "user_owner", serde_json::json!({ "act_sub": "user_priya", "act_name": " Priya " }));
        let claims = rs.verify(&jwt, 1_700_000_000).unwrap();
        assert!(claims.is_operator());
        assert_eq!(
            claims.actor,
            Some(crate::store::SessionActor { sub: "user_priya".into(), name: Some("Priya".into()), role: None, vault_export: None })
        );

        let plain = operator_token(&sk, "user_owner", serde_json::json!({}));
        assert_eq!(rs.verify(&plain, 1_700_000_000).unwrap().actor, None, "absent means not named");
        let blank = operator_token(&sk, "user_owner", serde_json::json!({ "act_sub": "  ", "act_name": "Priya" }));
        assert_eq!(rs.verify(&blank, 1_700_000_000).unwrap().actor, None, "a name alone names nobody");
        let long = operator_token(
            &sk,
            "user_owner",
            serde_json::json!({ "act_sub": "u".repeat(500), "act_name": "n".repeat(500) }),
        );
        let actor = rs.verify(&long, 1_700_000_000).unwrap().actor.unwrap();
        assert_eq!(actor.sub.chars().count(), MAX_ACTOR_SUB_LEN);
        assert_eq!(actor.name.unwrap().chars().count(), MAX_ACTOR_NAME_LEN);
    }

    /// A self-chosen name is recorded as text a reader can trust to look like what it is.
    #[test]
    fn an_actor_name_loses_control_bidi_and_zero_width_characters() {
        let (rs, sk) = rs();
        rs.repin_owner("user_owner");
        let jwt = operator_token(
            &sk,
            "user_owner",
            serde_json::json!({ "act_sub": "user_priya", "act_name": "Pri\u{200B}ya\u{202E}\u{1b}[2A  Raman\n" }),
        );
        let actor = rs.verify(&jwt, 1_700_000_000).unwrap().actor.unwrap();
        assert_eq!(actor.name.as_deref(), Some("Priya[2A Raman"));
        let jwt = operator_token(&sk, "user_owner", serde_json::json!({ "act_sub": "user_priya", "act_name": "\u{200B}\u{202E}" }));
        assert_eq!(rs.verify(&jwt, 1_700_000_000).unwrap().actor.unwrap().name, None, "nothing printable is no name");
    }

    /// The actor is never authority. A token addressed to someone other than the bound owner is
    /// refused even when its actor IS the owner, exactly as it was before the claim existed.
    #[test]
    fn the_acting_member_cannot_stand_in_for_the_owner() {
        let (rs, sk) = rs();
        rs.repin_owner("user_owner");
        let jwt = operator_token(&sk, "user_priya", serde_json::json!({ "act_sub": "user_owner" }));
        assert!(rs.verify(&jwt, 1_700_000_000).is_err(), "the owner check keys off sub alone");
    }

    /// Scope matching is per-token, not substring: a scope that merely CONTAINS the operator string
    /// must not grant it.
    #[test]
    fn a_lookalike_scope_does_not_grant_the_operator_plane() {
        for scope in ["permaura:operator-readonly", "notpermaura:operator", "permaura:operatorx"] {
            let claims = VerifiedClaims {
                sub: "user_sam".into(),
                azp: None,
                name: None,
                scope: Some(scope.into()),
                actor: None,
            };
            assert!(!claims.is_operator(), "{scope} must not grant the operator plane");
        }
        // ...while the real scope alongside others still does.
        let claims = VerifiedClaims {
            sub: "user_sam".into(),
            azp: None,
            name: None,
            scope: Some("openid permaura:operator profile".into()),
            actor: None,
        };
        assert!(claims.is_operator());
    }

    // ── step-up pairing tickets ────────────────────────────────────────────────────

    const NOW: i64 = 1_700_000_000;
    const PAIR_AUD: &str = "https://g-test.permaura.com/v1/approver-keys/pair";
    const FLOOR_AUD: &str = "https://g-test.permaura.com/v1/approval-floor";

    /// An owner-bound RS, as every hosted gateway is.
    fn owner_rs() -> (OAuthRs, SigningKey) {
        let (rs, sk) = rs();
        rs.repin_owner("user_sam");
        (rs, sk)
    }

    /// A well-formed `approver-pair` ticket. Tests mutate one field at a time so each assertion
    /// pins exactly one check rather than passing because the ticket was broken in some other way.
    fn ticket_claims() -> serde_json::Value {
        serde_json::json!({
            "sub": "user_sam", "iss": "https://permaura.com", "exp": NOW + 120,
            "aud": PAIR_AUD, "jti": "tkt_1", "purpose": "approver-pair",
            "approver_id": "device:a1b2c3", "pubkey_fp": "fp_abc",
            "amr": ["pwd", "otp"], "auth_time": NOW - 30,
        })
    }

    fn pair_binding() -> TicketBinding<'static> {
        TicketBinding::ApproverKey { approver_id: "device:a1b2c3", pubkey_fp: "fp_abc" }
    }


    /// Every purpose, pairing included, takes one sign-in method: the password, a passkey or the phone. A code alone is refused, and the refusal carries the claims so the caller can record them.
    #[test]
    fn a_ticket_needs_a_password_passkey_or_phone_whatever_its_purpose() {
        let (rs, sk) = owner_rs();
        for amr in [
            serde_json::json!(["otp"]),
            serde_json::json!(["totp"]),
            serde_json::json!(["backup"]),
            serde_json::json!(["session"]),
            serde_json::json!([]),
            serde_json::json!(["totp", "otp", "backup", "session"]),
        ] {
            let mut claims = ticket_claims();
            claims["amr"] = amr.clone();
            claims["act_sub"] = serde_json::json!("user_priya");
            let err = rs
                .verify_ticket(&mint_jwt(&sk, "k1", claims), TicketPurpose::ApproverPair, pair_binding(), NOW)
                .expect_err("a step-up with no sign-in method must be refused");
            assert!(err.reason.contains("password, passkey or phone approval"), "{amr}: {err}");
            let weak = err.weak_step_up.expect("the refusal keeps the claims for the audit record");
            assert_eq!(weak.jti.as_deref(), Some("tkt_1"));
            assert_eq!(serde_json::json!(weak.amr), amr);
            assert_eq!(weak.actor_sub.as_deref(), Some("user_priya"));
        }
        for amr in [
            serde_json::json!(["pwd"]),
            serde_json::json!(["passkey"]),
            serde_json::json!(["device"]),
            serde_json::json!(["pwd", "otp"]),
            serde_json::json!(["session", "passkey"]),
        ] {
            let mut claims = ticket_claims();
            claims["amr"] = amr.clone();
            let t = rs
                .verify_ticket(&mint_jwt(&sk, "k1", claims), TicketPurpose::ApproverPair, pair_binding(), NOW)
                .unwrap_or_else(|e| panic!("{amr} is a step-up: {e}"));
            assert_eq!(serde_json::json!(t.amr), amr, "the ticket keeps every method the AS named");
        }
    }

    /// An `approver-revoke` ticket is pinned to the one approver id it may revoke, and a mismatch says so, so the caller can refuse it outright.
    #[test]
    fn a_revoke_ticket_is_bound_to_its_approver_id() {
        let (rs, sk) = owner_rs();
        let mut claims = ticket_claims();
        claims["purpose"] = serde_json::json!("approver-revoke");
        claims["aud"] = serde_json::json!("https://g-test.permaura.com/v1/approver-keys/revoke");
        claims["amr"] = serde_json::json!(["pwd", "device"]);
        let jwt = mint_jwt(&sk, "k1", claims);
        let ours = TicketBinding::ApproverId { approver_id: "device:a1b2c3" };
        assert!(rs.verify_ticket(&jwt, TicketPurpose::ApproverRevoke, ours, NOW).is_ok());
        let other = TicketBinding::ApproverId { approver_id: "device:other" };
        let err = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverRevoke, other, NOW)
            .expect_err("a ticket for one device must not revoke another");
        assert!(err.unbound, "{err}");
        assert!(err.weak_step_up.is_none());
    }

    #[test]
    fn accepts_a_well_formed_pairing_ticket() {
        let (rs, sk) = owner_rs();
        let jwt = mint_jwt(&sk, "k1", ticket_claims());
        let t = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
            .expect("valid ticket");
        assert_eq!(t.jti, "tkt_1");
        assert_eq!(t.sub, "user_sam");
        assert_eq!(t.auth_time, NOW - 30);
        assert_eq!(t.amr, vec!["pwd".to_string(), "otp".to_string()]);
    }

    /// `sub` addresses the worker; `act_sub` names the human. On a team account they differ, and the
    /// audit record downstream is only honest if the second one survives verification.
    #[test]
    fn surfaces_the_actor_separately_from_the_owner_the_ticket_addresses() {
        let (rs, sk) = owner_rs();
        let mut claims = ticket_claims();
        claims["act_sub"] = serde_json::json!("user_priya");
        claims["act_name"] = serde_json::json!("Priya Raman");
        let jwt = mint_jwt(&sk, "k1", claims);
        let t = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
            .expect("valid ticket");
        assert_eq!(t.sub, "user_sam", "sub stays the worker's owner: it is how the ticket is pinned");
        assert_eq!(t.actor_sub.as_deref(), Some("user_priya"));
        assert_eq!(t.actor_name.as_deref(), Some("Priya Raman"));
    }

    /// `act_role` survives verification only as a role a recovery may rest on. Anything else,
    /// including a list that merely contains one, is no role, so it can never widen what is accepted.
    #[test]
    fn an_actor_role_is_kept_only_when_it_is_owner_or_admin() {
        let (rs, sk) = owner_rs();
        let role_of = |role: Option<&str>| {
            let mut claims = ticket_claims();
            claims["act_sub"] = serde_json::json!("user_priya");
            if let Some(role) = role {
                claims["act_role"] = serde_json::json!(role);
            }
            rs.verify_ticket(&mint_jwt(&sk, "k1", claims), TicketPurpose::ApproverPair, pair_binding(), NOW)
                .expect("valid ticket")
                .actor_role
        };
        assert_eq!(role_of(Some("admin")).as_deref(), Some("admin"));
        assert_eq!(role_of(Some(" Owner ")).as_deref(), Some("owner"));
        for other in [None, Some("member"), Some("viewer"), Some("owner,admin"), Some("")] {
            assert_eq!(role_of(other), None, "{other:?}");
        }
    }

    /// An AS too old to name an actor must leave the field EMPTY. Defaulting it to `sub` would write
    /// "the owner did this" into the one record kept to tell the owner whether they did.
    #[test]
    fn an_unnamed_actor_stays_unnamed_rather_than_defaulting_to_the_owner() {
        let (rs, sk) = owner_rs();
        let t = rs
            .verify_ticket(
                &mint_jwt(&sk, "k1", ticket_claims()),
                TicketPurpose::ApproverPair,
                pair_binding(),
                NOW,
            )
            .expect("a ticket without an actor claim still verifies");
        assert_eq!(t.actor_sub, None);
        assert_eq!(t.actor_name, None);

        // Whitespace identifies nobody either, and must not read as "an actor was named".
        let mut blank = ticket_claims();
        blank["act_sub"] = serde_json::json!("   ");
        blank["act_name"] = serde_json::json!("");
        let t = rs
            .verify_ticket(
                &mint_jwt(&sk, "k1", blank),
                TicketPurpose::ApproverPair,
                pair_binding(),
                NOW,
            )
            .expect("valid ticket");
        assert_eq!(t.actor_sub, None);
        assert_eq!(t.actor_name, None);
    }

    /// The display name is set by the account holder on themselves and ends up in a hash-chained
    /// record, so its length is bounded here rather than wherever it is later rendered.
    #[test]
    fn bounds_the_actor_display_name() {
        let (rs, sk) = owner_rs();
        let mut claims = ticket_claims();
        // Multi-byte on purpose: truncating by bytes would slice a codepoint and panic.
        claims["act_name"] = serde_json::json!("é".repeat(MAX_ACTOR_NAME_LEN * 3));
        let jwt = mint_jwt(&sk, "k1", claims);
        let t = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
            .expect("a long display name is trimmed, not a reason to refuse an enrolment");
        assert_eq!(t.actor_name.as_deref().map(|n| n.chars().count()), Some(MAX_ACTOR_NAME_LEN));
    }

    #[test]
    fn rejects_a_ticket_minted_for_another_audience() {
        let (rs, sk) = owner_rs();
        let mut claims = ticket_claims();
        claims["aud"] = serde_json::json!("https://g-other.permaura.com/v1/approver-keys/pair");
        let jwt = mint_jwt(&sk, "k1", claims);
        let err = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
            .unwrap_err().to_string();
        assert!(err.contains("audience"), "{err}");
    }

    #[test]
    fn rejects_a_ticket_for_a_different_purpose() {
        // The `purpose` claim is checked even though the audience already separates the two
        // classes, so a ticket cannot be repurposed by an AS that gets the audience right and the
        // purpose wrong.
        let (rs, sk) = owner_rs();
        let mut claims = ticket_claims();
        claims["purpose"] = serde_json::json!("approval-floor-lower");
        let jwt = mint_jwt(&sk, "k1", claims);
        let err = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
            .unwrap_err().to_string();
        assert!(err.contains("purpose"), "{err}");
    }

    /// A ticket authorises ONE key, once. Swapping in another approver id (the whole point of
    /// intercepting a ticket) must fail.
    #[test]
    fn rejects_a_ticket_bound_to_another_approver_id() {
        let (rs, sk) = owner_rs();
        let jwt = mint_jwt(&sk, "k1", ticket_claims());
        let bind = TicketBinding::ApproverKey { approver_id: "device:attacker", pubkey_fp: "fp_abc" };
        let err = rs.verify_ticket(&jwt, TicketPurpose::ApproverPair, bind, NOW).unwrap_err().to_string();
        assert!(err.contains("approver id"), "{err}");
    }

    #[test]
    fn rejects_a_ticket_bound_to_another_public_key() {
        let (rs, sk) = owner_rs();
        let jwt = mint_jwt(&sk, "k1", ticket_claims());
        let bind =
            TicketBinding::ApproverKey { approver_id: "device:a1b2c3", pubkey_fp: "fp_attacker" };
        let err = rs.verify_ticket(&jwt, TicketPurpose::ApproverPair, bind, NOW).unwrap_err().to_string();
        assert!(err.contains("public key"), "{err}");
    }

    #[test]
    fn rejects_a_stale_or_future_re_authentication() {
        let (rs, sk) = owner_rs();
        for amr in [serde_json::json!(["pwd", "otp"]), serde_json::json!(["pwd"]), serde_json::json!(["passkey"]), serde_json::json!(["device"])] {
            let mut stale = ticket_claims();
            stale["amr"] = amr.clone();
            stale["auth_time"] = serde_json::json!(NOW - (STEP_UP_MAX_AGE_SECS + 1));
            let jwt = mint_jwt(&sk, "k1", stale);
            let err = rs
                .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
                .unwrap_err().to_string();
            assert!(err.contains("stale"), "{amr}: {err}");
        }
        // An auth_time far in the future would otherwise buy an attacker extra freshness.
        let mut future = ticket_claims();
        future["auth_time"] = serde_json::json!(NOW + STEP_UP_MAX_AGE_SECS);
        let jwt = mint_jwt(&sk, "k1", future);
        let err = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
            .unwrap_err().to_string();
        assert!(err.contains("future"), "{err}");
    }

    /// Recovery keeps two factors while a step-up takes one: a recovery or recovery-code ticket needs the password and a second factor, so a password, passkey or phone on its own is refused and kept for the audit record.
    #[test]
    fn a_recovery_ticket_needs_the_password_and_a_second_factor() {
        let (rs, sk) = owner_rs();
        for (purpose, aud) in [
            (TicketPurpose::Recovery, "https://g-test.permaura.com/v1/recovery"),
            (TicketPurpose::RecoveryCodesIssue, "https://g-test.permaura.com/v1/recovery-codes"),
        ] {
            let claims_with = |amr: &serde_json::Value| {
                let mut claims = ticket_claims();
                claims.as_object_mut().unwrap().remove("approver_id");
                claims.as_object_mut().unwrap().remove("pubkey_fp");
                claims["purpose"] = serde_json::json!(purpose.claim());
                claims["aud"] = serde_json::json!(aud);
                claims["amr"] = amr.clone();
                claims
            };
            for amr in [
                serde_json::json!(["pwd"]),
                serde_json::json!(["passkey"]),
                serde_json::json!(["device"]),
                serde_json::json!(["otp", "backup"]),
                serde_json::json!(["pwd", "session"]),
            ] {
                let err = rs
                    .verify_ticket(&mint_jwt(&sk, "k1", claims_with(&amr)), purpose, TicketBinding::None, NOW)
                    .expect_err("a recovery ticket naming fewer than two factors must be refused");
                assert!(err.reason.contains("the password and a second factor"), "{purpose:?} {amr}: {err}");
                let weak = err.weak_step_up.expect("the refusal keeps the claims for the audit record");
                assert_eq!(serde_json::json!(weak.amr), amr);
            }
            for second in RECOVERY_SECOND_FACTORS {
                let amr = serde_json::json!(["pwd", second]);
                rs.verify_ticket(&mint_jwt(&sk, "k1", claims_with(&amr)), purpose, TicketBinding::None, NOW)
                    .unwrap_or_else(|e| panic!("{purpose:?} {amr} is a recovery: {e}"));
            }
        }
    }

    const RECOVERY_PURPOSES: [TicketPurpose; 2] = [TicketPurpose::Recovery, TicketPurpose::RecoveryCodesIssue];

    fn recovery_claims(purpose: TicketPurpose, amr: &serde_json::Value) -> serde_json::Value {
        let mut claims = ticket_claims();
        claims.as_object_mut().unwrap().remove("approver_id");
        claims.as_object_mut().unwrap().remove("pubkey_fp");
        claims["purpose"] = serde_json::json!(purpose.claim());
        claims["aud"] = serde_json::json!(format!("https://g-test.permaura.com{}", purpose.audience_path()));
        claims["amr"] = amr.clone();
        claims
    }

    /// permaura.com names a phone registered in the last day `new-device`. Wherever one method is enough it is the phone like any other, and it is never a factor of a recovery ticket, beside the password or beside another strong method.
    #[test]
    fn a_new_phone_is_a_sign_in_method_but_never_a_recovery_factor() {
        let (rs, sk) = owner_rs();
        let new_phone = serde_json::json!(["new-device"]);
        let mut pair = ticket_claims();
        pair["amr"] = new_phone.clone();
        rs.verify_ticket(&mint_jwt(&sk, "k1", pair), TicketPurpose::ApproverPair, pair_binding(), NOW)
            .expect("a new phone is a step-up for pairing");
        let mut revoke = ticket_claims();
        revoke["purpose"] = serde_json::json!("approver-revoke");
        revoke["aud"] = serde_json::json!("https://g-test.permaura.com/v1/approver-keys/revoke");
        revoke["amr"] = new_phone.clone();
        rs.verify_ticket(&mint_jwt(&sk, "k1", revoke), TicketPurpose::ApproverRevoke, TicketBinding::ApproverId { approver_id: "device:a1b2c3" }, NOW)
            .expect("a new phone is a step-up for a revocation");
        let floor = recovery_claims(TicketPurpose::ApprovalFloorLower, &new_phone);
        rs.verify_ticket(&mint_jwt(&sk, "k1", floor), TicketPurpose::ApprovalFloorLower, TicketBinding::None, NOW)
            .expect("a new phone is a step-up for lowering the floor");
        for purpose in RECOVERY_PURPOSES {
            for amr in [
                serde_json::json!(["new-device"]),
                serde_json::json!(["pwd", "new-device"]),
                serde_json::json!(["passkey", "new-device"]),
                serde_json::json!(["totp", "new-device"]),
                serde_json::json!(["device", "new-device"]),
            ] {
                let err = rs
                    .verify_ticket(&mint_jwt(&sk, "k1", recovery_claims(purpose, &amr)), purpose, TicketBinding::None, NOW)
                    .expect_err("a new phone is never a recovery factor");
                assert!(err.reason.contains("the password and a second factor"), "{purpose:?} {amr}: {err}");
                assert!(err.weak_step_up.is_some(), "{purpose:?} {amr}: the refusal is kept for the audit record");
            }
        }
    }

    /// An account with no password proves two different strong methods (a passkey, the phone, an authenticator code) in place of the password and a second factor. One method named twice is one method, and an emailed code is not one of the two.
    #[test]
    fn a_passwordless_recovery_takes_two_different_strong_methods() {
        let (rs, sk) = owner_rs();
        for purpose in RECOVERY_PURPOSES {
            for amr in [
                serde_json::json!(["passkey", "device"]),
                serde_json::json!(["passkey", "totp"]),
                serde_json::json!(["device", "totp"]),
                serde_json::json!(["passkey", "device", "totp"]),
            ] {
                rs.verify_ticket(&mint_jwt(&sk, "k1", recovery_claims(purpose, &amr)), purpose, TicketBinding::None, NOW)
                    .unwrap_or_else(|e| panic!("{purpose:?} {amr} is two strong methods: {e}"));
            }
            for amr in [
                serde_json::json!(["passkey", "passkey"]),
                serde_json::json!(["device", "device"]),
                serde_json::json!(["totp", "totp"]),
                serde_json::json!(["device", "otp"]),
                serde_json::json!(["passkey", "otp"]),
            ] {
                let err = rs
                    .verify_ticket(&mint_jwt(&sk, "k1", recovery_claims(purpose, &amr)), purpose, TicketBinding::None, NOW)
                    .expect_err("one strong method, however often it is named, is not two");
                assert!(err.reason.contains("two different strong methods"), "{purpose:?} {amr}: {err}");
            }
        }
    }

    /// An account with no password may also prove one strong method and a backup code, as a backup code may follow the password. A backup code alone, beside an emailed code or beside a phone in its first day, is not that.
    #[test]
    fn a_passwordless_recovery_takes_one_strong_method_and_a_backup_code() {
        let (rs, sk) = owner_rs();
        for purpose in RECOVERY_PURPOSES {
            for amr in [
                serde_json::json!(["passkey", "backup"]),
                serde_json::json!(["device", "backup"]),
                serde_json::json!(["totp", "backup"]),
                serde_json::json!(["totp", "otp", "backup"]),
            ] {
                rs.verify_ticket(&mint_jwt(&sk, "k1", recovery_claims(purpose, &amr)), purpose, TicketBinding::None, NOW)
                    .unwrap_or_else(|e| panic!("{purpose:?} {amr} is a strong method and a backup code: {e}"));
            }
            for amr in [
                serde_json::json!(["backup"]),
                serde_json::json!(["backup", "backup"]),
                serde_json::json!(["otp", "backup"]),
                serde_json::json!(["new-device", "backup"]),
            ] {
                let err = rs
                    .verify_ticket(&mint_jwt(&sk, "k1", recovery_claims(purpose, &amr)), purpose, TicketBinding::None, NOW)
                    .expect_err("a backup code needs a strong method or the password beside it");
                assert!(err.reason.contains("the password and a second factor"), "{purpose:?} {amr}: {err}");
            }
        }
    }

    #[test]
    fn rejects_a_ticket_asserting_no_interactive_factor() {
        let (rs, sk) = owner_rs();
        for amr in [serde_json::json!([]), serde_json::json!(["cookie", "sso"])] {
            let mut claims = ticket_claims();
            claims["amr"] = amr;
            claims["purpose"] = serde_json::json!("approval-floor-lower");
            claims["aud"] = serde_json::json!(FLOOR_AUD);
            let jwt = mint_jwt(&sk, "k1", claims);
            let err = rs
                .verify_ticket(&jwt, TicketPurpose::ApprovalFloorLower, TicketBinding::None, NOW)
                .unwrap_err().to_string();
            assert!(err.contains("password, passkey or phone approval"), "{err}");
        }
    }

    /// Without a jti the caller cannot spend the ticket, so it would be replayable for its whole
    /// TTL. Refused at verification rather than accepted and left unspendable.
    #[test]
    fn rejects_a_ticket_with_no_jti() {
        let (rs, sk) = owner_rs();
        for jti in [serde_json::Value::Null, serde_json::json!("  ")] {
            let mut claims = ticket_claims();
            claims["jti"] = jti;
            let jwt = mint_jwt(&sk, "k1", claims);
            let err = rs
                .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
                .unwrap_err().to_string();
            assert!(err.contains("jti"), "{err}");
        }
    }

    /// The structural separation that makes tickets worth having: an ordinary operator access token
    /// (same signing key, same issuer, same subject, and carrying the operator scope) is not a
    /// ticket, because it was minted for the MCP audience. If this ever passes, holding an operator
    /// token is enough to enrol an approver on a hosted worker.
    #[test]
    fn an_mcp_access_token_is_not_a_pairing_ticket() {
        let (rs, sk) = owner_rs();
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({
                "sub": "user_sam", "iss": "https://permaura.com", "exp": NOW + 120,
                "aud": "https://g-test.permaura.com/mcp", "scope": "permaura:operator",
                "jti": "tkt_1", "purpose": "approver-pair",
                "approver_id": "device:a1b2c3", "pubkey_fp": "fp_abc",
                "amr": ["pwd"], "auth_time": NOW - 5,
            }),
        );
        let err = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
            .unwrap_err().to_string();
        assert!(err.contains("audience"), "{err}");
        // ...and it is still a perfectly good access token, so the two paths really are disjoint.
        assert!(rs.verify(&jwt, NOW).unwrap().is_operator());
    }

    /// A ticket is minted for the operator; the owner binding in the shared verification path still
    /// applies, so another tenant's ticket for this gateway's endpoint is rejected.
    #[test]
    fn rejects_a_ticket_from_another_subject() {
        let (rs, sk) = owner_rs();
        let mut claims = ticket_claims();
        claims["sub"] = serde_json::json!("user_attacker");
        let jwt = mint_jwt(&sk, "k1", claims);
        let err = rs
            .verify_ticket(&jwt, TicketPurpose::ApproverPair, pair_binding(), NOW)
            .unwrap_err().to_string();
        assert!(err.contains("operator"), "{err}");
    }

    /// The floor-lowering ticket has no per-object binding, but still needs its own audience.
    #[test]
    fn a_floor_lowering_ticket_needs_its_own_audience() {
        let (rs, sk) = owner_rs();
        let mut claims = ticket_claims();
        claims["purpose"] = serde_json::json!("approval-floor-lower");
        let wrong_aud = mint_jwt(&sk, "k1", claims.clone());
        assert!(rs
            .verify_ticket(&wrong_aud, TicketPurpose::ApprovalFloorLower, TicketBinding::None, NOW)
            .unwrap_err()
            .to_string()
            .contains("audience"));
        claims["aud"] = serde_json::json!("https://g-test.permaura.com/v1/approval-floor");
        let ok = mint_jwt(&sk, "k1", claims);
        assert!(rs
            .verify_ticket(&ok, TicketPurpose::ApprovalFloorLower, TicketBinding::None, NOW)
            .is_ok());
    }

    /// The operator scope buys nothing without the owner binding: a different subject is still
    /// rejected outright by `verify`, before scope is ever consulted.
    #[test]
    fn operator_scope_from_another_subject_is_still_rejected() {
        let (rs, sk) = rs();
        rs.repin_owner("user_sam");
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({
                "sub": "user_someone_else", "iss": "https://permaura.com", "exp": 4_102_444_800i64,
                "aud": "https://g-test.permaura.com/mcp", "scope": "permaura:operator",
            }),
        );
        assert!(rs.verify(&jwt, 1_700_000_000).is_err());
    }

    // ── Hostname moves ────────────────────────────────────────────────────────────────────────────
    //
    // Renaming a gateway changes its OAuth audience, and an agent's token is bound to the audience it
    // was minted for. Without aliases the rename 401s every connected agent until each re-runs its
    // OAuth flow, which an unattended agent does not do. These pin the drain path: the old hostname
    // keeps verifying, the new one is the only one ever advertised, and nothing else gets in.

    #[test]
    fn accepts_a_token_minted_for_a_previous_hostname() {
        let (rs, sk) = rs_with_aliases(vec!["https://pw-acme.a.run.app".into()]);
        rs.repin_owner("claude-web");
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({ "sub": "claude-web", "iss": "https://permaura.com",
                "aud": "https://pw-acme.a.run.app/mcp", "exp": 9_999_999_999i64 }),
        );
        let claims = rs.verify(&jwt, 1_000).expect("the old hostname still verifies");
        assert_eq!(claims.sub, "claude-web");
    }

    #[test]
    fn the_canonical_hostname_still_verifies_alongside_an_alias() {
        let (rs, sk) = rs_with_aliases(vec!["https://pw-acme.a.run.app".into()]);
        rs.repin_owner("claude-web");
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({ "sub": "claude-web", "iss": "https://permaura.com",
                "aud": "https://g-test.permaura.com/mcp", "exp": 9_999_999_999i64 }),
        );
        assert!(rs.verify(&jwt, 1_000).is_ok());
    }

    #[test]
    fn a_hostname_that_is_neither_canonical_nor_an_alias_is_refused() {
        let (rs, sk) = rs_with_aliases(vec!["https://pw-acme.a.run.app".into()]);
        rs.repin_owner("claude-web");
        let jwt = mint_jwt(
            &sk,
            "k1",
            serde_json::json!({ "sub": "claude-web", "iss": "https://permaura.com",
                "aud": "https://someone-else.permaura.app/mcp", "exp": 9_999_999_999i64 }),
        );
        assert!(rs.verify(&jwt, 1_000).is_err());
    }

    #[test]
    fn an_alias_is_accepted_but_never_advertised() {
        let (rs, _) = rs_with_aliases(vec!["https://pw-acme.a.run.app".into()]);
        // What discovery publishes is the canonical resource alone, so every NEW token is minted for
        // the new hostname and the alias only ever drains.
        assert_eq!(rs.config().mcp_resource, "https://g-test.permaura.com/mcp");
        assert_eq!(
            rs.config().accepted_mcp_resources(),
            vec![
                "https://g-test.permaura.com/mcp".to_string(),
                "https://pw-acme.a.run.app/mcp".to_string(),
            ]
        );
    }

    #[test]
    fn ticket_audiences_cover_every_hostname_and_stay_pinned_to_one_route() {
        let (rs, _) = rs_with_aliases(vec!["https://pw-acme.a.run.app".into()]);
        let auds = rs.config().accepted_ticket_audiences("/v1/approver-keys/pair");
        assert_eq!(
            auds,
            vec![
                "https://g-test.permaura.com/v1/approver-keys/pair".to_string(),
                "https://pw-acme.a.run.app/v1/approver-keys/pair".to_string(),
            ]
        );
        // Still disjoint from the MCP resource, so neither class can be presented as the other.
        for aud in &auds {
            assert!(!rs.config().accepted_mcp_resources().contains(aud));
        }
    }

    #[test]
    fn alias_parsing_normalises_dedupes_and_drops_the_canonical_url() {
        let canonical = "https://acme.permaura.app";
        assert_eq!(parse_public_url_aliases("", canonical), Vec::<String>::new());
        assert_eq!(
            parse_public_url_aliases(
                " https://old.example.com/ , https://acme.permaura.app, https://old.example.com ,,",
                canonical,
            ),
            vec!["https://old.example.com".to_string()],
        );
        assert_eq!(
            parse_public_url_aliases("https://a.example.com https://b.example.com", canonical),
            vec!["https://a.example.com".to_string(), "https://b.example.com".to_string()],
        );
    }
}
