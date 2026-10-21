//! The OAuth authorization-code dance for connector credentials: the **bring-your-own-app** path
//! (Layer 3).
//!
//! The operator registers an OAuth app with the provider, hands the gateway its `client_id` and
//! `client_secret`, and authorises in a browser. The gateway exchanges the code itself, keeps the
//! refresh token, and mints access tokens from then on. permaura.com is never involved and never sees
//! any of it. This is the zero-knowledge layer, and it is what makes an OAuth connector work
//! *indefinitely* rather than for the lifetime of one hand-pasted access token.
//!
//! Two properties this module is responsible for:
//!
//! - **`state` is the only thing authenticating the callback.** The redirect arrives as an ordinary
//!   browser GET with no bearer token, so `state` must be CSPRNG-generated, single-use, and expiring.
//!   A guessable or replayable `state` would let anyone complete a dance the operator started, or
//!   graft an attacker's authorization onto the operator's connection (the classic OAuth CSRF).
//! - **The client secret never lands on disk unsealed.** It lives in memory for the few minutes the
//!   dance takes, then goes into the sealed credential alongside the tokens.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use base64::Engine;
use permaura_core::{Connection, SealedSecret, SecretString};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::connectors::{HttpClient, HttpRequest};
use crate::error::GatewayError;
use crate::oauth_credential::{OAuthCredential, OAuthLayer};
use crate::store::{Session, Store};

/// How long an operator has to complete the browser dance before the pending authorization is swept.
/// Long enough to find the right Google account and read a consent screen, short enough that a
/// `state` left in browser history is worthless.
pub const PENDING_TTL_MS: i64 = 10 * 60 * 1000;

/// Discriminator on the sealed credential blob. A connection's credential slot holds either raw
/// secret bytes (an API key) or this JSON envelope; the marker is what tells them apart, so an API
/// key that happens to be valid JSON is never mistaken for a token bundle.
pub const SEALED_KIND: &str = "permaura.oauth.v1";

/// Serialise an OAuth credential for the sealed credential slot, into text that is wiped when it drops
/// and was written without leaving a partial copy behind.
pub fn to_sealed_json(cred: &OAuthCredential) -> Result<SecretString, GatewayError> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        kind: &'static str,
        #[serde(flatten)]
        cred: &'a OAuthCredential,
    }
    let mut out = permaura_core::WipingBuffer::with_capacity(512);
    serde_json::to_writer(&mut out, &Envelope { kind: SEALED_KIND, cred })
        .map_err(|e| GatewayError::Internal(format!("oauth credential serialise failed: {e}")))?;
    out.into_secret_string().ok_or_else(|| GatewayError::Internal("oauth credential serialise failed: not UTF-8".into()))
}

/// Recover an OAuth credential from sealed bytes, or `None` when the slot holds a plain API key.
/// Deliberately total: anything that is not our tagged envelope is a raw secret, not an error.
///
/// Read in two passes over the same bytes, the tag and then the credential, rather than through
/// `#[serde(flatten)]`, which buffers every member of the document as an owned copy first. That matters
/// beyond OAuth: this runs on every call, over whatever the slot holds, a JSON service-account key included.
pub fn from_sealed_bytes(bytes: &[u8]) -> Option<OAuthCredential> {
    #[derive(Deserialize)]
    struct Tag<'a> {
        #[serde(borrow)]
        kind: std::borrow::Cow<'a, str>,
    }
    let tag: Tag = serde_json::from_slice(bytes).ok()?;
    if tag.kind != SEALED_KIND {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

/// One in-flight authorization, held only until its callback arrives. The client secret and the PKCE
/// verifier are wiped when it drops and never printed by `Debug`.
#[derive(Clone)]
pub struct PendingAuth {
    /// The connection whose credential this dance will seal.
    pub connection_id: String,
    /// The connector/provider id, recorded on the credential for display.
    pub provider: String,
    /// The operator's OAuth app.
    pub client_id: String,
    /// The operator's OAuth app secret. Held in memory for the life of the dance only.
    pub client_secret: SecretString,
    /// Echoed back at the token endpoint; providers require it to match the authorize request.
    pub redirect_uri: String,
    /// The provider's token endpoint.
    pub token_url: String,
    /// PKCE verifier, when the provider supports it.
    pub code_verifier: Option<SecretString>,
    /// Scopes requested, recorded on the resulting credential for re-auth diffing.
    pub scopes: Vec<String>,
    /// When this was created, for the TTL sweep.
    pub created_ms: i64,
    /// What the dance was started against, checked again before its credential is written.
    pub binding: PendingBinding,
}

impl std::fmt::Debug for PendingAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAuth")
            .field("connection_id", &self.connection_id)
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("token_url", &self.token_url)
            .field("code_verifier", &self.code_verifier.is_some())
            .field("scopes", &self.scopes)
            .field("created_ms", &self.created_ms)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

/// What an authorization was started against: the connection as it was, the slot its credential goes
/// into, the credential already there, and who asked.
///
/// The callback is an unauthenticated browser redirect that can arrive up to [`PENDING_TTL_MS`] after
/// `start`, so the connection it names may have been removed and made again as another connector, or
/// given a newer credential, or a dance started over the broker may have had a device enrolled under
/// it, by then. [`Self::stale`] is asked before the code is exchanged and again
/// inside the unit of work that writes, and a binding that no longer holds writes nothing.
#[derive(Debug, Clone)]
pub struct PendingBinding {
    /// The connection's creation stamp. It does not tell every incarnation apart: a vault import writes
    /// a bundle's stamp verbatim, so a connection exported, removed and imported again under the same id
    /// keeps it. The removal bumped [`Self::removal`], which refuses the dance in that case.
    pub created_at: i64,
    /// The connector the connection was made from, the provider this dance authorizes.
    pub connector: String,
    /// The secret slot the credential is written to.
    pub secret_id: String,
    /// The credential in that slot when the dance began, `None` when it had none.
    pub credential: Option<CredentialMark>,
    /// Deliberate changes to that slot since the dance began.
    pub watch: CredentialWatch,
    /// Removals of the connection since the dance began.
    pub removal: CredentialWatch,
    /// The operator session that started the dance, named on the credential write's audit record.
    /// Its bearer is not kept.
    pub initiator: Session,
    /// Whether `start` came over the broker. `start` refuses that while a device is enrolled, and
    /// [`Self::stale`] refuses the write once a device enrolled since would hold it
    /// ([`crate::service::EnforcementService::control_plane_hold_required`]), so an approval floor
    /// opted down to Approve lets it complete.
    pub remote: bool,
}

impl PendingBinding {
    /// Bind a dance to `connection` as it is now. The watch starts before the slot is read, so a write
    /// that lands in between counts as a change rather than going unseen.
    pub fn capture(
        service: &crate::service::EnforcementService,
        connection: &Connection,
        initiator: &Session,
        remote: bool,
    ) -> Result<Self, GatewayError> {
        let removal = service.watch_connection_removal(&connection.id);
        let watch = service.watch_credential(&connection.secret_id);
        let credential = service.store().get_secret(&connection.secret_id)?.map(|s| CredentialMark::of(&s.sealed));
        Ok(PendingBinding {
            created_at: connection.created_at,
            connector: connection.connector.clone(),
            secret_id: connection.secret_id.clone(),
            credential,
            watch,
            removal,
            initiator: Session { token: String::new(), ..initiator.clone() },
            remote,
        })
    }

    /// Why this dance may no longer write its credential into `connection_id`, or `None` while it may.
    pub fn stale(
        &self,
        service: &crate::service::EnforcementService,
        store: &dyn Store,
        connection_id: &str,
    ) -> Result<Option<Stale>, GatewayError> {
        let Some(connection) = store.get_connection(connection_id)? else {
            return Ok(Some(Stale::Removed));
        };
        if connection.created_at != self.created_at || connection.connector != self.connector || !self.removal.unchanged() {
            return Ok(Some(Stale::Replaced));
        }
        if connection.secret_id != self.secret_id || !self.watch.unchanged() {
            return Ok(Some(Stale::CredentialChanged));
        }
        if self.remote && service.control_plane_hold_required(true) {
            return Ok(Some(Stale::Held));
        }
        let unchanged = match (&self.credential, store.get_secret(&self.secret_id)?) {
            (None, None) => true,
            (Some(mark), Some(now)) => mark.admits(&now.sealed),
            _ => false,
        };
        Ok((!unchanged).then_some(Stale::CredentialChanged))
    }
}

/// Why a pending authorization was refused at its callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    /// The connection is gone.
    Removed,
    /// The connection was removed and made again, possibly as another connector.
    Replaced,
    /// The connection's credential was changed or removed after the dance began.
    CredentialChanged,
    /// The dance was started over the broker and a device enrolled since now holds its credential
    /// change for a device signature the browser redirect cannot carry.
    Held,
}

impl Stale {
    /// The callback page's explanation.
    pub fn explain(self) -> &'static str {
        match self {
            Stale::Removed => "The connection was removed while you were authorizing, so nothing was saved.",
            Stale::Replaced => {
                "The connection was removed and made again while you were authorizing, so nothing was saved."
            }
            Stale::CredentialChanged => {
                "The connection's credential changed while you were authorizing, so this older authorization was not saved over it."
            }
            Stale::Held => {
                "A device was enrolled for approvals while you were authorizing, so a credential change started over the broker can no longer complete without its signature, and nothing was saved."
            }
        }
    }
}

/// The credential a dance began over, kept as digests rather than bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMark {
    sealed_sha256: String,
    /// For an OAuth bundle, a digest of the app it was issued to.
    oauth_app: Option<String>,
}

impl CredentialMark {
    /// Mark the sealed credential in a slot.
    pub fn of(sealed: &SealedSecret) -> Self {
        CredentialMark {
            sealed_sha256: crate::secret_inventory::staged_digest(sealed),
            oauth_app: oauth_app_digest(sealed),
        }
    }

    /// Whether `sealed` is still the credential this mark was taken of or, when that was an OAuth bundle,
    /// a bundle for the same app. A refresh rotation rewrites a bundle that way, and a reconnect is not
    /// refused because one landed while the operator was at the provider. This cannot tell a refresh
    /// from any other write of a same-app bundle, so refusing a deliberate one rests on the watch, which
    /// every deliberate writer bumps; a new value of any other kind is a change here whether or not its
    /// writer bumped.
    fn admits(&self, sealed: &SealedSecret) -> bool {
        crate::secret_inventory::staged_digest(sealed) == self.sealed_sha256
            || (self.oauth_app.is_some() && oauth_app_digest(sealed) == self.oauth_app)
    }
}

/// A digest of the parts of an OAuth bundle a refresh keeps: who issued it to which app. `None` for a
/// slot that holds anything else.
fn oauth_app_digest(sealed: &SealedSecret) -> Option<String> {
    let plain = permaura_core::open(sealed, crate::service::vault_passphrase()).ok()?;
    let cred = from_sealed_bytes(&plain)?;
    let app = permaura_core::secret::to_json(&(&cred.layer, &cred.provider, &cred.token_url, &cred.client_id, &cred.client_secret)).ok()?;
    Some(permaura_core::audit::sha256_hex(&app))
}

/// How many deliberate changes each credential slot, and each connection, with an OAuth dance
/// outstanding against it has had since the dance began: a write or a delete for a slot, and its
/// removal for a connection. A refresh rotation is not one. An entry lives only while a
/// [`CredentialWatch`] on it does, so the table is the size of the dances in flight.
#[derive(Default)]
pub struct CredentialRevisions {
    inner: Mutex<HashMap<WatchKey, Watched>>,
}

/// What a [`CredentialWatch`] counts changes to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WatchKey {
    Slot(String),
    Connection(String),
}

struct Watched {
    watchers: usize,
    revision: u64,
}

impl CredentialRevisions {
    /// Start watching `secret_id`.
    pub fn watch(self: &Arc<Self>, secret_id: &str) -> CredentialWatch {
        self.watch_key(WatchKey::Slot(secret_id.to_string()))
    }

    /// Start watching for the removal of `connection_id`.
    pub fn watch_removal(self: &Arc<Self>, connection_id: &str) -> CredentialWatch {
        self.watch_key(WatchKey::Connection(connection_id.to_string()))
    }

    fn watch_key(self: &Arc<Self>, key: WatchKey) -> CredentialWatch {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let entry = map.entry(key.clone()).or_insert(Watched { watchers: 0, revision: 0 });
        entry.watchers += 1;
        let revision = entry.revision;
        CredentialWatch { revisions: self.clone(), key, revision }
    }

    /// Note a deliberate change to `secret_id`. Nothing to do when no dance watches it.
    pub fn note_change(&self, secret_id: &str) {
        self.bump(&WatchKey::Slot(secret_id.to_string()));
    }

    /// Note that `connection_id` was removed. Nothing to do when no dance watches it.
    pub fn note_removal(&self, connection_id: &str) {
        self.bump(&WatchKey::Connection(connection_id.to_string()));
    }

    fn bump(&self, key: &WatchKey) {
        if let Some(entry) = self.inner.lock().unwrap_or_else(|p| p.into_inner()).get_mut(key) {
            entry.revision += 1;
        }
    }

    /// How many slots are watched (for tests and diagnostics).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// True when nothing is watched.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One dance's watch on a credential slot or a connection; see [`CredentialRevisions`].
pub struct CredentialWatch {
    revisions: Arc<CredentialRevisions>,
    key: WatchKey,
    revision: u64,
}

impl CredentialWatch {
    /// True while what it watches has had no deliberate change since this watch began.
    pub fn unchanged(&self) -> bool {
        let map = self.revisions.inner.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&self.key).is_some_and(|w| w.revision == self.revision)
    }
}

impl Clone for CredentialWatch {
    fn clone(&self) -> Self {
        let mut map = self.revisions.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = map.get_mut(&self.key) {
            entry.watchers += 1;
        }
        CredentialWatch { revisions: self.revisions.clone(), key: self.key.clone(), revision: self.revision }
    }
}

impl Drop for CredentialWatch {
    fn drop(&mut self) {
        let mut map = self.revisions.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = map.get_mut(&self.key) {
            entry.watchers = entry.watchers.saturating_sub(1);
            if entry.watchers == 0 {
                map.remove(&self.key);
            }
        }
    }
}

impl std::fmt::Debug for CredentialWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialWatch").field("key", &self.key).field("revision", &self.revision).finish()
    }
}

/// In-memory table of in-flight authorizations, keyed by `state`.
///
/// Deliberately not persisted. A pending dance is worthless after a restart (the browser tab is gone
/// and the operator simply starts again), and not persisting means an un-completed `client_secret`
/// never touches disk at all. The consequence is that a multi-instance deployment must run the start
/// and the callback on the same instance, true today for a local gateway and for a single-instance
/// hosted worker, and the reason `start` is refused where that cannot be guaranteed.
#[derive(Default)]
pub struct PendingAuths {
    inner: Mutex<HashMap<String, PendingAuth>>,
}

impl PendingAuths {
    /// Record a pending authorization, sweeping anything already expired.
    pub fn insert(&self, state: String, pending: PendingAuth, now_ms: i64) {
        let mut map = self.inner.lock().expect("pending auth lock");
        map.retain(|_, p| now_ms.saturating_sub(p.created_ms) < PENDING_TTL_MS);
        map.insert(state, pending);
    }

    /// Take a pending authorization by `state`. Single-use: a replayed callback finds nothing, which
    /// is what stops an attacker reusing a `state` captured from browser history or a referrer.
    pub fn take(&self, state: &str, now_ms: i64) -> Option<PendingAuth> {
        let mut map = self.inner.lock().expect("pending auth lock");
        let pending = map.remove(state)?;
        (now_ms.saturating_sub(pending.created_ms) < PENDING_TTL_MS).then_some(pending)
    }

    /// How many authorizations are in flight (for tests and diagnostics).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("pending auth lock").len()
    }

    /// True when nothing is in flight.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 32 CSPRNG bytes, base64url-encoded without padding, used for both `state` and the PKCE verifier.
/// `OsRng`, not a seeded PRNG: `state` is the callback's only authentication.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The PKCE S256 challenge for a verifier (RFC 7636).
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Percent-encode a query-string value, leaving only the RFC 3986 unreserved set intact.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the provider's authorization URL.
///
/// `access_type=offline` and `prompt=consent` are Google-specific but harmless elsewhere (unknown
/// authorize params are ignored per RFC 6749 §3.1), and without them Google returns no refresh token
/// on a re-authorization, the single most common reason a BYO setup appears to work and then dies an
/// hour later.
pub fn authorize_url(
    authorize_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    code_challenge: Option<&str>,
) -> String {
    let mut url = format!(
        "{}{}response_type=code&client_id={}&redirect_uri={}&state={}&access_type=offline&prompt=consent",
        authorize_endpoint,
        if authorize_endpoint.contains('?') { "&" } else { "?" },
        pct(client_id),
        pct(redirect_uri),
        pct(state),
    );
    if !scopes.is_empty() {
        url.push_str(&format!("&scope={}", pct(&scopes.join(" "))));
    }
    if let Some(challenge) = code_challenge {
        url.push_str(&format!("&code_challenge={}&code_challenge_method=S256", pct(challenge)));
    }
    url
}

/// What the token endpoint returns on an authorization-code exchange.
#[derive(Deserialize)]
struct TokenResponse {
    #[serde(deserialize_with = "permaura_core::secret::unescaped::deserialize")]
    access_token: SecretString,
    #[serde(default, deserialize_with = "permaura_core::secret::unescaped::option")]
    refresh_token: Option<SecretString>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
}

/// Exchange an authorization code for tokens and build the credential to seal.
///
/// Refuses a response with no refresh token: without one the connection dies when the access token
/// expires, which is exactly the failure this whole path exists to remove. Far better to fail here,
/// where the operator can be told why (almost always a Google app left in "Testing", or a
/// re-authorization without `prompt=consent`), than to seal a credential that quietly stops working.
pub async fn exchange_code(
    http: &dyn HttpClient,
    pending: &PendingAuth,
    code: &str,
    now_ms: i64,
) -> Result<OAuthCredential, GatewayError> {
    let mut form = BTreeMap::new();
    form.insert("grant_type".to_string(), "authorization_code".to_string());
    form.insert("code".to_string(), code.to_string());
    form.insert("redirect_uri".to_string(), pending.redirect_uri.clone());
    form.insert("client_id".to_string(), pending.client_id.clone());
    form.insert("client_secret".to_string(), pending.client_secret.expose().to_string());
    if let Some(verifier) = &pending.code_verifier {
        form.insert("code_verifier".to_string(), verifier.expose().to_string());
    }

    let req = HttpRequest::post(pending.token_url.clone())
        .header("Accept", "application/json")
        .form_body(form)
        .credentialed();
    let resp = http
        .send_secret(req)
        .await
        .map_err(|e| GatewayError::upstream("oauth token exchange failed", &e))?;
    if resp.status >= 400 {
        // The provider's own error body is the useful part (invalid_grant, redirect_uri_mismatch,
        // invalid_client), so surface it rather than a bare status.
        #[derive(Deserialize)]
        struct Refusal {
            error: Option<serde_json::Value>,
            error_description: Option<serde_json::Value>,
        }
        let refusal: Option<Refusal> = serde_json::from_slice(&resp.body).ok();
        let detail = refusal
            .and_then(|r| r.error_description.or(r.error))
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "no detail".to_string());
        return Err(GatewayError::BadRequest(format!(
            "oauth token exchange rejected ({}): {detail}",
            resp.status
        )));
    }
    let token: TokenResponse = serde_json::from_slice(&resp.body)
        .map_err(|e| GatewayError::Internal(format!("oauth token exchange: bad response: {e}")))?;
    drop(resp);

    if token.refresh_token.is_none() {
        return Err(GatewayError::BadRequest(
            "the provider returned no refresh token, so this connection would stop working when the \
             access token expires. Check the app is not in a testing/sandbox mode that withholds \
             refresh tokens, and that the authorization asked for offline access."
                .to_string(),
        ));
    }

    let scopes = token
        .scope
        .map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| pending.scopes.clone());

    Ok(OAuthCredential {
        layer: OAuthLayer::ByoApp,
        provider: pending.provider.clone(),
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at: match token.expires_in {
            Some(secs) if secs > 0 => now_ms.saturating_add(secs.saturating_mul(1000)),
            _ => 0,
        },
        scopes,
        token_url: pending.token_url.clone(),
        client_id: Some(pending.client_id.clone()),
        client_secret: Some(pending.client_secret.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The type-level pin for what this module reads and holds.
    #[allow(dead_code)]
    fn secret_members_are_wiping_types<'a>(t: &'a TokenResponse, p: &'a PendingAuth) -> [Option<&'a SecretString>; 4] {
        [Some(&t.access_token), t.refresh_token.as_ref(), Some(&p.client_secret), p.code_verifier.as_ref()]
    }
    use crate::connectors::{HttpResponse, MockHttpClient};

    fn pending() -> PendingAuth {
        PendingAuth {
            connection_id: "gmail-work".into(),
            provider: "gmail".into(),
            client_id: "cid".into(),
            client_secret: "csecret".into(),
            redirect_uri: "http://127.0.0.1:7376/oauth/callback".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            code_verifier: Some("verifier".into()),
            scopes: vec!["https://www.googleapis.com/auth/gmail.readonly".into()],
            created_ms: 1_000,
            binding: binding(&Arc::new(CredentialRevisions::default())),
        }
    }

    fn binding(revisions: &Arc<CredentialRevisions>) -> PendingBinding {
        PendingBinding {
            created_at: 1,
            connector: "gmail".into(),
            secret_id: "sec_gmail-work".into(),
            credential: None,
            watch: revisions.watch("sec_gmail-work"),
            removal: revisions.watch_removal("gmail-work"),
            initiator: serde_json::from_value(serde_json::json!({
                "id": "sess_synthetic", "agent_id": "operator", "token": "", "created_at": 0, "revoked": false
            }))
            .unwrap(),
            remote: false,
        }
    }

    #[test]
    fn a_watch_sees_a_change_noted_after_it_began_and_only_on_its_own_slot() {
        let revisions = Arc::new(CredentialRevisions::default());
        revisions.note_change("sec_gmail-work");
        let watch = revisions.watch("sec_gmail-work");
        assert!(watch.unchanged(), "a change before the watch began is not one it sees");
        revisions.note_change("sec_other");
        assert!(watch.unchanged(), "another slot's change is not this one's");
        revisions.note_removal("sec_gmail-work");
        assert!(watch.unchanged(), "a connection's removal is not a change to a slot of the same name");
        let clone = watch.clone();
        revisions.note_change("sec_gmail-work");
        assert!(!watch.unchanged() && !clone.unchanged());
        let later = revisions.watch("sec_gmail-work");
        assert!(later.unchanged(), "a dance begun after the change binds to the slot as it is now");
    }

    #[test]
    fn the_watch_table_holds_only_what_a_dance_still_watches() {
        let revisions = Arc::new(CredentialRevisions::default());
        let first = binding(&revisions);
        let second = first.clone();
        assert_eq!(revisions.len(), 2, "the slot and the connection");
        drop(first);
        assert_eq!(revisions.len(), 2, "a clone still watches");
        drop(second);
        assert!(revisions.is_empty());
        let auths = PendingAuths::default();
        let mut p = pending();
        p.binding = binding(&revisions);
        auths.insert("st".into(), p, 1_000);
        assert_eq!(revisions.len(), 2);
        drop(auths.take("st", 1_000));
        assert!(revisions.is_empty(), "a callback that is done with its dance lets the slot and the connection go");
    }

    #[test]
    fn the_binding_keeps_no_bearer() {
        let revisions = Arc::new(CredentialRevisions::default());
        let mut b = binding(&revisions);
        b.initiator.token = "pgt_synthetic-bearer".into();
        let connection: Connection = serde_json::from_value(serde_json::json!({
            "id": "gmail-work", "connector": "gmail", "name": "Work", "label": "Gmail", "secret_id": "sec_gmail-work"
        }))
        .unwrap();
        let service = crate::service::EnforcementService::new(
            Arc::new(crate::store::memory::MemoryStore::new()),
            Arc::new(crate::connectors::MockHttpClient::new()),
        );
        let captured = PendingBinding::capture(&service, &connection, &b.initiator, false).unwrap();
        assert!(captured.initiator.token.is_empty());
        assert_eq!(captured.initiator.id, "sess_synthetic");
    }

    #[test]
    fn state_is_single_use_and_expires() {
        let auths = PendingAuths::default();
        auths.insert("st".into(), pending(), 1_000);
        // A replayed callback finds nothing: the OAuth CSRF guard.
        assert!(auths.take("st", 1_000).is_some());
        assert!(auths.take("st", 1_000).is_none());

        auths.insert("st2".into(), pending(), 1_000);
        assert!(auths.take("st2", 1_000 + PENDING_TTL_MS + 1).is_none(), "expired state is refused");
    }

    #[test]
    fn inserting_sweeps_expired_entries() {
        let auths = PendingAuths::default();
        auths.insert("old".into(), pending(), 1_000);
        let mut fresh = pending();
        fresh.created_ms = 1_000 + PENDING_TTL_MS + 1;
        auths.insert("new".into(), fresh, 1_000 + PENDING_TTL_MS + 1);
        assert_eq!(auths.len(), 1, "the expired entry is swept on insert");
    }

    #[test]
    fn authorize_url_carries_the_offline_and_pkce_params() {
        let url = authorize_url(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "cid",
            "http://127.0.0.1:7376/oauth/callback",
            &["a/b".to_string(), "c".to_string()],
            "st ate",
            Some("chal"),
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=cid"));
        // Without offline access Google issues no refresh token at all.
        assert!(url.contains("access_type=offline") && url.contains("prompt=consent"));
        // Scopes are space-joined then percent-encoded; the separator must not survive raw.
        assert!(url.contains("scope=a%2Fb%20c"), "got {url}");
        assert!(url.contains("state=st%20ate"));
        assert!(url.contains("code_challenge=chal&code_challenge_method=S256"));
    }

    #[test]
    fn s256_challenge_matches_rfc_7636() {
        // The worked example from RFC 7636 Appendix B.
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_sealed_oauth_blob_round_trips_and_an_api_key_is_not_mistaken_for_one() {
        let cred = OAuthCredential {
            layer: OAuthLayer::ByoApp,
            provider: "gmail".into(),
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            expires_at: 42,
            scopes: vec!["s".into()],
            token_url: "https://t".into(),
            client_id: Some("cid".into()),
            client_secret: Some("sec".into()),
        };
        let json = to_sealed_json(&cred).unwrap();
        assert_eq!(from_sealed_bytes(json.as_bytes()).unwrap(), cred);
        // A plain API key, and even a JSON-shaped one, must never parse as a token bundle.
        assert!(from_sealed_bytes(b"sk-live-abc123").is_none());
        assert!(from_sealed_bytes(br#"{"access_token":"x"}"#).is_none());
    }

    #[tokio::test]
    async fn exchange_posts_a_form_and_keeps_the_refresh_token() {
        let http = MockHttpClient::default();
        http.push_response(HttpResponse::json(
            200,
            serde_json::json!({
                "access_token": "at", "refresh_token": "rt",
                "expires_in": 3600, "scope": "scope.a scope.b"
            }),
        ));
        let cred = exchange_code(&http, &pending(), "the-code", 10_000).await.unwrap();

        let sent = http.requests();
        let form = sent[0].form.as_ref().expect("token exchange must be form-encoded, not JSON");
        assert_eq!(form.get("grant_type").unwrap(), "authorization_code");
        assert_eq!(form.get("code").unwrap(), "the-code");
        assert_eq!(form.get("code_verifier").unwrap(), "verifier");
        assert_eq!(form.get("client_secret").unwrap(), "csecret");
        assert!(sent[0].json().is_none(), "must not also send a JSON body");

        assert_eq!(cred.refresh_token.as_ref().map(permaura_core::SecretString::expose), Some("rt"));
        assert_eq!(cred.expires_at, 10_000 + 3_600_000);
        assert_eq!(cred.scopes, vec!["scope.a".to_string(), "scope.b".to_string()]);
        assert_eq!(cred.layer, OAuthLayer::ByoApp);
    }

    #[tokio::test]
    async fn exchange_refuses_a_response_with_no_refresh_token() {
        let http = MockHttpClient::default();
        http.push_response(HttpResponse::json(200, serde_json::json!({ "access_token": "at", "expires_in": 3600 })));
        let err = exchange_code(&http, &pending(), "code", 0).await.unwrap_err();
        // Failing loudly here beats sealing a credential that dies in an hour.
        assert!(format!("{err:?}").contains("no refresh token"), "got {err:?}");
    }

    #[tokio::test]
    async fn exchange_surfaces_the_providers_own_error() {
        let http = MockHttpClient::default();
        http.push_response(HttpResponse::json(
            400,
            serde_json::json!({ "error": "redirect_uri_mismatch", "error_description": "bad redirect" }),
        ));
        let err = exchange_code(&http, &pending(), "code", 0).await.unwrap_err();
        assert!(format!("{err:?}").contains("bad redirect"), "got {err:?}");
    }
}
