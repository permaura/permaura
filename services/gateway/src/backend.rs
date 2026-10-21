//! The secret-backend seam: the one place the enforcement loop turns a `secret_id` into
//! plaintext for a single call.
//!
//! [`SecretBackend::resolve`] is the generalisation of [`permaura_core::Vault::use_secret`]:
//! it hands back an [`OpenedSecret`] guarded handle (zeroized on drop) and encapsulates
//! *how* custody works, so policy, execution, redaction, and audit never have to care
//! where a secret physically lives. [`LocalVaultBackend`] opens the sealed
//! [`permaura_core::SecretRecord`] from the gateway [`Store`] under the local KEK passphrase
//! (exactly what the gateway did inline before this seam existed), and is the floor beneath
//! everything; [`InfisicalBackend`] and [`KmsBackend`] are the external custodians.
//!
//! **Which secret goes where is store state, not environment.** [`CustodyRouter`] reads a
//! [`crate::store::SecretCustody`] record per secret, so enrolling one into KMS
//! ([`enrol_secret_in_kms`]) is a runtime operation rather than a redeploy, and the set of
//! externally-held secrets can be enumerated ([`crate::secret_inventory`]) rather than inferred.
//! The environment still supplies the backends' *credentials*, and the pre-existing
//! `PERMAURA_*_SECRETS` lists are still honoured so an upgrade changes nothing.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use permaura_core::{OpenedSecret, SecretString, Vault};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::connectors::{HttpClient, HttpMethod, HttpRequest, ReqwestClient};
use crate::error::GatewayError;
use crate::store::{CustodyKind, SecretCustody, Store};

/// Resolves a `secret_id` to plaintext for a single operation.
///
/// This is the path every call and every vault export resolves a credential through. The gateway
/// decrypts in five other places, each into a wiping type: the OAuth refresh round and the reconnect
/// check open a stored OAuth bundle directly; the re-seal sweep opens a record to seal it again; the KMS
/// enrolment round trip unwraps what it just wrapped to check it; and bundle import, preview and
/// `permaura vault verify` open a vault bundle through [`crate::vault_bundle::open_payload`].
/// Callers use the returned [`OpenedSecret`] to shape exactly one upstream call (an HTTP header or a
/// command env value) and drop it (wiping the bytes) before touching the network or spawning a
/// child; the request or invocation it shaped wipes its own copy when it drops. There is deliberately
/// no method that returns a secret to an agent.
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Resolve `secret_id` to a guarded plaintext handle, failing if the secret is
    /// unknown or cannot be opened.
    ///
    /// This is the **stored-secret** path. A backend that mints a credential per call
    /// (see [`Lease`]) has nothing meaningful to return here (resolving without taking the
    /// lease would strand a live credential nobody revokes), and returns an error instead.
    /// Callers on the enforcement path use [`SecretBackend::acquire`].
    async fn resolve(&self, secret_id: &str) -> Result<OpenedSecret, GatewayError>;

    /// Obtain `secret_id` for exactly one call, together with the lease to hand back afterwards.
    ///
    /// The default is the stored-secret case: resolve, no lease, nothing to release. A dynamic
    /// backend overrides this to *mint* a short-TTL credential and return the lease that
    /// [`SecretBackend::release`] revokes, turning the exposure window from "until the TTL
    /// expires" into "for the duration of this one call".
    async fn acquire(&self, secret_id: &str) -> Result<LeasedSecret, GatewayError> {
        Ok(LeasedSecret::stored(self.resolve(secret_id).await?))
    }

    /// Hand a lease back early. Best-effort by contract: the caller runs it on every exit path but
    /// never fails a completed call because revocation did not land: the lease TTL is the backstop,
    /// which is why a dynamic backend must always mint with one.
    ///
    /// The default is a no-op, correct for every backend that never issues a lease.
    async fn release(&self, _lease: &Lease) {}

    /// Whether `secret_id` opens from a custodian other than this gateway's own sealed rows, judged from enrolment metadata alone: nothing is fetched, minted or unwrapped.
    /// An externally held credential has no local row, so a guard asking whether a credential slot is already in use must ask this as well as the store; a missing row is never proof the slot is free.
    fn holds_externally(&self, secret_id: &str) -> Result<bool, GatewayError>;
}

/// A minted credential's handle: what to revoke, and when it would expire on its own.
///
/// Carries `secret_id` so a router ([`CustodyRouter`]) can send the release back to the same
/// backend that minted it. Without that, a dynamic secret behind a composite would mint through one
/// backend and release through another, i.e. never release at all.
#[derive(Debug, Clone)]
pub struct Lease {
    /// The `secret_id` this lease was minted for. Routing key, not a credential.
    pub secret_id: String,
    /// The backend-assigned lease id used to revoke it.
    pub id: String,
    /// Absolute expiry in unix ms, when the backend reported one. The TTL backstop: if release
    /// never lands (crash, network loss), the credential still dies here.
    pub expires_at_ms: Option<i64>,
}

/// A secret opened for one call, plus the lease to release afterwards if one was minted.
///
/// The plaintext is in the [`OpenedSecret`] and is zeroized on drop as always; the lease is
/// deliberately kept *outside* it so releasing does not depend on when the plaintext is dropped.
pub struct LeasedSecret {
    secret: OpenedSecret,
    lease: Option<Lease>,
}

/// Deliberately hand-written and deliberately redacting: `#[derive(Debug)]` here would put live
/// credential bytes into any `dbg!`, panic message, or error format that ever touches this type.
impl std::fmt::Debug for LeasedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeasedSecret")
            .field("secret", &"<redacted>")
            .field("lease", &self.lease)
            .finish()
    }
}

impl LeasedSecret {
    /// A stored secret: nothing was minted, so there is nothing to release.
    pub fn stored(secret: OpenedSecret) -> Self {
        LeasedSecret { secret, lease: None }
    }

    /// A freshly minted credential and the lease that revokes it.
    pub fn leased(secret: OpenedSecret, lease: Lease) -> Self {
        LeasedSecret { secret, lease: Some(lease) }
    }

    /// Split into the plaintext handle and the lease, so the caller can drop (and zeroize) the
    /// plaintext as early as it always did while still holding the lease to release after the call.
    pub fn into_parts(self) -> (OpenedSecret, Option<Lease>) {
        (self.secret, self.lease)
    }
}

/// The local backend: custody lives in the gateway's own [`Store`], sealed under the
/// local KEK passphrase (the Keychain / Secure Enclave key in a real deployment, a fixed
/// dev passphrase in the offline runtime).
///
/// This wraps the path the gateway used inline before the [`SecretBackend`] seam existed:
/// it is a pure relocation behind the trait, with no behaviour change.
pub struct LocalVaultBackend {
    store: Arc<dyn Store>,
    keks: permaura_core::KekCache,
}

impl LocalVaultBackend {
    /// Build a local backend over a store and the KEK passphrase used to seal its secrets.
    pub fn new(store: Arc<dyn Store>, passphrase: impl Into<Vec<u8>>) -> Self {
        LocalVaultBackend {
            store,
            keks: permaura_core::KekCache::new(passphrase),
        }
    }

    /// How many records this backend holds a derived key for, for a test that wants to see the KDF
    /// run once rather than once per execution.
    pub fn cached_keys(&self) -> usize {
        self.keks.len()
    }
}

#[async_trait]
impl SecretBackend for LocalVaultBackend {
    async fn resolve(&self, secret_id: &str) -> Result<OpenedSecret, GatewayError> {
        let record = self
            .store
            .get_secret(secret_id)?
            .ok_or_else(|| GatewayError::NotFound(format!("secret '{secret_id}'")))?;

        // Open the sealed record through the core vault's closure (the audited crypto
        // path), and copy the plaintext into a zeroizing handle. `use_secret` wipes its
        // own buffer on return; the returned `OpenedSecret` owns and wipes the copy on
        // drop, so plaintext still never lives in an unguarded value.
        let mut vault = Vault::new();
        vault.insert_record(record);
        let opened = vault.use_secret_cached(secret_id, &self.keks, |bytes| {
            Ok(OpenedSecret::new(bytes.to_vec()))
        })?;
        permaura_core::secret::clear_stack();
        Ok(opened)
    }

    fn holds_externally(&self, _secret_id: &str) -> Result<bool, GatewayError> {
        Ok(false)
    }
}

// ── Infisical: the first external BYO-vault backend ──────────────────────────────────

/// Connection config for an Infisical machine-identity (Universal Auth) integration.
///
/// **Custody stays worker-local:** these credentials, and every secret resolved through them,
/// live only on the worker that holds this config. The control plane never sees the client secret
/// or the resolved value: it only records *that* a secret is Infisical-backed (`BackendRef`), so
/// "bring your own vault" never widens the trust surface toward the CP.
pub struct InfisicalConfig {
    /// API base, e.g. `https://app.infisical.com` (or a self-hosted instance).
    pub base_url: String,
    /// Universal-Auth machine identity client id.
    pub client_id: String,
    /// Universal-Auth machine identity client secret (never leaves the worker).
    pub client_secret: SecretString,
    /// The Infisical project (workspace) id.
    pub project_id: String,
    /// The environment slug, e.g. `prod`.
    pub environment: String,
    /// The secret path within the environment, e.g. `/`.
    pub secret_path: String,
}

impl InfisicalConfig {
    /// Read the backend **credentials** from `PERMAURA_INFISICAL_*`. Returns `None` unless the
    /// required fields (client id/secret, project, env) are all present and the URL is safe, so a
    /// half-configured deployment leaves the backend absent rather than half-live.
    ///
    /// Which secrets resolve here is no longer part of this: per-secret enrolment lives in the store
    /// as a [`crate::store::SecretCustody`] record, so it can change at runtime. The legacy env list
    /// is still honoured via [`InfisicalConfig::env_enrolled_secrets`].
    pub fn from_env() -> Option<InfisicalConfig> {
        const KEYS: &[&str] = &[
            "PERMAURA_INFISICAL_CLIENT_ID",
            "PERMAURA_INFISICAL_CLIENT_SECRET",
            "PERMAURA_INFISICAL_PROJECT",
            "PERMAURA_INFISICAL_ENV",
            "PERMAURA_INFISICAL_SECRETS",
            "PERMAURA_INFISICAL_URL",
            "PERMAURA_INFISICAL_PATH",
        ];
        let any_set = KEYS.iter().any(|k| non_empty_env(k).is_some());

        let built = (|| {
            let client_id = non_empty_env("PERMAURA_INFISICAL_CLIENT_ID")?;
            let client_secret = non_empty_env("PERMAURA_INFISICAL_CLIENT_SECRET")?;
            let project_id = non_empty_env("PERMAURA_INFISICAL_PROJECT")?;
            let environment = non_empty_env("PERMAURA_INFISICAL_ENV")?;
            let base_url = non_empty_env("PERMAURA_INFISICAL_URL")
                .unwrap_or_else(|| "https://app.infisical.com".to_string());
            // Refuse cleartext: the login carries the client secret and every fetch the bearer
            // token + secret value. Require https (http allowed ONLY to loopback for local dev),
            // so a flipped URL fails closed to the local vault rather than silently downgrading.
            if !is_secure_base_url(&base_url) {
                tracing::error!(url = %crate::connectors::scrub_url(&base_url), "PERMAURA_INFISICAL_URL must be https:// (http only for localhost): Infisical backend disabled");
                return None;
            }
            let secret_path =
                non_empty_env("PERMAURA_INFISICAL_PATH").unwrap_or_else(|| "/".to_string());
            Some(InfisicalConfig { base_url, client_id, client_secret: client_secret.into(), project_id, environment, secret_path })
        })();

        // A partial/invalid config (some PERMAURA_INFISICAL_* set, but incomplete or non-https) is a
        // footgun: secrets meant for Infisical would silently resolve locally. Surface it loudly.
        if any_set && built.is_none() {
            tracing::warn!(
                "Infisical is partially or invalidly configured (PERMAURA_INFISICAL_* set but incomplete or non-https): falling back to the local vault"
            );
        }
        built
    }

    /// The legacy per-secret enrolment list (`PERMAURA_INFISICAL_SECRETS`, comma-separated).
    ///
    /// Superseded by store custody records, and kept only so a deployment already carrying the
    /// variable does not silently change custody on upgrade. Empty when unset.
    pub fn env_enrolled_secrets() -> HashSet<String> {
        non_empty_env("PERMAURA_INFISICAL_SECRETS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A cached access token (Universal-Auth, or the cloud metadata server's) and its absolute expiry (unix ms).
struct CachedToken {
    token: SecretString,
    expires_at: i64,
}

/// `Authorization: Bearer <token>` built in a string of exactly that length, so no partial copy of the
/// token is left in a block it outgrew. The request it goes into wipes it on drop.
fn bearer(token: &SecretString) -> String {
    let mut value = String::with_capacity("Bearer ".len() + token.len());
    value.push_str("Bearer ");
    value.push_str(token.expose());
    value
}

/// What a token endpoint answers: the access token and how long it lasts. Read straight from the wiped
/// body into a [`SecretString`], unescaped there if the writer escaped it.
#[derive(Deserialize)]
struct IssuedToken {
    #[serde(alias = "accessToken", deserialize_with = "permaura_core::secret::unescaped::deserialize")]
    access_token: SecretString,
    #[serde(default, alias = "expiresIn")]
    expires_in: Option<serde_json::Value>,
}

impl IssuedToken {
    /// The lifetime in seconds, or an hour when the answer gives none it can read.
    fn ttl_secs(&self) -> i64 {
        self.expires_in.as_ref().and_then(serde_json::Value::as_i64).unwrap_or(3600)
    }
}

/// An external [`SecretBackend`] backed by Infisical (BYO-vault). The worker authenticates with a
/// machine identity and fetches the secret over HTTPS at call time; the credential and the
/// plaintext live only on this worker. Like every backend, it returns a guarded [`OpenedSecret`]
/// (zeroized on drop) and there is no path that hands a secret back to an agent.
pub struct InfisicalBackend {
    config: InfisicalConfig,
    auth: InfisicalAuth,
}

/// The Universal-Auth machine-identity login, shared by the static and dynamic Infisical backends.
///
/// The client secret is the worker's identity to the vault: the credential the whole BYO-vault
/// story protects. It lives here and nowhere else: never logged, never persisted, never returned.
pub struct InfisicalAuth {
    base_url: String,
    client_id: String,
    client_secret: SecretString,
    http: Arc<dyn HttpClient>,
    token: Mutex<Option<CachedToken>>,
}

impl InfisicalAuth {
    /// Build the login over the identity fields and an HTTP client (a real `ReqwestClient` in
    /// production, a `MockHttpClient` in tests, so it never touches `reqwest` directly).
    pub fn new(
        base_url: String,
        client_id: String,
        client_secret: SecretString,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        InfisicalAuth { base_url, client_id, client_secret, http, token: Mutex::new(None) }
    }

    fn base(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// Return a valid access token, performing a Universal-Auth login if none is cached or the
    /// cached one is within 5s of expiry.
    async fn access_token(&self) -> Result<SecretString, GatewayError> {
        if let Some(token) = self.cached_token() {
            return Ok(token);
        }
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Login<'a> {
            client_id: &'a str,
            client_secret: &'a SecretString,
        }
        let req = HttpRequest::post(format!("{}/api/v1/auth/universal-auth/login", self.base()))
            .secret_json_body(&Login { client_id: &self.client_id, client_secret: &self.client_secret })
            .map_err(|e| GatewayError::Internal(format!("infisical login: {e}")))?
            .credentialed();
        let resp = self
            .http
            .send_secret(req)
            .await
            .map_err(|e| GatewayError::upstream("infisical login failed", &e))?;
        if resp.status >= 400 {
            return Err(GatewayError::Internal(format!("infisical login returned {}", resp.status)));
        }
        let issued: IssuedToken = serde_json::from_slice(&resp.body)
            .map_err(|_| GatewayError::Internal("infisical login: no accessToken".into()))?;
        let ttl_secs = issued.ttl_secs();
        *self.token.lock().unwrap() = Some(CachedToken {
            token: issued.access_token.clone(),
            expires_at: now_ms().saturating_add(ttl_secs.saturating_mul(1000)),
        });
        Ok(issued.access_token)
    }

    fn cached_token(&self) -> Option<SecretString> {
        let guard = self.token.lock().unwrap();
        guard
            .as_ref()
            .filter(|c| c.expires_at > now_ms() + 5_000)
            .map(|c| c.token.clone())
    }

    fn clear_token(&self) {
        *self.token.lock().unwrap() = None;
    }
}

impl InfisicalBackend {
    /// Build the backend over a config and an HTTP client (a real `ReqwestClient` in production,
    /// a `MockHttpClient` in tests, so the backend never touches `reqwest` directly).
    pub fn new(config: InfisicalConfig, http: Arc<dyn HttpClient>) -> Self {
        let auth = InfisicalAuth::new(
            config.base_url.clone(),
            config.client_id.clone(),
            config.client_secret.clone(),
            http,
        );
        InfisicalBackend { config, auth }
    }

    fn base(&self) -> &str {
        self.config.base_url.trim_end_matches('/')
    }
}

#[async_trait]
impl SecretBackend for InfisicalBackend {
    async fn resolve(&self, secret_id: &str) -> Result<OpenedSecret, GatewayError> {
        let token = self.auth.access_token().await?;
        let url = format!(
            "{}/api/v3/secrets/raw/{}?workspaceId={}&environment={}&secretPath={}",
            self.base(),
            pct_encode(secret_id),
            pct_encode(&self.config.project_id),
            pct_encode(&self.config.environment),
            pct_encode(&self.config.secret_path),
        );
        let req = HttpRequest::get(url).header("Authorization", bearer(&token)).credentialed();
        drop(token);
        let resp = self
            .auth
            .http
            .send_secret(req)
            .await
            .map_err(|e| GatewayError::upstream("infisical fetch failed", &e))?;
        match resp.status {
            // A revoked/early-expired token: drop it so the next call re-authenticates.
            401 | 403 => {
                self.auth.clear_token();
                return Err(GatewayError::Internal(format!("infisical fetch denied ({})", resp.status)));
            }
            404 => return Err(GatewayError::NotFound(format!("infisical secret '{secret_id}'"))),
            s if s >= 400 => return Err(GatewayError::Internal(format!("infisical fetch returned {s}"))),
            _ => {}
        }
        // Response shape: { "secret": { "secretValue": "…", … } }. A multi-line value (a PEM key, a JSON key file)
        // always arrives escaped, so it is unescaped from its raw text into a wiping buffer.
        let fetched: Fetched = serde_json::from_slice(&resp.body)
            .map_err(|_| GatewayError::Internal(format!("infisical secret '{secret_id}': no secretValue")))?;
        drop(resp);
        permaura_core::secret::clear_stack();
        Ok(OpenedSecret::from(fetched.secret.secret_value))
    }

    /// On its own this backend fetches whatever name it is asked for, so every id may be held there.
    fn holds_externally(&self, _secret_id: &str) -> Result<bool, GatewayError> {
        Ok(true)
    }
}

// ── Infisical dynamic secrets: mint a short-TTL credential per call ──────────────────

/// One enrolled dynamic secret: which Infisical dynamic secret to mint from, and which field of
/// the minted credential this `secret_id` stands for.
#[derive(Debug, Clone)]
pub struct DynamicSecretRef {
    /// The Infisical dynamic-secret name, e.g. `pg-readonly`.
    pub name: String,
    /// Which key of the minted `data` object is the value, e.g. `DB_PASSWORD`. `None` is only
    /// valid when the provider returns exactly one field; anything else is refused rather than
    /// guessed, because guessing wrong means injecting the wrong credential into a live call.
    pub field: Option<String>,
}

/// Config for minting Infisical dynamic secrets. Separate from [`InfisicalConfig`] because the
/// dynamic API keys off the project **slug** where the static API uses the workspace **id**, and
/// because a deployment may use one, the other, or both.
pub struct InfisicalDynamicConfig {
    /// API base, e.g. `https://app.infisical.com`.
    pub base_url: String,
    /// Universal-Auth machine identity client id.
    pub client_id: String,
    /// Universal-Auth machine identity client secret (never leaves the worker).
    pub client_secret: SecretString,
    /// The project **slug** (not the id: the dynamic-secrets API takes the slug).
    pub project_slug: String,
    /// The environment slug, e.g. `prod`.
    pub environment: String,
    /// The path within the environment, e.g. `/`.
    pub path: String,
    /// TTL requested for each minted lease, in Infisical's duration form (`30s`, `5m`, `1h`).
    /// Deliberately short: this is the backstop for a release that never lands.
    pub ttl: String,
    /// `secret_id` → which dynamic secret and field it maps to.
    pub secrets: std::collections::HashMap<String, DynamicSecretRef>,
}

/// The default lease TTL when `PERMAURA_INFISICAL_DYNAMIC_TTL` is unset. Long enough for a slow
/// upstream call, short enough that a lease stranded by a crash dies on its own within minutes.
const DEFAULT_DYNAMIC_TTL: &str = "5m";

impl InfisicalDynamicConfig {
    /// Read `PERMAURA_INFISICAL_DYNAMIC_*` plus the shared `PERMAURA_INFISICAL_{CLIENT_ID,
    /// CLIENT_SECRET,ENV,PATH,URL}`. Returns the config and the enrolled `secret_id` set, or
    /// `None` when dynamic secrets are not configured.
    ///
    /// Enrolment form: `PERMAURA_INFISICAL_DYNAMIC_SECRETS="sec_db=pg-readonly:DB_PASSWORD,…"`.
    /// The `:FIELD` suffix is optional and may be omitted only for providers that return a single
    /// field.
    pub fn from_env() -> Option<(InfisicalDynamicConfig, HashSet<String>)> {
        const KEYS: &[&str] = &[
            "PERMAURA_INFISICAL_DYNAMIC_SECRETS",
            "PERMAURA_INFISICAL_DYNAMIC_PROJECT_SLUG",
            "PERMAURA_INFISICAL_DYNAMIC_TTL",
        ];
        let any_set = KEYS.iter().any(|k| non_empty_env(k).is_some());

        let built = (|| {
            let client_id = non_empty_env("PERMAURA_INFISICAL_CLIENT_ID")?;
            let client_secret = non_empty_env("PERMAURA_INFISICAL_CLIENT_SECRET")?;
            let project_slug = non_empty_env("PERMAURA_INFISICAL_DYNAMIC_PROJECT_SLUG")?;
            let environment = non_empty_env("PERMAURA_INFISICAL_ENV")?;
            let secrets = parse_dynamic_secrets(&non_empty_env("PERMAURA_INFISICAL_DYNAMIC_SECRETS")?);
            if secrets.is_empty() {
                return None;
            }
            let base_url = non_empty_env("PERMAURA_INFISICAL_URL")
                .unwrap_or_else(|| "https://app.infisical.com".to_string());
            // Same rule as the static backend: the login carries the client secret and every mint
            // returns a live database credential, so cleartext fails closed rather than downgrading.
            if !is_secure_base_url(&base_url) {
                tracing::error!(url = %crate::connectors::scrub_url(&base_url), "PERMAURA_INFISICAL_URL must be https:// (http only for localhost): dynamic secrets disabled");
                return None;
            }
            let path = non_empty_env("PERMAURA_INFISICAL_PATH").unwrap_or_else(|| "/".to_string());
            let ttl = non_empty_env("PERMAURA_INFISICAL_DYNAMIC_TTL")
                .unwrap_or_else(|| DEFAULT_DYNAMIC_TTL.to_string());
            let enrolled: HashSet<String> = secrets.keys().cloned().collect();
            Some((
                InfisicalDynamicConfig {
                    base_url,
                    client_id,
                    client_secret: client_secret.into(),
                    project_slug,
                    environment,
                    path,
                    ttl,
                    secrets,
                },
                enrolled,
            ))
        })();

        if any_set && built.is_none() {
            tracing::warn!(
                "Infisical dynamic secrets are partially or invalidly configured (PERMAURA_INFISICAL_DYNAMIC_* set but incomplete or non-https): those secrets fall back to the local vault"
            );
        }
        built
    }
}

/// Parse `id=name[:FIELD],…` into the enrolment map, skipping malformed entries.
fn parse_dynamic_secrets(raw: &str) -> std::collections::HashMap<String, DynamicSecretRef> {
    let mut out = std::collections::HashMap::new();
    for entry in raw.split(',') {
        let Some((id, spec)) = entry.trim().split_once('=') else { continue };
        let (id, spec) = (id.trim(), spec.trim());
        if id.is_empty() || spec.is_empty() {
            continue;
        }
        let (name, field) = match spec.split_once(':') {
            Some((name, field)) => (name.trim(), Some(field.trim().to_string()).filter(|f| !f.is_empty())),
            None => (spec, None),
        };
        if name.is_empty() {
            continue;
        }
        out.insert(id.to_string(), DynamicSecretRef { name: name.to_string(), field });
    }
    out
}

/// A [`SecretBackend`] that mints a **short-TTL credential per call** from Infisical's dynamic
/// secrets, and revokes it as soon as the call is done.
///
/// This is the phase-1 answer to "the credential in the worker is long-lived": what the worker
/// holds for the duration of one approved action is a credential the upstream itself issued
/// minutes ago and that Permaura hands back immediately afterwards. A stolen worker image, a
/// stolen store, a stolen log: none of them contain anything still valid.
///
/// **What is actually protected** is the machine identity allowed to mint, not the mint call.
/// A stolen identity can mint; scope, TTL, and the audit trail bound what that is worth, and
/// Permaura's policy gate stays a second, independent lock in front of it.
pub struct InfisicalDynamicBackend {
    config: InfisicalDynamicConfig,
    auth: InfisicalAuth,
}

impl InfisicalDynamicBackend {
    /// Build the backend over a config and an HTTP client.
    pub fn new(config: InfisicalDynamicConfig, http: Arc<dyn HttpClient>) -> Self {
        let auth = InfisicalAuth::new(
            config.base_url.clone(),
            config.client_id.clone(),
            config.client_secret.clone(),
            http,
        );
        InfisicalDynamicBackend { config, auth }
    }

    fn base(&self) -> &str {
        self.config.base_url.trim_end_matches('/')
    }

    /// The scope fields every dynamic-secrets call repeats.
    fn scope(&self) -> serde_json::Value {
        serde_json::json!({
            "projectSlug": self.config.project_slug,
            "environmentSlug": self.config.environment,
            "path": self.config.path,
        })
    }

    /// Pull the credential value out of a mint response's `data` object.
    ///
    /// With a configured field, take exactly that. Without one, accept a single-field `data` and
    /// refuse anything else: a multi-field provider (`DB_USERNAME` + `DB_PASSWORD`) has no
    /// defensible default, and picking one at random would inject the wrong half of a credential
    /// into a live call.
    fn extract_value(
        data: Option<&std::collections::BTreeMap<String, MintedField>>,
        secret_id: &str,
        field: Option<&str>,
    ) -> Result<SecretString, GatewayError> {
        let obj = data.ok_or_else(|| {
            GatewayError::Internal(format!("infisical dynamic '{secret_id}': lease had no data object"))
        })?;
        match field {
            Some(field) => obj
                .get(field)
                .and_then(MintedField::value)
                .ok_or_else(|| {
                    // The field names are operator config, not credential material, so safe to name.
                    GatewayError::Internal(format!(
                        "infisical dynamic '{secret_id}': lease data has no field '{field}'"
                    ))
                }),
            None if obj.len() == 1 => obj
                .values()
                .next()
                .and_then(MintedField::value)
                .ok_or_else(|| {
                    GatewayError::Internal(format!(
                        "infisical dynamic '{secret_id}': the single lease field is not a scalar"
                    ))
                }),
            None => Err(GatewayError::Internal(format!(
                "infisical dynamic '{secret_id}': lease returned {} fields: name one with 'id=name:FIELD'",
                obj.len()
            ))),
        }
    }
}

/// What an Infisical static fetch answers: `{ "secret": { "secretValue": "…", … } }`.
#[derive(Deserialize)]
struct Fetched {
    secret: FetchedSecret,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FetchedSecret {
    #[serde(deserialize_with = "permaura_core::secret::unescaped::deserialize")]
    secret_value: SecretString,
}

/// One field of a minted credential's `data`, read from its raw JSON text in the wiped body. A string is
/// unescaped into a wiping buffer; numbers and booleans are accepted because a provider may return a port or
/// a flag alongside the credential; objects, arrays and null are not a credential value.
pub(crate) struct MintedField(Option<SecretString>);

impl MintedField {
    fn from_raw(raw: &serde_json::value::RawValue) -> Self {
        let text = raw.get();
        MintedField(match text.as_bytes().first() {
            Some(b'"') => SecretString::from_json_literal(text),
            Some(b't' | b'f') if matches!(text, "true" | "false") => Some(SecretString::copied(text)),
            Some(b'-' | b'0'..=b'9') => text.parse::<serde_json::Number>().ok().map(|n| SecretString::new(n.to_string())),
            _ => None,
        })
    }

    fn value(&self) -> Option<SecretString> {
        self.0.clone()
    }
}

#[async_trait]
impl SecretBackend for InfisicalDynamicBackend {
    /// Refused on purpose. Minting without handing back the lease would leave a live database
    /// credential alive until its TTL with nothing tracking it: fail loudly instead of leaking
    /// quietly. The enforcement path calls [`SecretBackend::acquire`].
    async fn resolve(&self, secret_id: &str) -> Result<OpenedSecret, GatewayError> {
        Err(GatewayError::Internal(format!(
            "secret '{secret_id}' is a dynamic secret and must be acquired with a lease, not resolved"
        )))
    }

    fn holds_externally(&self, secret_id: &str) -> Result<bool, GatewayError> {
        Ok(self.config.secrets.contains_key(secret_id))
    }

    async fn acquire(&self, secret_id: &str) -> Result<LeasedSecret, GatewayError> {
        let reference = self.config.secrets.get(secret_id).ok_or_else(|| {
            GatewayError::NotFound(format!("dynamic secret '{secret_id}'"))
        })?;
        let token = self.auth.access_token().await?;

        let mut body = self.scope();
        body["dynamicSecretName"] = serde_json::Value::String(reference.name.clone());
        body["ttl"] = serde_json::Value::String(self.config.ttl.clone());
        let req = HttpRequest::post(format!("{}/api/v1/dynamic-secrets/leases", self.base()))
            .header("Authorization", bearer(&token))
            .json_body(body)
            .credentialed();
        drop(token);

        let resp = self
            .auth
            .http
            .send_secret(req)
            .await
            .map_err(|e| GatewayError::upstream("infisical dynamic mint failed", &e))?;
        match resp.status {
            401 | 403 => {
                self.auth.clear_token();
                return Err(GatewayError::Internal(format!(
                    "infisical dynamic mint denied ({})",
                    resp.status
                )));
            }
            404 => {
                return Err(GatewayError::NotFound(format!(
                    "infisical dynamic secret '{}'",
                    reference.name
                )))
            }
            s if s >= 400 => {
                return Err(GatewayError::Internal(format!(
                    "infisical dynamic mint returned {s}"
                )))
            }
            _ => {}
        }

        // Each member is read on its own, so a malformed `data` (or any other member) never costs the lease id:
        // the credential was minted whatever shape the rest of the answer took, and only the id can revoke it.
        // Repeated top-level keys keep the last, as a JSON object read into a map always has here.
        type Members<'a> = std::collections::BTreeMap<String, &'a serde_json::value::RawValue>;
        let top: Option<Members> = serde_json::from_slice(&resp.body).ok();
        let lease: Option<serde_json::Value> =
            top.as_ref().and_then(|t| t.get("lease")).and_then(|raw| serde_json::from_str(raw.get()).ok());
        let data: Option<std::collections::BTreeMap<String, MintedField>> = top
            .as_ref()
            .and_then(|t| t.get("data"))
            .and_then(|raw| serde_json::from_str::<Members>(raw.get()).ok())
            .map(|fields| fields.into_iter().map(|(name, raw)| (name, MintedField::from_raw(raw))).collect());
        drop(top);
        drop(resp);
        let lease_id = lease.as_ref().and_then(|l| l.get("id")).and_then(|v| v.as_str()).map(str::to_string);
        let value = Self::extract_value(data.as_ref(), secret_id, reference.field.as_deref());

        // A mint that produced a credential we cannot read is still a LIVE credential upstream.
        // Hand it straight back rather than letting the TTL carry it: the failure is ours, and a
        // misconfigured field would otherwise strand one credential per attempted call.
        let value = match value {
            Ok(value) => value,
            Err(e) => {
                if let Some(id) = lease_id {
                    let orphan = Lease {
                        secret_id: secret_id.to_string(),
                        id,
                        expires_at_ms: None,
                    };
                    self.release(&orphan).await;
                }
                return Err(e);
            }
        };

        let Some(lease_id) = lease_id else {
            // No lease id means nothing can ever revoke this credential. Refuse the call rather
            // than run it on a credential that will outlive the request untracked.
            return Err(GatewayError::Internal(format!(
                "infisical dynamic '{secret_id}': mint returned no lease id"
            )));
        };
        let expires_at_ms = lease.as_ref().and_then(|l| l.get("expireAt")).and_then(|v| v.as_str()).and_then(parse_rfc3339_ms);
        drop(data);
        permaura_core::secret::clear_stack();

        Ok(LeasedSecret::leased(
            OpenedSecret::from(value),
            Lease { secret_id: secret_id.to_string(), id: lease_id, expires_at_ms },
        ))
    }

    async fn release(&self, lease: &Lease) {
        let token = match self.auth.access_token().await {
            Ok(token) => token,
            Err(e) => {
                tracing::warn!(error = %e, lease = %lease.id, "infisical dynamic: could not authenticate to revoke a lease; it will expire on its TTL");
                return;
            }
        };
        let req = HttpRequest::new(
            HttpMethod::Delete,
            format!("{}/api/v1/dynamic-secrets/leases/{}", self.base(), pct_encode(&lease.id)),
        )
        .header("Authorization", bearer(&token))
        .json_body(self.scope())
        .credentialed();
        drop(token);

        match self.auth.http.send(req).await {
            Ok(resp) if resp.status < 400 => {
                tracing::debug!(lease = %lease.id, "infisical dynamic: lease revoked")
            }
            Ok(resp) => tracing::warn!(
                status = resp.status,
                lease = %lease.id,
                "infisical dynamic: revoke rejected; the lease will expire on its TTL"
            ),
            Err(e) => tracing::warn!(
                error = %crate::connectors::transport_error_text(&e),
                lease = %lease.id,
                "infisical dynamic: revoke failed; the lease will expire on its TTL"
            ),
        }
    }
}

/// Parse the RFC-3339 timestamp Infisical returns for a lease expiry into unix ms. Best-effort:
/// the value is used for logging and for deciding whether a lease is worth renewing, never for a
/// security decision, so an unparseable stamp degrades to `None` rather than failing the call.
fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| (t.unix_timestamp_nanos() / 1_000_000) as i64)
}

// ── KMS: a cloud-KMS-rooted external backend ─────────────────────────────────────────

/// The KMS unwrap operation, abstracted so the backend is provider- and credential-agnostic and so
/// tests run with no cloud. A real impl wraps the AWS/GCP/Azure KMS `Decrypt` call (envelope
/// decryption: the CMK never leaves the HSM; only this one ciphertext is unwrapped per call). The
/// workload's identity (instance role / OIDC) is the credential: there is no static token to store.
#[async_trait]
pub trait KmsClient: Send + Sync {
    /// Decrypt a KMS ciphertext to plaintext, in a buffer wiped when it drops. `key_id` scopes the
    /// operation to one CMK.
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, GatewayError>;
    /// Wrap plaintext under the CMK, returning the ciphertext. Used to seal the audit signing key so a
    /// database-only compromise holds ciphertext it cannot unwrap (Tier A custody).
    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, GatewayError>;
    /// The same wrap, reporting which key version produced it when the provider names one.
    ///
    /// A ciphertext outlives the version that made it only if that version still exists, so a
    /// snapshot that may be opened years later has to record the version it depends on. The version
    /// is only ever learned from a **wrap**: GCP KMS names the version in an encrypt response and
    /// does not in a decrypt one, which is why rewrapping is what upgrades a stored key to a
    /// versioned format rather than simply reading one.
    ///
    /// The default answers "this provider does not name versions", which stamps `none` and is the
    /// honest reading for a client that genuinely cannot say.
    async fn encrypt_versioned(
        &self,
        key_id: &str,
        plaintext: &[u8],
    ) -> Result<WrappedKey, GatewayError> {
        Ok(WrappedKey { ciphertext: self.encrypt(key_id, plaintext).await?, key_version: None })
    }
}

/// A KMS wrap and the key version that produced it, where the provider reports one.
pub struct WrappedKey {
    /// The ciphertext.
    pub ciphertext: Vec<u8>,
    /// The full key-version resource name, or `None` when the provider does not name it.
    pub key_version: Option<String>,
}

/// Static config for the [`KmsBackend`], read from `PERMAURA_KMS_*`: the CMK this worker may unwrap
/// under, plus any **legacy** env-listed ciphertexts. Per-secret enrolment now lives in the store as
/// a [`crate::store::SecretCustody`] record, which is where a KMS-enrolled secret's ciphertext comes
/// from; `ciphertexts` is only what `PERMAURA_KMS_SECRETS` still supplies, and is normally empty.
///
/// The ciphertext is not a secret: only KMS `Decrypt` permission (the workload's identity) can turn
/// it back into plaintext, so that permission *is* the custody root. The control plane never holds
/// the CMK or the plaintext.
pub struct KmsConfig {
    /// The CMK id / ARN the worker is allowed to decrypt under.
    pub key_id: String,
    /// `secret_id` → KMS ciphertext bytes (decoded from the base64 in `PERMAURA_KMS_SECRETS`).
    pub ciphertexts: std::collections::HashMap<String, Vec<u8>>,
}

impl KmsConfig {
    /// Read `PERMAURA_KMS_KEY_ID` (required) plus the legacy `PERMAURA_KMS_SECRETS`
    /// (`id=<base64-ciphertext>,…`, optional). `None` (KMS disabled) only when there is no key id,
    /// because the CMK alone is now enough: secrets are enrolled into it at runtime.
    pub fn from_env() -> Option<KmsConfig> {
        let any_set = non_empty_env("PERMAURA_KMS_KEY_ID").is_some()
            || non_empty_env("PERMAURA_KMS_SECRETS").is_some();
        let built = (|| {
            use base64::Engine;
            let key_id = non_empty_env("PERMAURA_KMS_KEY_ID")?;
            let mut ciphertexts = std::collections::HashMap::new();
            for pair in non_empty_env("PERMAURA_KMS_SECRETS").unwrap_or_default().split(',') {
                let Some((id, ct_b64)) = pair.trim().split_once('=') else {
                    continue;
                };
                let Ok(ct) = base64::engine::general_purpose::STANDARD.decode(ct_b64.trim()) else {
                    tracing::warn!(secret_id = %id.trim(), "PERMAURA_KMS_SECRETS entry is not valid base64: ignoring it");
                    continue;
                };
                if !id.trim().is_empty() && !ct.is_empty() {
                    ciphertexts.insert(id.trim().to_string(), ct);
                }
            }
            Some(KmsConfig { key_id, ciphertexts })
        })();
        if any_set && built.is_none() {
            tracing::warn!(
                "KMS is partially configured (PERMAURA_KMS_SECRETS set but no PERMAURA_KMS_KEY_ID): falling back to the local vault"
            );
        }
        built
    }
}

/// An external [`SecretBackend`] rooted in a cloud KMS. At call time it unwraps the enrolled secret's
/// KMS ciphertext via [`KmsClient::decrypt`] and returns a guarded [`OpenedSecret`]. The plaintext
/// lives only on this worker for the life of the one call; the CMK never leaves the KMS HSM.
pub struct KmsBackend {
    config: KmsConfig,
    kms: Arc<dyn KmsClient>,
}

impl KmsBackend {
    /// Build a KMS-backed secret resolver over a config (key id + per-secret ciphertexts) and a client.
    pub fn new(config: KmsConfig, kms: Arc<dyn KmsClient>) -> Self {
        KmsBackend { config, kms }
    }

    /// The CMK this worker unwraps under. The custody router checks a record's recorded key against
    /// it before decrypting, so a store-supplied key id can never redirect the unwrap.
    pub fn key_id(&self) -> &str {
        &self.config.key_id
    }

    /// The `secret_id`s this backend can resolve from its own static config, i.e. the legacy
    /// `PERMAURA_KMS_SECRETS` enrolment. Store custody records are resolved through
    /// [`KmsBackend::resolve_ciphertext`] instead and are not listed here.
    pub fn enrolled_ids(&self) -> HashSet<String> {
        self.config.ciphertexts.keys().cloned().collect()
    }

    /// Unwrap an explicitly-supplied ciphertext: the path a store custody record takes, where the
    /// ciphertext is a property of the enrolled secret rather than of this process's environment.
    pub async fn resolve_ciphertext(&self, ciphertext: &[u8]) -> Result<OpenedSecret, GatewayError> {
        let plaintext = self.kms.decrypt(&self.config.key_id, ciphertext).await?;
        Ok(OpenedSecret::wrap(plaintext))
    }
}

#[async_trait]
impl SecretBackend for KmsBackend {
    async fn resolve(&self, secret_id: &str) -> Result<OpenedSecret, GatewayError> {
        let ciphertext = self
            .config
            .ciphertexts
            .get(secret_id)
            .ok_or_else(|| GatewayError::NotFound(format!("kms secret '{secret_id}'")))?
            .clone();
        self.resolve_ciphertext(&ciphertext).await
    }

    fn holds_externally(&self, secret_id: &str) -> Result<bool, GatewayError> {
        Ok(self.config.ciphertexts.contains_key(secret_id))
    }
}

/// What a GCP KMS decrypt answers: the plaintext, base64, read into a wiping buffer.
#[derive(Deserialize)]
struct Decrypted {
    #[serde(deserialize_with = "permaura_core::secret::unescaped::deserialize")]
    plaintext: SecretString,
}

/// A Google Cloud KMS [`KmsClient`] over the REST API. Tokens come from the **Cloud Run / GCE
/// metadata server**: the worker runs *as* a Google service account and the metadata server mints
/// short-lived OAuth tokens for it, so there is no static key anywhere (the custody promise). Reuses
/// the worker's HTTP client; no GCP SDK. Activated by `PERMAURA_KMS_PROVIDER=gcp` (see
/// [`real_kms_client`]). `key_id` is the full key resource name
/// (`projects/P/locations/L/keyRings/R/cryptoKeys/K`).
pub struct GcpKmsClient {
    token: Arc<GcpTokenSource>,
    http: Arc<dyn HttpClient>,
}

impl GcpKmsClient {
    /// Build a GCP KMS client over an HTTP client (reqwest in prod, a mock in tests), minting its
    /// tokens through `token`. [`shared_gcp_token_source`] is what production passes, so KMS and
    /// Cloud Storage share one cached workload token.
    pub(crate) fn new(http: Arc<dyn HttpClient>, token: Arc<GcpTokenSource>) -> Self {
        GcpKmsClient { token, http }
    }

    async fn access_token(&self) -> Result<SecretString, GatewayError> {
        self.token.access_token().await
    }

    fn clear_token(&self) {
        self.token.clear();
    }
}

/// The workload's short-lived OAuth access token, minted by the Cloud Run / GCE **metadata server**
/// and cached until shortly before it expires.
///
/// One implementation and one cache for every Google service the gateway calls: the token is a
/// property of the workload, not of KMS or of Cloud Storage, and the HTTP client it is fetched over
/// has to be the unscreened one ([`crate::connectors::ReqwestClient::new_infra`]) because the
/// connector egress guard blocks `metadata.google.internal` by design.
pub(crate) struct GcpTokenSource {
    http: Arc<dyn HttpClient>,
    token: Mutex<Option<CachedToken>>,
}

impl GcpTokenSource {
    /// Build a token source over an HTTP client (an unscreened reqwest in prod, a mock in tests).
    pub(crate) fn new(http: Arc<dyn HttpClient>) -> Self {
        GcpTokenSource { http, token: Mutex::new(None) }
    }

    /// A cached metadata-server access token, refreshed when absent or within 5s of expiry.
    pub(crate) async fn access_token(&self) -> Result<SecretString, GatewayError> {
        if let Some(t) = self.cached() {
            return Ok(t);
        }
        let req = HttpRequest::get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        )
        .header("Metadata-Flavor", "Google");
        let resp = self
            .http
            .send_secret(req)
            .await
            .map_err(|e| GatewayError::upstream("gcp metadata token failed", &e))?;
        if resp.status >= 400 {
            return Err(GatewayError::Internal(format!("gcp metadata token returned {}", resp.status)));
        }
        let issued: IssuedToken = serde_json::from_slice(&resp.body)
            .map_err(|_| GatewayError::Internal("gcp metadata: no access_token".into()))?;
        let ttl = issued.ttl_secs();
        *self.token.lock().unwrap() = Some(CachedToken {
            token: issued.access_token.clone(),
            expires_at: now_ms().saturating_add(ttl.saturating_mul(1000)),
        });
        Ok(issued.access_token)
    }

    fn cached(&self) -> Option<SecretString> {
        self.token
            .lock()
            .unwrap()
            .as_ref()
            .filter(|c| c.expires_at > now_ms() + 5_000)
            .map(|c| c.token.clone())
    }

    /// Drop the cached token so the next call mints a fresh one. Called after a 401.
    pub(crate) fn clear(&self) {
        *self.token.lock().unwrap() = None;
    }
}

#[async_trait]
impl KmsClient for GcpKmsClient {
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, GatewayError> {
        use base64::Engine;
        let token = self.access_token().await?;
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        let url = format!("https://cloudkms.googleapis.com/v1/{key_id}:decrypt");
        let req = HttpRequest::post(url)
            .header("Authorization", bearer(&token))
            .json_body(serde_json::json!({ "ciphertext": ct_b64 }));
        drop(token);
        let resp = self
            .http
            .send_secret(req)
            .await
            .map_err(|e| GatewayError::upstream("gcp kms decrypt failed", &e))?;
        match resp.status {
            401 | 403 => {
                self.clear_token();
                return Err(GatewayError::Internal(format!("gcp kms decrypt denied ({})", resp.status)));
            }
            s if s >= 400 => return Err(GatewayError::Internal(format!("gcp kms decrypt returned {s}"))),
            _ => {}
        }
        let decrypted: Decrypted = serde_json::from_slice(&resp.body)
            .map_err(|_| GatewayError::Internal("gcp kms decrypt: no plaintext".into()))?;
        drop(resp);
        let encoded = decrypted.plaintext.as_bytes();
        let mut plaintext = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(encoded.len())]);
        let written = base64::engine::general_purpose::STANDARD
            .decode_slice(encoded, &mut plaintext)
            .map_err(|e| GatewayError::Internal(format!("gcp kms plaintext decode: {e}")))?;
        plaintext.truncate(written);
        drop(decrypted);
        permaura_core::secret::clear_stack();
        Ok(plaintext)
    }

    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, GatewayError> {
        Ok(self.encrypt_versioned(key_id, plaintext).await?.ciphertext)
    }

    /// GCP returns the key version that wrapped in the response's `name`, which is the only place
    /// the version is ever offered: a decrypt response carries `plaintext` and nothing that names a
    /// version.
    async fn encrypt_versioned(
        &self,
        key_id: &str,
        plaintext: &[u8],
    ) -> Result<WrappedKey, GatewayError> {
        use base64::Engine;
        let token = self.access_token().await?;
        let encoded_len = base64::encoded_len(plaintext.len(), true)
            .ok_or_else(|| GatewayError::Internal("gcp kms encrypt: plaintext too large".into()))?;
        let mut pt_b64 = Zeroizing::new(vec![0u8; encoded_len]);
        let written = base64::engine::general_purpose::STANDARD
            .encode_slice(plaintext, &mut pt_b64)
            .map_err(|e| GatewayError::Internal(format!("gcp kms encrypt: {e}")))?;
        #[derive(serde::Serialize)]
        struct Wrap<'a> {
            plaintext: &'a str,
        }
        let url = format!("https://cloudkms.googleapis.com/v1/{key_id}:encrypt");
        let req = HttpRequest::post(url)
            .header("Authorization", bearer(&token))
            .secret_json_body(&Wrap { plaintext: std::str::from_utf8(&pt_b64[..written]).unwrap_or_default() })
            .map_err(|e| GatewayError::Internal(format!("gcp kms encrypt: {e}")))?;
        drop(token);
        drop(pt_b64);
        let resp = self
            .http
            .send(req)
            .await
            .map_err(|e| GatewayError::upstream("gcp kms encrypt failed", &e))?;
        match resp.status {
            401 | 403 => {
                self.clear_token();
                return Err(GatewayError::Internal(format!("gcp kms encrypt denied ({})", resp.status)));
            }
            s if s >= 400 => return Err(GatewayError::Internal(format!("gcp kms encrypt returned {s}"))),
            _ => {}
        }
        let ct_b64 = resp
            .body
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::Internal("gcp kms encrypt: no ciphertext".into()))?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .map_err(|e| GatewayError::Internal(format!("gcp kms ciphertext decode: {e}")))?;
        let key_version = resp
            .body
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|n| !n.is_empty())
            .map(str::to_string);
        Ok(WrappedKey { ciphertext, key_version })
    }
}

/// Routes each `secret_id` to the backend its **custody record** names, so which layer holds a
/// secret is a store row an operator changes at runtime rather than an environment variable that
/// needs a redeploy. One worker mixes custody (some secrets in Infisical or KMS, the rest in its
/// own sealed store) behind the single [`SecretBackend`] the enforcement loop sees, with no change
/// to policy/execution/audit.
///
/// Routing rules, in order:
/// 1. a [`crate::store::SecretCustody`] record decides, and if it names a backend this worker does
///    not have, resolution **fails** rather than falling back, because a silent fallback is a silent
///    custody downgrade;
/// 2. otherwise the legacy env enrolment (`PERMAURA_INFISICAL_SECRETS` / `PERMAURA_KMS_SECRETS`)
///    still applies, so an existing deployment does not change custody on upgrade;
/// 3. otherwise the local sealed vault: the floor beneath everything.
pub struct CustodyRouter {
    store: Arc<dyn Store>,
    local: Arc<dyn SecretBackend>,
    infisical: Option<Arc<dyn SecretBackend>>,
    kms: Option<Arc<KmsBackend>>,
    dynamic: Option<Arc<dyn SecretBackend>>,
    env_infisical: HashSet<String>,
    env_kms: HashSet<String>,
    dynamic_secrets: HashSet<String>,
}

impl CustodyRouter {
    /// Build a router that reads custody from `store` and falls back to `local`. With no external
    /// backend attached this behaves exactly like the local vault alone.
    pub fn new(store: Arc<dyn Store>, local: Arc<dyn SecretBackend>) -> Self {
        CustodyRouter {
            store,
            local,
            infisical: None,
            kms: None,
            dynamic: None,
            env_infisical: HashSet::new(),
            env_kms: HashSet::new(),
            dynamic_secrets: HashSet::new(),
        }
    }

    /// Attach the Infisical backend, plus any ids the legacy `PERMAURA_INFISICAL_SECRETS` enrols.
    pub fn with_infisical(
        mut self,
        backend: Arc<dyn SecretBackend>,
        env_enrolled: impl IntoIterator<Item = String>,
    ) -> Self {
        self.infisical = Some(backend);
        self.env_infisical = env_enrolled.into_iter().collect();
        self
    }

    /// Attach the KMS backend. Ids it carries static ciphertexts for (the legacy
    /// `PERMAURA_KMS_SECRETS` enrolment) keep resolving through it.
    pub fn with_kms(mut self, backend: Arc<KmsBackend>) -> Self {
        self.env_kms = backend.enrolled_ids();
        self.kms = Some(backend);
        self
    }

    /// Attach the dynamic-secrets backend for the ids it is configured to mint. Dynamic ids are
    /// enrolled by configuration rather than by a custody record, because there is nothing stored to
    /// record custody of: the credential does not exist until a call mints it.
    pub fn with_dynamic(
        mut self,
        backend: Arc<dyn SecretBackend>,
        secrets: impl IntoIterator<Item = String>,
    ) -> Self {
        self.dynamic = Some(backend);
        self.dynamic_secrets = secrets.into_iter().collect();
        self
    }

    /// The dynamic backend, when this id is one it mints. Checked before custody records and before
    /// the env enrolments: a dynamic secret has no stored value for any of them to resolve, so
    /// letting one fall through would silently open the local vault instead of minting.
    fn dynamic_for(&self, secret_id: &str) -> Option<&Arc<dyn SecretBackend>> {
        self.dynamic_secrets.contains(secret_id).then_some(self.dynamic.as_ref()).flatten()
    }

    /// Resolve under an explicit custody record. `secret_id` is the id the caller asked for, not
    /// the one inside the record: the record is store data and only its *contents* are trusted to
    /// name a custodian, never to redirect which secret is being opened.
    async fn resolve_recorded(
        &self,
        secret_id: &str,
        custody: &SecretCustody,
    ) -> Result<OpenedSecret, GatewayError> {
        match custody.kind {
            CustodyKind::LocalVault => self.local.resolve(secret_id).await,
            CustodyKind::Infisical => {
                let backend = self.infisical.as_ref().ok_or_else(|| {
                    GatewayError::Internal(format!(
                        "secret '{secret_id}' is enrolled in Infisical but this worker has no Infisical backend configured: refusing to resolve it from the local vault"
                    ))
                })?;
                backend
                    .resolve(custody.infisical_name.as_deref().unwrap_or(secret_id))
                    .await
            }
            CustodyKind::Kms => {
                let backend = self.kms.as_ref().ok_or_else(|| {
                    GatewayError::Internal(format!(
                        "secret '{secret_id}' is enrolled in KMS but this worker has no KMS client configured: refusing to resolve it from the local vault"
                    ))
                })?;
                let ciphertext = custody.kms_ciphertext.as_deref().ok_or_else(|| {
                    GatewayError::Internal(format!(
                        "secret '{secret_id}' has a KMS custody record with no ciphertext: it cannot be unwrapped"
                    ))
                })?;
                // The key id is store data, and the store is not the custody root. Pinning it to the
                // configured CMK stops a tampered record redirecting the unwrap at a key the worker's
                // identity happens to also hold.
                if let Some(recorded) = custody.kms_key_id.as_deref() {
                    if recorded != backend.key_id() {
                        tracing::error!(
                            secret_id,
                            recorded_key = recorded,
                            configured_key = backend.key_id(),
                            "custody record names a different CMK than this worker is configured for"
                        );
                        return Err(GatewayError::Internal(format!(
                            "secret '{secret_id}' was wrapped under a CMK this worker is not configured for: refusing to decrypt"
                        )));
                    }
                }
                backend.resolve_ciphertext(ciphertext).await
            }
        }
    }
}

#[async_trait]
impl SecretBackend for CustodyRouter {
    async fn resolve(&self, secret_id: &str) -> Result<OpenedSecret, GatewayError> {
        if let Some(dynamic) = self.dynamic_for(secret_id) {
            // Deliberately routed here so the dynamic backend's own refusal surfaces: resolving a
            // dynamic secret would mint a credential with nowhere to hand the lease back, leaving a
            // live one alive for its whole TTL with nothing tracking it.
            return dynamic.resolve(secret_id).await;
        }
        if let Some(custody) = self.store.get_secret_custody(secret_id)? {
            return self.resolve_recorded(secret_id, &custody).await;
        }
        if self.env_infisical.contains(secret_id) {
            if let Some(backend) = &self.infisical {
                return backend.resolve(secret_id).await;
            }
        }
        if self.env_kms.contains(secret_id) {
            if let Some(backend) = &self.kms {
                return backend.resolve(secret_id).await;
            }
        }
        self.local.resolve(secret_id).await
    }

    async fn acquire(&self, secret_id: &str) -> Result<LeasedSecret, GatewayError> {
        match self.dynamic_for(secret_id) {
            Some(dynamic) => dynamic.acquire(secret_id).await,
            // Every stored custodian keeps its normal path, including custody records and the env
            // enrolments: a stored secret simply carries no lease.
            None => Ok(LeasedSecret::stored(self.resolve(secret_id).await?)),
        }
    }

    async fn release(&self, lease: &Lease) {
        // Routed on the lease's own `secret_id`, which `acquire` set to the id this router passed
        // down, so a lease always goes back to the backend that minted it. Revocation itself uses
        // `lease.id`; `secret_id` is only ever a routing key.
        if let Some(dynamic) = self.dynamic_for(&lease.secret_id) {
            dynamic.release(lease).await;
        }
    }

    /// The routing order of [`CustodyRouter::resolve`], read without resolving. An external custody record counts even when this worker has no backend for it, because the enrolment still names a credential that fixing the worker's configuration would bring back.
    fn holds_externally(&self, secret_id: &str) -> Result<bool, GatewayError> {
        if self.dynamic_secrets.contains(secret_id) {
            return Ok(true);
        }
        if let Some(custody) = self.store.get_secret_custody(secret_id)? {
            return Ok(custody.kind.is_external());
        }
        Ok(self.env_infisical.contains(secret_id) || self.env_kms.contains(secret_id))
    }
}

/// Build the worker's secret backend: the local sealed vault, fronted by whichever external
/// custodians this deployment has credentials for. Which secrets actually route to them comes from
/// the store's custody records (see [`CustodyRouter`]), and the env only supplies the *credentials*,
/// plus any legacy per-secret enrolment already in place.
///
/// The Infisical client is the worker's own real `ReqwestClient` (independent of the connector HTTP
/// client, which may be the offline mock), so the credential and the secret reach Infisical and
/// nothing else.
pub fn build_backend(store: Arc<dyn Store>) -> Arc<dyn SecretBackend> {
    let local: Arc<dyn SecretBackend> =
        Arc::new(LocalVaultBackend::new(store.clone(), crate::service::vault_passphrase().to_vec()));
    let mut router = CustodyRouter::new(store, local);

    // Infisical, if credentials are configured.
    if let Some(config) = InfisicalConfig::from_env() {
        match infisical_client(&config.base_url) {
            Ok(client) => {
                let env_enrolled = InfisicalConfig::env_enrolled_secrets();
                if !env_enrolled.is_empty() {
                    tracing::info!(
                        count = env_enrolled.len(),
                        "PERMAURA_INFISICAL_SECRETS is set: those ids stay enrolled alongside the store's custody records"
                    );
                }
                let backend: Arc<dyn SecretBackend> =
                    Arc::new(InfisicalBackend::new(config, Arc::new(client)));
                router = router.with_infisical(backend, env_enrolled);
                tracing::info!("Infisical backend available for secrets enrolled in it");
            }
            Err(e) => tracing::error!(
                error = %e,
                "could not build the Infisical HTTP client; Infisical-enrolled secrets will fail rather than resolve locally"
            ),
        }
    }

    // Infisical dynamic secrets, if configured. Enrolled by configuration rather than by a custody
    // record: there is nothing stored to record custody of, because the credential does not exist
    // until a call mints it.
    if let Some((config, secrets)) = InfisicalDynamicConfig::from_env() {
        match infisical_client(&config.base_url) {
            Ok(client) => {
                let backend: Arc<dyn SecretBackend> =
                    Arc::new(InfisicalDynamicBackend::new(config, Arc::new(client)));
                tracing::info!(
                    count = secrets.len(),
                    "Infisical dynamic secrets enabled: a short-TTL credential is minted per call and revoked after it"
                );
                router = router.with_dynamic(backend, secrets);
            }
            Err(e) => tracing::error!(
                error = %e,
                "could not build the Infisical HTTP client; dynamic secrets are disabled and those ids will resolve from the local vault"
            ),
        }
    }

    // Cloud KMS, if a CMK is configured. The KmsBackend + routing + tests are in-repo; the one
    // external piece is the real KMS client, which the hosted-worker (Mode C) build links via
    // `real_kms_client`.
    if let Some(config) = KmsConfig::from_env() {
        match real_kms_client(&config.key_id) {
            Some(client) => {
                let backend = Arc::new(KmsBackend::new(config, client));
                if !backend.enrolled_ids().is_empty() {
                    tracing::info!(
                        count = backend.enrolled_ids().len(),
                        "PERMAURA_KMS_SECRETS is set: those ids stay enrolled alongside the store's custody records"
                    );
                }
                router = router.with_kms(backend);
                tracing::info!("KMS backend available for secrets enrolled in it");
            }
            None => tracing::warn!(
                "PERMAURA_KMS_* is configured but no KMS client is linked in this build: the hosted-worker build supplies one; KMS-enrolled secrets will fail to resolve"
            ),
        }
    }
    Arc::new(router)
}

/// Move an existing locally-sealed secret into KMS custody: unseal it, wrap it under `key_id`, prove
/// the wrap round-trips, record custody, and only then delete the now-redundant local sealed row.
///
/// This is the enrolment operation the env-var design could never have: custody becomes a runtime
/// choice. It is deliberately a plain function on the backend layer so the REST/CLI surface can call
/// it without the backend depending on either.
///
/// Ordering is the safety property: the local copy is deleted **last**, and only after a decrypt of
/// the fresh ciphertext reproduces the plaintext byte for byte. A failure anywhere before that leaves
/// the secret exactly where it was.
pub async fn enrol_secret_in_kms(
    store: &dyn Store,
    kms: &dyn KmsClient,
    key_id: &str,
    passphrase: &[u8],
    secret_id: &str,
    now_ms: i64,
) -> Result<SecretCustody, GatewayError> {
    if let Some(existing) = store.get_secret_custody(secret_id)? {
        if existing.kind.is_external() {
            return Err(GatewayError::Internal(format!(
                "secret '{secret_id}' is already in {} custody: delete its custody record first if you mean to re-enrol it",
                existing.kind.as_str()
            )));
        }
    }
    let record = store
        .get_secret(secret_id)?
        .ok_or_else(|| GatewayError::NotFound(format!("secret '{secret_id}'")))?;

    let mut vault = Vault::new();
    vault.insert_record(record);
    let opened =
        vault.use_secret(secret_id, passphrase, |bytes| Ok(OpenedSecret::new(bytes.to_vec())))?;

    let ciphertext = kms.encrypt(key_id, opened.bytes()).await?;
    let round_trip = OpenedSecret::wrap(kms.decrypt(key_id, &ciphertext).await?);
    if round_trip.bytes() != opened.bytes() {
        return Err(GatewayError::Internal(format!(
            "KMS enrolment of '{secret_id}' did not round-trip: refusing to delete the local copy"
        )));
    }

    let custody = SecretCustody::kms(secret_id, ciphertext, key_id, now_ms);
    store.put_secret_custody(custody.clone())?;
    store.delete_secret(secret_id)?;
    tracing::info!(secret_id, "secret enrolled into KMS custody; local sealed copy removed");
    Ok(custody)
}

/// [`enrol_secret_in_kms`] wired to this process's environment: the CMK and provider from
/// `PERMAURA_KMS_*` and the vault passphrase the local backend seals under. Errors when no CMK is
/// configured or no KMS client is linked into this build, rather than silently leaving the secret
/// local.
pub async fn enrol_secret_in_kms_from_env(
    store: &dyn Store,
    secret_id: &str,
) -> Result<SecretCustody, GatewayError> {
    let config = KmsConfig::from_env().ok_or_else(|| {
        GatewayError::Internal(
            "no CMK is configured (PERMAURA_KMS_KEY_ID): cannot enrol a secret into KMS custody".into(),
        )
    })?;
    let client = real_kms_client(&config.key_id).ok_or_else(|| {
        GatewayError::Internal(
            "no KMS client is linked in this build (PERMAURA_KMS_PROVIDER): cannot enrol a secret into KMS custody".into(),
        )
    })?;
    enrol_secret_in_kms(
        store,
        client.as_ref(),
        &config.key_id,
        crate::service::vault_passphrase(),
        secret_id,
        now_ms(),
    )
    .await
}

/// The real cloud-KMS client for this deployment, selected by `PERMAURA_KMS_PROVIDER`:
/// - `gcp` → [`GcpKmsClient`] over the Cloud Run metadata server (no static key).
/// - unset/other → `None` (KMS inert; secrets fall back to the local vault).
///
/// AWS would slot in here the same way (`aws` → an `aws-sdk-kms`-backed client). The trait,
/// `KmsBackend`, composite routing, and tests are all in-repo, so a provider is just one arm.
fn real_kms_client(_key_id: &str) -> Option<Arc<dyn KmsClient>> {
    match std::env::var("PERMAURA_KMS_PROVIDER").ok().as_deref() {
        Some("gcp") => {
            let http = shared_gcp_http()?;
            Some(Arc::new(GcpKmsClient::new(http, shared_gcp_token_source()?)))
        }
        _ => None,
    }
}

/// The process's one **unscreened** HTTP client for Google's own endpoints.
///
/// Unscreened because the workload token comes from `metadata.google.internal`, a link-local address
/// the connector egress guard deliberately blocks. Safe because the only callers are the gateway's
/// own clients, whose hosts are hardcoded and whose variable input (a key id, a bucket name) is set
/// by provisioning and used as a URL path, never as the host. Never hand it to connector or agent
/// execution. See [`ReqwestClient::new_infra`].
pub(crate) fn shared_gcp_http() -> Option<Arc<dyn HttpClient>> {
    static HTTP: std::sync::OnceLock<Option<Arc<dyn HttpClient>>> = std::sync::OnceLock::new();
    HTTP.get_or_init(|| match ReqwestClient::new_infra() {
        Ok(client) => Some(Arc::new(client) as Arc<dyn HttpClient>),
        Err(e) => {
            tracing::error!(error = %e, "could not build the unscreened HTTP client for Google endpoints; KMS and object storage disabled");
            None
        }
    })
    .clone()
}

/// The process's one metadata-server token source, so KMS and Cloud Storage mint and refresh a
/// single workload token between them rather than one each.
pub(crate) fn shared_gcp_token_source() -> Option<Arc<GcpTokenSource>> {
    static TOKEN: std::sync::OnceLock<Option<Arc<GcpTokenSource>>> = std::sync::OnceLock::new();
    TOKEN.get_or_init(|| shared_gcp_http().map(|http| Arc::new(GcpTokenSource::new(http)))).clone()
}

/// The CMK a store uses to seal its audit signing key: a live [`KmsClient`] plus the key id it may
/// encrypt/decrypt under. Distinct from [`KmsConfig`] (which needs enrolled secret ciphertexts): the
/// audit key is wrapped as soon as a CMK exists, before any connection secret is added.
#[derive(Clone)]
pub struct AuditKeyWrap {
    /// The live KMS client the store wraps/unwraps the audit key through.
    pub kms: Arc<dyn KmsClient>,
    /// The full CMK resource name the store may encrypt/decrypt under (`projects/…/cryptoKeys/…`).
    pub key_id: String,
    /// Accept an audit key stored in plaintext and wrap it under this CMK. Off unless
    /// `PERMAURA_AUDIT_KEY_ADOPT_PLAINTEXT=1` is set for a one-time migration: a CMK-wrapped store never
    /// writes a plaintext key, so one appearing is a write by something that holds the bucket but not the key.
    pub adopt_plaintext: bool,
}

/// Build the audit-key wrapper from `PERMAURA_KMS_KEY_ID` + `PERMAURA_KMS_PROVIDER`. `None` when no CMK
/// is configured (local/self-hosted): the store then keeps its plaintext database/file custody and
/// says so. Present only on the hosted worker (Mode C), whose provisioning sets both.
pub fn audit_key_wrap_from_env() -> Option<AuditKeyWrap> {
    let key_id = non_empty_env("PERMAURA_KMS_KEY_ID")?;
    let kms = real_kms_client(&key_id)?;
    let adopt_plaintext = crate::service::truthy_env("PERMAURA_AUDIT_KEY_ADOPT_PLAINTEXT");
    Some(AuditKeyWrap { kms, key_id, adopt_plaintext })
}

/// The HTTP client the Infisical backends reach `base_url` through: pinned to that origin rather than screened as connector traffic is, so a local or self-hosted Infisical on loopback or a private network is reachable, as the configuration allows, and nothing else is.
fn infisical_client(base_url: &str) -> anyhow::Result<ReqwestClient> {
    ReqwestClient::for_configured_origin(base_url)
}

/// True iff `url` is safe to send the Infisical credential + secrets over: `https://` anywhere, or
/// `http://` ONLY to loopback (local dev), judged on the host as the URL parser reads it. A
/// non-loopback `http://` (or any other scheme, or userinfo) is rejected so the client secret and
/// secret values are never sent in cleartext.
fn is_secure_base_url(url: &str) -> bool {
    match crate::connectors::egress::parse_checked(url) {
        Ok((parsed, parts)) if parsed.username().is_empty() && parsed.password().is_none() => {
            parts.scheme == "https" || crate::release::is_loopback_http_url(url)
        }
        _ => false,
    }
}

/// `std::env::var` that treats empty/missing identically.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Percent-encode everything except the unreserved set (RFC 3986), enough to put a project id,
/// environment, secret name, or path safely into a query string.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The type-level pin for every credential this module reads or holds: these stop compiling if one stops being
    /// a wiping type. The runtime pin cannot reach the GCP paths (their constructors are crate-private), so this is
    /// what holds them.
    #[allow(dead_code)]
    fn credentials_are_held_in_wiping_types<'a>(
        issued: &'a IssuedToken,
        fetched: &'a FetchedSecret,
        decrypted: &'a Decrypted,
        minted: &'a MintedField,
        cached: &'a CachedToken,
        auth: &'a InfisicalAuth,
        config: &'a InfisicalConfig,
        dynamic: &'a InfisicalDynamicConfig,
    ) -> [Option<&'a SecretString>; 8] {
        [
            Some(&issued.access_token),
            Some(&fetched.secret_value),
            Some(&decrypted.plaintext),
            minted.0.as_ref(),
            Some(&cached.token),
            Some(&auth.client_secret),
            Some(&config.client_secret),
            Some(&dynamic.client_secret),
        ]
    }

    #[allow(dead_code)]
    async fn token_sources_and_kms_return_wiping_types(gcp: &GcpTokenSource, auth: &InfisicalAuth, kms: &GcpKmsClient) {
        let _: Result<SecretString, GatewayError> = gcp.access_token().await;
        let _: Result<SecretString, GatewayError> = auth.access_token().await;
        let _: Result<Zeroizing<Vec<u8>>, GatewayError> = kms.decrypt("", b"").await;
    }
    use crate::store::memory::MemoryStore;
    use permaura_core::{seal, Cipher, SecretMetadata, SecretRecord};

    fn store_with_secret(id: &str, value: &[u8], passphrase: &[u8]) -> Arc<dyn Store> {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let sealed = seal(Cipher::Aes256Gcm, passphrase, value).unwrap();
        store
            .put_secret(SecretRecord {
                id: id.to_string(),
                sealed,
                metadata: SecretMetadata::default(),
            })
            .unwrap();
        store
    }

    #[tokio::test]
    async fn local_backend_resolves_plaintext() {
        let pass = b"kek-passphrase";
        let store = store_with_secret("sec_gh", b"ghp_token_123", pass);
        let backend = LocalVaultBackend::new(store, pass.to_vec());

        let opened = backend.resolve("sec_gh").await.unwrap();
        assert_eq!(opened.bytes(), b"ghp_token_123");
    }

    #[tokio::test]
    async fn missing_secret_is_not_found() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let backend = LocalVaultBackend::new(store, b"p".to_vec());
        let err = backend.resolve("nope").await.unwrap_err();
        assert!(matches!(err, GatewayError::NotFound(_)));
    }

    #[tokio::test]
    async fn wrong_passphrase_fails_to_open() {
        let store = store_with_secret("s", b"value", b"right");
        let backend = LocalVaultBackend::new(store, b"wrong".to_vec());
        assert!(backend.resolve("s").await.is_err());
        assert_eq!(backend.cached_keys(), 0, "a key that opened nothing is not kept");
    }

    /// The KDF runs once per record, not once per execution. Every resolution used to derive
    /// the KEK again, a 19 MiB Argon2id working set per call.
    #[tokio::test]
    async fn repeated_resolutions_derive_the_key_once() {
        let pass = b"kek-passphrase";
        let store = store_with_secret("sec_gh", b"ghp_token_123", pass);
        let backend = LocalVaultBackend::new(store, pass.to_vec());
        for _ in 0..3 {
            assert_eq!(backend.resolve("sec_gh").await.unwrap().bytes(), b"ghp_token_123");
        }
        assert_eq!(backend.cached_keys(), 1);
    }

    #[test]
    fn opened_secret_debug_never_leaks_plaintext() {
        let opened = OpenedSecret::new(b"super-secret".to_vec());
        let rendered = format!("{opened:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("redacted"));
    }

    // ── Infisical backend ───────────────────────────────────────────────────────

    use crate::connectors::{HttpResponse, MockHttpClient};

    fn infisical_config() -> InfisicalConfig {
        InfisicalConfig {
            base_url: "https://vault.example.com".into(),
            client_id: "cid".into(),
            client_secret: "csec".into(),
            project_id: "proj_1".into(),
            environment: "prod".into(),
            secret_path: "/".into(),
        }
    }
    fn json_resp(status: u16, body: serde_json::Value) -> HttpResponse {
        HttpResponse::json(status, body)
    }

    #[tokio::test]
    async fn infisical_logs_in_then_fetches_the_secret() {
        let http = MockHttpClient::new();
        http.push_response(json_resp(200, serde_json::json!({ "accessToken": "tok_abc", "expiresIn": 3600 })));
        http.push_response(json_resp(200, serde_json::json!({ "secret": { "secretValue": "bt_live_xyz" } })));
        let backend = InfisicalBackend::new(infisical_config(), Arc::new(http.clone()));

        let opened = backend.resolve("BRAINTREE_KEY").await.unwrap();
        assert_eq!(opened.bytes(), b"bt_live_xyz");
        // The fetch carried the bearer token and the encoded path.
        let last = http.last_request().unwrap();
        assert_eq!(last.headers.get("Authorization").map(String::as_str), Some("Bearer tok_abc"));
        assert!(last.url.contains("secretPath=%2F"), "secret path must be percent-encoded: {}", last.url);
    }

    #[tokio::test]
    async fn infisical_caches_the_token_across_resolves() {
        let http = MockHttpClient::new();
        // One login response, then TWO secret fetches. If the backend re-logged-in, the FIFO queue
        // would desync and the second resolve would consume a secret body as a login (no token).
        http.push_response(json_resp(200, serde_json::json!({ "accessToken": "tok", "expiresIn": 3600 })));
        http.push_response(json_resp(200, serde_json::json!({ "secret": { "secretValue": "v1" } })));
        http.push_response(json_resp(200, serde_json::json!({ "secret": { "secretValue": "v2" } })));
        let backend = InfisicalBackend::new(infisical_config(), Arc::new(http));
        assert_eq!(backend.resolve("A").await.unwrap().bytes(), b"v1");
        assert_eq!(backend.resolve("B").await.unwrap().bytes(), b"v2");
    }

    #[tokio::test]
    async fn infisical_missing_secret_is_not_found() {
        let http = MockHttpClient::new();
        http.push_response(json_resp(200, serde_json::json!({ "accessToken": "t", "expiresIn": 3600 })));
        http.push_response(json_resp(404, serde_json::json!({ "message": "not found" })));
        let backend = InfisicalBackend::new(infisical_config(), Arc::new(http));
        assert!(matches!(backend.resolve("missing").await.unwrap_err(), GatewayError::NotFound(_)));
    }

    #[tokio::test]
    async fn infisical_login_failure_is_internal() {
        let http = MockHttpClient::new();
        http.push_response(json_resp(401, serde_json::json!({ "message": "bad creds" })));
        let backend = InfisicalBackend::new(infisical_config(), Arc::new(http));
        assert!(matches!(backend.resolve("x").await.unwrap_err(), GatewayError::Internal(_)));
    }

    // ── Infisical dynamic secrets: mint per call, revoke after ─────────────

    fn dynamic_config(field: Option<&str>) -> InfisicalDynamicConfig {
        let mut secrets = std::collections::HashMap::new();
        secrets.insert(
            "sec_db".to_string(),
            DynamicSecretRef {
                name: "pg-readonly".into(),
                field: field.map(|f| f.to_string()),
            },
        );
        InfisicalDynamicConfig {
            base_url: "https://vault.example.com".into(),
            client_id: "cid".into(),
            client_secret: "csec".into(),
            project_slug: "acme".into(),
            environment: "prod".into(),
            path: "/".into(),
            ttl: "5m".into(),
            secrets,
        }
    }

    fn login_ok() -> HttpResponse {
        json_resp(200, serde_json::json!({ "accessToken": "tok", "expiresIn": 3600 }))
    }

    fn mint_ok(data: serde_json::Value) -> HttpResponse {
        json_resp(
            200,
            serde_json::json!({
                "lease": { "id": "lease_1", "expireAt": "2026-08-08T12:00:00.000Z" },
                "dynamicSecret": { "name": "pg-readonly" },
                "data": data,
            }),
        )
    }

    #[tokio::test]
    async fn dynamic_mints_a_credential_and_names_the_lease() {
        let http = MockHttpClient::new();
        http.push_response(login_ok());
        http.push_response(mint_ok(
            serde_json::json!({ "DB_USERNAME": "u_tmp", "DB_PASSWORD": "p_tmp" }),
        ));
        let backend = InfisicalDynamicBackend::new(dynamic_config(Some("DB_PASSWORD")), Arc::new(http.clone()));

        let (opened, lease) = backend.acquire("sec_db").await.unwrap().into_parts();
        assert_eq!(opened.bytes(), b"p_tmp", "the named field is the credential");
        let lease = lease.expect("a dynamic secret must come back with a lease");
        assert_eq!(lease.id, "lease_1");
        assert_eq!(lease.secret_id, "sec_db", "the lease must know who to route its release to");
        assert!(lease.expires_at_ms.is_some(), "the TTL backstop must be recorded");

        let mint = http.last_request().unwrap();
        let body = mint.body.clone().unwrap();
        assert_eq!(body["dynamicSecretName"], "pg-readonly");
        assert_eq!(body["projectSlug"], "acme");
        assert_eq!(body["environmentSlug"], "prod");
        assert_eq!(body["ttl"], "5m");
        assert_eq!(mint.headers.get("Authorization").map(String::as_str), Some("Bearer tok"));
    }

    #[tokio::test]
    async fn dynamic_release_revokes_the_lease_by_id() {
        let http = MockHttpClient::new();
        http.push_response(login_ok());
        http.push_response(json_resp(200, serde_json::json!({ "message": "revoked" })));
        let backend = InfisicalDynamicBackend::new(dynamic_config(Some("DB_PASSWORD")), Arc::new(http.clone()));

        backend
            .release(&Lease { secret_id: "sec_db".into(), id: "lease_1".into(), expires_at_ms: None })
            .await;

        let del = http.last_request().unwrap();
        assert_eq!(del.method.as_str(), "DELETE");
        assert!(del.url.ends_with("/api/v1/dynamic-secrets/leases/lease_1"), "{}", del.url);
        let body = del.body.clone().unwrap();
        assert_eq!(body["projectSlug"], "acme");
        assert_eq!(body["environmentSlug"], "prod");
    }

    #[tokio::test]
    async fn a_single_field_lease_needs_no_field_name() {
        let http = MockHttpClient::new();
        http.push_response(login_ok());
        http.push_response(mint_ok(serde_json::json!({ "PASSWORD": "only_one" })));
        let backend = InfisicalDynamicBackend::new(dynamic_config(None), Arc::new(http));
        let (opened, _) = backend.acquire("sec_db").await.unwrap().into_parts();
        assert_eq!(opened.bytes(), b"only_one");
    }

    #[tokio::test]
    async fn a_multi_field_lease_without_a_field_name_is_refused_not_guessed() {
        let http = MockHttpClient::new();
        http.push_response(login_ok());
        http.push_response(mint_ok(
            serde_json::json!({ "DB_USERNAME": "u", "DB_PASSWORD": "p" }),
        ));
        // The revoke of the credential we could not read.
        http.push_response(json_resp(200, serde_json::json!({})));
        let http2 = Arc::new(http.clone());
        let backend = InfisicalDynamicBackend::new(dynamic_config(None), http2);

        let err = backend.acquire("sec_db").await.unwrap_err();
        assert!(matches!(err, GatewayError::Internal(_)));
        // Guessing which half of a credential to inject is worse than failing, and the credential
        // that WAS minted must not be left alive for its whole TTL.
        let last = http.last_request().unwrap();
        assert_eq!(last.method.as_str(), "DELETE", "an unreadable mint must still be revoked");
    }

    /// A malformed member beside a good lease id must not lose the id: the credential was minted whatever
    /// shape the rest of the answer took, and only the id can revoke it before its TTL.
    #[tokio::test]
    async fn a_mint_whose_data_or_lease_is_malformed_is_still_revoked() {
        for body in [
            serde_json::json!({ "lease": { "id": "lease_probe", "expireAt": 7 }, "data": [] }),
            serde_json::json!({ "lease": { "id": "lease_probe" }, "data": "not an object" }),
            serde_json::json!({ "lease": { "id": "lease_probe", "extra": { "deep": [1, 2] } }, "data": 42 }),
        ] {
            let http = MockHttpClient::new();
            http.push_response(login_ok());
            http.push_response(json_resp(200, body.clone()));
            http.push_response(json_resp(200, serde_json::json!({})));
            let backend = InfisicalDynamicBackend::new(dynamic_config(None), Arc::new(http.clone()));
            assert!(matches!(backend.acquire("sec_db").await.unwrap_err(), GatewayError::Internal(_)), "{body}");
            let last = http.last_request().unwrap();
            assert_eq!(last.method.as_str(), "DELETE", "the minted lease must be revoked: {body}");
            assert!(last.url.ends_with("/leases/lease_probe"), "{}", last.url);
        }
    }

    #[tokio::test]
    async fn a_mint_with_no_lease_id_is_refused() {
        let http = MockHttpClient::new();
        http.push_response(login_ok());
        // No `lease.id`: nothing could ever revoke this credential, so the call must not proceed
        // on it: running would trade a tracked short window for an untracked full-TTL one.
        http.push_response(json_resp(
            200,
            serde_json::json!({ "lease": {}, "data": { "PASSWORD": "p" } }),
        ));
        let backend = InfisicalDynamicBackend::new(dynamic_config(None), Arc::new(http));
        assert!(matches!(backend.acquire("sec_db").await.unwrap_err(), GatewayError::Internal(_)));
    }

    #[tokio::test]
    async fn resolving_a_dynamic_secret_without_a_lease_is_refused() {
        let http = MockHttpClient::new();
        let backend = InfisicalDynamicBackend::new(dynamic_config(None), Arc::new(http.clone()));
        let err = backend.resolve("sec_db").await.unwrap_err();
        assert!(matches!(err, GatewayError::Internal(_)));
        assert!(http.requests().is_empty(), "a refused resolve must not mint anything");
    }

    #[tokio::test]
    async fn an_unenrolled_id_is_not_found_without_minting() {
        let http = MockHttpClient::new();
        let backend = InfisicalDynamicBackend::new(dynamic_config(None), Arc::new(http.clone()));
        assert!(matches!(backend.acquire("nope").await.unwrap_err(), GatewayError::NotFound(_)));
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn a_denied_mint_clears_the_cached_token() {
        let http = MockHttpClient::new();
        http.push_response(login_ok());
        http.push_response(json_resp(403, serde_json::json!({ "message": "denied" })));
        // A second attempt must log in again rather than reuse the token the vault just rejected.
        http.push_response(login_ok());
        http.push_response(mint_ok(serde_json::json!({ "PASSWORD": "p2" })));
        let backend = InfisicalDynamicBackend::new(dynamic_config(None), Arc::new(http));

        assert!(backend.acquire("sec_db").await.is_err());
        let (opened, _) = backend.acquire("sec_db").await.unwrap().into_parts();
        assert_eq!(opened.bytes(), b"p2");
    }

    #[tokio::test]
    async fn the_router_sends_the_release_back_to_the_minting_backend() {
        let http = MockHttpClient::new();
        http.push_response(login_ok());
        http.push_response(mint_ok(serde_json::json!({ "PASSWORD": "p" })));
        http.push_response(json_resp(200, serde_json::json!({})));
        let dynamic: Arc<dyn SecretBackend> =
            Arc::new(InfisicalDynamicBackend::new(dynamic_config(None), Arc::new(http.clone())));
        let local: Arc<dyn SecretBackend> = Arc::new(LocalVaultBackend::new(
            store_with_secret("sec_local", b"local_val", b"p"),
            b"p".to_vec(),
        ));
        let router = CustodyRouter::new(store_with_secret("sec_local", b"local_val", b"p"), local)
            .with_dynamic(dynamic, ["sec_db".to_string()]);

        let (opened, lease) = router.acquire("sec_db").await.unwrap().into_parts();
        assert_eq!(opened.bytes(), b"p");
        let lease = lease.expect("the lease must survive the routing layer");
        router.release(&lease).await;
        assert_eq!(
            http.last_request().unwrap().method.as_str(),
            "DELETE",
            "release routed by lease.secret_id must reach the backend that minted it"
        );
    }

    /// A dynamic id must not fall through to the local vault. The router checks the dynamic backend
    /// before custody records and env enrolments precisely so this refusal surfaces: silently opening
    /// a stale stored copy of a credential meant to be minted per call is the failure this whole
    /// feature exists to remove.
    #[tokio::test]
    async fn resolving_a_dynamic_id_through_the_router_fails_closed_rather_than_opening_the_vault() {
        let dynamic: Arc<dyn SecretBackend> = Arc::new(InfisicalDynamicBackend::new(
            dynamic_config(None),
            Arc::new(MockHttpClient::new()),
        ));
        // The local vault deliberately holds a value under the SAME id, so a fall-through would
        // succeed and be invisible.
        let local: Arc<dyn SecretBackend> = Arc::new(LocalVaultBackend::new(
            store_with_secret("sec_db", b"stale_stored_copy", b"p"),
            b"p".to_vec(),
        ));
        let router = CustodyRouter::new(store_with_secret("sec_db", b"stale_stored_copy", b"p"), local)
            .with_dynamic(dynamic, ["sec_db".to_string()]);

        let err = router.resolve("sec_db").await.unwrap_err();
        assert!(
            !format!("{err}").contains("stale_stored_copy"),
            "the refusal must not leak the value it declined to use"
        );
    }

    #[tokio::test]
    async fn a_stored_secret_through_the_router_has_no_lease_to_release() {
        let dynamic: Arc<dyn SecretBackend> = Arc::new(InfisicalDynamicBackend::new(
            dynamic_config(None),
            Arc::new(MockHttpClient::new()),
        ));
        let local: Arc<dyn SecretBackend> = Arc::new(LocalVaultBackend::new(
            store_with_secret("sec_local", b"local_val", b"p"),
            b"p".to_vec(),
        ));
        let router = CustodyRouter::new(store_with_secret("sec_local", b"local_val", b"p"), local)
            .with_dynamic(dynamic, ["sec_db".to_string()]);
        let (opened, lease) = router.acquire("sec_local").await.unwrap().into_parts();
        assert_eq!(opened.bytes(), b"local_val");
        assert!(lease.is_none(), "a stored secret must not fabricate a lease");
    }

    #[test]
    fn dynamic_enrolment_parsing() {
        let parsed = parse_dynamic_secrets("sec_db=pg-readonly:DB_PASSWORD, sec_u=pg-readonly:DB_USERNAME, sec_x=solo");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed["sec_db"].name, "pg-readonly");
        assert_eq!(parsed["sec_db"].field.as_deref(), Some("DB_PASSWORD"));
        assert_eq!(parsed["sec_x"].field, None);
        // Malformed entries are skipped rather than producing a half-formed enrolment.
        let junk = parse_dynamic_secrets("no-equals,=name,id=,  ,id2=n2");
        assert_eq!(junk.len(), 1);
        assert!(junk.contains_key("id2"));
    }

    #[test]
    fn rfc3339_expiry_parses_to_unix_ms() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:01Z"), Some(1000));
        assert_eq!(parse_rfc3339_ms("not a date"), None);
    }

    #[test]
    fn base_url_must_be_https_except_loopback() {
        assert!(is_secure_base_url("https://app.infisical.com"));
        assert!(is_secure_base_url("https://vault.acme.internal/api"));
        assert!(is_secure_base_url("http://localhost:8080"));
        assert!(is_secure_base_url("http://127.0.0.1:8080/x"));
        assert!(is_secure_base_url("http://[::1]:8080"), "the bracketed IPv6 loopback the comment names");
        assert!(!is_secure_base_url("http://127.0.0.1:8080@evil.example/"), "a userinfo form naming another host");
        assert!(!is_secure_base_url("http://localhost.evil.example/"));
        // Cleartext to a non-loopback host (or no scheme) is refused.
        assert!(!is_secure_base_url("http://app.infisical.com"));
        assert!(!is_secure_base_url("http://evil.example.com"));
        assert!(!is_secure_base_url("ftp://x"));
        assert!(!is_secure_base_url("app.infisical.com"));
        assert!(!is_secure_base_url("https://"));
    }

    /// A loopback HTTP server answering every request with `reply`, keeping each request it got.
    async fn infisical_stand_in(reply: &'static str) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                record.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    /// The documented local Infisical (`http://localhost:8080`, or a self-hosted one on a private network) is reachable: the backend's client is pinned to the configured origin instead of the connector egress screen, which refuses loopback and private addresses by design. It reaches nothing else, follows no redirect, and refuses plain http to anything but loopback.
    #[tokio::test]
    async fn the_infisical_client_reaches_the_configured_origin_and_nothing_else() {
        const OK: &str = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 11\r\nconnection: close\r\n\r\n{\"ok\":true}";
        let (base, seen) = infisical_stand_in(OK).await;
        let client = infisical_client(&base).expect("a loopback Infisical is a configuration the docs give");
        let resp = client
            .send(HttpRequest::get(format!("{base}/api/v3/secrets/raw/X")).header("Authorization", "Bearer synthetic").credentialed())
            .await
            .expect("the configured Infisical is reached");
        assert_eq!(resp.status, 200);
        assert_eq!(seen.lock().unwrap().len(), 1);

        let (elsewhere, reached) = infisical_stand_in(OK).await;
        assert!(client.send(HttpRequest::get(format!("{elsewhere}/x")).credentialed()).await.is_err(), "another origin is refused");
        assert!(reached.lock().unwrap().is_empty(), "before anything is sent");

        let redirect = Box::leak(
            format!("HTTP/1.1 307 Temporary Redirect\r\nlocation: {elsewhere}/collect\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").into_boxed_str(),
        );
        let (redirecting, _) = infisical_stand_in(redirect).await;
        let pinned = infisical_client(&redirecting).unwrap();
        let resp = pinned.send(HttpRequest::get(format!("{redirecting}/api")).header("Authorization", "Bearer synthetic").credentialed()).await;
        assert!(resp.map(|r| r.status == 307).unwrap_or(true), "a redirect is answered, never followed");
        assert!(reached.lock().unwrap().is_empty(), "the redirect target got nothing");

        assert!(infisical_client("http://infisical.corp.example").is_err(), "plain http off loopback is refused");
        assert!(infisical_client("https://infisical.corp.example").is_ok(), "a private https deployment is allowed");
    }

    /// The configuration and the client it builds agree on every base: one the config accepts never then fails to build, which disabled the backend at boot after the config was called valid.
    #[test]
    fn the_config_and_the_client_agree_on_which_bases_are_usable() {
        for base in [
            "https://app.infisical.com",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.8.9.10:8080",
            "http://[::1]:8080",
            "http://[::ffff:127.0.0.1]:8080",
            "http://infisical.corp.example",
            "http://10.0.0.5:8080",
            "https://user@app.infisical.com",
        ] {
            assert_eq!(is_secure_base_url(base), infisical_client(base).is_ok(), "{base}");
        }
    }

    #[tokio::test]
    async fn the_router_sends_an_infisical_record_to_infisical_and_everything_else_local() {
        let pass = b"kek";
        let store = store_with_secret("sec_local", b"local_val", pass);
        store
            .put_secret_custody(SecretCustody::infisical("sec_ext", None, 0))
            .unwrap();
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), pass.to_vec()));
        let http = MockHttpClient::new();
        http.push_response(json_resp(200, serde_json::json!({ "accessToken": "t", "expiresIn": 3600 })));
        http.push_response(json_resp(200, serde_json::json!({ "secret": { "secretValue": "ext_val" } })));
        let external: Arc<dyn SecretBackend> = Arc::new(InfisicalBackend::new(infisical_config(), Arc::new(http)));
        let router = CustodyRouter::new(store, local).with_infisical(external, []);

        assert_eq!(router.resolve("sec_ext").await.unwrap().bytes(), b"ext_val", "enrolled id → Infisical");
        assert_eq!(router.resolve("sec_local").await.unwrap().bytes(), b"local_val", "no record → local vault");
    }

    /// The remote name override: the Infisical secret may be called something else entirely.
    #[tokio::test]
    async fn an_infisical_record_asks_for_its_remote_name() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        store
            .put_secret_custody(SecretCustody::infisical("sec_bt", Some("BRAINTREE_KEY".into()), 0))
            .unwrap();
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), b"kek".to_vec()));
        let http = MockHttpClient::new();
        http.push_response(json_resp(200, serde_json::json!({ "accessToken": "t", "expiresIn": 3600 })));
        http.push_response(json_resp(200, serde_json::json!({ "secret": { "secretValue": "v" } })));
        let external: Arc<dyn SecretBackend> =
            Arc::new(InfisicalBackend::new(infisical_config(), Arc::new(http.clone())));
        let router = CustodyRouter::new(store, local).with_infisical(external, []);

        assert_eq!(router.resolve("sec_bt").await.unwrap().bytes(), b"v");
        let last = http.last_request().unwrap();
        assert!(last.url.contains("BRAINTREE_KEY"), "must fetch the remote name, got {}", last.url);
    }

    /// The whole point of moving enrolment into the store: it can be set at runtime, and the very
    /// next resolve routes differently with no restart.
    #[tokio::test]
    async fn writing_a_custody_record_changes_routing_immediately() {
        let pass = b"kek";
        let store = store_with_secret("sec_x", b"local_val", pass);
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), pass.to_vec()));
        let router = CustodyRouter::new(store.clone(), local)
            .with_kms(Arc::new(kms_backend("unused", b"ct", b"kms_val", false)));

        assert_eq!(router.resolve("sec_x").await.unwrap().bytes(), b"local_val");
        store
            .put_secret_custody(SecretCustody::kms("sec_x", b"ct".to_vec(), "arn:test:cmk", 0))
            .unwrap();
        assert_eq!(router.resolve("sec_x").await.unwrap().bytes(), b"kms_val");
    }

    /// Fail closed: a record naming an external custodian this worker cannot reach must error, not
    /// quietly resolve the local copy: that would be a silent custody downgrade.
    #[tokio::test]
    async fn a_record_naming_a_backend_this_worker_lacks_fails_closed() {
        let pass = b"kek";
        let store = store_with_secret("sec_kms", b"stale_local", pass);
        store
            .put_secret_custody(SecretCustody::kms("sec_kms", b"ct".to_vec(), "cmk", 0))
            .unwrap();
        store
            .put_secret_custody(SecretCustody::infisical("sec_inf", None, 0))
            .unwrap();
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), pass.to_vec()));
        let router = CustodyRouter::new(store, local);

        let err = router.resolve("sec_kms").await.unwrap_err();
        assert!(matches!(err, GatewayError::Internal(_)), "got {err:?}");
        assert!(format!("{err}").contains("no KMS client"), "got {err}");
        assert!(matches!(router.resolve("sec_inf").await.unwrap_err(), GatewayError::Internal(_)));
    }

    /// The store is not the custody root, so a record may not redirect the unwrap at another CMK.
    #[tokio::test]
    async fn a_record_naming_a_different_cmk_is_refused() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        store
            .put_secret_custody(SecretCustody::kms("sec_kms", b"ct".to_vec(), "arn:attacker:cmk", 0))
            .unwrap();
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), b"kek".to_vec()));
        let router = CustodyRouter::new(store, local)
            .with_kms(Arc::new(kms_backend("sec_kms", b"ct", b"v", false)));

        let err = router.resolve("sec_kms").await.unwrap_err();
        assert!(format!("{err}").contains("not configured for"), "got {err}");
    }

    /// A KMS record with no ciphertext cannot be unwrapped; say so rather than resolving locally.
    #[tokio::test]
    async fn a_kms_record_without_a_ciphertext_is_an_error() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let mut custody = SecretCustody::kms("sec_kms", b"ct".to_vec(), "arn:test:cmk", 0);
        custody.kms_ciphertext = None;
        store.put_secret_custody(custody).unwrap();
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), b"kek".to_vec()));
        let router = CustodyRouter::new(store, local)
            .with_kms(Arc::new(kms_backend("sec_kms", b"ct", b"v", false)));

        assert!(format!("{}", router.resolve("sec_kms").await.unwrap_err()).contains("no ciphertext"));
    }

    /// An explicit local record is the same as no record: the floor is preserved either way.
    #[tokio::test]
    async fn an_explicit_local_record_resolves_locally() {
        let pass = b"kek";
        let store = store_with_secret("sec_l", b"local_val", pass);
        store.put_secret_custody(SecretCustody::local("sec_l", 0)).unwrap();
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), pass.to_vec()));
        let router = CustodyRouter::new(store, local)
            .with_kms(Arc::new(kms_backend("sec_l", b"ct", b"kms_val", false)));
        assert_eq!(router.resolve("sec_l").await.unwrap().bytes(), b"local_val");
    }

    /// Backward compatibility: a deployment already carrying `PERMAURA_*_SECRETS` keeps resolving
    /// those ids externally even though no custody record exists for them.
    #[tokio::test]
    async fn the_legacy_env_enrolment_is_still_honoured() {
        let pass = b"kek";
        let store = store_with_secret("sec_local", b"local_val", pass);
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), pass.to_vec()));
        let http = MockHttpClient::new();
        http.push_response(json_resp(200, serde_json::json!({ "accessToken": "t", "expiresIn": 3600 })));
        http.push_response(json_resp(200, serde_json::json!({ "secret": { "secretValue": "inf_val" } })));
        let infisical: Arc<dyn SecretBackend> =
            Arc::new(InfisicalBackend::new(infisical_config(), Arc::new(http)));
        let router = CustodyRouter::new(store, local)
            .with_infisical(infisical, ["sec_env_inf".to_string()])
            .with_kms(Arc::new(kms_backend("sec_env_kms", b"ct", b"kms_val", false)));

        assert_eq!(router.resolve("sec_env_inf").await.unwrap().bytes(), b"inf_val");
        assert_eq!(router.resolve("sec_env_kms").await.unwrap().bytes(), b"kms_val");
        assert_eq!(router.resolve("sec_local").await.unwrap().bytes(), b"local_val");
    }

    // ── KMS backend ─────────────────────────────────────────────────────────────

    /// A deterministic KMS for tests: it "decrypts" by mapping the known ciphertext to a plaintext,
    /// records the key_id it was asked for, and can be told to fail (a revoked/denied identity).
    struct MockKmsClient {
        key_id: String,
        ciphertext: Vec<u8>,
        plaintext: Vec<u8>,
        fail: bool,
    }
    #[async_trait]
    impl KmsClient for MockKmsClient {
        async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, GatewayError> {
            if self.fail {
                return Err(GatewayError::Internal("kms decrypt denied".into()));
            }
            assert_eq!(key_id, self.key_id, "backend must call KMS under the configured CMK");
            assert_eq!(ciphertext, self.ciphertext.as_slice(), "backend must pass the secret's ciphertext");
            Ok(Zeroizing::new(self.plaintext.clone()))
        }
        async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, GatewayError> {
            if self.fail {
                return Err(GatewayError::Internal("kms encrypt denied".into()));
            }
            assert_eq!(key_id, self.key_id, "backend must call KMS under the configured CMK");
            assert_eq!(plaintext, self.plaintext.as_slice(), "mock encrypts only its configured plaintext");
            Ok(self.ciphertext.clone())
        }
    }

    fn kms_backend(secret_id: &str, ciphertext: &[u8], plaintext: &[u8], fail: bool) -> KmsBackend {
        let mut ciphertexts = std::collections::HashMap::new();
        ciphertexts.insert(secret_id.to_string(), ciphertext.to_vec());
        KmsBackend::new(
            KmsConfig { key_id: "arn:test:cmk".into(), ciphertexts },
            Arc::new(MockKmsClient {
                key_id: "arn:test:cmk".into(),
                ciphertext: ciphertext.to_vec(),
                plaintext: plaintext.to_vec(),
                fail,
            }),
        )
    }

    #[tokio::test]
    async fn kms_backend_unwraps_the_secret_via_the_client() {
        let backend = kms_backend("sec_api", b"\x01\x02ciphertext", b"sk_live_123", false);
        let opened = backend.resolve("sec_api").await.unwrap();
        assert_eq!(opened.bytes(), b"sk_live_123");
    }

    #[tokio::test]
    async fn kms_backend_unknown_secret_is_not_found() {
        let backend = kms_backend("sec_api", b"ct", b"v", false);
        assert!(matches!(backend.resolve("sec_other").await.unwrap_err(), GatewayError::NotFound(_)));
    }

    #[tokio::test]
    async fn kms_backend_propagates_a_decrypt_denial() {
        let backend = kms_backend("sec_api", b"ct", b"v", true);
        assert!(matches!(backend.resolve("sec_api").await.unwrap_err(), GatewayError::Internal(_)));
    }

    #[tokio::test]
    async fn the_router_unwraps_a_kms_record_and_leaves_the_rest_local() {
        let pass = b"kek";
        let store = store_with_secret("sec_local", b"local_val", pass);
        store
            .put_secret_custody(SecretCustody::kms("sec_kms", b"ct".to_vec(), "arn:test:cmk", 0))
            .unwrap();
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), pass.to_vec()));
        let router = CustodyRouter::new(store, local)
            .with_kms(Arc::new(kms_backend("sec_kms", b"ct", b"kms_val", false)));
        assert_eq!(router.resolve("sec_kms").await.unwrap().bytes(), b"kms_val", "enrolled id → KMS");
        assert_eq!(router.resolve("sec_local").await.unwrap().bytes(), b"local_val", "other id → local vault");
    }

    // ── KMS enrolment (custody becomes a runtime choice) ────────────────────────

    /// A reversible stand-in for a cloud KMS: XOR is symmetric, so encrypt/decrypt round-trip for
    /// any input, enough to exercise the enrolment path without an HSM. `corrupt` makes decrypt
    /// return something else, standing in for a wrap that would not come back.
    struct XorKms {
        corrupt: bool,
    }
    #[async_trait]
    impl KmsClient for XorKms {
        async fn decrypt(&self, _key_id: &str, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, GatewayError> {
            if self.corrupt {
                return Ok(Zeroizing::new(b"not-the-original".to_vec()));
            }
            Ok(Zeroizing::new(ct.iter().map(|b| b ^ 0x5A).collect()))
        }
        async fn encrypt(&self, _key_id: &str, pt: &[u8]) -> Result<Vec<u8>, GatewayError> {
            Ok(pt.iter().map(|b| b ^ 0x5A).collect())
        }
    }

    #[tokio::test]
    async fn enrolling_a_secret_in_kms_records_custody_and_drops_the_local_copy() {
        let pass = b"kek";
        let store = store_with_secret("sec_api", b"sk_live_123", pass);
        let kms = XorKms { corrupt: false };

        let custody = enrol_secret_in_kms(store.as_ref(), &kms, "arn:test:cmk", pass, "sec_api", 42)
            .await
            .unwrap();
        assert_eq!(custody.kind, CustodyKind::Kms);
        assert_eq!(custody.kms_key_id.as_deref(), Some("arn:test:cmk"));
        assert_eq!(custody.enrolled_at, 42);
        assert!(store.get_secret("sec_api").unwrap().is_none(), "the local sealed row must be gone");
        assert_eq!(store.get_secret_custody("sec_api").unwrap().unwrap(), custody);

        // And the router now resolves it through KMS, to the same plaintext.
        let local: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), pass.to_vec()));
        let backend = Arc::new(KmsBackend::new(
            KmsConfig { key_id: "arn:test:cmk".into(), ciphertexts: Default::default() },
            Arc::new(XorKms { corrupt: false }),
        ));
        let router = CustodyRouter::new(store, local).with_kms(backend);
        assert_eq!(router.resolve("sec_api").await.unwrap().bytes(), b"sk_live_123");
    }

    /// The local copy is the only copy until the wrap is proven reversible, so a KMS that cannot
    /// give the value back must leave the secret exactly where it was.
    #[tokio::test]
    async fn a_wrap_that_does_not_round_trip_never_deletes_the_local_copy() {
        let pass = b"kek";
        let store = store_with_secret("sec_api", b"sk_live_123", pass);
        let err = enrol_secret_in_kms(
            store.as_ref(),
            &XorKms { corrupt: true },
            "arn:test:cmk",
            pass,
            "sec_api",
            0,
        )
        .await
        .unwrap_err();

        assert!(format!("{err}").contains("round-trip"), "got {err}");
        assert!(store.get_secret("sec_api").unwrap().is_some(), "the secret must survive a failed enrolment");
        assert!(store.get_secret_custody("sec_api").unwrap().is_none(), "no custody record on failure");
    }

    #[tokio::test]
    async fn enrolling_an_already_external_secret_is_refused() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        store
            .put_secret_custody(SecretCustody::infisical("sec_api", None, 0))
            .unwrap();
        let err = enrol_secret_in_kms(
            store.as_ref(),
            &XorKms { corrupt: false },
            "arn:test:cmk",
            b"kek",
            "sec_api",
            0,
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("already in infisical custody"), "got {err}");
    }

    #[tokio::test]
    async fn enrolling_an_unknown_secret_is_not_found() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let err = enrol_secret_in_kms(
            store.as_ref(),
            &XorKms { corrupt: false },
            "arn:test:cmk",
            b"kek",
            "nope",
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, GatewayError::NotFound(_)), "got {err:?}");
    }

    // ── GCP KMS client (the real provider) ──────────────────────────────────────

    /// A token source over the test's mock HTTP, standing in for the shared one production builds.
    fn token_source(http: MockHttpClient) -> Arc<GcpTokenSource> {
        Arc::new(GcpTokenSource::new(Arc::new(http)))
    }

    #[tokio::test]
    async fn gcp_kms_client_fetches_a_metadata_token_then_decrypts() {
        use base64::Engine;
        let http = MockHttpClient::new();
        // 1) metadata-server token, 2) cloudkms decrypt returning base64(plaintext).
        http.push_response(json_resp(200, serde_json::json!({ "access_token": "ya29.tok", "expires_in": 3600 })));
        let pt_b64 = base64::engine::general_purpose::STANDARD.encode(b"sk_live_999");
        http.push_response(json_resp(200, serde_json::json!({ "plaintext": pt_b64 })));
        let client = GcpKmsClient::new(Arc::new(http.clone()), token_source(http.clone()));

        let key = "projects/example-project/locations/europe-west2/keyRings/example/cryptoKeys/worker";
        let out = client.decrypt(key, b"\x00\x01ciphertext").await.unwrap();
        assert_eq!(out.as_slice(), b"sk_live_999");
        // The decrypt call hit the right resource URL with a bearer token.
        let last = http.last_request().unwrap();
        assert!(last.url.ends_with(&format!("/v1/{key}:decrypt")), "url was {}", last.url);
        assert_eq!(last.headers.get("Authorization").map(String::as_str), Some("Bearer ya29.tok"));
    }

    #[tokio::test]
    async fn gcp_kms_client_surfaces_a_decrypt_denial() {
        let http = MockHttpClient::new();
        http.push_response(json_resp(200, serde_json::json!({ "access_token": "t", "expires_in": 3600 })));
        http.push_response(json_resp(403, serde_json::json!({ "error": "permission denied" })));
        let client = GcpKmsClient::new(Arc::new(http.clone()), token_source(http));
        assert!(matches!(
            client.decrypt("projects/p/locations/l/keyRings/r/cryptoKeys/k", b"ct").await.unwrap_err(),
            GatewayError::Internal(_)
        ));
    }

    #[tokio::test]
    async fn gcp_kms_client_encrypts_under_the_cmk() {
        use base64::Engine;
        let http = MockHttpClient::new();
        http.push_response(json_resp(200, serde_json::json!({ "access_token": "ya29.tok", "expires_in": 3600 })));
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode(b"wrapped-seed-ciphertext");
        http.push_response(json_resp(200, serde_json::json!({ "ciphertext": ct_b64 })));
        let client = GcpKmsClient::new(Arc::new(http.clone()), token_source(http.clone()));

        let key = "projects/example-project/locations/europe-west2/keyRings/example/cryptoKeys/org-x";
        let out = client.encrypt(key, b"an-audit-signing-seed").await.unwrap();
        assert_eq!(out, b"wrapped-seed-ciphertext");
        let last = http.last_request().unwrap();
        assert!(last.url.ends_with(&format!("/v1/{key}:encrypt")), "url was {}", last.url);
        assert_eq!(last.headers.get("Authorization").map(String::as_str), Some("Bearer ya29.tok"));
    }

    /// End-to-end: a KmsBackend backed by the *real* GcpKmsClient (over a mock metadata+KMS HTTP),
    /// proving the provider drops into the same backend the enforcement loop uses.
    #[tokio::test]
    async fn kms_backend_over_gcp_client_resolves_a_secret() {
        use base64::Engine;
        let http = MockHttpClient::new();
        http.push_response(json_resp(200, serde_json::json!({ "access_token": "t", "expires_in": 3600 })));
        http.push_response(json_resp(200, serde_json::json!({
            "plaintext": base64::engine::general_purpose::STANDARD.encode(b"resolved")
        })));
        let mut ciphertexts = std::collections::HashMap::new();
        ciphertexts.insert("sec_api".to_string(), b"opaque-kms-ciphertext".to_vec());
        let backend = KmsBackend::new(
            KmsConfig { key_id: "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(), ciphertexts },
            Arc::new(GcpKmsClient::new(Arc::new(http.clone()), token_source(http))),
        );
        assert_eq!(backend.resolve("sec_api").await.unwrap().bytes(), b"resolved");
    }

    /// The in-use question follows the router's own routing order and is answered from enrolment metadata, so no custodian is ever asked for a value.
    #[test]
    fn the_router_says_which_ids_an_external_custodian_holds_without_asking_it() {
        let pass = b"kek";
        let store = store_with_secret("sec_local", b"local_val", pass);
        store.put_secret_custody(SecretCustody::infisical("sec_recorded", Some("REMOTE".into()), 0)).unwrap();
        store.put_secret_custody(SecretCustody::kms("sec_unwired_kms", b"ct".to_vec(), "cmk", 0)).unwrap();
        store.put_secret_custody(SecretCustody::local("sec_env_but_local", 0)).unwrap();
        let local: Arc<dyn SecretBackend> = Arc::new(LocalVaultBackend::new(store.clone(), pass.to_vec()));
        let infisical_http = MockHttpClient::new();
        let dynamic_http = MockHttpClient::new();
        let router = CustodyRouter::new(store, local)
            .with_infisical(
                Arc::new(InfisicalBackend::new(infisical_config(), Arc::new(infisical_http.clone()))),
                ["sec_env".to_string(), "sec_env_but_local".to_string()],
            )
            .with_kms(Arc::new(kms_backend("sec_env_kms", b"ct", b"v", false)))
            .with_dynamic(
                Arc::new(InfisicalDynamicBackend::new(dynamic_config(None), Arc::new(dynamic_http.clone()))),
                ["sec_db".to_string()],
            );

        for id in ["sec_env", "sec_env_kms", "sec_recorded", "sec_unwired_kms", "sec_db"] {
            assert!(router.holds_externally(id).unwrap(), "{id} is held outside this gateway");
        }
        for id in ["sec_local", "sec_env_but_local", "sec_never_seen"] {
            assert!(!router.holds_externally(id).unwrap(), "{id} is not");
        }
        assert!(infisical_http.requests().is_empty() && dynamic_http.requests().is_empty(), "nothing was fetched or minted");
    }
}
