//! Runtime-installable connector manifests: the standardized way to add a connector to a gateway
//! without recompiling the binary.
//!
//! A manifest is exactly a [`crate::presets::Preset`] (the same declarative shape the bundled
//! marketplace catalog uses), delivered inside a small envelope. Permaura-published connectors carry
//! an **Ed25519 signature** over the canonical bytes, verified against public keys **compiled into
//! the binary** ([`pmconn_pubkeys`]); a user may also install their **own** unsigned manifest, which
//! is accepted but recorded with `provenance = user` so the operator always knows whether Permaura
//! vouches for a connector or they brought it themselves.
//!
//! Trust rides on the signature, not the transport: the manifest may reach the gateway via the
//! browser, the phone, or a file, all equally untrusted, because the gateway verifies the exact
//! signed bytes. `permaura-policy` is unchanged: an installed manifest is inert until an operator
//! instantiates it and grants capabilities, and risky verbs still land disabled. An unsigned
//! manifest's own posture lines may only raise what the method and action give a capability (more
//! risk, an approval, switched off), never lower it ([`InstalledManifest::preset`]).

use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::presets::Preset;

/// Ed25519 public keys this binary trusts to sign connector manifests, keyed by `key_id`. Distinct
/// from the OAuth AS keys and from the (pending) binary-release key: independent blast radius and
/// rotation. Carry the active key plus the next one during a rotation window. Values are base64 of
/// the raw 32-byte key. Production keys are minted OFFLINE and added here as they are created.
const PINNED_PUBKEYS: &[(&str, &str)] = &[
    // Production keys go here once minted offline (none yet, signed install is dev-only for now).
];

/// The development signer (`scripts/sign-connector.ts` default). Its secret is never committed, and
/// it is trusted ONLY in debug/test builds: a release binary must never accept the low-assurance dev
/// key as "Permaura-signed", or a leaked dev secret would forge signed provenance in production.
#[cfg(debug_assertions)]
const DEV_PUBKEYS: &[(&str, &str)] =
    &[("pmconn-dev", "dMGMFyKfZk9LTE27N1ICKXfhb2SkRwC5Z5oqPKHy2iU=")];
#[cfg(not(debug_assertions))]
const DEV_PUBKEYS: &[(&str, &str)] = &[];

/// ROOT public keys: the offline cold anchor of the chain. The root
/// signs ONLY intermediate certificates, never manifests; a v2 chained envelope is trusted iff its
/// intermediate cert is root-signed. This is compiled into the binary and NEVER fetched from a
/// server: the anchor's value is that no one on the network can swap it. Carry active+next during a
/// rotation window. Production roots are minted OFFLINE (see `scripts/pmconn-ca.ts`) and added here.
const ROOT_PUBKEYS: &[(&str, &str)] = &[
    // Production root `pmconn-root-2026a`, minted offline 2026-07 (secret held cold, never on any server).
    ("pmconn-root-2026a", "kAdmtaXZtxvzfgO41g0bnOImC5hj7eaHQpskFSFV4Mk="),
];

/// The development ROOT (debug/test builds only), for exercising the v2 chain locally. Its secret is
/// never committed. A release binary trusts no dev root.
#[cfg(debug_assertions)]
const DEV_ROOT_PUBKEYS: &[(&str, &str)] = &[(
    "pmconn-root-dev",
    "L3aD9kgxXhu3gBGSrpPSxqhfWukMIHE41d6mY3SUZYI=",
)];
#[cfg(not(debug_assertions))]
const DEV_ROOT_PUBKEYS: &[(&str, &str)] = &[];

/// Length-prefixed, domain-separated preimage builder (the convention from `permaura-relay::sig`):
/// signatures are NEVER computed over serialized JSON (ambiguous key order/whitespace). Each field is
/// u32-BE-length-prefixed after a fixed domain tag, so no field-boundary collision is possible.
fn lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// The preimage the ROOT signs to issue an intermediate certificate. Integers are ASCII decimal so
/// the TS ceremony tool (`scripts/pmconn-ca.ts`) produces byte-identical bytes.
fn cert_preimage(
    key_id: &str,
    pubkey_raw: &[u8],
    issued_at: i64,
    expires_at: i64,
    root_key_id: &str,
) -> Vec<u8> {
    let mut out = Vec::from(&b"permaura-pmconn/v1/intermediate-cert"[..]);
    lp(&mut out, key_id.as_bytes());
    lp(&mut out, pubkey_raw);
    lp(&mut out, issued_at.to_string().as_bytes());
    lp(&mut out, expires_at.to_string().as_bytes());
    lp(&mut out, root_key_id.as_bytes());
    out
}

/// An intermediate signing key's certificate: the intermediate pubkey + validity window, signed by a
/// pinned ROOT. Carried in a v2 install envelope so the gateway can verify the chain offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntermediateCert {
    /// The intermediate key's id (echoed as the envelope `key_id` and the `Signed` provenance).
    pub key_id: String,
    /// base64 raw 32-byte intermediate public key.
    pub pubkey: String,
    /// Unix-ms issue time.
    pub issued_at: i64,
    /// Unix-ms expiry: short-lived so a leaked intermediate self-limits.
    pub expires_at: i64,
    /// Which pinned ROOT signed this cert.
    pub root_key_id: String,
    /// base64 Ed25519 signature by the ROOT over [`cert_preimage`].
    pub root_sig: String,
}

/// One revoked manifest id (up to and including a version), for the root-signed revocation list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedManifest {
    /// The connector/manifest id.
    pub id: String,
    /// Revoked for every version ≤ this.
    pub up_to_version: u32,
}

/// A root-signed revocation list: revoked intermediate key ids and revoked manifests. Because it is
/// root-signed over [`revocation_preimage`], which fixes which items belong to which list, it is safe
/// to distribute over untrusted transport (a compromised server can't forge or re-split it).
/// `serial` is signed but not enforced: a gateway loads one list at boot and keeps no record of the
/// serials it has seen, so it does not refuse an older genuine list put in place of a newer one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
    #[serde(default)]
    pub revoked_manifests: Vec<RevokedManifest>,
    pub issued_at: i64,
    pub serial: u64,
    pub root_key_id: String,
    pub root_sig: String,
}

/// A verified, ready-to-query revocation state. Construct via [`Revocation::verified`] (checks the
/// root signature) or [`Revocation::empty`] (nothing revoked, the default when none is configured).
#[derive(Debug, Clone, Default)]
pub struct Revocation {
    key_ids: std::collections::HashSet<String>,
    manifests: BTreeMap<String, u32>,
    /// A list was configured and could not be verified, so nothing it might revoke is trusted.
    unverifiable: bool,
}

impl Revocation {
    /// The empty revocation state (nothing revoked).
    pub fn empty() -> Self {
        Revocation::default()
    }

    /// Verify a revocation list against the pinned roots and materialise it. A list whose root
    /// signature does not verify is rejected: an unsigned/forged list can never suppress a connector.
    pub fn verified(
        list: &RevocationList,
        roots: &[(String, VerifyingKey)],
    ) -> Result<Self, String> {
        let root = roots
            .iter()
            .find(|(id, _)| id == &list.root_key_id)
            .map(|(_, k)| k)
            .ok_or_else(|| format!("revocation: unknown root key '{}'", list.root_key_id))?;
        let preimage = revocation_preimage(list);
        let sig = decode_sig(&list.root_sig)?;
        root.verify_strict(&preimage, &sig)
            .map_err(|_| "revocation: root signature invalid".to_string())?;
        Ok(Revocation {
            key_ids: list.revoked_key_ids.iter().cloned().collect(),
            manifests: list.revoked_manifests.iter().map(|m| (m.id.clone(), m.up_to_version)).collect(),
            unverifiable: false,
        })
    }

    fn is_key_revoked(&self, key_id: &str) -> bool {
        self.key_ids.contains(key_id)
    }

    fn is_manifest_revoked(&self, id: &str, version: u32) -> bool {
        self.manifests
            .get(id)
            .is_some_and(|&up_to| version <= up_to)
    }

    /// Why an installed manifest may not run under this state, or `None`. Only a Permaura-signed one
    /// can be revoked: the operator's own unsigned manifest is outside the list.
    pub fn refuses_installed(&self, installed: &InstalledManifest) -> Option<String> {
        let key_id = match &installed.provenance {
            Provenance::Signed { key_id } => Some(key_id.as_str()),
            Provenance::User => None,
        };
        self.refuses_origin(&installed.manifest.id, installed.version, key_id)
    }

    /// [`Self::refuses_installed`] for manifest `id` at `version` signed with `key_id`, whether or not it is still installed. `None` for an unsigned one.
    pub fn refuses_origin(&self, id: &str, version: u32, key_id: Option<&str>) -> Option<String> {
        let key_id = key_id?;
        if self.unverifiable {
            return Some("PERMAURA_PMCONN_REVOCATION is set but its list does not verify".into());
        }
        if self.is_key_revoked(key_id) {
            return Some(format!("its signing key '{key_id}' is revoked"));
        }
        if self.is_manifest_revoked(id, version) {
            return Some(format!("version {version} is revoked"));
        }
        None
    }
}

/// Log every installed Permaura-signed manifest `revocation` refuses, once at boot. Each call checks
/// its own connector as well, so a store that cannot be listed here changes what is logged, not what
/// runs.
pub fn log_revoked_installed(store: &dyn crate::store::Store, revocation: &Revocation) {
    match store.list_connector_manifests() {
        Ok(installed) => {
            for m in installed {
                if let Some(why) = revocation.refuses_installed(&m) {
                    tracing::error!(
                        connector = %m.manifest.id,
                        version = m.version,
                        "installed Permaura-signed connector is revoked ({why}): every capability on its connections is refused, and it cannot be removed or replaced while they exist"
                    );
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "the installed connectors could not be listed against the revocation list; each call still checks its own connector"),
    }
}

/// The bytes the ROOT signs for a revocation list: the domain tag, `serial`, `issued_at`, then each
/// list under its own name and item count, key ids sorted and manifests sorted by id, then
/// `root_key_id`. Without the names and counts nothing fixed where the key ids end and the manifests
/// begin, so one signature verified a different split of the same items. Integers are ASCII decimal
/// so the TS ceremony tool (`scripts/pmconn-lib.ts`) produces byte-identical bytes.
pub fn revocation_preimage(list: &RevocationList) -> Vec<u8> {
    let mut out = Vec::from(&b"permaura-pmconn/v2/revocation"[..]);
    lp(&mut out, list.serial.to_string().as_bytes());
    lp(&mut out, list.issued_at.to_string().as_bytes());
    let mut key_ids = list.revoked_key_ids.clone();
    key_ids.sort();
    lp(&mut out, b"revoked_key_ids");
    lp(&mut out, key_ids.len().to_string().as_bytes());
    for k in &key_ids {
        lp(&mut out, k.as_bytes());
    }
    let mut mans = list.revoked_manifests.clone();
    mans.sort_by(|a, b| a.id.cmp(&b.id));
    lp(&mut out, b"revoked_manifests");
    lp(&mut out, mans.len().to_string().as_bytes());
    for m in &mans {
        lp(&mut out, m.id.as_bytes());
        lp(&mut out, m.up_to_version.to_string().as_bytes());
    }
    lp(&mut out, list.root_key_id.as_bytes());
    out
}

fn decode_pubkey_raw(b64: &str) -> Result<VerifyingKey, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "public key is not valid base64".to_string())?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| "public key is not 32 bytes".to_string())?;
    permaura_relay::strict_verifying_key(&arr).map_err(|_| "public key is not a valid Ed25519 key".to_string())
}

fn decode_sig(b64: &str) -> Result<Signature, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "signature is not valid base64".to_string())?;
    let arr = <[u8; 64]>::try_from(bytes.as_slice())
        .map_err(|_| "signature is not 64 bytes".to_string())?;
    Ok(Signature::from_bytes(&arr))
}

/// How much a gateway trusts an installed manifest's *shape*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    /// Signed by Permaura and verified against a pinned key.
    Signed { key_id: String },
    /// Provided by the operator themselves; unsigned. Permaura does not vouch for it.
    User,
}

/// A manifest as persisted in the store: the definition plus the trust + version metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledManifest {
    /// The connector definition.
    pub manifest: Preset,
    /// The installed version (monotonic per id).
    pub version: u32,
    /// Whether Permaura signed it, or the operator provided it.
    pub provenance: Provenance,
    /// Unix-ms install time.
    pub installed_at: i64,
    /// Every endpoint host the install named, as [`Preset::endpoint_hosts`] read the manifest the change was asked for with. OAuth start sends a client secret to no host outside it, so a record edited afterwards cannot redirect one. Empty on a record written before it was kept, whose install named the base URL's host alone ([`Self::named_hosts`]).
    #[serde(default)]
    pub endpoint_hosts: Vec<String>,
}

impl InstalledManifest {
    /// The definition with its posture lines trusted as far as its provenance allows: as written when Permaura signed it, held to the floor the method and action give otherwise ([`Preset::vouched`]).
    pub fn preset(&self) -> Preset {
        let mut preset = self.manifest.clone();
        preset.vouched = matches!(self.provenance, Provenance::Signed { .. });
        preset
    }

    /// The hosts this manifest's install named.
    pub fn named_hosts(&self) -> Vec<String> {
        if !self.endpoint_hosts.is_empty() {
            return self.endpoint_hosts.clone();
        }
        crate::connectors::shown_host(&self.manifest.base_url).into_iter().collect()
    }
}

/// Canonical bytes for signing/verification: compact JSON with recursively-sorted object keys over
/// `{"manifest": <value>, "version": <n>}`, where `<value>` is the manifest **exactly as authored**
/// (the raw JSON the signer signed and the gateway received), never a re-serialized `Preset`, whose
/// `#[serde(default)]` fields would materialise and diverge from the author's JSON. The offline
/// signer (`scripts/sign-connector.ts`) canonicalises the same input, so the bytes match.
///
/// The two sides agree only on the format the signers accept: every number a safe integer, no object
/// key with a character above U+FFFF (UTF-16 and code-point order differ there), and no lone
/// surrogate. Today's signers refuse anything else, so they never produce a signature over it (one made
/// before that rule, over a number such as 0.5, still verifies, correctly).
pub fn canonical_bytes(manifest: &serde_json::Value, version: u32) -> Vec<u8> {
    let value = serde_json::json!({ "manifest": manifest, "version": version });
    let mut out = String::new();
    canonicalize(&value, &mut out);
    out.into_bytes()
}

fn canonicalize(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<&String, &serde_json::Value> = BTreeMap::new();
            for (k, val) in map {
                sorted.insert(k, val);
            }
            out.push('{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                canonicalize(val, out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonicalize(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Number(n) => out.push_str(&canonical_number(n)),
        other => out.push_str(&serde_json::to_string(other).unwrap_or_else(|_| "null".into())),
    }
}

/// JavaScript's largest exactly representable integer, 2^53 - 1.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// A number as JavaScript's `JSON.stringify` prints it, for every number the signers accept: an integral value in the safe range prints as a plain integer whether it was authored as `100`, `100.0` or `1e2`. Anything else keeps serde_json's form.
fn canonical_number(n: &serde_json::Number) -> String {
    if n.is_i64() || n.is_u64() {
        return n.to_string();
    }
    match n.as_f64() {
        Some(x) if x.is_finite() && x.fract() == 0.0 && x.abs() <= MAX_SAFE_INTEGER => (x as i64).to_string(),
        _ => n.to_string(),
    }
}

fn parse_pubkeys(entries: &[(&str, &str)]) -> Vec<(String, VerifyingKey)> {
    let mut keys = Vec::new();
    for (id, b64) in entries {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                if let Ok(vk) = permaura_relay::strict_verifying_key(&arr) {
                    keys.push(((*id).to_string(), vk));
                }
            }
        }
    }
    keys
}

/// The v1 directly-pinned LEAF key set: production pinned keys, plus the dev signer in debug builds.
pub fn pmconn_pubkeys() -> Vec<(String, VerifyingKey)> {
    let mut keys = parse_pubkeys(PINNED_PUBKEYS);
    keys.extend(parse_pubkeys(DEV_PUBKEYS));
    keys
}

/// The pinned ROOT key set for the v2 chain (prod roots + the dev root in debug builds).
pub fn pmconn_root_pubkeys() -> Vec<(String, VerifyingKey)> {
    let mut keys = parse_pubkeys(ROOT_PUBKEYS);
    keys.extend(parse_pubkeys(DEV_ROOT_PUBKEYS));
    keys
}

/// The list `PERMAURA_PMCONN_REVOCATION` names, verified: a path to, or the inline JSON of, a
/// root-signed [`RevocationList`]. [`Revocation::empty`] when the variable is unset or blank. An
/// error names the variable and why its list cannot be trusted; the gateway refuses to start on one.
pub fn configured_revocation() -> Result<Revocation, String> {
    revocation_config(std::env::var("PERMAURA_PMCONN_REVOCATION").ok().as_deref(), &pmconn_root_pubkeys())
}

/// The revocation state a gateway runs with. `permaura start` has already refused to start on a
/// list [`configured_revocation`] cannot verify; any other constructor gets a state under which no
/// Permaura-signed manifest installs, because a list that fails to verify (a corrupted signature, a
/// v1 list, an unreadable file) must not leave revoked connectors installable.
pub fn load_revocation() -> Revocation {
    revocation_state(std::env::var("PERMAURA_PMCONN_REVOCATION").ok().as_deref(), &pmconn_root_pubkeys())
}

fn revocation_state(raw: Option<&str>, roots: &[(String, VerifyingKey)]) -> Revocation {
    revocation_config(raw, roots).unwrap_or_else(|why| {
        tracing::error!("{why}; no Permaura-signed connector installs until it is fixed or unset");
        Revocation { unverifiable: true, ..Revocation::default() }
    })
}

fn revocation_config(raw: Option<&str>, roots: &[(String, VerifyingKey)]) -> Result<Revocation, String> {
    let raw = match raw {
        Some(v) if !v.trim().is_empty() => v,
        _ => return Ok(Revocation::empty()),
    };
    let json = if raw.trim_start().starts_with('{') {
        raw.to_string()
    } else {
        std::fs::read_to_string(raw)
            .map_err(|e| format!("PERMAURA_PMCONN_REVOCATION names a file that cannot be read ({e})"))?
    };
    let list = serde_json::from_str::<RevocationList>(&json)
        .map_err(|e| format!("PERMAURA_PMCONN_REVOCATION is not a revocation list ({e})"))?;
    Revocation::verified(&list, roots).map_err(|e| format!("PERMAURA_PMCONN_REVOCATION does not verify ({e})"))
}

/// Verify a LEAF signature over `canonical_bytes(manifest, version)` against one public key.
fn verify_leaf_sig(
    manifest: &serde_json::Value,
    version: u32,
    sig_b64: &str,
    vk: &VerifyingKey,
) -> Result<(), String> {
    let sig = decode_sig(sig_b64)?;
    vk.verify_strict(&canonical_bytes(manifest, version), &sig)
        .map_err(|_| "signature does not verify".to_string())
}

/// Verify an intermediate certificate against the pinned roots, returning its public key. Checks the
/// root signature and the validity window (`now_ms` must be within `[issued_at, expires_at)`).
pub fn verify_cert(
    cert: &IntermediateCert,
    roots: &[(String, VerifyingKey)],
    now_ms: i64,
) -> Result<VerifyingKey, String> {
    let root = roots
        .iter()
        .find(|(id, _)| id == &cert.root_key_id)
        .map(|(_, k)| k)
        .ok_or_else(|| format!("unknown root key '{}'", cert.root_key_id))?;
    let int_vk = decode_pubkey_raw(&cert.pubkey)?;
    let preimage = cert_preimage(
        &cert.key_id,
        &int_vk.to_bytes(),
        cert.issued_at,
        cert.expires_at,
        &cert.root_key_id,
    );
    let sig = decode_sig(&cert.root_sig)?;
    root.verify_strict(&preimage, &sig)
        .map_err(|_| "intermediate cert: root signature invalid".to_string())?;
    if now_ms >= cert.expires_at {
        return Err("intermediate cert has expired".into());
    }
    if now_ms < cert.issued_at {
        return Err("intermediate cert is not yet valid".into());
    }
    Ok(int_vk)
}

/// Resolve a received manifest to its [`Provenance`], verifying the signature when present against the
/// directly-pinned LEAF keys (v1 flat model). `manifest` is the raw JSON as received (so the canonical
/// bytes match the signer's). A signature that is present but unverifiable is rejected, never
/// downgraded to `user`.
pub fn verify(
    manifest: &serde_json::Value,
    version: u32,
    signature: Option<&str>,
    key_id: Option<&str>,
    allowed: &[(String, VerifyingKey)],
) -> Result<Provenance, String> {
    match (signature, key_id) {
        (None, _) => Ok(Provenance::User),
        (Some(_), None) => Err("signature present without a key_id".into()),
        (Some(sig_b64), Some(key_id)) => {
            let vk = allowed
                .iter()
                .find(|(id, _)| id == key_id)
                .map(|(_, k)| k)
                .ok_or_else(|| format!("unknown signing key '{key_id}'"))?;
            verify_leaf_sig(manifest, version, sig_b64, vk)?;
            Ok(Provenance::Signed {
                key_id: key_id.to_string(),
            })
        }
    }
}

/// Full envelope verification (v1 flat OR v2 chained), the entry point the install handler uses.
///
/// - No signature → `User`.
/// - `cert` present (v2): the intermediate cert must be root-signed, unexpired, and its key not
///   revoked; the leaf signature must verify against the cert's key; the manifest id/version must not
///   be revoked. Provenance = `Signed { key_id: cert.key_id }`.
/// - `cert` absent (v1): the leaf signature is checked directly against the pinned leaf keys, and
///   the manifest id/version must not be revoked.
/// - A configured revocation list that did not verify refuses every signed envelope.
///
/// A signed envelope that fails any check is REJECTED, never silently downgraded to `User`.
#[allow(clippy::too_many_arguments)]
pub fn verify_envelope(
    manifest: &serde_json::Value,
    version: u32,
    signature: Option<&str>,
    key_id: Option<&str>,
    cert: Option<&IntermediateCert>,
    roots: &[(String, VerifyingKey)],
    leaf_pinned: &[(String, VerifyingKey)],
    revocation: &Revocation,
    now_ms: i64,
) -> Result<Provenance, String> {
    if signature.is_some() && revocation.unverifiable {
        return Err("PERMAURA_PMCONN_REVOCATION is set but its list does not verify, so no Permaura-signed connector installs".into());
    }
    match (signature, cert) {
        (None, _) => Ok(Provenance::User),
        (Some(sig_b64), Some(cert)) => {
            if revocation.is_key_revoked(&cert.key_id) {
                return Err(format!("intermediate key '{}' is revoked", cert.key_id));
            }
            let int_vk = verify_cert(cert, roots, now_ms)?;
            verify_leaf_sig(manifest, version, sig_b64, &int_vk)?;
            let manifest_id = manifest
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if revocation.is_manifest_revoked(manifest_id, version) {
                return Err(format!("manifest '{manifest_id}' v{version} is revoked"));
            }
            Ok(Provenance::Signed {
                key_id: cert.key_id.clone(),
            })
        }
        (Some(sig_b64), None) => {
            let provenance = verify(manifest, version, Some(sig_b64), key_id, leaf_pinned)?;
            let manifest_id = manifest.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            if revocation.is_manifest_revoked(manifest_id, version) {
                return Err(format!("manifest '{manifest_id}' v{version} is revoked"));
            }
            Ok(provenance)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn dev_manifest(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id, "name": "Test", "vertical": "data", "base_url": "https://api.example.com",
            "capabilities": [ { "id": "things.list", "method": "GET", "path": "/things" } ]
        })
    }

    const NOW: i64 = 1_783_000_000_000;
    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// Build a root-signed intermediate cert for `int` valid [issued, issued+span_ms).
    fn make_cert(
        root: &SigningKey,
        root_id: &str,
        int: &SigningKey,
        int_id: &str,
        issued: i64,
        span_ms: i64,
    ) -> IntermediateCert {
        let expires = issued + span_ms;
        let pre = cert_preimage(
            int_id,
            &int.verifying_key().to_bytes(),
            issued,
            expires,
            root_id,
        );
        IntermediateCert {
            key_id: int_id.to_string(),
            pubkey: b64(&int.verifying_key().to_bytes()),
            issued_at: issued,
            expires_at: expires,
            root_key_id: root_id.to_string(),
            root_sig: b64(&root.sign(&pre).to_bytes()),
        }
    }

    fn leaf_sig(int: &SigningKey, manifest: &serde_json::Value, version: u32) -> String {
        b64(&int.sign(&canonical_bytes(manifest, version)).to_bytes())
    }

    /// Every PINNED production key must actually decode. `parse_pubkeys` silently drops an entry whose
    /// base64 is malformed (e.g. missing padding) or whose length isn't 32, which would leave the
    /// trust anchor unloaded with NO build error. This guards the pins themselves.
    #[test]
    fn pinned_production_keys_all_decode() {
        assert_eq!(
            parse_pubkeys(ROOT_PUBKEYS).len(),
            ROOT_PUBKEYS.len(),
            "a pinned ROOT_PUBKEYS entry did not decode (bad base64/length) and was silently dropped",
        );
        assert_eq!(
            parse_pubkeys(PINNED_PUBKEYS).len(),
            PINNED_PUBKEYS.len(),
            "a pinned PINNED_PUBKEYS entry did not decode and was silently dropped",
        );
    }

    /// A shipped binary must trust the offline-minted production root and nothing else. Only a release
    /// build can show this: a debug build also carries `pmconn-root-dev`, so it cannot distinguish the
    /// anchor set from the dev one. Catches a pin that no longer decodes (`parse_pubkeys` drops it
    /// silently, with no build error), a removed or renamed root, and a dev anchor that survived into
    /// release. Substituted key material is caught by
    /// [`the_pinned_production_root_signed_the_committed_intermediate_cert`] instead, which verifies a
    /// real ceremony artifact rather than the pin's shape.
    #[cfg(not(debug_assertions))]
    #[test]
    fn a_release_build_trusts_only_the_production_root() {
        let anchored: Vec<String> = pmconn_root_pubkeys().into_iter().map(|(id, _)| id).collect();
        assert_eq!(
            anchored,
            vec!["pmconn-root-2026a".to_string()],
            "a release build's root anchor set must be exactly the production root",
        );
        assert!(DEV_ROOT_PUBKEYS.is_empty(), "a release binary trusts no dev root");
        assert!(DEV_PUBKEYS.is_empty(), "a release binary trusts no dev leaf signer");
    }

    /// The certificate the offline root ceremony actually minted, committed verbatim. A certificate is
    /// a public artifact, so committing one is safe; only the ceremony that produces it is restricted.
    /// This is the same file `sig.permaura.com` serves from `/health` as its own `key_id` and
    /// `cert_expires_at`, so the fixture is the production chain rather than a lookalike.
    fn committed_production_cert() -> IntermediateCert {
        serde_json::from_str(include_str!("../tests/fixtures/pmconn-int-2026b-cert.json"))
            .expect("the committed production intermediate cert must parse")
    }

    /// A fixed instant inside the committed certificate's validity window. The point of the fixture is
    /// the chain, not the clock, so the window is pinned rather than read from the host: a test that
    /// used the real time would start failing the day the certificate expires and would be reporting
    /// the calendar, not the pin.
    const INSIDE_PRODUCTION_CERT_WINDOW: i64 = 1_800_000_000_000;

    /// The one check that guards the pin's VALUE rather than its shape.
    ///
    /// Every other test here builds its own root, so swapping `ROOT_PUBKEYS` for another well-formed
    /// 32-byte key leaves them all green: the suite would still pass on a binary that trusts an
    /// attacker's root. This verifies a signature the real offline root produced, so substituted key
    /// material fails it. Proven by mutation rather than assumed: flipping one byte of the pinned
    /// base64 (still valid base64 of the right length) turns this red.
    #[test]
    fn the_pinned_production_root_signed_the_committed_intermediate_cert() {
        let cert = committed_production_cert();
        assert_eq!(
            cert.root_key_id, "pmconn-root-2026a",
            "the committed fixture must be signed by the pinned production root, not a dev one",
        );
        let int_vk = verify_cert(&cert, &pmconn_root_pubkeys(), INSIDE_PRODUCTION_CERT_WINDOW)
            .expect("the pinned production root must verify the certificate it signed");
        assert_eq!(
            b64(&int_vk.to_bytes()),
            cert.pubkey,
            "verification must return the intermediate key the certificate names",
        );
    }

    /// The negative half: a root that is well-formed but not the one that signed the fixture is
    /// refused. Without this the test above could pass for the wrong reason (an empty anchor set, say,
    /// would fail differently), and it is the shape a key substitution actually takes.
    #[test]
    fn a_substituted_root_cannot_verify_the_committed_cert() {
        let cert = committed_production_cert();
        let imposter = SigningKey::generate(&mut rand::rngs::OsRng);
        let roots = vec![("pmconn-root-2026a".to_string(), imposter.verifying_key())];
        let err = verify_cert(&cert, &roots, INSIDE_PRODUCTION_CERT_WINDOW)
            .expect_err("a root that did not sign this certificate must not verify it");
        assert!(err.contains("root signature invalid"), "{err}");
    }

    /// The gateway checks the window at install time, so the committed certificate stops admitting new
    /// signed connectors once it expires. This pins the date the chain has to be reissued by, in the
    /// one place a reader of this module will look. A substituted root turns this red too, for a
    /// different reason: the signature fails before the window is ever consulted.
    #[test]
    fn the_committed_cert_expires_and_the_expiry_is_enforced() {
        let cert = committed_production_cert();
        assert_eq!(
            cert.expires_at, 1_854_344_153_557,
            "pmconn-int-2026b expires 2028-10-05; reissuing it is an offline root ceremony",
        );
        let err = verify_cert(&cert, &pmconn_root_pubkeys(), cert.expires_at)
            .expect_err("an expired certificate must be refused");
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn v2_valid_chain_verifies() {
        let root = SigningKey::generate(&mut rand::rngs::OsRng);
        let int = SigningKey::generate(&mut rand::rngs::OsRng);
        let roots = vec![("root-a".to_string(), root.verifying_key())];
        let cert = make_cert(&root, "root-a", &int, "int-1", NOW - 1000, 90 * 86_400_000);
        let m = dev_manifest("acme");
        let sig = leaf_sig(&int, &m, 4);
        assert_eq!(
            verify_envelope(
                &m,
                4,
                Some(&sig),
                Some("int-1"),
                Some(&cert),
                &roots,
                &[],
                &Revocation::empty(),
                NOW
            )
            .unwrap(),
            Provenance::Signed {
                key_id: "int-1".to_string()
            },
        );
    }

    #[test]
    fn v2_expired_cert_rejected() {
        let root = SigningKey::generate(&mut rand::rngs::OsRng);
        let int = SigningKey::generate(&mut rand::rngs::OsRng);
        let roots = vec![("root-a".to_string(), root.verifying_key())];
        let cert = make_cert(&root, "root-a", &int, "int-1", NOW - 100_000, 1000); // expired well before NOW
        let m = dev_manifest("acme");
        let sig = leaf_sig(&int, &m, 1);
        let err = verify_envelope(
            &m,
            1,
            Some(&sig),
            Some("int-1"),
            Some(&cert),
            &roots,
            &[],
            &Revocation::empty(),
            NOW,
        )
        .unwrap_err();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn v2_cert_signed_by_untrusted_root_rejected() {
        let real_root = SigningKey::generate(&mut rand::rngs::OsRng);
        let fake_root = SigningKey::generate(&mut rand::rngs::OsRng);
        let int = SigningKey::generate(&mut rand::rngs::OsRng);
        let roots = vec![("root-a".to_string(), real_root.verifying_key())];
        // Cert claims root-a but is actually signed by the fake root.
        let cert = make_cert(&fake_root, "root-a", &int, "int-1", NOW - 1000, 86_400_000);
        let m = dev_manifest("acme");
        let sig = leaf_sig(&int, &m, 1);
        assert!(verify_envelope(
            &m,
            1,
            Some(&sig),
            Some("int-1"),
            Some(&cert),
            &roots,
            &[],
            &Revocation::empty(),
            NOW
        )
        .is_err());
    }

    #[test]
    fn v2_revoked_intermediate_key_rejected() {
        let root = SigningKey::generate(&mut rand::rngs::OsRng);
        let int = SigningKey::generate(&mut rand::rngs::OsRng);
        let roots = vec![("root-a".to_string(), root.verifying_key())];
        let cert = make_cert(&root, "root-a", &int, "int-1", NOW - 1000, 86_400_000);
        let m = dev_manifest("acme");
        let sig = leaf_sig(&int, &m, 1);
        // Root-signed revocation listing int-1.
        let list = signed_revocation(&root, "root-a", 1, &["int-1"], &[]);
        let rev = Revocation::verified(&list, &roots).unwrap();
        let err = verify_envelope(
            &m,
            1,
            Some(&sig),
            Some("int-1"),
            Some(&cert),
            &roots,
            &[],
            &rev,
            NOW,
        )
        .unwrap_err();
        assert!(err.contains("revoked"), "{err}");
    }

    #[test]
    fn v2_revoked_manifest_rejected_up_to_version() {
        let root = SigningKey::generate(&mut rand::rngs::OsRng);
        let int = SigningKey::generate(&mut rand::rngs::OsRng);
        let roots = vec![("root-a".to_string(), root.verifying_key())];
        let cert = make_cert(&root, "root-a", &int, "int-1", NOW - 1000, 86_400_000);
        let m = dev_manifest("acme");
        let list = signed_revocation(&root, "root-a", 1, &[], &[("acme", 5)]);
        let rev = Revocation::verified(&list, &roots).unwrap();
        // v5 revoked, v6 allowed.
        assert!(verify_envelope(
            &m,
            5,
            Some(&leaf_sig(&int, &m, 5)),
            Some("int-1"),
            Some(&cert),
            &roots,
            &[],
            &rev,
            NOW
        )
        .is_err());
        assert!(verify_envelope(
            &m,
            6,
            Some(&leaf_sig(&int, &m, 6)),
            Some("int-1"),
            Some(&cert),
            &roots,
            &[],
            &rev,
            NOW
        )
        .is_ok());
    }

    #[test]
    fn v2_tampered_leaf_under_valid_cert_rejected() {
        let root = SigningKey::generate(&mut rand::rngs::OsRng);
        let int = SigningKey::generate(&mut rand::rngs::OsRng);
        let roots = vec![("root-a".to_string(), root.verifying_key())];
        let cert = make_cert(&root, "root-a", &int, "int-1", NOW - 1000, 86_400_000);
        // Sign one manifest, present another.
        let sig = leaf_sig(&int, &dev_manifest("acme"), 1);
        assert!(verify_envelope(
            &dev_manifest("evil"),
            1,
            Some(&sig),
            Some("int-1"),
            Some(&cert),
            &roots,
            &[],
            &Revocation::empty(),
            NOW
        )
        .is_err());
    }

    /// Cross-language guard for the v2 CHAIN: a full envelope produced by the TS CA + signer
    /// (`pmconn-ca.ts issue-cert` + `sign-connector.ts --cert`) with the dev root/intermediate must
    /// verify against the pinned `pmconn-root-dev` root. Fails the moment the TS `certPreimage` or
    /// `canonical` drifts from the Rust `cert_preimage`/`canonicalize`.
    #[cfg(debug_assertions)]
    #[test]
    fn ts_ca_output_verifies_against_pinned_dev_root() {
        let envelope: serde_json::Value = serde_json::from_str(
            r#"{
              "manifest": { "id": "acme-crm", "name": "Acme CRM", "vertical": "crm",
                "base_url": "https://api.acme.example",
                "capabilities": [ { "id": "contacts.list", "method": "GET", "path": "/contacts", "description": "List contacts" } ] },
              "version": 5,
              "signature": "bCpJEq6AhKHLA9Ao5EeS4MZ6398O5WrgQF1Pl9G7axPrMuVPCGoq6DabhqmPxb5FEoepXiOpnAuoBcmksr1fBw==",
              "key_id": "pmconn-int-dev",
              "cert": {
                "key_id": "pmconn-int-dev",
                "pubkey": "990t0YGzWSZECychaE8wN08YYdJL5wJkU2ypMqitJ8I=",
                "issued_at": 1783000000000, "expires_at": 4936600000000,
                "root_key_id": "pmconn-root-dev",
                "root_sig": "erc4cfchh7j125JzeiY/jlN7EDjhZlkYZjt3IeUt9thW79Uf3oU8nouTcIAP+Ak8tKEJ3jUocjYD6pcDmNUFBQ==" },
              "envelope_version": 2 }"#,
        )
        .unwrap();
        let cert: IntermediateCert = serde_json::from_value(envelope["cert"].clone()).unwrap();
        let now = 1_783_000_100_000; // just after issued_at, well before expiry
        assert_eq!(
            verify_envelope(
                &envelope["manifest"],
                5,
                envelope["signature"].as_str(),
                envelope["key_id"].as_str(),
                Some(&cert),
                &pmconn_root_pubkeys(),
                &pmconn_pubkeys(),
                &Revocation::empty(),
                now,
            )
            .unwrap(),
            Provenance::Signed {
                key_id: "pmconn-int-dev".to_string()
            },
            "TS CA + signer v2 output must verify against the pinned dev root",
        );
    }

    /// Cross-language guard for REVOCATION: a revocation list signed by the TS CA (`pmconn-ca.ts
    /// sign-revocation`), from UNSORTED inputs, must verify in Rust. Guards the TS preimage (the list
    /// names and counts) and its byte-order sort against the Rust ones (a `localeCompare` mismatch
    /// would fail the revocation open). Signed with a throwaway test root, the seed of 32 bytes of
    /// 0x5a, since the dev root's secret is not in the repository.
    #[test]
    fn ts_signed_revocation_verifies_and_sorts_bytewise() {
        let list: RevocationList = serde_json::from_str(
            r#"{
              "revoked_key_ids": ["int-b", "int-a"],
              "revoked_manifests": [ { "id": "zeta", "up_to_version": 3 }, { "id": "alpha", "up_to_version": 9 } ],
              "issued_at": 1783000000000, "serial": 7, "root_key_id": "pmconn-root-test",
              "root_sig": "U0A9UkXg6BV1r/Wx9G8F6Q2rTqcFJ7gogwD1lqUqkqv1DJP8bdl654ueQ0zoZzCqlH543nW172FVSRvtzoXfAg==" }"#,
        )
        .unwrap();
        let roots = vec![("pmconn-root-test".to_string(), SigningKey::from_bytes(&[0x5a; 32]).verifying_key())];
        let rev = Revocation::verified(&list, &roots).expect("TS-signed revocation must verify");
        assert!(rev.is_key_revoked("int-a") && rev.is_key_revoked("int-b"));
        assert!(rev.is_manifest_revoked("alpha", 9) && !rev.is_manifest_revoked("alpha", 10));
        assert!(rev.is_manifest_revoked("zeta", 3));
    }

    #[test]
    fn forged_revocation_is_rejected_not_honoured() {
        let root = SigningKey::generate(&mut rand::rngs::OsRng);
        let attacker = SigningKey::generate(&mut rand::rngs::OsRng);
        let roots = vec![("root-a".to_string(), root.verifying_key())];
        // A revocation signed by an attacker (not the root) must fail verification, not silently take effect.
        let list = signed_revocation(&attacker, "root-a", 9, &["int-1"], &[]);
        assert!(Revocation::verified(&list, &roots).is_err());
    }

    /// Whoever carries a root-signed list must not be able to move an item from one list to the other and keep the signature: re-read as two key ids, a manifest revocation would vanish, and re-read as a manifest, a key revocation would.
    #[test]
    fn a_resplit_revocation_list_does_not_verify_under_the_same_signature() {
        let root = SigningKey::from_bytes(&[41; 32]);
        let roots = vec![("root-a".to_string(), root.verifying_key())];
        let resplit = |list: &RevocationList, keys: &[&str], mans: &[(&str, u32)]| RevocationList {
            revoked_key_ids: keys.iter().map(|k| k.to_string()).collect(),
            revoked_manifests: mans.iter().map(|(id, v)| RevokedManifest { id: id.to_string(), up_to_version: *v }).collect(),
            ..list.clone()
        };

        let manifest_revoked = signed_revocation(&root, "root-a", 3, &[], &[("1password", 7)]);
        let rev = Revocation::verified(&manifest_revoked, &roots).expect("the genuine list verifies");
        assert!(rev.is_manifest_revoked("1password", 7));
        let as_keys = resplit(&manifest_revoked, &["1password", "7"], &[]);
        assert!(Revocation::verified(&as_keys, &roots).is_err(), "the manifest revocation must not be re-read as two key ids");

        let key_revoked = signed_revocation(&root, "root-a", 4, &["0day", "1"], &[("stripe", 4)]);
        let rev = Revocation::verified(&key_revoked, &roots).expect("the genuine list verifies");
        assert!(rev.is_key_revoked("0day"));
        let as_manifest = resplit(&key_revoked, &[], &[("0day", 1), ("stripe", 4)]);
        assert!(Revocation::verified(&as_manifest, &roots).is_err(), "the key revocation must not be re-read as a manifest");
    }

    /// A root, a valid v2 chain under it, and a directly pinned leaf key, for the configured-list tests.
    struct Chain {
        root: SigningKey,
        roots: Vec<(String, VerifyingKey)>,
        int: SigningKey,
        cert: IntermediateCert,
        leaf: SigningKey,
        leaf_keys: Vec<(String, VerifyingKey)>,
    }

    fn chain() -> Chain {
        let root = SigningKey::from_bytes(&[51; 32]);
        let int = SigningKey::from_bytes(&[52; 32]);
        let leaf = SigningKey::from_bytes(&[53; 32]);
        let cert = make_cert(&root, "root-t", &int, "int-1", NOW - 1000, 90 * 86_400_000);
        Chain {
            roots: vec![("root-t".to_string(), root.verifying_key())],
            leaf_keys: vec![("leaf-1".to_string(), leaf.verifying_key())],
            root,
            int,
            cert,
            leaf,
        }
    }

    fn installs(rev: &Revocation, c: &Chain) -> (Result<Provenance, String>, Result<Provenance, String>) {
        let m = dev_manifest("acme");
        let v2 = verify_envelope(&m, 4, Some(&leaf_sig(&c.int, &m, 4)), Some("int-1"), Some(&c.cert), &c.roots, &[], rev, NOW);
        let v1 = verify_envelope(&m, 4, Some(&leaf_sig(&c.leaf, &m, 4)), Some("leaf-1"), None, &c.roots, &c.leaf_keys, rev, NOW);
        (v2, v1)
    }

    /// A configured list that cannot be verified must not leave the gateway trusting what the list might have revoked: no Permaura-signed manifest installs under it, and an unsigned one still installs as the operator's own.
    fn installs_nothing_signed(rev: &Revocation, c: &Chain, arm: &str) {
        let (v2, v1) = installs(rev, c);
        assert!(v2.is_err(), "{arm}: a v2 chain must not install: {v2:?}");
        assert!(v1.is_err(), "{arm}: nor a directly signed manifest: {v1:?}");
        let unsigned = verify_envelope(&dev_manifest("acme"), 4, None, None, None, &c.roots, &c.leaf_keys, rev, NOW);
        assert_eq!(unsigned, Ok(Provenance::User), "{arm}: an unsigned manifest is still the operator's own");
    }

    #[test]
    fn an_unreadable_configured_revocation_list_installs_nothing_signed() {
        let c = chain();
        let missing = std::env::temp_dir().join(format!("permaura-no-such-revocation-{}.json", std::process::id()));
        installs_nothing_signed(&revocation_state(Some(missing.to_str().unwrap()), &c.roots), &c, "unreadable");
    }

    #[test]
    fn a_configured_revocation_list_that_is_not_json_installs_nothing_signed() {
        let c = chain();
        installs_nothing_signed(&revocation_state(Some("{ this is not a revocation list"), &c.roots), &c, "not JSON");
    }

    #[test]
    fn a_configured_revocation_list_with_a_bad_signature_installs_nothing_signed() {
        let c = chain();
        let carrier = SigningKey::from_bytes(&[54; 32]);
        let list = serde_json::to_string(&signed_revocation(&carrier, "root-t", 2, &[], &[])).unwrap();
        installs_nothing_signed(&revocation_state(Some(&list), &c.roots), &c, "bad signature");
    }

    #[test]
    fn a_configured_v1_revocation_list_installs_nothing_signed() {
        let c = chain();
        let mut v1 = Vec::from(&b"permaura-pmconn/v1/revocation"[..]);
        lp(&mut v1, b"2");
        lp(&mut v1, NOW.to_string().as_bytes());
        lp(&mut v1, b"root-t");
        let list = RevocationList {
            revoked_key_ids: Vec::new(),
            revoked_manifests: Vec::new(),
            issued_at: NOW,
            serial: 2,
            root_key_id: "root-t".into(),
            root_sig: b64(&c.root.sign(&v1).to_bytes()),
        };
        let list = serde_json::to_string(&list).unwrap();
        installs_nothing_signed(&revocation_state(Some(&list), &c.roots), &c, "v1 list");
    }

    #[test]
    fn a_verified_or_absent_revocation_list_still_installs_what_it_does_not_revoke() {
        let c = chain();
        let genuine = serde_json::to_string(&signed_revocation(&c.root, "root-t", 3, &["int-9"], &[("other", 1)])).unwrap();
        for (arm, raw) in [("verified", Some(genuine.as_str())), ("unset", None), ("blank", Some("  "))] {
            let (v2, v1) = installs(&revocation_state(raw, &c.roots), &c);
            assert!(v2.is_ok(), "{arm}: {v2:?}");
            assert!(v1.is_ok(), "{arm}: {v1:?}");
        }
    }

    #[test]
    fn an_unverifiable_configured_list_names_the_variable_and_the_reason() {
        let c = chain();
        let carrier = serde_json::to_string(&signed_revocation(&SigningKey::from_bytes(&[54; 32]), "root-t", 2, &[], &[])).unwrap();
        let unknown_root = serde_json::to_string(&signed_revocation(&c.root, "root-x", 2, &[], &[])).unwrap();
        let missing = std::env::temp_dir().join(format!("permaura-no-such-revocation-{}.json", std::process::id()));
        for (raw, reason) in [
            (missing.to_str().unwrap(), "cannot be read"),
            ("{ this is not a revocation list", "is not a revocation list"),
            (carrier.as_str(), "root signature invalid"),
            (unknown_root.as_str(), "unknown root key"),
        ] {
            let why = revocation_config(Some(raw), &c.roots).expect_err(reason);
            assert!(why.starts_with("PERMAURA_PMCONN_REVOCATION ") && why.contains(reason), "{why}");
        }
    }

    #[test]
    fn a_directly_signed_manifest_is_refused_when_the_list_revokes_it() {
        let c = chain();
        let list = signed_revocation(&c.root, "root-t", 4, &[], &[("acme", 4)]);
        let rev = Revocation::verified(&list, &c.roots).unwrap();
        let (v2, v1) = installs(&rev, &c);
        assert!(v2.unwrap_err().contains("revoked"));
        assert!(v1.unwrap_err().contains("revoked"), "the v1 path consults the list too");
    }

    /// A small-order root with `R = identity, s = 0` would sign every cert, list and leaf under a non-strict verify. Roots are pinned, so this pins the primitive rather than a path.
    #[test]
    fn a_small_order_key_verifies_no_cert_revocation_or_leaf() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).unwrap();
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let forged = b64(&forged);
        let roots = vec![("root-w".to_string(), weak)];

        let int = SigningKey::from_bytes(&[42; 32]);
        let cert = IntermediateCert {
            key_id: "int-w".into(),
            pubkey: b64(int.verifying_key().as_bytes()),
            issued_at: NOW - 1,
            expires_at: NOW + 86_400_000,
            root_key_id: "root-w".into(),
            root_sig: forged.clone(),
        };
        assert!(verify_cert(&cert, &roots, NOW).is_err(), "a weak root must certify nothing");

        let list = RevocationList {
            revoked_key_ids: Vec::new(),
            revoked_manifests: Vec::new(),
            issued_at: NOW,
            serial: 1,
            root_key_id: "root-w".into(),
            root_sig: forged.clone(),
        };
        assert!(Revocation::verified(&list, &roots).is_err(), "nor sign a revocation list");

        let leaf_keys = vec![("leaf-w".to_string(), weak)];
        assert!(verify(&dev_manifest("acme"), 1, Some(&forged), Some("leaf-w"), &leaf_keys).is_err(), "nor a manifest");
    }

    fn signed_revocation(
        root: &SigningKey,
        root_id: &str,
        serial: u64,
        keys: &[&str],
        mans: &[(&str, u32)],
    ) -> RevocationList {
        let revoked_key_ids: Vec<String> = keys.iter().map(|s| s.to_string()).collect();
        let revoked_manifests: Vec<RevokedManifest> = mans
            .iter()
            .map(|(id, v)| RevokedManifest {
                id: id.to_string(),
                up_to_version: *v,
            })
            .collect();
        let mut list = RevocationList {
            revoked_key_ids,
            revoked_manifests,
            issued_at: NOW,
            serial,
            root_key_id: root_id.to_string(),
            root_sig: String::new(),
        };
        list.root_sig = b64(&root.sign(&revocation_preimage(&list)).to_bytes());
        list
    }

    #[test]
    fn unsigned_manifest_is_user_provenance() {
        assert_eq!(
            verify(&dev_manifest("acme"), 1, None, None, &pmconn_pubkeys()).unwrap(),
            Provenance::User,
        );
    }

    #[test]
    fn valid_signature_verifies_and_is_signed() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let allowed = vec![("test-key".to_string(), sk.verifying_key())];
        let manifest = dev_manifest("acme");
        let sig = base64::engine::general_purpose::STANDARD
            .encode(sk.sign(&canonical_bytes(&manifest, 3)).to_bytes());
        assert_eq!(
            verify(&manifest, 3, Some(&sig), Some("test-key"), &allowed).unwrap(),
            Provenance::Signed {
                key_id: "test-key".to_string()
            },
        );
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let allowed = vec![("test-key".to_string(), sk.verifying_key())];
        let sig = base64::engine::general_purpose::STANDARD.encode(
            sk.sign(&canonical_bytes(&dev_manifest("acme"), 1))
                .to_bytes(),
        );
        // Same signature, different manifest body.
        assert!(verify(
            &dev_manifest("evil"),
            1,
            Some(&sig),
            Some("test-key"),
            &allowed
        )
        .is_err());
    }

    #[test]
    fn unknown_key_id_is_rejected() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let manifest = dev_manifest("acme");
        let sig = base64::engine::general_purpose::STANDARD
            .encode(sk.sign(&canonical_bytes(&manifest, 1)).to_bytes());
        assert!(verify(&manifest, 1, Some(&sig), Some("nope"), &pmconn_pubkeys()).is_err());
    }

    #[test]
    fn an_integral_number_prints_as_javascript_prints_it_however_it_was_authored() {
        for (authored, js) in [
            ("100", "100"),
            ("100.0", "100"),
            ("1e2", "100"),
            ("-0.0", "0"),
            ("-42.0", "-42"),
            ("9007199254740991.0", "9007199254740991"),
            ("0.5", "0.5"),
        ] {
            let manifest: serde_json::Value = serde_json::from_str(&format!(r#"{{"x-n":{authored}}}"#)).unwrap();
            assert_eq!(
                String::from_utf8(canonical_bytes(&manifest, 1)).unwrap(),
                format!(r#"{{"manifest":{{"x-n":{js}}},"version":1}}"#),
                "authored {authored}"
            );
        }
    }

    #[test]
    fn canonical_bytes_are_stable_and_key_order_independent() {
        let a = serde_json::json!({ "b": 1, "a": [ { "y": 2, "x": 1 } ] });
        let b = serde_json::json!({ "a": [ { "x": 1, "y": 2 } ], "b": 1 });
        assert_eq!(canonical_bytes(&a, 1), canonical_bytes(&b, 1));
    }

    /// Cross-language guard: a FROZEN envelope produced by `scripts/sign-connector.ts` with the dev
    /// key must verify against the pinned dev pubkey. This catches drift in the RUST `canonicalize`
    /// (any change that breaks a known-good TS signature fails here). It does NOT re-run the TS
    /// signer, so a change to the TS `canonical()` must be caught by regenerating this fixture: the
    /// dev-key round-trip in `scripts/` (and the shared algorithm doc) is the other half of the guard.
    #[cfg(debug_assertions)]
    #[test]
    fn ts_signer_output_verifies_against_pinned_dev_key() {
        let envelope_json = r#"{
          "manifest": { "id": "acme-crm", "name": "Acme CRM", "vertical": "crm",
            "base_url": "https://api.acme.example",
            "capabilities": [ { "id": "contacts.list", "method": "GET", "path": "/contacts", "description": "List contacts" } ] },
          "version": 5,
          "signature": "sga2lTbUdqeS7jVDpcO3Nn0b/pqb63dlkiX0p94eAU082SyCqD9cN1Sq23gVQ1D+an1HtyMdyMTuYRhrNU+4Dg==",
          "key_id": "pmconn-dev" }"#;
        let env: serde_json::Value = serde_json::from_str(envelope_json).unwrap();
        assert_eq!(
            verify(
                &env["manifest"],
                env["version"].as_u64().unwrap() as u32,
                env["signature"].as_str(),
                env["key_id"].as_str(),
                &pmconn_pubkeys(),
            )
            .unwrap(),
            Provenance::Signed {
                key_id: "pmconn-dev".to_string()
            },
            "TS signer output must verify against the pinned dev pubkey",
        );
    }
}
