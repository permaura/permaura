//! The portable **vault bundle** envelope: one sealed artefact a customer holds themselves.
//!
//! This module owns only the *envelope*: sealing an opaque payload under a customer-chosen
//! passphrase, and opening it again. The payload's schema (connections, policies, grants,
//! capabilities, secrets) belongs to the gateway, which has the domain types; keeping it opaque here
//! is what lets `permaura-core` stay dependency-light and lets the payload evolve without touching
//! crypto.
//!
//! ## Why the whole payload is sealed, not each secret
//!
//! A per-secret seal leaves connection ids, host allowlists, capability specs and policy rules in
//! cleartext beside the ciphertext. [`crate::crypto::seal`] authenticates only what it encrypts under
//! a **fixed** AAD constant, so anything outside a sealed blob is unauthenticated: an attacker who
//! can edit the file could repoint a capability's base URL, widen `allowed_hosts`, clear a
//! connection's kill switch, or move one secret's sealed blob onto another secret's id, and every
//! individual envelope would still open cleanly. Sealing the payload as a single blob makes the whole
//! artefact tamper-evident with the crypto that already exists, and it costs one Argon2 derivation
//! instead of one per secret.
//!
//! ## Threat model note on the KDF
//!
//! The vault's own KEK is a random 256-bit value, so [`KdfParams::generate`]'s interactive profile is
//! ample there. A bundle is different in kind: the passphrase is human-chosen and the file is held by
//! the customer (and potentially by an attacker) indefinitely, with unlimited offline guesses. So
//! bundles use [`bundle_kdf_params`], which is deliberately far more expensive. The vault default is
//! left alone because it runs on the invoke hot path.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{open, seal_with_params, Cipher, KdfParams, SealedSecret};
use crate::error::{PermauraError, Result};

/// The `format` discriminator written into every bundle. A file without exactly this string is not
/// a Permaura vault bundle and is refused before any key derivation happens.
pub const BUNDLE_FORMAT: &str = "permaura.vault.bundle";

/// The bundle schema version this build writes.
pub const BUNDLE_VERSION: u32 = 1;

/// Argon2id memory cost for a bundle, in KiB (256 MiB).
///
/// Roughly thirteen times the vault default. The vault seals under a random 256-bit KEK where cost
/// buys nothing; a bundle seals under a human passphrase in a file an attacker may hold forever,
/// where it is the only thing standing between a weak passphrase and every credential the customer
/// owns.
const BUNDLE_MEM_COST_KIB: u32 = 256 * 1024;
/// Argon2id time cost (passes) for a bundle.
const BUNDLE_TIME_COST: u32 = 4;
/// Argon2id parallelism for a bundle. One lane keeps derivation deterministic across machines.
const BUNDLE_PARALLELISM: u32 = 1;

/// Lowest memory cost we will open a bundle at, in KiB (32 MiB).
///
/// A bundle claiming less than this was never meaningfully protected, so opening it silently would
/// let a downgraded file masquerade as a safe one. Refuse and say so.
const MIN_OPEN_MEM_COST_KIB: u32 = 32 * 1024;
/// Highest memory cost we will open a bundle at, in KiB: the export setting, 256 MiB.
///
/// `kdf_params` arrives from an untrusted file and is fed straight to Argon2, which allocates that
/// much memory. A hosted worker has 512 MiB, so anything above what this gateway's own export uses
/// is a request to end the worker, and no bundle this code wrote needs more.
const MAX_OPEN_MEM_COST_KIB: u32 = BUNDLE_MEM_COST_KIB;
/// Highest Argon2 time cost we will open a bundle at, the CPU-burn half of the same denial of service.
const MAX_OPEN_TIME_COST: u32 = 16;
/// Highest Argon2 parallelism we will open a bundle at.
const MAX_OPEN_PARALLELISM: u32 = 8;

/// KDF parameters for a new bundle: a fresh random salt at bundle-grade cost.
pub fn bundle_kdf_params() -> KdfParams {
    KdfParams {
        salt: KdfParams::generate().salt,
        mem_cost_kib: BUNDLE_MEM_COST_KIB,
        time_cost: BUNDLE_TIME_COST,
        parallelism: BUNDLE_PARALLELISM,
    }
}

/// Where a bundle came from. Descriptive only, never trusted by the importer for any decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BundleSource {
    /// The exporting gateway's id, when it has one.
    #[serde(default)]
    pub gateway_id: String,
    /// `hosted` or `self-run`, as the exporter understood itself.
    #[serde(default)]
    pub mode: String,
}

/// The cleartext header of a bundle, plus the single sealed blob holding everything else.
///
/// Only the header is readable without the passphrase, and it is deliberately free of anything
/// describing the customer's estate: no connection names, no hosts, no counts. `created_at_ms` and
/// `source` are the concession, and they are copied *inside* the seal too so a rewrite of either is
/// detected on open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultBundle {
    /// Always [`BUNDLE_FORMAT`].
    pub format: String,
    /// The schema version of the sealed payload.
    pub version: u32,
    /// Unix-millisecond time the bundle was produced.
    pub created_at_ms: i64,
    /// Where it came from. Informational.
    #[serde(default)]
    pub source: BundleSource,
    /// The whole payload, sealed under the customer's passphrase.
    pub sealed: SealedSecret,
}

/// The header fields repeated inside the seal, so tampering with the cleartext header is detected.
///
/// [`crate::crypto::seal`] authenticates under a fixed AAD constant and cannot bind extra context,
/// so binding is done here instead: on open, these must equal what the cleartext header claims.
/// Without this an attacker could rewrite `version` to steer the importer down a different parsing
/// path, or restamp `source` to make a bundle look like it came from a gateway the operator trusts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SealedHeader {
    format: String,
    version: u32,
    created_at_ms: i64,
    source: BundleSource,
}

/// The sealed blob's plaintext as it is written: the bound header plus the caller's payload, serialized
/// in place rather than through an intermediate tree.
#[derive(Serialize)]
struct SealedBody<'a, P: ?Sized> {
    header: SealedHeader,
    /// The gateway's payload, verbatim. Opaque to this crate.
    payload: &'a P,
}

/// The header half of the sealed blob as it is read back; the payload is skipped without copying any of it.
#[derive(Deserialize)]
struct SealedHeaderOnly {
    header: SealedHeader,
}

/// The payload half of the sealed blob as it is read back.
#[derive(Deserialize)]
struct SealedPayloadOnly<T> {
    payload: T,
}

/// An opened bundle: its plaintext, in a buffer wiped when this drops, with the sealed header already
/// checked against the cleartext one. [`Self::payload`] reads the caller's type straight from it.
///
/// There is no tree of the payload in between, which is the point: a `serde_json::Value` holds every
/// credential in the estate in strings nothing wipes, and the caller could not wipe them either.
pub struct OpenedBundle(Zeroizing<Vec<u8>>);

/// A type an [`OpenedBundle`]'s payload may be read as. The caller's type decides how each secret in it is
/// held, so this is a deliberate opt-in: a crate implements it for a payload type of its own, and the orphan
/// rule keeps anyone outside this crate from implementing it for `serde_json::Value`, whose strings nothing
/// wipes.
pub trait TypedPayload: DeserializeOwned {}

#[cfg(test)]
impl TypedPayload for serde_json::Value {}

impl OpenedBundle {
    /// Read the payload as `T`. A string field reaches `T`'s deserializer borrowed from the wiped
    /// plaintext when it holds no JSON escape, so a type that copies it into a wiping buffer of its own
    /// (as [`crate::SecretString`] does) leaves no other copy behind.
    pub fn payload<T: TypedPayload>(&self) -> Result<T> {
        let body: SealedPayloadOnly<T> = serde_json::from_slice(&self.0).map_err(PermauraError::from)?;
        Ok(body.payload)
    }
}

impl std::fmt::Debug for OpenedBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenedBundle([redacted; {} bytes])", self.0.len())
    }
}

impl zeroize::ZeroizeOnDrop for OpenedBundle {}

#[cfg(test)]
#[allow(dead_code)]
fn opened_bundle_keeps_its_plaintext_in_a_wiping_type(b: &OpenedBundle) -> &Zeroizing<Vec<u8>> {
    &b.0
}

/// Seal `payload` into a bundle under `passphrase`, using the standard [`bundle_kdf_params`].
///
/// `payload` is whatever the caller wants to carry; this crate neither inspects nor validates it.
/// `created_at_ms` is supplied rather than read from the clock so the function stays deterministic
/// and testable.
///
/// The passphrase is borrowed and never copied, stored or logged.
pub fn seal_bundle<P: Serialize>(
    passphrase: &[u8],
    payload: P,
    created_at_ms: i64,
    source: BundleSource,
) -> Result<VaultBundle> {
    seal_bundle_with_params(passphrase, payload, created_at_ms, source, bundle_kdf_params())
}

/// Seal a bundle with caller-chosen KDF parameters, mirroring [`crate::crypto::seal_with_params`].
///
/// Export always goes through [`seal_bundle`] and the deliberately expensive default; this overload
/// exists so a test can seal at the open floor without paying a quarter-gigabyte KDF per case. A
/// bundle sealed below [`open_bundle`]'s accepted floor still fails to open, so weak parameters
/// cannot produce a bundle that quietly reads back as protected.
pub fn seal_bundle_with_params<P: Serialize>(
    passphrase: &[u8],
    payload: P,
    created_at_ms: i64,
    source: BundleSource,
    params: KdfParams,
) -> Result<VaultBundle> {
    if passphrase.is_empty() {
        return Err(PermauraError::InvalidInput(
            "a vault bundle passphrase cannot be empty".into(),
        ));
    }
    let header = SealedHeader {
        format: BUNDLE_FORMAT.to_string(),
        version: BUNDLE_VERSION,
        created_at_ms,
        source: source.clone(),
    };
    // It holds every credential in the estate, so it is written straight into a buffer that wipes each
    // block it outgrows, and is wiped itself once sealed.
    let body = crate::secret::to_json(&SealedBody { header, payload: &payload }).map_err(PermauraError::from)?;
    let sealed = seal_with_params(Cipher::Aes256Gcm, passphrase, &body, params)?;
    Ok(VaultBundle {
        format: BUNDLE_FORMAT.to_string(),
        version: BUNDLE_VERSION,
        created_at_ms,
        source,
        sealed,
    })
}

/// Reject KDF parameters that came from an untrusted file before handing them to Argon2.
///
/// The ceiling is a denial-of-service guard (Argon2 allocates `mem_cost_kib`); the floor refuses a
/// bundle whose protection was never real. Both fail loudly rather than being silently adjusted:
/// clamping a hostile value would open a file under parameters it was not sealed with, which just
/// fails later with a confusing error.
fn check_kdf_params(p: &KdfParams) -> Result<()> {
    if p.mem_cost_kib > MAX_OPEN_MEM_COST_KIB
        || p.time_cost > MAX_OPEN_TIME_COST
        || p.parallelism > MAX_OPEN_PARALLELISM
    {
        return Err(PermauraError::InvalidInput(format!(
            "bundle KDF parameters exceed the accepted maximum \
             (memory {} KiB > {MAX_OPEN_MEM_COST_KIB}, or time {} > {MAX_OPEN_TIME_COST}, \
             or parallelism {} > {MAX_OPEN_PARALLELISM}): refusing to open",
            p.mem_cost_kib, p.time_cost, p.parallelism
        )));
    }
    if p.mem_cost_kib < MIN_OPEN_MEM_COST_KIB {
        return Err(PermauraError::InvalidInput(format!(
            "bundle KDF memory cost {} KiB is below the minimum {MIN_OPEN_MEM_COST_KIB} KiB: \
             this bundle was not sealed with meaningful protection and will not be opened",
            p.mem_cost_kib
        )));
    }
    Ok(())
}

/// Open a bundle, returning its plaintext for [`OpenedBundle::payload`] to read.
///
/// Checks the format discriminator and the parameter bounds *before* deriving anything, so a
/// file outside the bounds costs nothing; a file within them still costs up to one 256 MiB,
/// 16-pass Argon2id derivation per attempt. After opening, the header sealed inside must match the
/// cleartext header, which is what makes the unencrypted part of the file tamper-evident.
///
/// A wrong passphrase and a tampered ciphertext both surface as [`PermauraError::Crypto`] with the
/// same message, matching [`crate::crypto::open`]'s deliberate refusal to distinguish them. A header
/// that disagrees with the seal is [`PermauraError::Tampered`] instead: it is only reachable once the
/// passphrase has already opened the file, so naming it gives an attacker nothing and tells the person
/// holding a modified file the one thing they need to know.
pub fn open_bundle(bundle: &VaultBundle, passphrase: &[u8]) -> Result<OpenedBundle> {
    if bundle.format != BUNDLE_FORMAT {
        return Err(PermauraError::InvalidInput(format!(
            "not a Permaura vault bundle: expected format '{BUNDLE_FORMAT}', found '{}'",
            bundle.format
        )));
    }
    if bundle.version > BUNDLE_VERSION {
        return Err(PermauraError::InvalidInput(format!(
            "bundle version {} is newer than this build understands (max {BUNDLE_VERSION}): \
             upgrade the gateway before importing",
            bundle.version
        )));
    }
    check_kdf_params(&bundle.sealed.kdf_params)?;

    let plaintext = open(&bundle.sealed, passphrase)?;
    let body: SealedHeaderOnly = serde_json::from_slice(&plaintext).map_err(PermauraError::from)?;

    if body.header.format != bundle.format
        || body.header.version != bundle.version
        || body.header.created_at_ms != bundle.created_at_ms
        || body.header.source != bundle.source
    {
        return Err(PermauraError::Tampered(
            "the bundle's cleartext header does not match the contents sealed inside it, so the file \
             has been modified since it was written"
                .into(),
        ));
    }
    Ok(OpenedBundle(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A hosted worker has 512 MiB. A bundle claiming more than the export setting could only have come
    /// from something other than this gateway's export, and opening it is a request to spend the worker.
    #[test]
    fn a_bundle_claiming_more_memory_than_an_export_uses_is_refused_before_derivation() {
        let claim = |mem_cost_kib| KdfParams { mem_cost_kib, ..bundle_kdf_params() };
        assert!(check_kdf_params(&claim(BUNDLE_MEM_COST_KIB)).is_ok(), "an export's own setting opens");
        for over in [BUNDLE_MEM_COST_KIB + 1, 512 * 1024, 1024 * 1024] {
            assert!(check_kdf_params(&claim(over)).is_err(), "{over} KiB must be refused");
        }
    }

    /// Cheap-but-in-bounds params so tests stay fast without disabling the bounds check.
    fn fast_bundle(passphrase: &[u8], payload: serde_json::Value) -> VaultBundle {
        fast_bundle_at(passphrase, payload, 1_754_500_000_000)
    }

    fn fast_bundle_at(passphrase: &[u8], payload: serde_json::Value, at: i64) -> VaultBundle {
        let mut b = seal_bundle(passphrase, payload, at, source()).unwrap();
        // Re-seal at the floor so the suite does not pay 256 MiB per case.
        let body = crate::secret::to_json(&SealedBody {
            header: SealedHeader {
                format: b.format.clone(),
                version: b.version,
                created_at_ms: b.created_at_ms,
                source: b.source.clone(),
            },
            payload: &open_bundle(&b, passphrase).unwrap().payload::<serde_json::Value>().unwrap(),
        })
        .unwrap();
        let params = KdfParams {
            salt: KdfParams::generate().salt,
            mem_cost_kib: MIN_OPEN_MEM_COST_KIB,
            time_cost: 1,
            parallelism: 1,
        };
        b.sealed = seal_with_params(Cipher::Aes256Gcm, passphrase, &body, params).unwrap();
        b
    }

    fn source() -> BundleSource {
        BundleSource { gateway_id: "gw_test".into(), mode: "hosted".into() }
    }

    fn payload() -> serde_json::Value {
        json!({
            "connections": [{ "id": "braintree_production", "connector": "braintree" }],
            "secrets": [{ "id": "sec_braintree_prod", "value": "bt_live_PRIVATE_KEY_9931" }],
        })
    }

    #[test]
    fn round_trips_the_payload() {
        let pass = b"correct horse battery staple";
        let bundle = fast_bundle(pass, payload());
        assert_eq!(open_bundle(&bundle, pass).unwrap().payload::<serde_json::Value>().unwrap(), payload());
    }

    #[test]
    fn serialized_bundle_contains_no_plaintext_credential() {
        let bundle = fast_bundle(b"pass", payload());
        let json = serde_json::to_string(&bundle).unwrap();
        // Acceptance criterion 2, asserted on the artefact itself.
        assert!(!json.contains("bt_live_PRIVATE_KEY_9931"));
        // And nothing about the estate leaks through the cleartext header either.
        assert!(!json.contains("braintree_production"));
        assert!(!json.contains("sec_braintree_prod"));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let bundle = fast_bundle(b"right", payload());
        let err = open_bundle(&bundle, b"wrong").unwrap_err();
        assert!(matches!(err, PermauraError::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn empty_passphrase_is_refused_at_seal() {
        let err = seal_bundle(b"", payload(), 0, source()).unwrap_err();
        assert!(matches!(err, PermauraError::InvalidInput(_)));
    }

    #[test]
    fn a_rewritten_cleartext_header_is_detected() {
        let pass = b"pass";
        let mut bundle = fast_bundle(pass, payload());
        // The attack the sealed header exists to stop: restamp provenance without the passphrase.
        bundle.source.gateway_id = "gw_trusted".into();
        let err = open_bundle(&bundle, pass).unwrap_err();
        assert!(matches!(err, PermauraError::Tampered(_)), "got {err:?}");
    }

    #[test]
    fn a_rewritten_created_at_is_detected() {
        let pass = b"pass";
        let mut bundle = fast_bundle(pass, payload());
        bundle.created_at_ms += 1;
        let err = open_bundle(&bundle, pass).unwrap_err();
        assert!(matches!(err, PermauraError::Tampered(_)), "got {err:?}");
    }

    /// The whole point of the split: a modified file and a mistyped passphrase must not read alike.
    #[test]
    fn tampering_and_a_wrong_passphrase_are_different_errors() {
        let bundle = fast_bundle(b"pass", payload());
        assert!(matches!(open_bundle(&bundle, b"not the pass").unwrap_err(), PermauraError::Crypto(_)));

        let mut edited = fast_bundle(b"pass", payload());
        edited.source.mode = "self-run".into();
        assert!(matches!(open_bundle(&edited, b"pass").unwrap_err(), PermauraError::Tampered(_)));
    }

    #[test]
    fn a_foreign_format_is_refused_before_any_derivation() {
        let pass = b"pass";
        let mut bundle = fast_bundle(pass, payload());
        bundle.format = "something.else".into();
        let err = open_bundle(&bundle, pass).unwrap_err();
        assert!(matches!(err, PermauraError::InvalidInput(_)));
    }

    #[test]
    fn a_newer_version_is_refused_rather_than_misparsed() {
        let pass = b"pass";
        let mut bundle = fast_bundle(pass, payload());
        bundle.version = BUNDLE_VERSION + 1;
        let err = open_bundle(&bundle, pass).unwrap_err();
        assert!(matches!(err, PermauraError::InvalidInput(_)));
    }

    #[test]
    fn a_hostile_memory_cost_is_refused_instead_of_allocated() {
        let pass = b"pass";
        let mut bundle = fast_bundle(pass, payload());
        // 8 GiB: without the ceiling this line OOM-kills the importing gateway.
        bundle.sealed.kdf_params.mem_cost_kib = 8 * 1024 * 1024;
        let err = open_bundle(&bundle, pass).unwrap_err();
        assert!(matches!(err, PermauraError::InvalidInput(_)), "got {err:?}");
    }

    #[test]
    fn a_downgraded_memory_cost_is_refused() {
        let pass = b"pass";
        let mut bundle = fast_bundle(pass, payload());
        bundle.sealed.kdf_params.mem_cost_kib = 8;
        let err = open_bundle(&bundle, pass).unwrap_err();
        assert!(matches!(err, PermauraError::InvalidInput(_)), "got {err:?}");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let pass = b"pass";
        let mut bundle = fast_bundle(pass, payload());
        bundle.sealed.ciphertext[0] ^= 0x01;
        assert!(open_bundle(&bundle, pass).is_err());
    }

    /// Grafting one bundle's sealed blob onto another's header is rejected, because the header is
    /// bound inside the seal.
    ///
    /// Residual, and inherent: if every bound field matches (same gateway, same millisecond), the
    /// two blobs are genuinely interchangeable, and wholesale replacement of the file with an
    /// earlier bundle from the same gateway (a rollback) cannot be detected from the file alone.
    /// Import previews the contents for exactly this reason: the operator sees what they are about
    /// to write.
    #[test]
    fn a_sealed_blob_from_another_bundle_does_not_open_in_this_one() {
        let pass = b"pass";
        let a = fast_bundle_at(pass, payload(), 1_754_500_000_000);
        let mut b = fast_bundle_at(pass, json!({ "connections": [], "secrets": [] }), 1_754_600_000_000);
        // Same passphrase, so the DEK unwraps; the bound header is what rejects the graft.
        b.sealed = a.sealed.clone();
        let err = open_bundle(&b, pass).unwrap_err();
        assert!(matches!(err, PermauraError::Tampered(_)), "got {err:?}");
    }

    #[test]
    fn bundle_kdf_is_far_stronger_than_the_vault_default() {
        let vault = KdfParams::generate();
        let bundle = bundle_kdf_params();
        assert!(
            bundle.mem_cost_kib > vault.mem_cost_kib * 8,
            "a customer-held file needs materially more than the interactive vault profile"
        );
        assert!(bundle.time_cost > vault.time_cost);
        assert_eq!(bundle.salt.len(), 16);
        assert_ne!(bundle_kdf_params().salt, bundle_kdf_params().salt, "salt must be fresh per bundle");
    }

    #[test]
    fn the_real_bundle_profile_round_trips() {
        // The fast path above swaps the KDF; prove the shipped parameters actually work end to end.
        let pass = b"a real passphrase";
        let bundle = seal_bundle(pass, payload(), 1_754_500_000_000, source()).unwrap();
        assert_eq!(bundle.sealed.kdf_params.mem_cost_kib, BUNDLE_MEM_COST_KIB);
        assert_eq!(open_bundle(&bundle, pass).unwrap().payload::<serde_json::Value>().unwrap(), payload());
    }
}
