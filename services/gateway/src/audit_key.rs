//! The audit chain's public key, as this gateway reports it to an authenticated caller.
//!
//! WHY A CALLER NEEDS IT. The chain verifies under the key in the store, so anyone who can rewrite the
//! store can re-sign a rewritten history under a key of their own and every verification here still
//! passes. Nothing inside the store can catch that. What can is a copy of the key held somewhere
//! the store cannot reach: the control plane records the key the first time it sees this gateway report
//! it, and compares every later report against that record. This module is the reporting half; the
//! comparison lives with whoever holds the pin.
//!
//! The report is the key the store actually loaded and signs with, never a configured or remembered
//! value, because a report that could disagree with the signing key would let a substituted key pass the
//! very comparison it exists for.
//!
//! THE FINGERPRINT IS ITS OWN SCHEME. It is SHA-256 over the 32 raw key bytes, full length, lowercase
//! hex. It is deliberately not [`crate::service::key_fingerprint`], which hashes the base64 text of an
//! APPROVER key and truncates to 64 bits for display and ticket binding: a pin is compared against a
//! key an attacker chooses, so it needs the full digest, and the two must never be mistaken for one
//! another, which a different length and a different name make hard to do.

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::store::Store;

/// The signature scheme the audit chain is signed with, named in the report so a verifier does not
/// have to assume it.
pub const ALGORITHM: &str = "ed25519";

/// SHA-256 of the raw 32-byte verifying key, lowercase hex, 64 characters.
pub fn fingerprint(verifying_key: &[u8; 32]) -> String {
    Sha256::digest(verifying_key).iter().map(|b| format!("{b:02x}")).collect()
}

/// The `audit_key` object every authenticated audit surface carries.
pub fn report(verifying_key: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "algorithm": ALGORITHM,
        "public_key": base64::engine::general_purpose::STANDARD.encode(verifying_key),
        "fingerprint": fingerprint(verifying_key),
    })
}

/// [`report`] for the key `store` signs with, or `null` when it cannot be read.
///
/// `null` rather than an error: the documents this rides on answer other questions too, and a missing
/// key is a reason for the pin holder to say "not reported", which it already has to handle for every
/// gateway built before this field existed.
pub fn report_for(store: &dyn Store) -> serde_json::Value {
    match store.audit_verifying_key() {
        Ok(key) => report(&key),
        Err(e) => {
            tracing::warn!(error = %e, "could not read the audit verifying key to report it");
            serde_json::Value::Null
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produced by `ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key()`. The web pins the
    /// same vector, so a change to either side's scheme fails a test on both.
    const KEY_B64: &str = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";
    const KEY_FINGERPRINT: &str = "fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889";

    fn key() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
    }

    #[test]
    fn the_report_names_the_key_and_its_full_digest() {
        let report = report(&key());
        assert_eq!(report["algorithm"], "ed25519");
        assert_eq!(report["public_key"], KEY_B64);
        assert_eq!(report["fingerprint"], KEY_FINGERPRINT);
    }

    #[test]
    fn the_digest_is_over_the_key_bytes_not_the_base64_text() {
        let over_bytes = fingerprint(&key());
        let over_text: String =
            Sha256::digest(KEY_B64.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        assert_ne!(over_bytes, over_text);
        assert_ne!(&over_bytes[..16], crate::service::key_fingerprint(KEY_B64));
    }
}
