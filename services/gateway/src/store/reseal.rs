//! Re-seal secrets that were written under the public dev KEK.
//!
//! [`crypto::open`] takes one passphrase and has no fallback, so changing a KEK orphans everything
//! sealed under the old one. The old KEK here is not a lost secret though: it is
//! `DEV_VAULT_PASSPHRASE`, a constant compiled into this binary. So the sweep can simply try it: a
//! secret that opens under the dev constant was sealed under it, and gets re-sealed under whatever
//! real KEK this process resolved. A secret sealed under some *other* real KEK fails to open under
//! the dev constant and is left strictly alone.
//!
//! It fixes two populations with one implementation:
//!
//! - **Hosted.** A worker provisioned before a real KEK was injected sealed its connections under the
//!   dev constant, because `PERMAURA_HOSTED` deliberately skips the persistent per-install KEK (a
//!   Cloud Run filesystem is ephemeral, so a regenerated file would orphan the vault on every cold
//!   start). Re-keying such a worker without this sweep destroys the tenant's credentials.
//! - **Self-hosted.** Any install predating the per-install KEK was also sealing under the dev
//!   constant, and upgrading hands it a fresh per-install KEK that cannot open its own stored
//!   secrets: a silent breakage on a routine `npx` upgrade.
//!
//! **This runs on every open, not as a stamped one-shot migration**, and that is the whole design.
//! A worker that boots on this release while still on the dev constant has nothing to re-seal *to*;
//! stamping the work as done at that moment would mean the later re-key (the entire point) found a
//! completed migration and silently orphaned five real connections. The sweep therefore stays armed
//! until a real KEK actually arrives. It is skipped outright while the active KEK *is* the dev
//! constant, so a dev or test process pays nothing.
//!
//! The cost when a real KEK is present is one Argon2 derivation per stored secret per boot, because
//! each secret carries its own salt and the only way to know whether the dev constant opens it is to
//! try. At the handful of secrets an install actually holds that is milliseconds, and it is worth
//! more than a cached "already clean" marker would be: such a marker would have to be trusted across
//! a boot that ran without a real KEK and sealed *new* secrets under the dev constant, which is
//! exactly the case it would then wrongly skip.

use permaura_core::crypto;
use permaura_core::SecretRecord;

use crate::error::GatewayError;
use crate::service::DEV_VAULT_PASSPHRASE;

/// `gateway_meta` key recording the last sweep that actually changed something.
pub(crate) const MARKER_KEY: &str = "dev_kek_reseal";

fn map<E: std::fmt::Display>(e: E) -> GatewayError {
    GatewayError::Internal(format!("dev-KEK re-seal: {e}"))
}

/// Whether a sweep can achieve anything. Re-sealing the dev constant under the dev constant is pure
/// churn, and worse, it would rewrite every row for no gain.
pub(crate) fn is_worth_running(real_kek: &[u8]) -> bool {
    real_kek != DEV_VAULT_PASSPHRASE
}

/// Try the dev constant against one stored `secrets.data` blob. `Ok(None)` means it did not open
/// (either it is already under a real KEK, or under one this binary cannot know), and the row must be
/// left untouched.
///
/// The re-seal keeps the record's cipher and takes fresh [`crypto::KdfParams`], so the new envelope
/// gets a new salt rather than inheriting the one an attacker may already have ground against.
pub(crate) fn reseal_blob(data: &str, real_kek: &[u8]) -> Result<Option<String>, GatewayError> {
    let mut record: SecretRecord = serde_json::from_str(data).map_err(map)?;
    let Ok(plaintext) = crypto::open(&record.sealed, DEV_VAULT_PASSPHRASE) else {
        return Ok(None);
    };
    record.sealed = crypto::seal(record.sealed.cipher, real_kek, &plaintext).map_err(map)?;
    Ok(Some(serde_json::to_string(&record).map_err(map)?))
}

/// Whether one stored `secrets.data` blob opens under the dev constant, which is to say whether the
/// re-seal sweep can still move it to whatever real KEK this process ends up with. A blob this build
/// cannot even parse is not one of those.
pub(crate) fn opens_under_dev(data: &str) -> bool {
    serde_json::from_str::<SecretRecord>(data).is_ok_and(|record| crypto::open(&record.sealed, DEV_VAULT_PASSPHRASE).is_ok())
}

/// The marker value written after a sweep that re-sealed at least one secret. Non-secret by
/// construction: a count and a timestamp, never an id or any key material.
pub(crate) fn marker(count: usize, at_ms: i64) -> String {
    format!(r#"{{"resealed":{count},"at_ms":{at_ms}}}"#)
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// What a completed sweep did, so each store can log and record it identically.
pub(crate) fn report(count: usize) {
    if count > 0 {
        tracing::warn!(
            resealed = count,
            "re-sealed secrets that were stored under the PUBLIC dev KEK; they are now under this install's real KEK. If these were live credentials they should be treated as exposed and rotated at the provider."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permaura_core::crypto::Cipher;
    use permaura_core::vault::SecretMetadata;

    const REAL: &[u8] = b"a-real-kek-that-is-not-the-dev-constant";

    fn record(id: &str, passphrase: &[u8], value: &[u8]) -> SecretRecord {
        SecretRecord {
            id: id.to_string(),
            sealed: crypto::seal(Cipher::Aes256Gcm, passphrase, value).unwrap(),
            metadata: SecretMetadata::default(),
        }
    }

    #[test]
    fn a_dev_sealed_secret_is_resealed_and_the_dev_constant_no_longer_opens_it() {
        let json = serde_json::to_string(&record("s1", DEV_VAULT_PASSPHRASE, b"hunter2")).unwrap();

        let out = reseal_blob(&json, REAL).unwrap().expect("must re-seal a dev-sealed secret");
        let after: SecretRecord = serde_json::from_str(&out).unwrap();

        assert_eq!(crypto::open(&after.sealed, REAL).unwrap().as_slice(), b"hunter2", "value must survive");
        assert!(
            crypto::open(&after.sealed, DEV_VAULT_PASSPHRASE).is_err(),
            "the dev constant must no longer open it"
        );
    }

    #[test]
    fn a_secret_already_under_a_real_kek_is_left_untouched() {
        let json = serde_json::to_string(&record("s2", REAL, b"hunter2")).unwrap();
        assert!(reseal_blob(&json, REAL).unwrap().is_none());
    }

    /// A secret sealed under a KEK this binary has never seen must not be mangled or dropped: the
    /// sweep only ever claims the one key it can prove.
    #[test]
    fn a_secret_under_an_unknown_kek_is_left_untouched() {
        let json = serde_json::to_string(&record("s3", b"some-other-install-kek", b"hunter2")).unwrap();
        assert!(reseal_blob(&json, REAL).unwrap().is_none());
    }

    #[test]
    fn the_sweep_is_skipped_when_the_active_kek_is_still_the_dev_constant() {
        assert!(!is_worth_running(DEV_VAULT_PASSPHRASE));
        assert!(is_worth_running(REAL));
    }

    #[test]
    fn re_sealing_twice_is_stable() {
        let json = serde_json::to_string(&record("s4", DEV_VAULT_PASSPHRASE, b"hunter2")).unwrap();
        let once = reseal_blob(&json, REAL).unwrap().unwrap();
        assert!(reseal_blob(&once, REAL).unwrap().is_none(), "a second sweep must be a no-op");
    }

    #[test]
    fn the_marker_records_only_a_count_and_a_time() {
        assert_eq!(marker(5, 1_700_000_000_000), r#"{"resealed":5,"at_ms":1700000000000}"#);
    }
}
