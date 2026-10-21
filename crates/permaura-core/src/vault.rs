//! In-memory secret vault.
//!
//! The vault stores [`SecretRecord`]s (each a [`SealedSecret`] plus metadata) and
//! opens one in a single way, in two forms: [`Vault::use_secret`], and
//! [`Vault::use_secret_cached`], which reuses keys already derived. Each decrypts the
//! secret, lends the plaintext bytes to a caller-supplied closure, and wipes the buffer
//! when the closure returns, fails or panics.
//!
//! There is deliberately **no** method here that returns plaintext to the caller in a
//! plain `Vec` or `String`. The product's first principle ("the model never receives raw
//! secrets") rests on what callers do with the bytes: a connector shapes its upstream
//! request from them, inside the closure or from an [`OpenedSecret`] it is handed,
//! returns only a redacted result, and the response is scrubbed of the credential before
//! an agent sees it.
//!
//! What the types do not do is confine the bytes. The closure is trusted code, and
//! nothing here stops it copying them out (`b.to_vec()`); a closure that keeps the
//! plaintext past the call keeps it in a type that wipes itself, as the gateway does
//! when it moves it into an [`OpenedSecret`]. [`crate::crypto::open`] and
//! [`crate::crypto::KekCache::open`] decrypt without a closure and return the plaintext
//! in a [`Zeroizing`] buffer for the same reason. Wiping covers the buffers these types
//! own and the blocks they outgrow; it does not reach the copies a transport makes when
//! the secret is sent or received, such as an HTTP client's buffers or a child process's
//! environment.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, SealedSecret};
use crate::error::{PermauraError, Result};
use crate::model::{ExecutionLocation, RiskTier};

/// Non-secret metadata describing a stored secret: the
/// `secret_metadata` split (labels, risk classification, allowed execution
/// locations, last-used) kept separate from the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecretMetadata {
    /// Arbitrary labels (e.g. `["financial", "production"]`).
    #[serde(default)]
    pub labels: Vec<String>,
    /// How sensitive the secret itself is.
    #[serde(default = "default_risk")]
    pub risk_classification: RiskTier,
    /// Where this secret is allowed to be used from.
    #[serde(default)]
    pub allowed_execution_locations: Vec<ExecutionLocation>,
    /// Unix-millisecond timestamp of last use, if ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
}

fn default_risk() -> RiskTier {
    RiskTier::High
}

/// A stored secret: its id, the sealed envelope, and its metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecord {
    /// Stable secret id (e.g. `sec_braintree_prod`).
    pub id: String,
    /// The envelope-encrypted secret value.
    pub sealed: SealedSecret,
    /// Non-secret metadata.
    pub metadata: SecretMetadata,
}

/// Plaintext resolved for the duration of a single operation.
///
/// This generalises the discipline of [`Vault::use_secret`] into a guarded *handle*: it
/// owns the plaintext in a [`Zeroizing`] buffer (wiped on drop), lends only `&[u8]`, never
/// prints it, and is deliberately **not** `Clone`. A secret backend (the local vault, Infisical
/// or a KMS) can therefore resolve a secret, including across an `async` boundary, into a
/// value that cannot be cloned or logged and that wipes the plaintext when it drops. The borrow
/// from [`OpenedSecret::bytes`] does not outlive the handle, and the handle should be dropped
/// the instant the call is shaped. Like the vault's closure, whoever holds the borrow is trusted:
/// a copy made from it is that code's to wipe.
pub struct OpenedSecret(Zeroizing<Vec<u8>>);

impl OpenedSecret {
    /// Wrap freshly-resolved plaintext. The `Vec` is moved into a zeroizing buffer; the
    /// caller must keep no other copy.
    pub fn new(plaintext: Vec<u8>) -> Self {
        OpenedSecret(Zeroizing::new(plaintext))
    }

    /// Take plaintext that is already in a zeroizing buffer, as [`crate::crypto::open`] returns it.
    pub fn wrap(plaintext: Zeroizing<Vec<u8>>) -> Self {
        OpenedSecret(plaintext)
    }

    /// Borrow the plaintext bytes. The buffer is zeroized when this handle drops.
    pub fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<crate::secret::SecretString> for OpenedSecret {
    /// Move the text's own buffer into the handle, so the plaintext is not copied on the way.
    fn from(text: crate::secret::SecretString) -> Self {
        OpenedSecret(Zeroizing::new(text.into_bytes_wiped()))
    }
}

impl std::fmt::Debug for OpenedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the plaintext, even in debug output.
        write!(f, "OpenedSecret([redacted; {} bytes])", self.0.len())
    }
}

/// An in-memory collection of sealed secrets. The daemon persists these to an
/// encrypted store; this type holds only the sealed records, and the buffer
/// [`Vault::use_secret`] or [`Vault::use_secret_cached`] decrypts into is wiped when
/// the call returns. What the closure copies out of it is the closure's to wipe.
#[derive(Default)]
pub struct Vault {
    secrets: HashMap<String, SecretRecord>,
}

impl Vault {
    /// Create an empty vault.
    pub fn new() -> Self {
        Vault {
            secrets: HashMap::new(),
        }
    }

    /// Seal `plaintext` under `passphrase` and store it as `id`. Returns the id.
    /// The plaintext slice passed in is the caller's responsibility to zeroize;
    /// from here on only the sealed form is retained.
    pub fn put_secret(
        &mut self,
        id: impl Into<String>,
        passphrase: &[u8],
        plaintext: &[u8],
        metadata: SecretMetadata,
    ) -> Result<String> {
        let id = id.into();
        let sealed = crypto::seal(crypto::Cipher::Aes256Gcm, passphrase, plaintext)?;
        let record = SecretRecord {
            id: id.clone(),
            sealed,
            metadata,
        };
        self.secrets.insert(id.clone(), record);
        Ok(id)
    }

    /// Insert an already-sealed record (e.g. loaded from disk).
    pub fn insert_record(&mut self, record: SecretRecord) {
        self.secrets.insert(record.id.clone(), record);
    }

    /// True if a secret with this id exists.
    pub fn contains(&self, id: &str) -> bool {
        self.secrets.contains_key(id)
    }

    /// Number of stored secrets.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// True if the vault holds no secrets.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Borrow a secret's metadata without touching the ciphertext.
    pub fn metadata(&self, id: &str) -> Option<&SecretMetadata> {
        self.secrets.get(id).map(|r| &r.metadata)
    }

    /// Remove a secret (a per-secret kill switch / rotation step).
    pub fn remove(&mut self, id: &str) -> Option<SecretRecord> {
        self.secrets.remove(id)
    }

    /// Open the secret `id` with `passphrase`, pass the plaintext bytes to `f`,
    /// then wipe the buffer and return `f`'s result.
    ///
    /// The closure receives a `&[u8]` borrow that does not outlive the call, and the
    /// backing buffer is wiped when this method returns, on every error path, and when
    /// `f` panics and the panic unwinds through here. The closure is trusted code: it
    /// can still copy the bytes out (`b.to_vec()`), which nothing here prevents.
    /// Connectors do their upstream HTTP signing here and return only a redacted result.
    pub fn use_secret<T, F>(&self, id: &str, passphrase: &[u8], f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> Result<T>,
    {
        let record = self
            .secrets
            .get(id)
            .ok_or_else(|| PermauraError::NotFound(format!("secret '{id}'")))?;

        let plaintext = crypto::open(&record.sealed, passphrase)?;
        f(&plaintext)
    }

    /// [`Self::use_secret`], opening through `keks` so a record already opened once is not run
    /// through the KDF again.
    pub fn use_secret_cached<T, F>(&self, id: &str, keks: &crypto::KekCache, f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> Result<T>,
    {
        let record = self
            .secrets
            .get(id)
            .ok_or_else(|| PermauraError::NotFound(format!("secret '{id}'")))?;

        let plaintext = keks.open(&record.sealed)?;
        f(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_use_without_exposing_plaintext() {
        let mut vault = Vault::new();
        let pass = b"vault-passphrase";
        vault
            .put_secret("sec_gh", pass, b"ghp_token_123", SecretMetadata::default())
            .unwrap();

        // The access path lends bytes to a closure and returns a derived value.
        let len = vault
            .use_secret("sec_gh", pass, |bytes| Ok(bytes.len()))
            .unwrap();
        assert_eq!(len, "ghp_token_123".len());
    }

    #[test]
    fn closure_sees_correct_bytes() {
        let mut vault = Vault::new();
        let pass = b"p";
        vault
            .put_secret("s", pass, b"hello-secret", SecretMetadata::default())
            .unwrap();
        let header = vault
            .use_secret("s", pass, |bytes| {
                Ok(format!("Bearer {}", String::from_utf8_lossy(bytes)))
            })
            .unwrap();
        assert_eq!(header, "Bearer hello-secret");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let mut vault = Vault::new();
        vault
            .put_secret("s", b"right", b"value", SecretMetadata::default())
            .unwrap();
        let err = vault.use_secret("s", b"wrong", |_| Ok(())).unwrap_err();
        assert!(matches!(err, PermauraError::Crypto(_)));
    }

    #[test]
    fn missing_secret_is_not_found() {
        let vault = Vault::new();
        let err = vault.use_secret("nope", b"p", |_| Ok(())).unwrap_err();
        assert!(matches!(err, PermauraError::NotFound(_)));
    }

    #[test]
    fn metadata_is_accessible_without_passphrase() {
        let mut vault = Vault::new();
        let meta = SecretMetadata {
            labels: vec!["financial".into()],
            risk_classification: RiskTier::Critical,
            allowed_execution_locations: vec![ExecutionLocation::LocalOnly],
            last_used_at: None,
        };
        vault
            .put_secret("s", b"p", b"v", meta.clone())
            .unwrap();
        assert_eq!(vault.metadata("s").unwrap().risk_classification, RiskTier::Critical);
    }

    #[test]
    fn remove_acts_as_kill_switch() {
        let mut vault = Vault::new();
        vault
            .put_secret("s", b"p", b"v", SecretMetadata::default())
            .unwrap();
        assert!(vault.contains("s"));
        vault.remove("s");
        assert!(!vault.contains("s"));
        assert!(vault.use_secret("s", b"p", |_| Ok(())).is_err());
    }
}
