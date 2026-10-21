//! Envelope encryption for secret material.
//!
//! The scheme:
//!
//! ```text
//! secret_value  → encrypted with a random per-secret DEK   (AES-256-GCM or ChaCha20-Poly1305)
//! DEK           → wrapped by a vault KEK                    (same AEAD family)
//! KEK           → derived from a passphrase via Argon2id
//! ```
//!
//! The passphrase is the gateway's KEK: its own per-install key, or one handed over on stdin or
//! at a file path, which is how a hosted gateway receives it. A secret kept in a KMS custody is
//! not sealed with this envelope at all.
//!
//! A [`SealedSecret`] carries everything needed to re-open the secret *given the
//! passphrase*: the ciphertext, its nonce, the wrapped DEK, the DEK's wrap nonce,
//! and the KDF parameters (salt + cost) so the KEK can be re-derived deterministically.
//! No plaintext, no DEK, and no KEK are ever serialized.
//!
//! All transient key material (`Kek`, `Dek`) is [`Zeroize`]d on drop so it does not
//! linger in freed memory longer than necessary, and [`open`], [`open_with_kek`] and
//! [`KekCache::open`] return the plaintext in a [`Zeroizing`] buffer, so it is wiped when the
//! caller drops it.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{PermauraError, Result};

/// Length of an AEAD key (256 bits) for both AES-256-GCM and ChaCha20-Poly1305.
const KEY_LEN: usize = 32;
/// Length of the 96-bit nonce used by both AEADs.
const NONCE_LEN: usize = 12;
/// Length of the Argon2id salt.
const SALT_LEN: usize = 16;

/// The AEAD cipher used to seal a payload. Both are 256-bit-key, 96-bit-nonce,
/// 128-bit-tag AEADs; the choice is recorded in [`SealedSecret`] so opening picks
/// the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Cipher {
    /// AES-256-GCM, hardware-accelerated on most modern CPUs.
    #[default]
    Aes256Gcm,
    /// ChaCha20-Poly1305, constant-time in software.
    ChaCha20Poly1305,
}

/// Argon2id cost parameters, persisted alongside the salt so a KEK can be
/// re-derived from the same passphrase later. Defaults are a sane interactive
/// profile; callers can dial them up for higher-value vaults.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KdfParams {
    /// Random per-vault salt (base of the KDF). 16 bytes.
    pub salt: Vec<u8>,
    /// Memory cost in KiB.
    pub mem_cost_kib: u32,
    /// Number of iterations (time cost).
    pub time_cost: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl KdfParams {
    /// Generate fresh parameters with a random salt and interactive cost defaults.
    pub fn generate() -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        KdfParams {
            salt,
            // 19 MiB / 2 passes / 1 lane is a common interactive Argon2id profile.
            mem_cost_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
        }
    }

    /// The hasher for these parameters and how many memory blocks it works in.
    fn argon2(&self) -> Result<(Argon2<'static>, usize)> {
        let params = Params::new(
            self.mem_cost_kib,
            self.time_cost,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|e| PermauraError::KeyDerivation(e.to_string()))?;
        let blocks = params.block_count();
        Ok((Argon2::new(Algorithm::Argon2id, Version::V0x13, params), blocks))
    }
}

/// A 256-bit key-encryption key derived from a passphrase. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Kek([u8; KEY_LEN]);

impl Kek {
    /// Derive a KEK from a passphrase and [`KdfParams`] using Argon2id.
    pub fn derive(passphrase: &[u8], params: &KdfParams) -> Result<Self> {
        let mut key = [0u8; KEY_LEN];
        let (argon2, blocks) = params.argon2()?;
        // The working memory determines the key, so it is wiped rather than freed as it was.
        let mut memory = Zeroizing::new(vec![argon2::Block::default(); blocks]);
        argon2
            .hash_password_into_with_memory(passphrase, &params.salt, &mut key, memory.as_mut_slice())
            .map_err(|e| PermauraError::KeyDerivation(e.to_string()))?;
        drop(memory);
        let kek = Kek(key);
        key.zeroize();
        Ok(kek)
    }
}

/// A random 256-bit per-secret data-encryption key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; KEY_LEN]);

impl Dek {
    /// Generate a fresh random DEK from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Dek(key)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_LEN {
            return Err(PermauraError::Crypto("invalid DEK length".into()));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Dek(key))
    }
}

/// A sealed secret: the full envelope, safe to persist. Contains no plaintext and
/// no usable key material on its own: opening requires the originating passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    /// Which AEAD sealed both the payload and the DEK.
    pub cipher: Cipher,
    /// The secret plaintext, encrypted under the DEK.
    pub ciphertext: Vec<u8>,
    /// Nonce used to encrypt the payload.
    pub nonce: Vec<u8>,
    /// The DEK, encrypted ("wrapped") under the KEK.
    pub wrapped_dek: Vec<u8>,
    /// Nonce used to wrap the DEK.
    pub dek_nonce: Vec<u8>,
    /// KDF parameters needed to re-derive the KEK from the passphrase.
    pub kdf_params: KdfParams,
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

/// Encrypt `plaintext` with `key` under the selected `cipher`. `aad` is authenticated
/// but not encrypted. Returns `(nonce, ciphertext)`.
fn aead_seal(cipher: Cipher, key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = random_nonce();
    let ciphertext = match cipher {
        Cipher::Aes256Gcm => {
            let aead = Aes256Gcm::new(key.into());
            aead.encrypt(AesNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        }
        Cipher::ChaCha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(key.into());
            aead.encrypt(ChaNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        }
    }
    .map_err(|_| PermauraError::Crypto("AEAD encryption failed".into()))?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt `ciphertext` with `key` under the selected `cipher`, verifying `aad`.
fn aead_open(
    cipher: Cipher,
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(PermauraError::Crypto("invalid nonce length".into()));
    }
    let plaintext = match cipher {
        Cipher::Aes256Gcm => {
            let aead = Aes256Gcm::new(key.into());
            aead.decrypt(AesNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        }
        Cipher::ChaCha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(key.into());
            aead.decrypt(ChaNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        }
    }
    .map_err(|_| PermauraError::Crypto("AEAD decryption/authentication failed".into()))?;
    Ok(plaintext)
}

/// Seal `plaintext` into a [`SealedSecret`] under a passphrase-derived KEK.
///
/// A fresh DEK and fresh [`KdfParams`] (random salt) are generated for this secret;
/// the DEK encrypts the payload and is itself wrapped by the KEK.
pub fn seal(cipher: Cipher, passphrase: &[u8], plaintext: &[u8]) -> Result<SealedSecret> {
    seal_with_params(cipher, passphrase, plaintext, KdfParams::generate())
}

/// Like [`seal`] but with caller-supplied KDF parameters (e.g. to reuse a vault salt).
pub fn seal_with_params(
    cipher: Cipher,
    passphrase: &[u8],
    plaintext: &[u8],
    kdf_params: KdfParams,
) -> Result<SealedSecret> {
    let kek = Kek::derive(passphrase, &kdf_params)?;
    let dek = Dek::generate();

    // Encrypt the payload under the DEK.
    let (nonce, ciphertext) = aead_seal(cipher, &dek.0, plaintext, b"permaura-secret-v1")?;
    // Wrap the DEK under the KEK.
    let (dek_nonce, wrapped_dek) = aead_seal(cipher, &kek.0, &dek.0, b"permaura-dek-v1")?;

    Ok(SealedSecret {
        cipher,
        ciphertext,
        nonce,
        wrapped_dek,
        dek_nonce,
        kdf_params,
    })
}

/// Open a [`SealedSecret`] back to plaintext, given the originating passphrase.
///
/// The KEK is re-derived from the passphrase + stored KDF params, the DEK is
/// unwrapped, and the payload decrypted. The intermediate KEK and DEK are zeroized
/// on drop. Returns [`PermauraError::Crypto`] uniformly on any failure (wrong
/// passphrase, tampered ciphertext, tampered AAD) so callers cannot use the error
/// to distinguish failure modes.
///
/// The plaintext comes back in the buffer it was decrypted into, wrapped in [`Zeroizing`], so it is
/// wiped wherever the caller drops it, on every path including a panic. A caller that copies it out
/// takes on wiping the copy.
pub fn open(sealed: &SealedSecret, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let kek = Kek::derive(passphrase, &sealed.kdf_params)?;
    open_with_kek(sealed, &kek)
}

/// Open a [`SealedSecret`] with a KEK already derived from its own [`KdfParams`]. Fails exactly as
/// [`open`] does when the KEK is not the one that sealed it, and returns the plaintext the same way.
pub fn open_with_kek(sealed: &SealedSecret, kek: &Kek) -> Result<Zeroizing<Vec<u8>>> {
    // A temporary copy of key material, wiped on the error path as well as after the copy into `dek`.
    let dek_bytes = Zeroizing::new(aead_open(
        sealed.cipher,
        &kek.0,
        &sealed.dek_nonce,
        &sealed.wrapped_dek,
        b"permaura-dek-v1",
    )?);
    let dek = Dek::from_bytes(&dek_bytes)?;
    drop(dek_bytes);

    aead_open(
        sealed.cipher,
        &dek.0,
        &sealed.nonce,
        &sealed.ciphertext,
        b"permaura-secret-v1",
    )
    .map(Zeroizing::new)
}

/// One passphrase and the KEKs already derived from it, keyed by the [`KdfParams`] (salt included)
/// each came from, so a long-running process opening the same records over and over pays for
/// Argon2id once per record rather than once per use.
///
/// The derivation is deterministic and the cache holds the passphrase it derives from, so a cached
/// KEK exposes nothing the process did not already hold; what it removes is the KDF's working set
/// (19 MiB at the default cost) and its CPU time from every execution. On a 512 MiB worker that
/// working set was the memory: glibc keeps a freed block of that size in the arena that served it,
/// so each concurrent execution left one more behind.
///
/// Bounded, and emptied rather than grown past the bound. Keys sit behind an `Arc`, so a map that
/// reallocates moves pointers rather than key bytes, and each key is zeroized when its last holder
/// drops it.
pub struct KekCache {
    passphrase: zeroize::Zeroizing<Vec<u8>>,
    entries: std::sync::Mutex<std::collections::HashMap<KdfParams, std::sync::Arc<Kek>>>,
    capacity: usize,
}

impl KekCache {
    /// The number of distinct records a cache holds keys for before it starts again.
    pub const DEFAULT_CAPACITY: usize = 256;

    /// An empty cache for `passphrase` with [`Self::DEFAULT_CAPACITY`].
    pub fn new(passphrase: impl Into<Vec<u8>>) -> Self {
        Self::with_capacity(passphrase, Self::DEFAULT_CAPACITY)
    }

    /// An empty cache for `passphrase` that holds at most `capacity` keys.
    pub fn with_capacity(passphrase: impl Into<Vec<u8>>, capacity: usize) -> Self {
        KekCache {
            passphrase: zeroize::Zeroizing::new(passphrase.into()),
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// How many keys are held.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// True when no key is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Open `sealed` under this cache's passphrase, deriving its KEK only when this cache has not
    /// already.
    ///
    /// A key is remembered only after it has opened its record, so a record sealed under another
    /// passphrase, or tampered with, never takes a slot. The plaintext comes back as [`open`] returns it.
    pub fn open(&self, sealed: &SealedSecret) -> Result<Zeroizing<Vec<u8>>> {
        let held = self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&sealed.kdf_params)
            .cloned();
        if let Some(kek) = held {
            return open_with_kek(sealed, &kek);
        }
        let kek = std::sync::Arc::new(Kek::derive(&self.passphrase, &sealed.kdf_params)?);
        let plaintext = open_with_kek(sealed, &kek)?;
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if entries.len() >= self.capacity {
            entries.clear();
        }
        entries.insert(sealed.kdf_params.clone(), kek);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap KDF params so tests stay fast. Real callers use KdfParams::generate().
    fn fast_params() -> KdfParams {
        let mut p = KdfParams::generate();
        p.mem_cost_kib = 256;
        p.time_cost = 1;
        p.parallelism = 1;
        p
    }

    #[test]
    fn aes_round_trip() {
        let pass = b"correct horse battery staple";
        let secret = b"sk_live_braintree_private_key";
        let sealed = seal_with_params(Cipher::Aes256Gcm, pass, secret, fast_params()).unwrap();
        let opened = open(&sealed, pass).unwrap();
        assert_eq!(opened.as_slice(), secret);
    }

    #[test]
    fn chacha_round_trip() {
        let pass = b"a different passphrase";
        let secret = b"ghp_github_token_value_here";
        let sealed =
            seal_with_params(Cipher::ChaCha20Poly1305, pass, secret, fast_params()).unwrap();
        let opened = open(&sealed, pass).unwrap();
        assert_eq!(opened.as_slice(), secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let sealed = seal_with_params(Cipher::Aes256Gcm, b"right", b"top secret", fast_params())
            .unwrap();
        let err = open(&sealed, b"wrong").unwrap_err();
        assert!(matches!(err, PermauraError::Crypto(_)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed =
            seal_with_params(Cipher::Aes256Gcm, b"pass", b"top secret", fast_params()).unwrap();
        // Flip a bit in the payload ciphertext; the AEAD tag must reject it.
        sealed.ciphertext[0] ^= 0x01;
        assert!(open(&sealed, b"pass").is_err());
    }

    #[test]
    fn tampered_wrapped_dek_fails() {
        let mut sealed =
            seal_with_params(Cipher::Aes256Gcm, b"pass", b"top secret", fast_params()).unwrap();
        sealed.wrapped_dek[0] ^= 0xFF;
        assert!(open(&sealed, b"pass").is_err());
    }

    #[test]
    fn sealed_secret_serializes_without_plaintext() {
        let secret = b"super-secret-token";
        let sealed = seal_with_params(Cipher::Aes256Gcm, b"pass", secret, fast_params()).unwrap();
        let json = serde_json::to_string(&sealed).unwrap();
        // The plaintext bytes must not appear anywhere in the serialized envelope.
        assert!(!json.contains("super-secret-token"));
        // And it must round-trip.
        let back: SealedSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(open(&back, b"pass").unwrap().as_slice(), secret);
    }

    #[test]
    fn a_cached_kek_opens_exactly_what_open_does() {
        let sealed = seal_with_params(Cipher::Aes256Gcm, b"pass", b"top secret", fast_params()).unwrap();
        let cache = KekCache::new(b"pass".to_vec());
        assert_eq!(cache.open(&sealed).unwrap(), open(&sealed, b"pass").unwrap());
        assert_eq!(cache.len(), 1);
        // The second open is served by the held key, and still authenticates the record.
        assert_eq!(cache.open(&sealed).unwrap().as_slice(), b"top secret");
        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 0x01;
        assert!(cache.open(&tampered).is_err());
    }

    #[test]
    fn a_cache_never_opens_a_record_another_passphrase_sealed() {
        let sealed = seal_with_params(Cipher::Aes256Gcm, b"right", b"top secret", fast_params()).unwrap();
        let wrong = KekCache::new(b"wrong".to_vec());
        assert!(matches!(wrong.open(&sealed).unwrap_err(), PermauraError::Crypto(_)));
        assert!(wrong.is_empty(), "a key that opened nothing is not remembered");
    }

    #[test]
    fn a_full_cache_starts_again_rather_than_growing() {
        let cache = KekCache::with_capacity(b"pass".to_vec(), 2);
        for _ in 0..5 {
            let sealed = seal_with_params(Cipher::Aes256Gcm, b"pass", b"x", fast_params()).unwrap();
            assert_eq!(cache.open(&sealed).unwrap().as_slice(), b"x");
            assert!(cache.len() <= 2);
        }
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce_and_dek() {
        let a = seal_with_params(Cipher::Aes256Gcm, b"pass", b"same", fast_params()).unwrap();
        let b = seal_with_params(Cipher::Aes256Gcm, b"pass", b"same", fast_params()).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.wrapped_dek, b.wrapped_dek);
    }
}
