//! Worker private-key custody.
//!
//! [`FileKeystore`] loads (or generates) the worker's ed25519 signing key from a `0600` file.
//! The **public** key is what the worker enrolled with the control plane (`Worker.pubkey`); the
//! **private** key never leaves this host: it only ever signs the relay handshake. The file is the
//! only custody this key has; neither the OS Keychain nor the Secure Enclave holds it.

use std::fs;
use std::io;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

/// A worker signing key stored as a `0600` file of the 32-byte seed.
pub struct FileKeystore {
    path: PathBuf,
}

impl FileKeystore {
    /// A keystore backed by `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileKeystore { path: path.into() }
    }

    /// Load the signing key, generating + persisting a fresh one (`0600`) if the file is absent.
    pub fn load_or_create(&self) -> io::Result<SigningKey> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "worker key file must be 32 bytes")
                })?;
                Ok(SigningKey::from_bytes(&seed))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let sk = SigningKey::generate(&mut rand::rngs::OsRng);
                self.write_key(&sk)?;
                Ok(sk)
            }
            Err(e) => Err(e),
        }
    }

    fn write_key(&self, sk: &SigningKey) -> io::Result<()> {
        // Shared owner-only secret write (`0600` on Unix, atomic `create_new`); creates parent dirs.
        // Only reached when the key is absent (the load path's NotFound arm), so `create_new` refusing
        // to overwrite is exactly right. The DACL is the Windows half of the same guarantee: mode bits
        // do not exist there, and a new file otherwise carries whatever the directory hands down.
        permaura_core::write_secret_file(&self.path, &sk.to_bytes())?;
        permaura_credential_store::restrict_to_owner(&self.path)
    }

    /// The base64 public key to register at enrollment.
    pub fn public_key_b64(sk: &SigningKey) -> String {
        STANDARD.encode(sk.verifying_key().to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reloads_the_same_key() {
        let path = std::env::temp_dir().join(format!("permaura-ks-{}.key", std::process::id()));
        let _ = fs::remove_file(&path);
        let ks = FileKeystore::new(&path);

        let sk1 = ks.load_or_create().unwrap();
        let sk2 = ks.load_or_create().unwrap(); // second call reads the persisted key
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert!(!FileKeystore::public_key_b64(&sk1).is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "worker key must be owner-only");
        }
        let _ = fs::remove_file(&path);
    }
}
