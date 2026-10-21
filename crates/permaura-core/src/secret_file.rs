//! Owner-private writes for secret material at rest.
//!
//! The secret files Permaura writes on a host (the relay worker signing key, the audit signing key,
//! the vault KEK fallback, the published operator bearer, the approver keyring) are created through
//! this module, so only the owner can read them and none exists even momentarily in a
//! group/world-readable state. [`write_secret_file`] creates one; [`replace_secret_file`] replaces
//! one that may already exist.
//!
//! The sealed SQLite store does not go through here: SQLite creates it and its WAL and SHM sidecars
//! at the umask, and the gateway narrows them to owner-only afterward, best effort.
//!
//! On Unix both open the file with mode `0600` from its first byte, so there is no write-then-chmod
//! window, and both put a `0700` directory around it when they are the call that created the
//! directory.
//!
//! On Windows the file is created with a protected DACL granting only the process user and SYSTEM
//! access. The security descriptor is passed to `CreateFileW`, before any content is written. The
//! small `permaura-platform` crate owns the FFI, keeping this core crate unsafe-free.

use std::io;
use std::path::{Path, PathBuf};

/// Create `path` as a fresh owner-private file containing `bytes`, creating any missing parent
/// directories first.
///
/// Uses `create_new`, so it fails with [`io::ErrorKind::AlreadyExists`] if the file already exists:
/// callers write a secret only when generating it (the "absent" branch of a load-or-create), and an
/// existing file must never be silently truncated. Use [`replace_secret_file`] where replacing is the
/// intent. On Unix the file is opened `0600` from its first byte. On Windows the owner-only DACL
/// is supplied at creation.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    ensure_private_parent(path)?;

    let mut file = permaura_platform::create_private_file(path)?;
    file.write_all(bytes)
}

/// Replace `path` with an owner-private file containing `bytes`, whether or not one is already there.
///
/// The secret is written to `.<name>.tmp-<random>` beside the target, created with `create_new` and
/// mode `0600`, flushed to the device, and then renamed over the target. Three properties come out of
/// that, and every one of them is why this exists rather than `fs::write` followed by a `chmod`:
///
/// - The new content is never observable in a non-private state. `fs::write` creates at the umask,
///   so a `0644` window is open between the create and the `set_permissions` that narrows it.
/// - A caller reading the target concurrently sees either the whole old file or the whole new one.
///   `rename` is atomic on POSIX and replaces on Windows.
/// - A failure part-way through leaves the previous secret intact. A truncating write that dies mid
///   way leaves neither the old value nor the new one, which for a KEK means an unopenable vault.
///
/// The temp name is random rather than derived, so nothing can pre-create the path this call is about
/// to write through: `create_new` refuses an existing file, including a symlink someone planted.
/// On Windows the temporary file also receives its protected DACL at creation.
pub fn replace_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let dir = ensure_private_parent(path)?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("{} names no file", path.display()))
    })?;
    let temp = dir.join(format!(".{}.tmp-{}", name.to_string_lossy(), random_suffix()));

    let mut file = permaura_platform::create_private_file(&temp)?;

    // `sync_all` before the rename, not after: a rename that reaches the directory ahead of the
    // content would survive a crash as a target that exists and is empty, which for a key file is
    // worse than either outcome this is choosing between.
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written.and_then(|()| std::fs::rename(&temp, path)) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(())
}

/// Make sure `path`'s directory exists, and is `0700` when this call is what created it, returning it.
///
/// Only when this call created it. Narrowing a directory somebody else made would silently change the
/// permissions of whatever else lives there, and `PERMAURA_HOME` can be a location an operator chose
/// deliberately. A home that already exists and is too wide is the gateway's to warn about at boot.
fn ensure_private_parent(path: &Path) -> io::Result<PathBuf> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(PathBuf::from("."));
    };
    #[cfg_attr(not(unix), allow(unused_variables))]
    let existed = parent.is_dir();
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(parent.to_path_buf())
}

/// A 128-bit hex suffix for the temp file, from the OS entropy source the rest of this crate seals
/// with. Unguessable is the requirement; unique is a consequence.
fn random_suffix() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("permaura-secret-{}-{}", std::process::id(), name))
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn writes_content_and_is_owner_only_on_unix() {
        let path = tmp("write");
        let _ = std::fs::remove_file(&path);
        write_secret_file(&path, b"seedbytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"seedbytes");

        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600, "secret file must be created owner-only");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuses_to_overwrite_existing() {
        let path = tmp("exists");
        let _ = std::fs::remove_file(&path);
        write_secret_file(&path, b"first").unwrap();
        let err = write_secret_file(&path, b"second").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"first", "existing secret must not be truncated");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn creates_missing_parent_dirs() {
        let dir = tmp("nested-dir");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sub").join("key");
        write_secret_file(&path, b"k").unwrap();
        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Replacing must land on `0600` the same way creating does, and must actually replace.
    #[test]
    fn replacing_creates_and_then_replaces_owner_only() {
        let path = tmp("replace");
        let _ = std::fs::remove_file(&path);

        replace_secret_file(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600, "a replaced secret must be created owner-only");

        replace_secret_file(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second", "the replacement must land");
        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600, "and must not inherit the umask on the way");

        let _ = std::fs::remove_file(&path);
    }

    /// A replacement over a file the umask had left `0644` must narrow it, because the whole point is
    /// that the value on disk after this call is private no matter what was there before.
    #[cfg(unix)]
    #[test]
    fn replacing_a_world_readable_file_narrows_it() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("replace-wide");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"was-wide").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        replace_secret_file(&path, b"now-narrow").unwrap();

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"now-narrow");
        let _ = std::fs::remove_file(&path);
    }

    /// No temp file may survive a successful replace, and none may be left behind by a failed one.
    /// A leftover `.name.tmp-…` is a full copy of the secret sitting beside the file that protects it.
    #[test]
    fn a_replace_leaves_no_temp_file_behind() {
        let dir = tmp("replace-temp-dir");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("kek");
        replace_secret_file(&path, b"v1").unwrap();
        replace_secret_file(&path, b"v2").unwrap();

        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "kek")
            .collect();
        assert!(strays.is_empty(), "temp files left beside the secret: {strays:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write that cannot succeed must leave the previous secret exactly as it was. Reaching the
    /// failure through a directory in the target's place is the one way to make the rename fail on
    /// every platform without a fault-injection layer.
    #[test]
    fn a_failed_replace_leaves_the_old_secret_intact() {
        let dir = tmp("replace-fail-dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kek");
        std::fs::create_dir(&path).unwrap();

        assert!(replace_secret_file(&path, b"never-lands").is_err());
        assert!(path.is_dir(), "the target must be untouched by a failed replace");
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "kek")
            .collect();
        assert!(strays.is_empty(), "a failed replace must clean up its temp file: {strays:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The temp file the secret passes through must be as private as the file it becomes, or the
    /// window this whole function exists to close is simply moved to a different name.
    #[cfg(unix)]
    #[test]
    fn the_temp_file_is_owner_only_while_the_secret_is_in_it() {
        let dir = tmp("temp-mode-dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Exercise the production factory used by both writers, before any content is written.
        let temp = dir.join(".kek.tmp-deadbeef");
        let _file = permaura_platform::create_private_file(&temp).unwrap();
        assert_eq!(mode_of(&temp), 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory this call creates for a secret is the owner's alone. One it did not create is left
    /// as it is, because narrowing a directory somebody else made changes what else lives there.
    #[cfg(unix)]
    #[test]
    fn a_directory_created_for_a_secret_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("parent-mode-dir");
        let _ = std::fs::remove_dir_all(&dir);

        replace_secret_file(&dir.join("nested").join("kek"), b"k").unwrap();
        assert_eq!(mode_of(&dir.join("nested")), 0o700, "a directory we created");

        let theirs = dir.join("theirs");
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o755)).unwrap();
        replace_secret_file(&theirs.join("kek"), b"k").unwrap();
        assert_eq!(mode_of(&theirs), 0o755, "a directory that was already there");
        assert_eq!(mode_of(&theirs.join("kek")), 0o600, "but the secret in it is still ours");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
