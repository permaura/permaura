//! The shared `~/.permaura` home directory, resolved the same way on every platform.
//!
//! Everything Permaura persists on a host (the SQLite store, the vault, the relay worker key, the
//! audit signing key, per-host config) lives under one directory. [`permaura_home`] is the single
//! resolver: the `PERMAURA_HOME` override if set, otherwise `<user home>/.permaura`, where the user
//! home comes from `dirs::home_dir()` (`$HOME` on Unix, the user profile / `USERPROFILE` on Windows).
//!
//! It returns `None` when neither the override nor a home directory can be resolved. Callers that
//! write **secrets** (keys, sealed DBs) must treat `None` as a hard error and refuse to write, rather
//! than fall back to a relative path: a `"."` fallback would drop key material into the current
//! working directory, world-readable and easy to leak into a repo.

use std::path::PathBuf;

/// The Permaura home directory: `$PERMAURA_HOME` if set and non-empty, otherwise
/// `<user home>/.permaura`. `None` when neither resolves.
///
/// The override is taken verbatim (already an absolute directory the operator chose); the default
/// appends `.permaura` to the OS-reported home. There is deliberately no relative-path fallback.
/// See the module docs.
pub fn permaura_home() -> Option<PathBuf> {
    if let Some(override_dir) = std::env::var_os("PERMAURA_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(override_dir));
    }
    dirs::home_dir()
        .filter(|home| !home.as_os_str().is_empty())
        .map(|home| home.join(".permaura"))
}

/// [`permaura_home`] joined with `rel`, or `None` when no home resolves. Convenience for the common
/// `~/.permaura/<file>` shape (e.g. `worker.key`, `gateway.db`).
pub fn permaura_path(rel: impl AsRef<std::path::Path>) -> Option<PathBuf> {
    permaura_home().map(|home| home.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env-var reads make these tests order-dependent within one process, so they run under a
    /// process-wide lock and each restores what it changed.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<T>(home: Option<&str>, permaura_home: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev_home = std::env::var_os("HOME");
        let prev_override = std::env::var_os("PERMAURA_HOME");
        match home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match permaura_home {
            Some(v) => std::env::set_var("PERMAURA_HOME", v),
            None => std::env::remove_var("PERMAURA_HOME"),
        }
        let out = f();
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_override {
            Some(v) => std::env::set_var("PERMAURA_HOME", v),
            None => std::env::remove_var("PERMAURA_HOME"),
        }
        out
    }

    #[test]
    fn override_wins_over_home() {
        let got = with_env(Some("/home/alice"), Some("/custom/permaura"), permaura_home);
        assert_eq!(got, Some(PathBuf::from("/custom/permaura")));
    }

    #[test]
    fn defaults_to_home_dot_permaura() {
        // `dirs::home_dir()` derives from $HOME on Unix; this asserts the default shape there. On
        // Windows the profile is read from the OS, so we only assert the override path cross-platform.
        #[cfg(unix)]
        {
            let got = with_env(Some("/home/bob"), None, permaura_home);
            assert_eq!(got, Some(PathBuf::from("/home/bob/.permaura")));
        }
    }

    #[test]
    fn empty_override_is_ignored() {
        #[cfg(unix)]
        {
            let got = with_env(Some("/home/carol"), Some(""), permaura_home);
            assert_eq!(got, Some(PathBuf::from("/home/carol/.permaura")));
        }
    }

    // The macOS-unchanged regression guard: with no override, $HOME/.permaura, byte-for-byte
    // what the earlier HOME-only code produced. Runs on the macOS and Linux CI lanes.
    #[test]
    #[cfg(unix)]
    fn default_is_home_dot_permaura_unchanged() {
        let got = with_env(Some("/Users/x"), None, permaura_home);
        assert_eq!(got, Some(PathBuf::from("/Users/x/.permaura")));
    }

    // permaura_path joins under the resolved home with the OS separator (via the override so the
    // base is deterministic on every platform). This is what every secret/db call site goes through.
    #[test]
    fn permaura_path_joins_under_home() {
        let base = if cfg!(windows) { r"C:\perma" } else { "/perma" };
        let got = with_env(None, Some(base), || permaura_path("gateway.db"));
        assert_eq!(got, Some(PathBuf::from(base).join("gateway.db")));
    }

    // On Windows the override is still read from PERMAURA_HOME (our code, not dirs), and with no
    // override the default resolves to the real user profile + `.permaura` (non-None on a runner).
    // USERPROFILE itself is not overridable in a unit test (`dirs::home_dir()` queries the OS
    // known-folder API, not the env), so the real-profile branch is what the Windows CI lane covers.
    #[test]
    #[cfg(windows)]
    fn windows_override_and_default() {
        let overridden = with_env(None, Some(r"D:\custom\permaura"), permaura_home);
        assert_eq!(overridden, Some(PathBuf::from(r"D:\custom\permaura")));

        let default = with_env(None, None, permaura_home);
        let default = default.expect("a Windows runner has a user profile");
        assert!(
            default.ends_with(".permaura"),
            "default must be <profile>\\.permaura, got {default:?}"
        );
    }
}
