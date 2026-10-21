//! Byte caps on what a single upstream call is allowed to bring back into the gateway's heap.
//!
//! The SSH connector has had real caps since it was written ([`crate::ssh::DEFAULT_EXEC_OUTPUT_BYTES`]
//! for process output, [`crate::ssh::DEFAULT_SFTP_MAX_BYTES`] for transferred bytes) while the HTTP
//! and command connectors read their upstream to EOF. This module holds the two caps that close that
//! gap and the one env-reading helper all three share, so the three connectors agree by class rather
//! than by coincidence: process output is capped at the SSH exec figure, transferred bytes at the
//! SFTP figure.
//!
//! The clamps matter more than the defaults. A response is held three times at peak (the raw bytes,
//! the `serde_json::Value` tree parsed from them, and the clone `permaura_core::redact` makes), so a
//! cap an operator is free to set to anything is a cap that can be set above what the instance can
//! hold.

use std::sync::OnceLock;

/// The default cap on an upstream HTTP response body (5 MiB), matching
/// [`crate::ssh::DEFAULT_SFTP_MAX_BYTES`]: both are "bytes this call moved across the network".
pub const DEFAULT_HTTP_MAX_RESPONSE_BYTES: u64 = 5 * 1024 * 1024;

/// The default cap on each of a command's captured streams (1 MiB), matching
/// [`crate::ssh::DEFAULT_EXEC_OUTPUT_BYTES`]: both are "bytes a process wrote".
pub const DEFAULT_COMMAND_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

/// The floor any configured cap is clamped up to. Below this a legitimate paginated API response
/// would fail, which turns a cost guard into an outage.
pub const MIN_CAP_BYTES: u64 = 16 * 1024;

/// The ceiling any configured cap is clamped down to. At 32 MiB the three peak copies of one
/// response are already about 200 MiB, which is most of a 512 MiB instance; anything above this is
/// not a cap the instance can honour.
pub const MAX_CAP_BYTES: u64 = 32 * 1024 * 1024;

/// Read a byte cap from `var`, clamped into [`MIN_CAP_BYTES`]..=[`MAX_CAP_BYTES`], falling back to
/// `default` when unset or unparseable. Unparseable is deliberately the default rather than a
/// failure: a typo in an env var must not stop a gateway booting.
pub fn cap_from_env(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(MIN_CAP_BYTES, MAX_CAP_BYTES)
}

/// The effective HTTP response cap, read once per process.
pub fn http_max_response_bytes() -> u64 {
    static CAP: OnceLock<u64> = OnceLock::new();
    *CAP.get_or_init(|| {
        cap_from_env(
            "PERMAURA_HTTP_MAX_RESPONSE_BYTES",
            DEFAULT_HTTP_MAX_RESPONSE_BYTES,
        )
    })
}

/// The effective per-stream command output cap, read once per process.
pub fn command_max_output_bytes() -> u64 {
    static CAP: OnceLock<u64> = OnceLock::new();
    *CAP.get_or_init(|| {
        cap_from_env(
            "PERMAURA_COMMAND_MAX_OUTPUT_BYTES",
            DEFAULT_COMMAND_MAX_OUTPUT_BYTES,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_variable_yields_the_default() {
        assert_eq!(
            cap_from_env("PERMAURA_CAP_TEST_UNSET", DEFAULT_HTTP_MAX_RESPONSE_BYTES),
            DEFAULT_HTTP_MAX_RESPONSE_BYTES
        );
    }

    #[test]
    fn a_default_below_the_floor_is_clamped_up() {
        assert_eq!(cap_from_env("PERMAURA_CAP_TEST_UNSET", 4096), MIN_CAP_BYTES);
    }

    #[test]
    fn the_shipped_defaults_sit_inside_the_clamp() {
        // A default outside the clamp would be silently rewritten on every boot, so the default
        // an operator reads in the docs would not be the one running.
        for (name, default) in [
            ("http", DEFAULT_HTTP_MAX_RESPONSE_BYTES),
            ("command", DEFAULT_COMMAND_MAX_OUTPUT_BYTES),
        ] {
            assert_eq!(
                cap_from_env("PERMAURA_CAP_TEST_UNSET", default),
                default,
                "the {name} default is rewritten by the clamp"
            );
        }
    }

    #[test]
    fn the_http_cap_matches_sftp_and_the_command_cap_matches_ssh_exec() {
        assert_eq!(
            DEFAULT_HTTP_MAX_RESPONSE_BYTES,
            crate::ssh::DEFAULT_SFTP_MAX_BYTES
        );
        assert_eq!(
            DEFAULT_COMMAND_MAX_OUTPUT_BYTES,
            crate::ssh::DEFAULT_EXEC_OUTPUT_BYTES
        );
    }
}
