//! Is this gateway behind the release channel?
//!
//! There is no outbound security-response channel to the installed fleet. `curl | sh` pins an
//! immutable release tag and never self-upgrades, so a critical gateway advisory today has no
//! delivery mechanism at all: the operator finds out if and when they happen to look. This module is
//! the minimum answer: the running process compares its own version against the signed release
//! manifest and says so in `/health`, where a keyword monitor, the console, or a support engineer
//! reading a ticket can all see it.
//!
//! **It never installs anything.** It is a fact in a health document, not an updater.
//!
//! Trust: the manifest lives on a MUTABLE branch of the public dist repo, so its contents are not
//! evidence of anything on their own. What makes the answer trustworthy is the detached Ed25519
//! signature over the exact manifest bytes, verified against a key pinned in this binary, the same
//! `pmrel-2026a` key pinned in the npm CLI, the desktop updater and permaura.com's `/install`. An
//! unverifiable manifest leaves the answer `unknown`; it never downgrades to "trust the JSON".
//!
//! Outbound network: one GET pair, at most every [`REFRESH_INTERVAL`], to a public raw.githubusercontent
//! URL, carrying nothing about this install beyond the request itself. Skipped entirely on a mock or
//! demo posture, and disabled with `PERMAURA_NO_UPGRADE=1` (the same variable the npm CLI already
//! honours) or `PERMAURA_UPDATE_CHECK=0`.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use crate::Posture;

/// The single source of truth for "what's the latest gateway": the same static JSON the npm CLI and
/// the desktop updater read. A debug build takes `PERMAURA_MANIFEST_URL` in its place; see [`dev_override`].
const MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/pixelitemedia/permaura-dist/main/manifests/gateway.json";

/// The manifest this process reads.
pub fn manifest_url() -> String {
    dev_override("PERMAURA_MANIFEST_URL").unwrap_or_else(|| MANIFEST_URL.to_string())
}

/// A non-empty `name` from the environment, honored in a debug build only. The manifest source and the
/// release key are the trust root of `permaura upgrade`, so a release build ignores both and says so:
/// whatever can set its environment (a shell profile, a unit file, a project's settings) could
/// otherwise have it install a gateway signed by a key of its own.
fn dev_override(name: &'static str) -> Option<String> {
    trust_root_override(name, "the pinned release key and manifest")
}

/// A non-empty `name` from the environment, honored in a debug build only; a release build ignores it and says once per process that it trusts only `pinned`. Used for the release key and manifest above, the account API `permaura remote` and pairing talk to, and the control plane every announce link talks to; the authorization server's issuer and JWKS (`PERMAURA_AS_ISSUER`, `PERMAURA_AS_JWKS`) do not pass through it and are honored in any build.
pub fn trust_root_override(name: &'static str, pinned: &str) -> Option<String> {
    trust_root_override_unless(name, pinned, |_| false)
}

/// [`trust_root_override`], except that a release build also honors a value `allowed_in_release` accepts.
pub fn trust_root_override_unless(name: &'static str, pinned: &str, allowed_in_release: fn(&str) -> bool) -> Option<String> {
    static REPORTED: std::sync::Mutex<std::collections::BTreeSet<&'static str>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    let (value, report) =
        override_in(name, std::env::var(name).ok(), cfg!(debug_assertions), allowed_in_release, &REPORTED);
    if report {
        tracing::warn!("{name} is set and ignored: a release build trusts only {pinned}");
        eprintln!("permaura: {name} is set and ignored: a release build trusts only {pinned}.");
    }
    value
}

/// The value a trust-root override takes in a build that is (`debug_build`) or is not a debug build, without the report; see [`trust_root_override_unless`].
pub fn trust_root_override_in(value: Option<String>, debug_build: bool, allowed_in_release: fn(&str) -> bool) -> Option<String> {
    override_in("", value, debug_build, allowed_in_release, &std::sync::Mutex::new(std::collections::BTreeSet::new())).0
}

/// The override `name` takes, and whether this is the call that reports a release build ignoring it: the first per `reported` set, so once per process although the update check asks every cycle.
fn override_in(
    name: &'static str,
    value: Option<String>,
    debug_build: bool,
    allowed_in_release: fn(&str) -> bool,
    reported: &std::sync::Mutex<std::collections::BTreeSet<&'static str>>,
) -> (Option<String>, bool) {
    let Some(value) = value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) else { return (None, false) };
    if debug_build || allowed_in_release(&value) {
        return (Some(value), false);
    }
    (None, reported.lock().unwrap_or_else(|p| p.into_inner()).insert(name))
}

/// An http(s) URL with no userinfo whose host is this machine: `localhost`, `127.0.0.0/8`, `::1` or an IPv4-mapped loopback, judged on the parsed host so `http://127.0.0.1.example` is not.
pub fn is_loopback_http_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else { return false };
    if !matches!(parsed.scheme(), "http" | "https") || !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    let Some(host) = parsed.host_str() else { return false };
    match host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        Err(_) => host == "localhost",
    }
}

/// The release signing keys this binary accepts (Ed25519, SPKI PEM), newest first.
///
/// MUST stay in step with the other three pin sites, or an install verifies on one surface and fails
/// on another:
///   packages/gateway/bin/cli.mjs            → PINNED_RELEASE_PUBKEY_PEMS
///   the desktop app's binary updater        → RELEASE_PUBKEY_PEMS
///   permaura.com's install route            → RELEASE_PUBKEY_PEMS
///
/// **Why a list.** One pinned key cannot be rotated. Sign with a new key and everything pinned to the
/// old one rejects the manifest, with no route back: the thing that would carry the new key is itself
/// signed with it. That is tolerable while every client re-fetches its verifier on each run, and it
/// stopped being tolerable when `npm i -g` became the recommended install, because a launcher then
/// sits on a machine until someone updates it. A set gives rotation an overlap window, and the set has
/// to exist BEFORE the key it will carry, which is why this is a list of one today.
///
/// The rotation procedure is part of the release process. The short version: add the incoming key here and at the
/// other three sites, ship, wait, and only then point CI's signing step at it.
const RELEASE_PUBKEY_PEMS: &[&str] = &[
    // pmrel-2026a, generated 2026-08-03.
    "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAKqPdId97cJ1iXDNMq767UseY9eMKe7jBSOKNzjQp76Q=\n\
-----END PUBLIC KEY-----",
];

/// How often a long-lived gateway re-asks. Deliberately slow: this answers "should someone upgrade",
/// a question whose useful resolution is hours, and a chatty check would be a fleet-wide load on a
/// third party's CDN for no gain.
const REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Wait this long after boot before the first check, so a cold start never blocks behind a network
/// round trip and `/health` answers immediately.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(30);

const UNKNOWN: u8 = 0;
const UP_TO_DATE: u8 = 1;
const BEHIND: u8 = 2;

/// Tri-state rather than a bool: "we have not been able to ask" and "you are current" are different
/// answers, and collapsing them would report every offline or air-gapped gateway as up to date,
/// a green light meaning nothing, which is the failure this whole layer exists to avoid.
static STATE: AtomicU8 = AtomicU8::new(UNKNOWN);

/// Whether a newer gateway than this one has been published. `None` when no manifest has been
/// verified yet: never checked, offline, disabled, or the signature did not verify.
pub fn manifest_behind() -> Option<bool> {
    match STATE.load(Ordering::Relaxed) {
        UP_TO_DATE => Some(false),
        BEHIND => Some(true),
        _ => None,
    }
}

fn truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Whether this process should ask the release channel anything at all.
///
/// A mock or demo gateway is excluded because its version is not a fact about anyone's install, and
/// because a demo estate exists precisely to run with no network. `PERMAURA_NO_UPGRADE` is the npm
/// CLI's existing opt-out, reused so an operator who has already turned off update checking on the
/// launcher does not have to discover a second variable.
fn enabled(posture: Posture) -> bool {
    posture == Posture::Real
        && !truthy("PERMAURA_NO_UPGRADE")
        && std::env::var("PERMAURA_UPDATE_CHECK").as_deref() != Ok("0")
}

/// Start the background refresh. Returns `None` when checking is disabled, so a caller can log the
/// reason rather than silently doing nothing.
pub fn spawn_update_check(posture: Posture) -> Option<tokio::task::JoinHandle<()>> {
    if !enabled(posture) {
        tracing::debug!(posture = posture.as_str(), "release-channel check disabled");
        return None;
    }
    Some(tokio::spawn(async move {
        tokio::time::sleep(FIRST_CHECK_DELAY).await;
        loop {
            check_now().await;
            tokio::time::sleep(REFRESH_INTERVAL).await;
        }
    }))
}

/// One fetch → verify → compare cycle, returning the answer it settled on. Every failure leaves the
/// previous answer in place: a flaky network must not flip a gateway from "behind" to "unknown" and
/// quiet a warning that was true.
///
/// Public so a caller can ask once and now: the background loop, and any on-demand diagnostic that
/// wants the current answer rather than the last cached one.
pub async fn check_now() -> Option<bool> {
    let url = manifest_url();
    match fetch_latest(&url).await {
        Ok(latest) => {
            let running = env!("CARGO_PKG_VERSION");
            let behind = compare_versions(running, &latest) < 0;
            STATE.store(if behind { BEHIND } else { UP_TO_DATE }, Ordering::Relaxed);
            if behind {
                // The console reads `manifest_behind` off `/health` for its banner; this line is for
                // whoever is reading logs instead, and for a headless install that has no console.
                tracing::warn!(
                    running,
                    latest = %latest,
                    "a newer gateway has been published: run `permaura upgrade` (or re-run the installer)"
                );
            } else {
                tracing::debug!(running, latest = %latest, "gateway is current with the release channel");
            }
        }
        Err(e) => tracing::debug!(
            error = %crate::connectors::scrub_urls(&e),
            url = %crate::connectors::scrub_url(&url),
            "could not check the release channel"
        ),
    }
    manifest_behind()
}

/// Fetch the manifest and its detached signature, verify, and return the version it advertises.
async fn fetch_latest(url: &str) -> Result<String, String> {
    let manifest = fetch_verified(url).await?;
    manifest
        .get("version")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim().to_string())
        .ok_or_else(|| "the manifest carries no version".to_string())
}

/// Fetch the release manifest, verify its detached signature against the pinned key, and return the
/// parsed document.
///
/// Public because `permaura upgrade` needs the asset URLs and checksums out of the SAME verified
/// document this module compares versions against: an updater that re-fetched the manifest through
/// its own unverified path would be a second, weaker trust decision about the same bytes.
pub async fn fetch_verified(url: &str) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let raw = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("manifest: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("manifest body: {e}"))?;
    let sig = client
        .get(format!("{url}.sig"))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("signature: {e}"))?
        .text()
        .await
        .map_err(|e| format!("signature body: {e}"))?;

    let accepted = release_pubkeys();
    let accepted: Vec<&str> = accepted.iter().map(String::as_str).collect();
    verify_manifest_signature_any(&raw, &sig, &accepted)?;

    serde_json::from_slice(&raw).map_err(|e| format!("manifest is not JSON: {e}"))
}

/// In a debug build `PERMAURA_RELEASE_PUBKEY` replaces the whole accepted set with one key, which is
/// how the tests drive a throwaway one; a release build keeps the pins ([`dev_override`]).
fn release_pubkeys() -> Vec<String> {
    match dev_override("PERMAURA_RELEASE_PUBKEY") {
        Some(key) => vec![key],
        None => RELEASE_PUBKEY_PEMS.iter().map(|p| (*p).to_string()).collect(),
    }
}

/// Verify a detached Ed25519 signature over the EXACT manifest bytes.
///
/// Detached-over-raw-bytes on purpose (the same contract as the npm CLI's `verifyDetachedSignature`
/// and the desktop updater's copy): signing a field *inside* the JSON would mean canonicalising it
/// first, and every canonicalisation bug is a signature bypass. The bytes verified here are the bytes
/// parsed.
/// Verify against ANY accepted key. The signature's own shape is key-independent, so a malformed one
/// is reported as malformed rather than as "no key matched", which would send the reader hunting for
/// a key problem they do not have.
fn verify_manifest_signature_any(raw: &[u8], sig_b64: &str, pubkey_pems: &[&str]) -> Result<(), String> {
    if pubkey_pems.is_empty() {
        return Err("no release key is pinned, so nothing can be verified".into());
    }
    let mut last = String::new();
    for pem in pubkey_pems {
        match verify_manifest_signature(raw, sig_b64, pem) {
            Ok(()) => return Ok(()),
            // Malformed input is the same answer for every key; stop rather than repeat it.
            Err(e) if e.contains("malformed") || e.contains("not valid base64") => return Err(e),
            Err(e) => last = e,
        }
    }
    if pubkey_pems.len() == 1 {
        return Err(last);
    }
    Err(format!(
        "the release manifest's signature did not verify against any of the {} pinned Permaura release keys",
        pubkey_pems.len()
    ))
}

fn verify_manifest_signature(raw: &[u8], sig_b64: &str, pubkey_pem: &str) -> Result<(), String> {
    use base64::Engine as _;
    use ed25519_dalek::Signature;

    // Parse the SPKI PEM: strip the armour, base64-decode, and take the trailing 32 bytes (an Ed25519
    // SPKI is a fixed 12-byte header followed by the raw key).
    let body: String = pubkey_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim().as_bytes())
        .map_err(|e| format!("the pinned release key is not valid base64: {e}"))?;
    if der.len() < 32 {
        return Err("the pinned release key is too short to be an ed25519 SPKI key".into());
    }
    let raw_key: [u8; 32] = der[der.len() - 32..]
        .try_into()
        .map_err(|_| "the pinned release key is not 32 bytes".to_string())?;
    let vk = permaura_relay::strict_verifying_key(&raw_key)
        .map_err(|e| format!("the pinned release key is not a valid ed25519 key: {e}"))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim().as_bytes())
        .map_err(|_| "the manifest signature is not valid base64".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "the manifest signature is malformed (expected 64 bytes, got {})",
            sig_bytes.len()
        )
    })?;

    vk.verify_strict(raw, &Signature::from_bytes(&sig_arr))
        .map_err(|_| {
            "the release manifest's signature did not verify against the pinned Permaura release key"
                .to_string()
        })
}

/// Dotted-numeric comparison, ignoring a leading `v` and any `-prerelease` suffix. Mirrors the npm
/// CLI's `compareVersions` and the desktop updater's copy, so all three channels agree on which of
/// two releases is newer.
pub fn compare_versions(a: &str, b: &str) -> i32 {
    fn parts(v: &str) -> Vec<u64> {
        v.trim()
            .trim_start_matches('v')
            .split('-')
            .next()
            .unwrap_or("")
            .split('.')
            .map(|n| n.parse::<u64>().unwrap_or(0))
            .collect()
    }
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..pa.len().max(pb.len()) {
        let (x, y) = (
            pa.get(i).copied().unwrap_or(0),
            pb.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return if x < y { -1 } else { 1 };
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn ordering_matches_the_other_channels() {
        assert_eq!(compare_versions("1.2.4", "1.2.4"), 0);
        assert_eq!(compare_versions("1.2.3", "1.2.4"), -1);
        assert_eq!(compare_versions("1.2.4", "1.2.3"), 1);
        assert_eq!(compare_versions("1.10.0", "1.9.0"), 1);
        // A leading `v` and a prerelease suffix are both stripped, so `gateway-v1.2.4`'s version
        // string and a plain `1.2.4` compare equal rather than reading as a downgrade.
        assert_eq!(compare_versions("v1.2.4", "1.2.4"), 0);
        assert_eq!(compare_versions("1.2.4-rc.1", "1.2.4"), 0);
        // Missing components are zero, not "unknown": 1.2 is 1.2.0.
        assert_eq!(compare_versions("1.2", "1.2.0"), 0);
    }

    #[test]
    fn the_pinned_key_parses_as_ed25519() {
        // Guards the pin itself: a mangled paste of the shared PEM would otherwise only surface as a
        // silent "unknown" on every install, months later.
        let err = verify_manifest_signature(b"anything", "AA==", RELEASE_PUBKEY_PEMS[0]).unwrap_err();
        assert!(
            err.contains("malformed"),
            "the key should parse and the SIGNATURE should be what fails, got: {err}"
        );
    }

    #[test]
    fn a_release_build_ignores_the_trust_root_overrides() {
        let reported = std::sync::Mutex::new(std::collections::BTreeSet::new());
        for name in ["PERMAURA_MANIFEST_URL", "PERMAURA_RELEASE_PUBKEY"] {
            assert_eq!(override_in(name, Some("attacker".into()), false, |_| false, &reported).0, None, "{name}");
            assert_eq!(override_in(name, Some(" throwaway ".into()), true, |_| false, &reported).0.as_deref(), Some("throwaway"), "{name}");
            assert_eq!(override_in(name, Some("  ".into()), true, |_| false, &reported).0, None, "{name}");
            assert_eq!(override_in(name, None, true, |_| false, &reported).0, None, "{name}");
        }
    }

    #[test]
    fn an_ignored_override_is_reported_once_per_process() {
        let reported = std::sync::Mutex::new(std::collections::BTreeSet::new());
        let reports = |name| {
            (0..4).filter(|_| override_in(name, Some("attacker".into()), false, |_| false, &reported).1).count()
        };
        assert_eq!(reports("PERMAURA_MANIFEST_URL"), 1);
        assert_eq!(reports("PERMAURA_RELEASE_PUBKEY"), 1);
        assert_eq!(reports("PERMAURA_MANIFEST_URL"), 0);
        assert_eq!(override_in("PERMAURA_RELEASE_PUBKEY", Some("dev".into()), true, |_| false, &reported), (Some("dev".into()), false));
    }

    #[test]
    fn a_wrong_signature_is_refused() {
        let sig = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let err = verify_manifest_signature(b"{}", &sig, RELEASE_PUBKEY_PEMS[0]).unwrap_err();
        assert!(err.contains("did not verify"), "got: {err}");
    }

    /// An Ed25519 SPKI is a fixed 12-byte header followed by the raw 32-byte key, so a PEM can be
    /// built without pulling in a DER encoder just for the tests.
    fn spki_pem(key: &ed25519_dalek::SigningKey) -> String {
        use base64::Engine as _;
        const SPKI_PREFIX: [u8; 12] =
            [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        let mut der = SPKI_PREFIX.to_vec();
        der.extend_from_slice(key.verifying_key().as_bytes());
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
    }

    /// A pinned key is not attacker-chosen, but the release verify is the same primitive as every other: a small-order key with `R = identity, s = 0` must not pass.
    #[test]
    fn a_small_order_key_verifies_no_manifest() {
        use base64::Engine as _;
        const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        let mut der = SPKI_PREFIX.to_vec();
        der.push(1);
        der.extend_from_slice(&[0u8; 31]);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            base64::engine::general_purpose::STANDARD.encode(der)
        );
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let sig = base64::engine::general_purpose::STANDARD.encode(forged);
        assert!(verify_manifest_signature(b"{\"version\":\"99.0.0\"}", &sig, &pem).is_err());
    }

    /// Every pinned key must be usable. A typo in one would otherwise shrink the accepted set in a
    /// shipped binary while the source still claims two, which is exactly the state rotation cannot
    /// survive: you would ship the overlap, believe it was there, and find out when you signed.
    #[test]
    fn every_pinned_release_key_is_a_usable_ed25519_key() {
        assert!(!RELEASE_PUBKEY_PEMS.is_empty(), "a gateway with no pinned key verifies nothing");
        let sig = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        for pem in RELEASE_PUBKEY_PEMS {
            let err = verify_manifest_signature(b"{}", &sig, pem).unwrap_err();
            assert!(
                err.contains("did not verify"),
                "pin should parse and only the SIGNATURE should fail, got: {err}"
            );
        }
    }

    /// Rotation's whole point: a manifest signed by the incoming key verifies on a client that still
    /// lists the outgoing one first. Without this the overlap window does not exist.
    #[test]
    fn a_signature_from_any_accepted_key_verifies() {
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};

        let outgoing = SigningKey::from_bytes(&[7u8; 32]);
        let incoming = SigningKey::from_bytes(&[8u8; 32]);
        let msg = b"{\"version\":\"9.9.9\"}";
        let sig = base64::engine::general_purpose::STANDARD.encode(incoming.sign(msg).to_bytes());
        let accepted = [spki_pem(&outgoing), spki_pem(&incoming)];
        let accepted: Vec<&str> = accepted.iter().map(String::as_str).collect();

        verify_manifest_signature_any(msg, &sig, &accepted).expect("the incoming key must verify");

        // And a key outside the set is still refused, however many are listed.
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let bad = base64::engine::general_purpose::STANDARD.encode(attacker.sign(msg).to_bytes());
        let err = verify_manifest_signature_any(msg, &bad, &accepted).unwrap_err();
        assert!(err.contains("did not verify against any of the 2"), "got: {err}");
    }

    #[test]
    fn an_unchecked_gateway_reports_unknown_not_current() {
        // The default. Reporting `false` here would tell every offline install it was up to date.
        assert_eq!(manifest_behind(), None);
    }

    #[test]
    fn checking_is_off_for_mock_and_demo_postures() {
        assert!(!enabled(Posture::Mock));
        assert!(!enabled(Posture::Demo));
    }
}
